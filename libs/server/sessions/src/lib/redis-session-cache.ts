import { z } from 'zod';

import type { SessionCache, SessionCacheLookup } from './ports';
import type { CachedSession } from './types';

/**
 * The Redis commands the session cache sends. An `ioredis` client fits; the
 * library does not depend on one.
 */
export interface SessionRedisClient {
  mget(...keys: string[]): Promise<(string | null)[]>;
  set(key: string, value: string, mode: 'PX', milliseconds: number): Promise<unknown>;
  del(...keys: string[]): Promise<number>;
}

/** The layout version of a cache entry. A change of layout raises it. */
const ENTRY_VERSION = 1;

const lifetimeSeconds = z.number().nullable();

/**
 * A cache entry as stored. A value that does not match is read as a miss, so
 * a corrupt or foreign value can never come back as a session.
 */
const entrySchema = z.object({
  v: z.literal(ENTRY_VERSION),
  record: z.object({
    id: z.string(),
    realmId: z.string(),
    userId: z.string(),
    authTime: z.number(),
    amr: z.array(z.string()),
    assuranceLevel: z.enum(['substantial', 'high']).nullable(),
    expiresAt: z.number(),
    createdAt: z.number(),
    lastSeenAt: z.number(),
  }),
  lifetimes: z.object({
    maxLifespanSeconds: lifetimeSeconds,
    idleTimeoutSeconds: lifetimeSeconds,
  }),
  freshUntil: z.number(),
});

/**
 * The key of a session's cache entry. The realm is part of it, and the `sid`
 * is a hash tag, so the entry and its tombstone share a Redis Cluster slot and
 * one `MGET` reads both.
 */
export function sessionCacheKey(realmId: string, sid: string): string {
  return `browser-session:${realmId}:{${sid}}`;
}

/** The key of a session's revocation tombstone. */
export function sessionTombstoneKey(realmId: string, sid: string): string {
  return `${sessionCacheKey(realmId, sid)}:revoked`;
}

function parseEntry(raw: string): CachedSession | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  const result = entrySchema.safeParse(parsed);
  if (!result.success) return null;
  const { record, lifetimes, freshUntil } = result.data;
  return { record, lifetimes, freshUntil };
}

function ttlOf(ttlMs: number): number {
  // Redis refuses a PX of 0; a positive fraction of a millisecond rounds up.
  return Math.max(1, Math.ceil(ttlMs));
}

/**
 * The session cache over Redis (ADR-019 Decision 3). Its own keys
 * (`browser-session:…`), apart from the generic `session:` store that still
 * holds the other short-lived flow records.
 *
 * A revocation writes the tombstone first and deletes the entry second, and a
 * read takes both in one `MGET`: a tombstone wins over any entry, so a fill
 * racing the revocation cannot bring the session back.
 */
export function createRedisSessionCache(redis: SessionRedisClient): SessionCache {
  return {
    async read(realmId: string, sid: string): Promise<SessionCacheLookup> {
      const [raw, tombstone] = await redis.mget(
        sessionCacheKey(realmId, sid),
        sessionTombstoneKey(realmId, sid)
      );
      if (tombstone !== null && tombstone !== undefined) return { kind: 'revoked' };
      if (raw === null || raw === undefined) return { kind: 'empty' };
      const entry = parseEntry(raw);
      return entry === null ? { kind: 'empty' } : { kind: 'entry', entry };
    },

    async write(entry: CachedSession, ttlMs: number): Promise<void> {
      const value = JSON.stringify({
        v: ENTRY_VERSION,
        record: entry.record,
        lifetimes: entry.lifetimes,
        freshUntil: entry.freshUntil,
      });
      await redis.set(
        sessionCacheKey(entry.record.realmId, entry.record.id),
        value,
        'PX',
        ttlOf(ttlMs)
      );
    },

    async markRevoked(realmId: string, sid: string, ttlMs: number): Promise<void> {
      await redis.set(sessionTombstoneKey(realmId, sid), '1', 'PX', ttlOf(ttlMs));
      await redis.del(sessionCacheKey(realmId, sid));
    },
  };
}
