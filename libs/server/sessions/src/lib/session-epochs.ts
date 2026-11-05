import { z } from 'zod';

import type { SessionLogger } from './ports';

/**
 * EACH USER'S SESSION EPOCH (#642; ADR-017 Decision 8, ADR-019 Decision 3):
 * when the user's password was last reset. A browser session, or a sign-in in
 * progress, created no later than that belongs to the old password and is
 * treated as absent.
 *
 * Postgres is the source of truth (`user_session_epochs`, advanced in the
 * reset's transaction); Redis is a cache in front of it, as for the sessions
 * themselves. A read takes the cache first and Postgres on a miss, then fills
 * the cache only where it is still empty (`SET NX`). A reset publishes the
 * epoch it committed over whatever the cache holds. So a fill that read
 * Postgres before the reset committed and writes after the publish changes
 * nothing, and one that writes before the publish is overwritten by it. A
 * user never reset is cached too, as `null`, so the common case costs one
 * Redis read.
 *
 * A cache that fails or is slow is skipped: the read goes to Postgres. A
 * Postgres read that fails throws, so the caller refuses rather than keeps a
 * session it could not check. A publish that fails leaves the cache stale for
 * at most its TTL; the reset itself revokes the user's sessions in Postgres,
 * which the epoch only backs up.
 */

/**
 * The Redis commands the epoch cache sends. An `ioredis` client fits; the
 * library does not depend on one.
 */
export interface SessionEpochRedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode: 'PX', milliseconds: number): Promise<unknown>;
  set(
    key: string,
    value: string,
    mode: 'PX',
    milliseconds: number,
    condition: 'NX'
  ): Promise<unknown>;
}

/** The Postgres port: the epoch row of a user, `undefined` for a user never reset. */
export interface SessionEpochStore {
  find(realmId: string, userId: string): Promise<{ readonly advancedAt: number } | undefined>;
}

/** A user's session epoch, as {@link SessionEpochs} reads and publishes it. */
export interface SessionEpochOwner {
  readonly realmId: string;
  readonly userId: string;
}

/** The session epochs of every user, through the cache. */
export interface SessionEpochs {
  /**
   * When the user's password was last reset, in epoch ms, or `null` when it
   * never was.
   *
   * @throws when Postgres cannot be read and the cache had no answer
   */
  lastReset(owner: SessionEpochOwner): Promise<number | null>;
  /**
   * Write the epoch a committed reset advanced to over whatever the cache
   * holds. Rejects when Redis fails; the caller reports it.
   */
  publish(owner: SessionEpochOwner & { readonly advancedAt: number }): Promise<void>;
}

/** How long an epoch stays cached when nothing publishes a new one: the session cache's TTL. */
export const DEFAULT_SESSION_EPOCH_CACHE_TTL_SECONDS = 60;

/** How long one cache call may take before the read goes to Postgres. */
export const DEFAULT_SESSION_EPOCH_CACHE_TIMEOUT_MS = 250;

/** Options of {@link createSessionEpochs}. */
export interface SessionEpochsOptions {
  readonly store: SessionEpochStore;
  readonly redis: SessionEpochRedisClient;
  readonly logger: SessionLogger;
  /** {@link DEFAULT_SESSION_EPOCH_CACHE_TTL_SECONDS} by default. */
  readonly cacheTtlSeconds?: number;
  /** {@link DEFAULT_SESSION_EPOCH_CACHE_TIMEOUT_MS} by default. */
  readonly cacheTimeoutMs?: number;
}

/** The layout version of a cache entry. A change of layout raises it. */
const ENTRY_VERSION = 1;

/**
 * A cache entry as stored. A value that does not match is read as a miss, so
 * a corrupt or foreign value never stands for an epoch.
 */
const entrySchema = z.strictObject({
  v: z.literal(ENTRY_VERSION),
  advancedAt: z.number().int().positive().nullable(),
});

/**
 * The key of a user's epoch in the cache. The realm is part of it, and the
 * user id is a hash tag, so a Redis Cluster keeps it on one slot.
 */
export function sessionEpochCacheKey(realmId: string, userId: string): string {
  return `session-epoch:${realmId}:{${userId}}`;
}

class SessionEpochCacheTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`The session epoch cache did not answer within ${timeoutMs} ms`);
    this.name = 'SessionEpochCacheTimeoutError';
  }
}

function positive(name: string, value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`session epochs: ${name} must be a positive number`);
  }
  return value;
}

function encode(advancedAt: number | null): string {
  return JSON.stringify({ v: ENTRY_VERSION, advancedAt });
}

/** The cached epoch: a number, `null` for a user never reset, or `undefined` for a miss. */
function decode(raw: string | null | undefined): number | null | undefined {
  if (raw === null || raw === undefined) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  const entry = entrySchema.safeParse(parsed);
  return entry.success ? entry.data.advancedAt : undefined;
}

/** The epochs of every user, over Postgres and its Redis cache (see the module comment). */
export function createSessionEpochs(options: SessionEpochsOptions): SessionEpochs {
  const { store, redis, logger } = options;
  const ttlMs =
    positive(
      'cacheTtlSeconds',
      options.cacheTtlSeconds ?? DEFAULT_SESSION_EPOCH_CACHE_TTL_SECONDS
    ) * 1000;
  const timeoutMs = positive(
    'cacheTimeoutMs',
    options.cacheTimeoutMs ?? DEFAULT_SESSION_EPOCH_CACHE_TIMEOUT_MS
  );

  /** A cache call, given up after `timeoutMs`; its late failure is ignored. */
  function bounded<T>(call: Promise<T>): Promise<T> {
    call.catch(() => undefined);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new SessionEpochCacheTimeoutError(timeoutMs)), timeoutMs);
    });
    return Promise.race([call, timeout]).finally(() => clearTimeout(timer));
  }

  return Object.freeze({
    async lastReset({ realmId, userId }: SessionEpochOwner): Promise<number | null> {
      const key = sessionEpochCacheKey(realmId, userId);
      try {
        const cached = decode(await bounded(redis.get(key)));
        if (cached !== undefined) return cached;
      } catch (error) {
        logger.warn({ err: error, realmId }, 'Session epoch cache read failed; reading Postgres');
      }
      const row = await store.find(realmId, userId);
      const advancedAt = row === undefined ? null : row.advancedAt;
      if (advancedAt !== null && (!Number.isSafeInteger(advancedAt) || advancedAt <= 0)) {
        throw new Error('session epochs: the stored epoch is not a time');
      }
      try {
        await bounded(redis.set(key, encode(advancedAt), 'PX', ttlMs, 'NX'));
      } catch (error) {
        logger.warn({ err: error, realmId }, 'Session epoch cache fill failed');
      }
      return advancedAt;
    },

    async publish({
      realmId,
      userId,
      advancedAt,
    }: SessionEpochOwner & { readonly advancedAt: number }): Promise<void> {
      if (!Number.isSafeInteger(advancedAt) || advancedAt <= 0) {
        throw new Error('session epochs: an epoch is a positive time in epoch ms');
      }
      await bounded(
        redis.set(sessionEpochCacheKey(realmId, userId), encode(advancedAt), 'PX', ttlMs)
      );
    },
  });
}
