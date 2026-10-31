import { createSecretKey, type KeyObject } from 'node:crypto';

import type { FastifyInstance } from 'fastify';

/**
 * The realm cookie keys this process signs and verifies its cookies with
 * (ADR-019 Decision 3 and Decision 9, issue #493).
 *
 * The signer hands the browser-facing role the realm's cookie HMAC secrets
 * (`getCookieSecrets`): the current one, which signs new cookies, and the
 * previous one, the one the last rotation retired, which only verifies the
 * cookies it signed. This module keeps them in memory, per realm, and reads
 * them again at most once per {@link COOKIE_KEY_REFRESH_INTERVAL_MS}, so a
 * request with a warm cache makes no signer call. A rotation reaches this
 * process within one interval, or as soon as a cookie names a key this process
 * does not know yet ({@link CookieKeyRing.find}): another node may already
 * sign with it.
 *
 * Each secret is imported into a `KeyObject` and the buffer the signer handed
 * out is zeroed at once, so no plaintext copy stays on the JavaScript heap.
 */

/** How long a realm's cookie keys are trusted before the signer is asked again, in ms. */
export const COOKIE_KEY_REFRESH_INTERVAL_MS = 60_000;

/**
 * The shortest time between two reads that a cookie naming an unknown key
 * forces, per realm, in ms. Without it, a stream of made-up `kid`s would turn
 * every request into a signer call.
 */
export const COOKIE_KEY_FORCED_REFRESH_INTERVAL_MS = 5_000;

/**
 * What {@link CookieKeyRing.find} found for a `kid`:
 *
 * - `found`: the realm's current or previous key has it;
 * - `absent`: neither has it, after a read of the signer made for this `kid`,
 *   which reads its store again too: no key of the realm verifies the cookie;
 * - `unchecked`: neither has it, and a read for an unknown `kid` was already
 *   made within {@link COOKIE_KEY_FORCED_REFRESH_INTERVAL_MS}: the key may be
 *   one this process has not read yet.
 */
export type CookieKeyLookup =
  | { readonly status: 'found'; readonly key: CookieKey }
  | { readonly status: 'absent' }
  | { readonly status: 'unchecked' };

/** One cookie key: its `kid` and the HMAC-SHA256 secret, which never leaves this module's callers. */
export interface CookieKey {
  readonly kid: string;
  readonly key: KeyObject;
}

/** A realm's cookie keys, as the signer last returned them. */
export interface RealmCookieKeys {
  /** Signs new cookies, and verifies them. */
  readonly current: CookieKey;
  /** Only verifies cookies signed before the last rotation; `null` when there is none. */
  readonly previous: CookieKey | null;
}

/** The cookie keys of every realm this process serves. */
export interface CookieKeyRing {
  /**
   * The realm's cookie keys, read from the signer when the cached ones are
   * older than the refresh interval.
   *
   * @throws the signer's error: `SignerKeyNotFoundError` when the realm has no
   *   active cookie key, `TemporarilyUnavailableError` when this process
   *   cannot reach the signer. Nothing is cached then.
   */
  keys(realmId: string): Promise<RealmCookieKeys>;
  /**
   * The realm's key named `kid`, the current or the previous one. A `kid`
   * neither names makes one more read of the signer, naming that `kid` so the
   * signer reads its store again too, at most once per
   * {@link COOKIE_KEY_FORCED_REFRESH_INTERVAL_MS} per realm: another process
   * may already sign with a key this one has not read yet.
   *
   * @throws as {@link keys}
   */
  find(realmId: string, kid: string): Promise<CookieKeyLookup>;
}

/** What {@link createCookieKeyRing} reads the secrets from: the signer. */
export type CookieSecretSource = Pick<FastifyInstance['signer'], 'getCookieSecrets'>;

/** What a cookie helper needs of the Fastify instance: its signer. */
export interface CookieKeyHolder {
  readonly signer: CookieSecretSource;
}

/** Options of {@link createCookieKeyRing}. */
export interface CookieKeyRingOptions {
  /** How long a realm's keys are trusted, in ms. {@link COOKIE_KEY_REFRESH_INTERVAL_MS} by default. */
  readonly refreshIntervalMs?: number;
  /** The clock, in epoch ms. `Date.now` by default. */
  readonly now?: () => number;
}

/**
 * The signer's caller name. In a single deployment every role shares one
 * process, so it is `local`, as for every other signer call of the auth
 * server; the remote signer (#497) takes the caller's role from its client
 * certificate instead.
 */
const SIGNER_CALLER = 'local';

interface CachedKeys {
  readonly keys: RealmCookieKeys;
  readonly readAt: number;
}

/** Create a key ring over `source`. Each ring keeps its own cache. */
export function createCookieKeyRing(
  source: CookieSecretSource,
  options: CookieKeyRingOptions = {}
): CookieKeyRing {
  const refreshIntervalMs = options.refreshIntervalMs ?? COOKIE_KEY_REFRESH_INTERVAL_MS;
  // Read through `Date` at each call, so a test that moves the clock moves this one too.
  const now = options.now ?? (() => Date.now());
  const cache = new Map<string, CachedKeys>();
  const pending = new Map<string, Promise<CachedKeys>>();
  /** Per realm: when a read for an unknown `kid` last started. */
  const forcedAt = new Map<string, number>();

  /**
   * One signer read per realm at a time, concurrent callers sharing it; a
   * read for an unknown `kid` is its own, as it asks the signer for more.
   */
  function read(realmId: string, kid?: string): Promise<CachedKeys> {
    const slot = kid === undefined ? realmId : `${realmId}\u0000forced`;
    let shared = pending.get(slot);
    if (shared === undefined) {
      const readAt = now();
      const request =
        kid === undefined
          ? source.getCookieSecrets(SIGNER_CALLER, realmId)
          : source.getCookieSecrets(SIGNER_CALLER, realmId, { kid });
      shared = request
        .then((secrets) => {
          const entry: CachedKeys = {
            keys: Object.freeze({
              current: importKey(secrets.current),
              previous: secrets.previous === null ? null : importKey(secrets.previous),
            }),
            readAt,
          };
          const held = cache.get(realmId);
          if (held === undefined || held.readAt <= readAt) cache.set(realmId, entry);
          return entry;
        })
        .finally(() => {
          pending.delete(slot);
        });
      pending.set(slot, shared);
    }
    return shared;
  }

  async function cached(realmId: string, trustedForMs: number): Promise<CachedKeys> {
    const entry = cache.get(realmId);
    if (entry !== undefined && now() - entry.readAt < trustedForMs) return entry;
    return read(realmId);
  }

  return Object.freeze({
    async keys(realmId: string): Promise<RealmCookieKeys> {
      return (await cached(realmId, refreshIntervalMs)).keys;
    },

    async find(realmId: string, kid: string): Promise<CookieKeyLookup> {
      const known = named((await cached(realmId, refreshIntervalMs)).keys, kid);
      if (known !== null) return { status: 'found', key: known };
      const last = forcedAt.get(realmId);
      if (last !== undefined && now() - last < COOKIE_KEY_FORCED_REFRESH_INTERVAL_MS) {
        return { status: 'unchecked' };
      }
      forcedAt.set(realmId, now());
      const again = named((await read(realmId, kid)).keys, kid);
      return again === null ? { status: 'absent' } : { status: 'found', key: again };
    },
  });
}

function named(keys: RealmCookieKeys, kid: string): CookieKey | null {
  if (keys.current.kid === kid) return keys.current;
  if (keys.previous !== null && keys.previous.kid === kid) return keys.previous;
  return null;
}

/** Import a secret the signer handed out, then zero the buffer: it belongs to this caller. */
function importKey(secret: { readonly kid: string; readonly secret: Buffer }): CookieKey {
  try {
    return Object.freeze({ kid: secret.kid, key: createSecretKey(secret.secret) });
  } finally {
    secret.secret.fill(0);
  }
}

/** The key ring of each signer: one per server, since each server has its own signer. */
const rings = new WeakMap<object, CookieKeyRing>();

/**
 * The key ring of `fastify`'s signer, created on first use. Every cookie of
 * the auth server goes through it, so the whole process shares one cache.
 */
export function cookieKeyRing(fastify: CookieKeyHolder): CookieKeyRing {
  const { signer } = fastify;
  if (signer === undefined || signer === null) {
    throw new Error('The cookie keys come from fastify.signer, which this instance does not have');
  }
  let ring = rings.get(signer);
  if (ring === undefined) {
    ring = createCookieKeyRing(signer);
    rings.set(signer, ring);
  }
  return ring;
}
