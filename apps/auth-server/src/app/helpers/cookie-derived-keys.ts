import { createSecretKey, type KeyObject } from 'node:crypto';

import type { CookieDerivedKeySource } from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance } from 'fastify';

/**
 * THE KEYS DERIVED FROM A REALM'S COOKIE KEY, AS THIS PROCESS HOLDS THEM
 * (ADR-017 Decision 7, ADR-019 Decision 9, issue #497).
 *
 * The failure ladder's identifier and end-user IP digests and the emailed
 * code's digest are HMACs under keys derived from the realm's current cookie
 * secret, one per label. The signer derives them (`getCookieDerivedKey`) and
 * hands them to every role that makes those digests, `api` among them, which
 * may not hold the cookie secret itself: the derived keys make no cookie.
 * Every process of a realm so keys an account the same way, whichever role
 * serves the route.
 *
 * This module keeps each realm's keys in memory, one per label, and reads
 * them again at most once per {@link COOKIE_DERIVED_KEY_REFRESH_INTERVAL_MS},
 * as the cookie key ring (`cookie-keys.ts`) reads the secrets: a sign-in with
 * a warm cache makes no signer call, and a rotation of the cookie key reaches
 * the digests within a minute of it. Each key is imported into a `KeyObject`
 * and the buffer the signer handed out is zeroed at once; a digest is handed
 * a fresh export of it, which the digest zeroes once used.
 */

/** How long a realm's derived keys are trusted before the signer is asked again, in ms. */
export const COOKIE_DERIVED_KEY_REFRESH_INTERVAL_MS = 60_000;

/** What the derived keys are read from: the signer. */
export type CookieDerivedKeyReader = Pick<FastifyInstance['signer'], 'getCookieDerivedKey'>;

/** What a digest helper needs of the Fastify instance: its signer. */
export interface CookieDerivedKeyHolder {
  readonly signer: CookieDerivedKeyReader;
}

/** Options of {@link createCookieDerivedKeyRing}. */
export interface CookieDerivedKeyRingOptions {
  /** How long a realm's keys are trusted, in ms. {@link COOKIE_DERIVED_KEY_REFRESH_INTERVAL_MS} by default. */
  readonly refreshIntervalMs?: number;
  /** The clock, in epoch ms. `Date.now` by default. */
  readonly now?: () => number;
}

/**
 * The signer's caller name: `local`, as for every other signer call of the
 * auth server. The signer service takes the caller's role from its client
 * certificate instead, and hands derived keys to `web` and `api`.
 */
const SIGNER_CALLER = 'local';

interface CachedKey {
  readonly key: KeyObject;
  readonly readAt: number;
}

/**
 * The derived keys over `source`, one cache per call. Concurrent reads of one
 * realm's key for one label share one signer call; nothing is cached when it
 * fails, so the digest that asked fails with the signer's error.
 */
export function createCookieDerivedKeyRing(
  source: CookieDerivedKeyReader,
  options: CookieDerivedKeyRingOptions = {}
): CookieDerivedKeySource {
  const refreshIntervalMs = options.refreshIntervalMs ?? COOKIE_DERIVED_KEY_REFRESH_INTERVAL_MS;
  // Read through `Date` at each call, so a test that moves the clock moves this one too.
  const now = options.now ?? (() => Date.now());
  const cache = new Map<string, CachedKey>();
  const pending = new Map<string, Promise<KeyObject>>();

  function read(slot: string, realmId: string, label: string): Promise<KeyObject> {
    let shared = pending.get(slot);
    if (shared === undefined) {
      const readAt = now();
      shared = source
        .getCookieDerivedKey(SIGNER_CALLER, { realmId, label })
        .then(({ key }) => {
          let imported: KeyObject;
          try {
            imported = createSecretKey(key);
          } finally {
            key.fill(0);
          }
          const held = cache.get(slot);
          if (held === undefined || held.readAt <= readAt)
            cache.set(slot, { key: imported, readAt });
          return imported;
        })
        .finally(() => {
          pending.delete(slot);
        });
      pending.set(slot, shared);
    }
    return shared;
  }

  return Object.freeze({
    async derivedKey(realmId: string, label: string): Promise<Buffer> {
      const slot = `${realmId}\u0000${label}`;
      const entry = cache.get(slot);
      const key =
        entry !== undefined && now() - entry.readAt < refreshIntervalMs
          ? entry.key
          : await read(slot, realmId, label);
      return key.export();
    },
  });
}

/** The derived keys of each signer: one per server, since each server has its own signer. */
const rings = new WeakMap<object, CookieDerivedKeySource>();

/**
 * The derived keys of `fastify`'s signer, created on first use. Every digest
 * of the auth server goes through it, so the whole process shares one cache.
 */
export function cookieDerivedKeyRing(fastify: CookieDerivedKeyHolder): CookieDerivedKeySource {
  const { signer } = fastify;
  if (signer === undefined || signer === null) {
    throw new Error(
      'The derived cookie keys come from fastify.signer, which this instance does not have'
    );
  }
  let ring = rings.get(signer);
  if (ring === undefined) {
    ring = createCookieDerivedKeyRing(signer);
    rings.set(signer, ring);
  }
  return ring;
}
