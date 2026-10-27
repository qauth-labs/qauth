import { randomUUID } from 'node:crypto';

import { generateSigningKeyPair } from '@qauth-labs/core-crypto';
import { type CryptoKey, exportJWK, type JWK } from 'jose';
import { type Mock, vi } from 'vitest';

import type { EgressGetResult } from '../app/helpers/egress-get';

/**
 * TEST SUPPORT — a fake enterprise IdP for the ID-JAG key resolver (#433), and
 * an in-memory Redis whose `EX` expiry runs on a clock the test moves.
 *
 * The issuer answers what the resolver fetches through the SSRF-guarded
 * fetcher: wire it with `egressGet.mockImplementation((_fastify, url) => idp.fetch(url))`. It counts
 * every fetch of each document, rotates its signing key, goes down and hangs
 * on demand, so a test can state "N requests cost one refresh" or "an outage costs
 * one attempt per window" in fetches the issuer actually saw.
 */

/** Which of the issuer's two documents fail while it is down. */
export type FakeIdJagIssuerOutage = 'discovery' | 'jwks';

export interface FakeIdJagIssuer {
  /** The issuer identifier, as `ID_JAG_TRUSTED_ISSUERS` lists it. */
  readonly issuer: string;
  /** The `kid` of the key the issuer publishes and signs with now. */
  readonly kid: string;
  /** The private half of that key, for signing assertions. */
  readonly privateKey: CryptoKey;
  /** How many times each document was fetched since the last {@link resetFetches}. */
  readonly fetches: { readonly discovery: number; readonly jwks: number };
  /** Discovery and JWKS fetches together. */
  totalFetches(): number;
  resetFetches(): void;
  /** Answer one fetch as `egressGet` would: a 200, or a transport error while down. */
  fetch(url: string): Promise<EgressGetResult>;
  /** Publish a new key under a new `kid` and withdraw the old one. */
  rotate(): Promise<void>;
  /** Fail fetches of the named documents (both by default) until {@link comeBack}. */
  goDown(documents?: readonly FakeIdJagIssuerOutage[]): void;
  comeBack(): void;
  /**
   * Hold every fetch from now on unanswered, as a host that drops packets does
   * until the fetch timeout, until {@link release}. Fetches are counted when
   * they arrive, not when they are answered.
   */
  hang(): void;
  /** Answer the held fetches, as the issuer is at that moment (up or down). */
  release(): void;
}

/** Create a fake issuer publishing one Ed25519 key under `kid` `key-1`. */
export async function createFakeIdJagIssuer(
  issuer = 'https://idp.example.com'
): Promise<FakeIdJagIssuer> {
  const discoveryUrl = `${issuer}/.well-known/openid-configuration`;
  const jwksUri = `${issuer}/jwks.json`;

  let generation = 0;
  let current: { kid: string; privateKey: CryptoKey; publicJwk: JWK };
  const down = new Set<FakeIdJagIssuerOutage>();
  const fetches = { discovery: 0, jwks: 0 };
  let held: { promise: Promise<void>; open: () => void } | undefined;

  async function newKey(): Promise<void> {
    generation += 1;
    const { privateKey, publicKey } = await generateSigningKeyPair('EdDSA', { extractable: true });
    const kid = `key-${generation}`;
    current = { kid, privateKey, publicJwk: { ...(await exportJWK(publicKey)), kid } };
  }
  await newKey();

  function respond(document: FakeIdJagIssuerOutage, body: unknown): EgressGetResult {
    if (down.has(document)) {
      throw new Error(`connect ECONNREFUSED (fake issuer ${document} is down)`);
    }
    return { status: 200, body: JSON.stringify(body), headers: {} };
  }

  return {
    issuer,
    get kid() {
      return current.kid;
    },
    get privateKey() {
      return current.privateKey;
    },
    fetches,
    totalFetches: () => fetches.discovery + fetches.jwks,
    resetFetches() {
      fetches.discovery = 0;
      fetches.jwks = 0;
    },
    async fetch(url) {
      let document: FakeIdJagIssuerOutage;
      if (url === discoveryUrl) document = 'discovery';
      else if (url === jwksUri) document = 'jwks';
      else throw new Error(`unexpected fetch: ${url}`);

      fetches[document] += 1;
      if (held) await held.promise;
      return document === 'discovery'
        ? respond('discovery', { issuer, jwks_uri: jwksUri })
        : respond('jwks', { keys: [current.publicJwk] });
    },
    rotate: newKey,
    goDown(documents = ['discovery', 'jwks']) {
      for (const document of documents) down.add(document);
    },
    comeBack() {
      down.clear();
    },
    hang() {
      let open = () => undefined as void;
      const promise = new Promise<void>((resolve) => {
        open = resolve;
      });
      held = { promise, open };
    },
    release() {
      held?.open();
      held = undefined;
    },
  };
}

/** A signing key the issuer never published, under a random `kid`. */
export async function strangerKey(): Promise<{ kid: string; privateKey: CryptoKey }> {
  const { privateKey } = await generateSigningKeyPair('EdDSA', { extractable: true });
  return { kid: `forged-${randomUUID()}`, privateKey };
}

/**
 * The slice of ioredis `fastify.redis` the ID-JAG paths use — `get` and
 * `set key value [EX seconds] [NX]` — with expiry on a manual clock.
 *
 * `EX` is validated as Redis validates it (a positive integer), so passing an
 * unset setting fails the test instead of storing a key that never expires.
 */
export interface ExpiringRedis {
  get: Mock<(key: string) => Promise<string | null>>;
  set: Mock<(key: string, value: string, ...options: (string | number)[]) => Promise<'OK' | null>>;
  /** Move the clock forward; a key whose `EX` has run out is gone, as in Redis. */
  advance(seconds: number): void;
  /** The keys held now, expired ones excluded. */
  keys(): string[];
}

export function createExpiringRedis(): ExpiringRedis {
  let nowMs = 0;
  const entries = new Map<string, { value: string; expiresAt: number }>();

  function live(key: string) {
    const entry = entries.get(key);
    if (entry && entry.expiresAt <= nowMs) {
      entries.delete(key);
      return undefined;
    }
    return entry;
  }

  return {
    get: vi.fn(async (key: string) => live(key)?.value ?? null),
    set: vi.fn(async (key: string, value: string, ...options: (string | number)[]) => {
      let expiresAt = Number.POSITIVE_INFINITY;
      let onlyIfAbsent = false;
      for (let i = 0; i < options.length; i += 1) {
        const option = options[i];
        if (option === 'EX') {
          const seconds = options[i + 1];
          if (typeof seconds !== 'number' || !Number.isInteger(seconds) || seconds <= 0) {
            throw new Error("ERR invalid expire time in 'set' command");
          }
          expiresAt = nowMs + seconds * 1000;
          i += 1;
        } else if (option === 'NX') {
          onlyIfAbsent = true;
        } else {
          throw new Error(`fake redis: unsupported SET option ${String(option)}`);
        }
      }
      if (onlyIfAbsent && live(key)) return null;
      entries.set(key, { value, expiresAt });
      return 'OK';
    }),
    advance(seconds: number) {
      nowMs += seconds * 1000;
    },
    keys() {
      return [...entries.keys()].filter((key) => live(key) !== undefined);
    },
  };
}
