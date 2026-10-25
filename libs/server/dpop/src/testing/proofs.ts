import { randomUUID } from 'node:crypto';

import { CompactSign, type CryptoKey, exportJWK, generateKeyPair, type JWK } from 'jose';

import type { DpopReplayStore } from '../lib/replay-store';

/**
 * Test helpers: keys, proofs and a replay store, for this library's tests
 * only. Not exported from the package.
 */

/** A key pair for signing test proofs. */
export interface TestKey {
  readonly alg: string;
  readonly privateKey: CryptoKey;
  /** The public JWK, as a proof's `jwk` header carries it. */
  readonly publicJwk: JWK;
  /** The private JWK, for the cases that put private members in a header. */
  readonly privateJwk: JWK;
}

/** A fresh key pair for `alg`. */
export async function testKey(alg = 'ES256'): Promise<TestKey> {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  return {
    alg,
    privateKey,
    publicJwk: await exportJWK(publicKey),
    privateJwk: await exportJWK(privateKey),
  };
}

/** What a test proof says; a member set to `undefined` is left out. */
export interface ProofParts {
  readonly key: TestKey;
  readonly header?: Record<string, unknown>;
  readonly claims?: Record<string, unknown>;
}

/** The test proofs' default request. */
export const TEST_METHOD = 'POST';
export const TEST_URL = 'https://auth.example.com/oauth/token';

function withoutUndefined(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([, member]) => member !== undefined));
}

/**
 * A signed proof for {@link TEST_METHOD} {@link TEST_URL} at `iat`, with a
 * fresh `jti`, overridden by `header` and `claims`.
 */
export async function signProof(parts: ProofParts & { readonly iat: number }): Promise<string> {
  const header = withoutUndefined({
    typ: 'dpop+jwt',
    alg: parts.key.alg,
    jwk: parts.key.publicJwk,
    ...parts.header,
  });
  const claims = withoutUndefined({
    jti: randomUUID(),
    htm: TEST_METHOD,
    htu: TEST_URL,
    iat: parts.iat,
    ...parts.claims,
  });
  return new CompactSign(new TextEncoder().encode(JSON.stringify(claims)))
    .setProtectedHeader(header as { alg: string })
    .sign(parts.key.privateKey);
}

/** A compact JWS from raw parts, signed or not: for headers jose will not sign. */
export function rawJws(
  header: Record<string, unknown>,
  claims: unknown,
  signature = 'c2lnbmF0dXJl'
): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode(header)}.${encode(claims)}.${signature}`;
}

/** An in-memory replay store over a manual clock, recording every call. */
export interface FakeReplayStore extends DpopReplayStore {
  readonly calls: Array<{ key: string; ttlMs: number }>;
  readonly entries: Map<string, number>;
}

export function fakeReplayStore(now: () => number): FakeReplayStore {
  const entries = new Map<string, number>();
  const calls: Array<{ key: string; ttlMs: number }> = [];
  return {
    calls,
    entries,
    async record(key, ttlMs) {
      calls.push({ key, ttlMs });
      const expiresAt = entries.get(key);
      if (expiresAt !== undefined && expiresAt > now()) return false;
      entries.set(key, now() + ttlMs);
      return true;
    },
  };
}
