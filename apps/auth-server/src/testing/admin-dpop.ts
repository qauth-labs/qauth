import { createHash, randomUUID } from 'node:crypto';

import type { FastifyInstance } from 'fastify';
import { calculateJwkThumbprint, CompactSign, exportJWK, generateKeyPair, type JWK } from 'jose';

/**
 * TEST SUPPORT — DPoP-bound admin tokens (#520).
 *
 * Every call to the admin listener carries a token bound to a DPoP key
 * (`cnf.jkt`) under the `DPoP` scheme, and a proof made with that key for the
 * request's method and for ADMIN_API_BASE_URL followed by its path. A suite
 * boots the listener with {@link ADMIN_LISTENER_ENVIRONMENT}, mints its admin
 * tokens with {@link signBoundAccessToken}, which remembers each token's key,
 * and sends each call with {@link adminCallHeaders}.
 */

/** The ADMIN_API_BASE_URL the suites boot the admin listener with. */
export const TEST_ADMIN_API_BASE_URL = 'http://admin.qauth.test';

/** The environment that turns the admin listener on: DPoP and the base URL its proofs name. */
export const ADMIN_LISTENER_ENVIRONMENT: Readonly<Record<string, string>> = Object.freeze({
  ADMIN_API_ENABLED: 'true',
  ADMIN_API_BASE_URL: TEST_ADMIN_API_BASE_URL,
  DPOP_ENABLED: 'true',
});

/** A client's DPoP key: the private key it signs proofs with, and its RFC 7638 thumbprint. */
export interface DpopTestKey {
  readonly privateKey: CryptoKey;
  readonly jwk: JWK;
  readonly thumbprint: string;
}

/** A fresh ES256 DPoP key. */
export async function dpopTestKey(): Promise<DpopTestKey> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return { privateKey, jwk, thumbprint: await calculateJwkThumbprint(jwk, 'sha256') };
}

/** What one proof says; `claims` overrides any member, `undefined` leaves it out. */
export interface ProofOptions {
  readonly method: string;
  /** The full URL the proof is for, its query and fragment ignored. */
  readonly url: string;
  /** The token sent with the proof: its hash becomes `ath`. */
  readonly accessToken?: string;
  readonly claims?: Readonly<Record<string, unknown>>;
}

/** A DPoP proof (RFC 9449 §4.2) signed with `key`, with a fresh `jti` and `iat` now. */
export async function dpopProof(key: DpopTestKey, options: ProofOptions): Promise<string> {
  const claims = Object.fromEntries(
    Object.entries({
      jti: randomUUID(),
      htm: options.method,
      htu: options.url.split(/[?#]/, 1)[0],
      iat: Math.floor(Date.now() / 1000),
      ...(options.accessToken === undefined
        ? {}
        : { ath: createHash('sha256').update(options.accessToken).digest('base64url') }),
      ...options.claims,
    }).filter(([, value]) => value !== undefined)
  );
  return new CompactSign(new TextEncoder().encode(JSON.stringify(claims)))
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk })
    .sign(key.privateKey);
}

/** The key of each token {@link signBoundAccessToken} minted. */
const keysOfTokens = new Map<string, DpopTestKey>();

/** The key `token` is bound to, when {@link signBoundAccessToken} minted it. */
export function keyOfToken(token: string): DpopTestKey | undefined {
  return keysOfTokens.get(token);
}

/** Remember that `token`, made by hand with `cnf.jkt`, is bound to `key`. */
export function rememberTokenKey(token: string, key: DpopTestKey): void {
  keysOfTokens.set(token, key);
}

/**
 * An access token of `realm`, signed with its keys, bound to `key` (a fresh
 * one by default) through `cnf.jkt`. The key is remembered, so
 * {@link adminCallHeaders} finds it from the token alone.
 */
export async function signBoundAccessToken(
  app: FastifyInstance,
  realm: Parameters<FastifyInstance['jwtUtils']['signAccessToken']>[0],
  claims: Parameters<FastifyInstance['jwtUtils']['signAccessToken']>[1],
  key?: DpopTestKey
): Promise<string> {
  const bound = key ?? (await dpopTestKey());
  const token = await app.jwtUtils.signAccessToken(realm, {
    ...claims,
    cnf: { jkt: bound.thumbprint },
  });
  keysOfTokens.set(token, bound);
  return token;
}

/** How {@link adminCallHeaders} makes the proof, beside the token's own key. */
export interface AdminCallOptions {
  /** Sign the proof with this key instead of the token's. */
  readonly key?: DpopTestKey;
  /** The base URL the proof names; ADMIN_API_BASE_URL by default. */
  readonly baseUrl?: string;
  /** Members of the proof to override. */
  readonly claims?: Readonly<Record<string, unknown>>;
}

/**
 * The headers of an admin call with `token`: `Authorization: DPoP <token>`
 * and, when the token's key is known (or `options.key` is given), a `DPoP`
 * proof for `method` and the base URL followed by `path`, with the token's
 * `ath`. A token of unknown key goes without a proof.
 */
export async function adminCallHeaders(
  token: string,
  method: string,
  path: string,
  options: AdminCallOptions = {}
): Promise<Record<string, string>> {
  const key = options.key ?? keyOfToken(token);
  const headers: Record<string, string> = { authorization: `DPoP ${token}` };
  if (key !== undefined) {
    headers['dpop'] = await dpopProof(key, {
      method,
      url: `${options.baseUrl ?? TEST_ADMIN_API_BASE_URL}${path}`,
      accessToken: token,
      ...(options.claims === undefined ? {} : { claims: options.claims }),
    });
  }
  return headers;
}
