import type { AuthMethodEgress } from '@qauth-labs/server-federation';
import type { JWK } from 'jose';

import type { UpstreamIdTokenAlgorithm } from './config';
import { invalidResponse } from './errors';
import { TtlCache } from './ttl-cache';
import {
  jsonObjectBody,
  UPSTREAM_OIDC_CALL_CAPS,
  UPSTREAM_OIDC_PURPOSES,
  upstreamCall,
} from './upstream-call';

/**
 * The provider's JSON Web Key Set, fetched through the egress client and
 * kept in this process, by the rule QAuth's own docs give relying parties
 * for its JWKS (ADR-019 Decision 9): keep it at most five minutes, and fetch
 * it again for an unknown `kid` at most once a minute.
 */

/** How long a fetched key set is used, in milliseconds. */
export const UPSTREAM_JWKS_TTL_MS = 5 * 60 * 1000;

/** How often an unknown `kid` may fetch the key set again, in milliseconds. */
export const UPSTREAM_JWKS_REFRESH_INTERVAL_MS = 60 * 1000;

/** The most keys a provider's key set may hold. */
export const MAX_UPSTREAM_JWKS_KEYS = 64;

/** How many key sets one method keeps. */
const MAX_CACHED_KEY_SETS = 256;

/** Members of a JWK that hold private or secret key material. */
const SECRET_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const;

/** The members of a published key the client reads, each a string. */
const STRING_MEMBERS = ['kty', 'kid', 'alg', 'use', 'crv', 'x', 'y', 'n', 'e'] as const;

/** The key type, and the curve where there is one, each algorithm verifies with. */
const KEY_FAMILY: Readonly<
  Record<UpstreamIdTokenAlgorithm, { readonly kty: string; readonly crv?: string }>
> = Object.freeze({
  RS256: { kty: 'RSA' },
  RS384: { kty: 'RSA' },
  RS512: { kty: 'RSA' },
  PS256: { kty: 'RSA' },
  PS384: { kty: 'RSA' },
  PS512: { kty: 'RSA' },
  ES256: { kty: 'EC', crv: 'P-256' },
  ES384: { kty: 'EC', crv: 'P-384' },
  ES512: { kty: 'EC', crv: 'P-521' },
  EdDSA: { kty: 'OKP', crv: 'Ed25519' },
});

/**
 * Parse a key set document: a `keys` list of 1 to
 * {@link MAX_UPSTREAM_JWKS_KEYS} public keys. A key that carries private or
 * secret material refuses the whole set: a provider that publishes one is
 * broken or hostile. Only the members the client reads are kept.
 *
 * @throws UpstreamOidcError `invalid_response` when the document fails a check
 */
export function parseJwks(document: Record<string, unknown>): readonly JWK[] {
  const purpose = UPSTREAM_OIDC_PURPOSES.jwks;
  const keys = Object.hasOwn(document, 'keys') ? document['keys'] : undefined;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > MAX_UPSTREAM_JWKS_KEYS) {
    throw invalidResponse(
      `${purpose}: the key set is not a list of 1 to ${MAX_UPSTREAM_JWKS_KEYS} keys`
    );
  }
  return Object.freeze(
    keys.map((key: unknown) => {
      if (typeof key !== 'object' || key === null || Array.isArray(key)) {
        throw invalidResponse(`${purpose}: a key is not an object`);
      }
      const member = (name: string): unknown =>
        Object.hasOwn(key, name) ? (key as Record<string, unknown>)[name] : undefined;
      if (SECRET_MEMBERS.some((name) => member(name) !== undefined)) {
        throw invalidResponse(`${purpose}: a published key carries private key material`);
      }
      const kept: Record<string, unknown> = {};
      for (const name of STRING_MEMBERS) {
        const value = member(name);
        if (value === undefined) continue;
        if (typeof value !== 'string' || value.length === 0 || value.length > 8192) {
          throw invalidResponse(`${purpose}: a key's ${name} is not a string`);
        }
        kept[name] = value;
      }
      if (kept['kty'] === undefined) throw invalidResponse(`${purpose}: a key has no kty`);
      const keyOps = member('key_ops');
      if (keyOps !== undefined) {
        if (!Array.isArray(keyOps) || !keyOps.every((op) => typeof op === 'string')) {
          throw invalidResponse(`${purpose}: a key's key_ops is not a list of strings`);
        }
        kept['key_ops'] = Object.freeze([...keyOps]);
      }
      return Object.freeze(kept) as JWK;
    })
  );
}

/**
 * The keys of `keys` that may verify a JWS whose protected header is
 * `header`: a signing key of the algorithm's family (and curve), whose
 * `alg`, `use` and `key_ops` do not rule it out, with the header's `kid`
 * when it names one.
 */
export function verificationCandidates(
  keys: readonly JWK[],
  algorithm: UpstreamIdTokenAlgorithm,
  kid: string | undefined
): readonly JWK[] {
  const family = KEY_FAMILY[algorithm];
  return keys.filter(
    (key) =>
      key.kty === family.kty &&
      (family.crv === undefined || key.crv === family.crv) &&
      (key.alg === undefined || key.alg === algorithm) &&
      (key.use === undefined || key.use === 'sig') &&
      (key.key_ops === undefined || key.key_ops.includes('verify')) &&
      (kid === undefined || key.kid === kid)
  );
}

/** Where a key set comes from. */
export interface JwksLocation {
  /**
   * What keeps one realm's key sets apart from another's, such as the
   * callback URL: whether a fetch may use the allowlist depends on the realm.
   */
  readonly scope: string;
  readonly uri: string;
  readonly source: 'admin' | 'remote_document';
}

/** The key sets of one method's providers, fetched through the egress client. */
export class UpstreamJwksCache {
  readonly #sets = new TtlCache<readonly JWK[]>(UPSTREAM_JWKS_TTL_MS, MAX_CACHED_KEY_SETS);
  /** When each key set was last fetched again for an unknown `kid`. */
  readonly #refreshedAt = new Map<string, number>();

  /**
   * The keys that may verify a JWS of `algorithm` with `kid`. When the
   * kept set holds none, the set is fetched again, at most once per
   * {@link UPSTREAM_JWKS_REFRESH_INTERVAL_MS}, so a rotated key is found
   * without letting every forged `kid` cost the provider a fetch.
   *
   * @throws UpstreamOidcError when the key set cannot be fetched or fails a check
   */
  async candidates(
    egress: AuthMethodEgress,
    location: JwksLocation,
    algorithm: UpstreamIdTokenAlgorithm,
    kid: string | undefined
  ): Promise<readonly JWK[]> {
    const key = JSON.stringify([location.scope, location.uri, location.source]);
    const load = () => fetchJwks(egress, location);
    const found = verificationCandidates(await this.#sets.get(key, load), algorithm, kid);
    if (found.length > 0) return found;
    const now = Date.now();
    const last = this.#refreshedAt.get(key);
    if (last !== undefined && now - last < UPSTREAM_JWKS_REFRESH_INTERVAL_MS) return found;
    this.#refreshedAt.delete(key);
    this.#refreshedAt.set(key, now);
    while (this.#refreshedAt.size > MAX_CACHED_KEY_SETS) {
      this.#refreshedAt.delete(this.#refreshedAt.keys().next().value as string);
    }
    this.#sets.delete(key);
    return verificationCandidates(await this.#sets.get(key, load), algorithm, kid);
  }
}

/**
 * Fetch a key set through the egress client.
 *
 * @throws UpstreamOidcError `upstream_unavailable` when it cannot be read,
 *   `invalid_response` when it fails a check
 */
async function fetchJwks(
  egress: AuthMethodEgress,
  location: JwksLocation
): Promise<readonly JWK[]> {
  const purpose = UPSTREAM_OIDC_PURPOSES.jwks;
  const response = await upstreamCall(egress, {
    method: 'GET',
    url: location.uri,
    headers: { accept: 'application/jwk-set+json, application/json' },
    purpose,
    source: location.source,
    caps: UPSTREAM_OIDC_CALL_CAPS.jwks,
  });
  if (response.status !== 200) {
    throw invalidResponse(`${purpose}: the provider answered ${response.status}`);
  }
  return parseJwks(jsonObjectBody(response, purpose));
}
