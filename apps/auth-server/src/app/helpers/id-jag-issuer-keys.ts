import type { JwsAlgorithm, SigningKey } from '@qauth-labs/core-crypto';
import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { REDIS_KEYS } from '../constants/redis-keys';
import {
  ALLOWLISTED_ISSUER_SIGNING_ALG_VALUES,
  type AllowlistedIssuerKeyOptions,
  createAllowlistedIssuerKeyResolver,
  type IssuerKeyRequest,
  isAllowlistedIssuerAlgorithm,
  MAX_ISSUER_LENGTH,
  type ResolvedIssuerKey,
} from './allowlisted-issuer-keys';
import { resolveIssuerIdentifier } from './discovery';

/**
 * Trusted-issuer signing-key resolution for the Identity Assertion
 * Authorization Grant (ID-JAG / EMA, ADR-011).
 *
 * ## The whole trust model, in one paragraph
 *
 * An ID-JAG arrives as an unauthenticated blob of attacker-controlled bytes. The
 * only thing that can make it meaningful is a key, and the ONLY way a key is
 * obtained here is:
 *
 *   1. read the assertion's CLAIMED `iss` (untrusted text),
 *   2. canonicalise it (trailing slash only — {@link resolveIssuerIdentifier})
 *      and require BYTE EQUALITY with an entry in `ID_JAG_TRUSTED_ISSUERS`,
 *   3. only then, run OIDC discovery against THAT ALLOWLISTED IDENTIFIER and
 *      fetch the `jwks_uri` the issuer's own document names.
 *
 * Step 2 happens before any network call, so an unlisted issuer costs one string
 * comparison and never turns the AS into a fetch primitive. `ID_JAG_ENABLED`
 * defaults to false and `ID_JAG_TRUSTED_ISSUERS` defaults to EMPTY, so with no
 * operator configuration this module resolves nothing at all — every assertion
 * is rejected. That is the intended posture, not a gap.
 *
 * No URL is ever taken from the assertion. Nothing about trust is self-asserted:
 * an assertion cannot nominate its own issuer metadata, its own JWKS, or its own
 * key. Wildcards are deliberately unsupported — an issuer identifier is an exact
 * trust anchor, and `*.idp.example` would hand every subdomain the ability to
 * mint access tokens for every MCP server this deployment protects.
 *
 * ## Shape
 *
 * {@link IdJagIssuerKeyResolver} mirrors `IssuerKeyResolver` /
 * `ResolvedIssuerKey` from `libs/server/federation/src/oid4vp/issuer-key-resolution.ts`
 * rather than inventing a parallel abstraction: a request carries the UNVERIFIED
 * `iss` plus the header's `kid`/`alg`, and a successful resolution returns the
 * key together with the identifier the resolution CONFIRMED. As in that module,
 * "unknown issuer" resolves to `undefined` rather than throwing — an ordinary
 * refusal on an attacker-reachable path, not an exception shape a caller might
 * mistake for an infrastructure fault.
 *
 * It is a local resolver rather than a reuse of the federation one because the
 * backends differ completely: that one reads key sets pinned in configuration,
 * this one performs two SSRF-guarded HTTPS fetches with a bounded Redis cache.
 * `server-federation` is a pure `scope:server` library with no HTTP client and
 * no configuration, which is exactly why the port exists.
 *
 * ## The fetches, the caches and their bounds
 *
 * Live in `allowlisted-issuer-keys.ts`, which the CI workload issuer keys
 * (#526) share. This module gives them the ID-JAG allowlist
 * (`ID_JAG_TRUSTED_ISSUERS`), its own Redis keys, the `ID_JAG_*` bounds, and
 * the `operator` source of the discovery fetch: its URL is built from the
 * operator's configuration. The cache is held for `ID_JAG_JWKS_CACHE_TTL`,
 * which config validation caps at one hour; with `0` nothing is cached and
 * only the negative cache and the in-flight sharing bound the fetches.
 */

/**
 * JOSE `alg` values an ID-JAG may be signed with.
 *
 * DERIVED, not written: the intersection of the workspace-wide
 * `ASSERTION_SIGNING_ALG_VALUES_SUPPORTED` (the single source of truth
 * `discovery.ts` publishes) with the algorithms QAuth's crypto abstraction can
 * actually carry in a compact JWS (`JwsAlgorithm`). Deriving it means removing
 * an algorithm from the shared constant removes it here too, and it can never
 * name an algorithm the verifier would then fail to import a key for.
 *
 * `alg: none` is impossible by construction and every MAC algorithm (`HS*`) is
 * absent: a symmetric assertion would be verified with a shared secret, and an
 * enterprise IdP and this AS share no secret. An assertion whose header names
 * anything outside this list is rejected BEFORE any key is resolved.
 *
 * The list is currently narrower than what discovery advertises for
 * `token_endpoint_auth_signing_alg_values_supported` because the crypto layer
 * carries `EdDSA` / `RS256` / `ES256` only. That is a conservative gap, not a
 * conformance one: that metadata field describes CLIENT AUTHENTICATION
 * assertions, and no metadata field advertises which algorithms a trusted IdP's
 * ID-JAG may use. Widening `JwsAlgorithm` widens this automatically.
 */
export const ID_JAG_SIGNING_ALG_VALUES_SUPPORTED: readonly JwsAlgorithm[] =
  ALLOWLISTED_ISSUER_SIGNING_ALG_VALUES;

/**
 * Whether `alg` is one this module will resolve a key for. Used as the gate in
 * front of key resolution so an unsupported / absent / non-string `alg` is
 * refused before any allowlist lookup or network call.
 */
export function isSupportedIdJagAlgorithm(alg: unknown): alg is JwsAlgorithm {
  return isAllowlistedIssuerAlgorithm(alg);
}

/**
 * Resolve the operator's trusted-issuer allowlist into canonical identifiers.
 *
 * Canonicalisation is `resolveIssuerIdentifier` — a trailing-slash strip and
 * NOTHING else. Deliberately not `new URL()` normalisation, which would
 * case-fold the authority, elide default ports and rewrite percent-encoding:
 * an issuer identifier is compared by simple string comparison (RFC 8414 §2,
 * RFC 9207 §2.4 spirit), so a normaliser that "helpfully" rewrites it would
 * make the trust anchor and the compared value two different strings.
 */
function trustedIssuerIdentifiers(): string[] {
  return env.ID_JAG_TRUSTED_ISSUERS.map((entry) => resolveIssuerIdentifier(entry));
}

/**
 * Return the CANONICAL identifier of an allowlisted ID-JAG issuer, or
 * `undefined` when the issuer is not trusted.
 *
 * Fail-closed on every axis: the feature flag being off, an empty allowlist, a
 * non-string / empty `iss`, and an `iss` that is not byte-equal to a listed
 * entry all answer `undefined`. An EMPTY allowlist therefore rejects
 * everything, which is the documented default posture.
 *
 * The returned value — not the caller's input — is what must be used for
 * discovery, for the `iss` assertion at verification time, and for cache keys.
 * That is the same rule `ResolvedIssuerKey.identifier` carries in the
 * federation port: use the identifier the resolution ESTABLISHED, never the
 * credential's own unverified claim.
 */
export function resolveTrustedIdJagIssuer(issuer: unknown): string | undefined {
  if (!env.ID_JAG_ENABLED) return undefined;
  if (typeof issuer !== 'string' || issuer.length === 0) return undefined;
  // Bound the comparison input: `iss` is attacker-controlled and there is no
  // legitimate issuer identifier anywhere near this long.
  if (issuer.length > MAX_ISSUER_LENGTH) return undefined;

  const candidate = resolveIssuerIdentifier(issuer);
  return trustedIssuerIdentifiers().find((trusted) => trusted === candidate);
}

/**
 * What a caller knows about an assertion when it needs a key — all of it
 * UNVERIFIED, because nothing can be verified before a key exists.
 */
export interface IdJagIssuerKeyRequest extends IssuerKeyRequest {
  /**
   * The `iss` the assertion CLAIMS. Attacker-controlled text: used to look a key
   * up against the allowlist, never as an established identity.
   */
  readonly issuer: string;
  /** The protected header's `kid`, when it carried one. */
  readonly keyId?: string;
  /**
   * The algorithm the header declares, ALREADY checked against
   * {@link ID_JAG_SIGNING_ALG_VALUES_SUPPORTED} by the caller. Passed so the key
   * is imported PINNED to it — a key must be imported for one primitive, never
   * left algorithm-ambiguous.
   */
  readonly algorithm: JwsAlgorithm;
  /**
   * Bypass the cache for exactly this attempt. Set on the ONE retry a caller
   * makes after a `kid` miss, so a key rotation is picked up without waiting out
   * `ID_JAG_JWKS_CACHE_TTL`.
   *
   * A request for a refresh, not a guarantee of one: the resolver refreshes an
   * issuer at most once per `ID_JAG_JWKS_REFRESH_COOLDOWN`, across all requests
   * and processes, and not at all while the negative cache holds the issuer.
   * A refused refresh resolves `undefined` without a fetch. That is what stops
   * an attacker turning every forged `kid` into an outbound fetch.
   */
  readonly forceRefresh?: boolean;
}

/** A verification key, plus the issuer identity that obtaining it established. */
export interface ResolvedIdJagIssuerKey extends ResolvedIssuerKey {
  /** The public key to verify the assertion with. */
  readonly key: SigningKey;
  /**
   * The issuer identifier this resolution CONFIRMED — the allowlist entry the
   * claimed `iss` matched, NOT the assertion's own text. Callers pass this (and
   * only this) as the expected `iss` when verifying.
   */
  readonly identifier: string;
}

/**
 * Resolve the key an ID-JAG must verify under. Returns `undefined` — never
 * throws — when no key can be obtained, so "untrusted issuer", "issuer
 * unreachable", "no such kid" and "unimportable key" all land on the same
 * fail-closed answer.
 */
export type IdJagIssuerKeyResolver = (
  request: IdJagIssuerKeyRequest
) => Promise<ResolvedIdJagIssuerKey | undefined>;

/** The ID-JAG resolver's allowlist, Redis keys, bounds and log label. */
const ID_JAG_ISSUER_KEYS: AllowlistedIssuerKeyOptions = {
  label: 'ID-JAG',
  allowlist: resolveTrustedIdJagIssuer,
  documentNames: (documentIssuer, identifier) =>
    resolveIssuerIdentifier(documentIssuer) === identifier,
  discoveryUrl: (identifier) => `${identifier}/.well-known/openid-configuration`,
  discoverySource: 'operator',
  purposes: { discovery: 'id-jag-discovery', jwks: 'id-jag-jwks' },
  keys: {
    discovery: REDIS_KEYS.ID_JAG_DISCOVERY,
    fetchRefused: REDIS_KEYS.ID_JAG_FETCH_REFUSED,
    jwks: REDIS_KEYS.ID_JAG_JWKS,
    keyRefresh: REDIS_KEYS.ID_JAG_KEY_REFRESH,
    fetchFailed: REDIS_KEYS.ID_JAG_FETCH_FAILED,
  },
  limits: () => ({
    cacheTtlSeconds: env.ID_JAG_JWKS_CACHE_TTL,
    refreshCooldownSeconds: env.ID_JAG_JWKS_REFRESH_COOLDOWN,
    negativeCacheTtlSeconds: env.ID_JAG_JWKS_NEGATIVE_CACHE_TTL,
    fetchTimeoutMs: env.ID_JAG_FETCH_TIMEOUT_MS,
    maxDocumentBytes: env.ID_JAG_MAX_DOCUMENT_BYTES,
  }),
};

/**
 * Build the deployment's ID-JAG issuer key resolver.
 *
 * @param fastify - Server instance (redis for the bounded cache, log for
 *   operator-visible refusal reasons, the egress client for the fetches).
 * @param realm - The name of the realm the assertion is presented to: the
 *   deployment allowlist entries that name it apply to the discovery fetch.
 */
export function createIdJagIssuerKeyResolver(
  fastify: FastifyInstance,
  realm: string
): IdJagIssuerKeyResolver {
  return createAllowlistedIssuerKeyResolver(fastify, realm, ID_JAG_ISSUER_KEYS);
}
