import {
  importPublicSigningJwk,
  type JwsAlgorithm,
  type SigningKey,
} from '@qauth-labs/core-crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { env } from '../../config/env';
import { REDIS_KEYS } from '../constants/redis-keys';
import { ASSERTION_SIGNING_ALG_VALUES_SUPPORTED } from '../schemas/oauth';
import { resolveIssuerIdentifier } from './discovery';
import { SsrfBlockedError, ssrfSafeGet } from './ssrf-safe-fetch';

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
 * ## Every fetch follows the CIMD pattern
 *
 * Both outbound requests go through {@link ssrfSafeGet}: https-only, no
 * credentials in the URL, DNS-pinned IP validation (TOCTOU-safe), redirects
 * surfaced as errors rather than followed, response size bound, per-request
 * timeout. Non-200 is rejected by this module (the fetcher reports status; it
 * does not judge it). See `fetchAndValidateCimdDocument` for the reference
 * shape this mirrors.
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
export const ID_JAG_SIGNING_ALG_VALUES_SUPPORTED: readonly JwsAlgorithm[] = Object.freeze(
  (['EdDSA', 'RS256', 'ES256'] satisfies JwsAlgorithm[]).filter((alg) =>
    (ASSERTION_SIGNING_ALG_VALUES_SUPPORTED as readonly string[]).includes(alg)
  )
);

/**
 * Whether `alg` is one this module will resolve a key for. Used as the gate in
 * front of key resolution so an unsupported / absent / non-string `alg` is
 * refused before any allowlist lookup or network call.
 */
export function isSupportedIdJagAlgorithm(alg: unknown): alg is JwsAlgorithm {
  return (
    typeof alg === 'string' &&
    (ID_JAG_SIGNING_ALG_VALUES_SUPPORTED as readonly string[]).includes(alg)
  );
}

/** Defensive bound on an `iss` claim / configured issuer identifier. */
const MAX_ISSUER_LENGTH = 2048;

/** Defensive bound on the number of keys accepted from an issuer's JWK Set. */
const MAX_JWKS_KEYS = 50;

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
 * The two members of an OIDC discovery document key resolution needs.
 *
 * Everything else is stripped (Zod default): we neither read nor cache the rest,
 * so a large or hostile document contributes nothing but the bytes the size
 * bound already caps.
 */
const issuerMetadataSchema = z.object({
  issuer: z.string().min(1).max(MAX_ISSUER_LENGTH),
  jwks_uri: z.string().min(1).max(MAX_ISSUER_LENGTH),
});

type IssuerMetadata = z.infer<typeof issuerMetadataSchema>;

/**
 * JWK members that carry PRIVATE key material. Mirrors the list
 * `importPublicSigningJwk` refuses on.
 */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as const;

/**
 * A single published verification key.
 *
 * Two deliberate behaviours:
 *
 *  - a key carrying ANY private member is REFUSED, not repaired. The schema is
 *    `looseObject` precisely so the refusal can see members it does not model —
 *    a plain `z.object` would silently strip `d` and then happily import the
 *    public half, hiding the fact that an "issuer" published its private key.
 *    An issuer that does that is broken or hostile, and both cases must surface
 *    as a refusal (the same stance `importPublicSigningJwk` takes).
 *  - after that check, only the members needed to SELECT and IMPORT a key are
 *    carried forward, so nothing else is ever held or cached.
 */
const issuerJwkSchema = z
  .looseObject({
    kty: z.string().min(1).max(16),
    kid: z.string().min(1).max(256).optional(),
    alg: z.string().min(1).max(32).optional(),
    use: z.string().min(1).max(16).optional(),
    crv: z.string().min(1).max(32).optional(),
    x: z.string().min(1).max(2048).optional(),
    y: z.string().min(1).max(2048).optional(),
    n: z.string().min(1).max(8192).optional(),
    e: z.string().min(1).max(64).optional(),
  })
  .refine((jwk) => PRIVATE_JWK_MEMBERS.every((member) => jwk[member] === undefined), {
    message: 'a published verification key must not carry private key material',
  })
  .transform((jwk) => ({
    kty: jwk.kty,
    ...(jwk.kid !== undefined ? { kid: jwk.kid } : {}),
    ...(jwk.alg !== undefined ? { alg: jwk.alg } : {}),
    ...(jwk.use !== undefined ? { use: jwk.use } : {}),
    ...(jwk.crv !== undefined ? { crv: jwk.crv } : {}),
    ...(jwk.x !== undefined ? { x: jwk.x } : {}),
    ...(jwk.y !== undefined ? { y: jwk.y } : {}),
    ...(jwk.n !== undefined ? { n: jwk.n } : {}),
    ...(jwk.e !== undefined ? { e: jwk.e } : {}),
  }));

const issuerJwksSchema = z.object({
  keys: z.array(issuerJwkSchema).min(1).max(MAX_JWKS_KEYS),
});

type IssuerJwks = z.infer<typeof issuerJwksSchema>;

/**
 * What a caller knows about an assertion when it needs a key — all of it
 * UNVERIFIED, because nothing can be verified before a key exists.
 */
export interface IdJagIssuerKeyRequest {
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
   * `ID_JAG_JWKS_CACHE_TTL` — and without letting an attacker turn every forged
   * `kid` into an outbound fetch, because the retry happens at most once per
   * request and only after the allowlist check has already passed.
   */
  readonly forceRefresh?: boolean;
}

/** A verification key, plus the issuer identity that obtaining it established. */
export interface ResolvedIdJagIssuerKey {
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

async function readCache<T>(
  fastify: FastifyInstance,
  key: string,
  schema: z.ZodType<T>
): Promise<T | undefined> {
  try {
    const raw = await fastify.redis.get(key);
    if (!raw) return undefined;
    const parsed = schema.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : undefined;
  } catch {
    // Best-effort cache: an unreachable store or a corrupt entry behaves
    // exactly like a miss. This is safe to swallow because a miss re-fetches
    // through the same guarded path — unlike the `jti` replay store, where a
    // failure MUST fail closed.
    return undefined;
  }
}

async function writeCache(fastify: FastifyInstance, key: string, value: unknown): Promise<void> {
  const ttl = env.ID_JAG_JWKS_CACHE_TTL;
  if (ttl <= 0) return;
  try {
    await fastify.redis.set(key, JSON.stringify(value), 'EX', ttl);
  } catch {
    // Best-effort cache; a write failure only costs a re-fetch.
  }
}

/**
 * SSRF-guarded HTTPS GET of a small JSON document, bounded and non-200-rejecting.
 *
 * Returns `undefined` for every failure mode (blocked target, transport error,
 * non-200, unparseable body, schema mismatch) so no caller has to distinguish
 * them: for key resolution they are all "no key". The reason is logged at
 * `debug` for operators — never surfaced to the requester, which would turn the
 * AS into an oracle for what its network can reach.
 */
async function fetchJsonDocument<T>(
  fastify: FastifyInstance,
  url: string,
  schema: z.ZodType<T>,
  what: string
): Promise<T | undefined> {
  let result;
  try {
    result = await ssrfSafeGet(url, {
      timeoutMs: env.ID_JAG_FETCH_TIMEOUT_MS,
      maxBytes: env.ID_JAG_MAX_DOCUMENT_BYTES,
      allowPrivateAddresses: env.ID_JAG_ALLOW_PRIVATE_ADDRESSES,
    });
  } catch (err) {
    fastify.log.debug(
      { url, what, blocked: err instanceof SsrfBlockedError },
      'ID-JAG issuer document fetch failed'
    );
    return undefined;
  }

  if (result.status !== 200) {
    fastify.log.debug({ url, what, status: result.status }, 'ID-JAG issuer document not 200');
    return undefined;
  }

  let json: unknown;
  try {
    json = JSON.parse(result.body);
  } catch {
    fastify.log.debug({ url, what }, 'ID-JAG issuer document is not valid JSON');
    return undefined;
  }

  const parsed = schema.safeParse(json);
  if (!parsed.success) {
    fastify.log.debug({ url, what }, 'ID-JAG issuer document failed schema validation');
    return undefined;
  }
  return parsed.data;
}

/**
 * Fetch (or read from cache) the OIDC discovery document of an ALREADY
 * ALLOWLISTED issuer.
 *
 * The URL is derived from the CANONICAL allowlist entry — `<issuer>` +
 * `/.well-known/openid-configuration` (OIDC Discovery §4) — so it is operator
 * data, not request data.
 *
 * The document's own `issuer` member MUST equal the identifier it was fetched
 * under (OIDC Discovery §4.3). Without that check, a host that an operator
 * allowlisted could publish metadata claiming to be a DIFFERENT issuer and
 * point key resolution at that issuer's key set — the same self-binding failure
 * `fetchAndValidateCimdDocument` closes with its `client_id == URL` assertion.
 */
async function resolveIssuerMetadata(
  fastify: FastifyInstance,
  issuer: string,
  forceRefresh: boolean
): Promise<IssuerMetadata | undefined> {
  const cacheKey = REDIS_KEYS.ID_JAG_DISCOVERY(issuer);
  if (!forceRefresh) {
    const cached = await readCache(fastify, cacheKey, issuerMetadataSchema);
    if (cached) return cached;
  }

  const metadata = await fetchJsonDocument(
    fastify,
    `${issuer}/.well-known/openid-configuration`,
    issuerMetadataSchema,
    'discovery'
  );
  if (!metadata) return undefined;

  if (resolveIssuerIdentifier(metadata.issuer) !== issuer) {
    fastify.log.debug(
      { issuer, documentIssuer: metadata.issuer },
      'ID-JAG issuer metadata declares a different issuer; refusing'
    );
    return undefined;
  }

  // The jwks_uri comes from the TRUSTED issuer's own metadata — never from an
  // assertion — but it is still remote input, so it is re-checked here and then
  // re-guarded by `ssrfSafeGet`. https-only is asserted explicitly so a plain
  // `http://` value is refused with a clear reason instead of deep inside the
  // fetcher.
  let jwksUrl: URL;
  try {
    jwksUrl = new URL(metadata.jwks_uri);
  } catch {
    fastify.log.debug({ issuer }, 'ID-JAG issuer metadata has an unparseable jwks_uri');
    return undefined;
  }
  if (jwksUrl.protocol !== 'https:') {
    fastify.log.debug({ issuer }, 'ID-JAG issuer jwks_uri is not https');
    return undefined;
  }

  await writeCache(fastify, cacheKey, metadata);
  return metadata;
}

/** Fetch (or read from cache) an allowlisted issuer's JWK Set. */
async function resolveIssuerJwks(
  fastify: FastifyInstance,
  issuer: string,
  jwksUri: string,
  forceRefresh: boolean
): Promise<IssuerJwks | undefined> {
  const cacheKey = REDIS_KEYS.ID_JAG_JWKS(issuer);
  if (!forceRefresh) {
    const cached = await readCache(fastify, cacheKey, issuerJwksSchema);
    if (cached) return cached;
  }

  const jwks = await fetchJsonDocument(fastify, jwksUri, issuerJwksSchema, 'jwks');
  if (!jwks) return undefined;

  await writeCache(fastify, cacheKey, jwks);
  return jwks;
}

/**
 * Pick the one JWK an assertion addresses, fail-closed.
 *
 * Selection rules mirror `createStaticIssuerKeyResolver`:
 *  - with a `kid`, EXACTLY the key carrying it. A `kid` naming no published key
 *    resolves to nothing rather than falling back to "try them all" — a fallback
 *    would make `kid` a hint an attacker can drop to widen the key set.
 *  - without a `kid`, the set must hold exactly ONE key. An ambiguous key set is
 *    a set the assertion cannot address, and guessing which key was meant is how
 *    a rotated-out key stays live.
 */
function selectJwk(jwks: IssuerJwks, keyId: string | undefined) {
  if (keyId === undefined) {
    return jwks.keys.length === 1 ? jwks.keys[0] : undefined;
  }
  const matches = jwks.keys.filter((candidate) => candidate.kid === keyId);
  return matches.length === 1 ? matches[0] : undefined;
}

/**
 * Build the deployment's ID-JAG issuer key resolver.
 *
 * @param fastify - Server instance (redis for the bounded cache, log for
 *   operator-visible refusal reasons).
 */
export function createIdJagIssuerKeyResolver(fastify: FastifyInstance): IdJagIssuerKeyResolver {
  return async (request) => {
    // ALLOWLIST FIRST — before any network call, any cache read, any parsing.
    // An unlisted issuer costs one canonicalisation and one string comparison.
    const identifier = resolveTrustedIdJagIssuer(request.issuer);
    if (identifier === undefined) return undefined;

    const forceRefresh = request.forceRefresh === true;

    const metadata = await resolveIssuerMetadata(fastify, identifier, forceRefresh);
    if (!metadata) return undefined;

    const jwks = await resolveIssuerJwks(fastify, identifier, metadata.jwks_uri, forceRefresh);
    if (!jwks) return undefined;

    const jwk = selectJwk(jwks, request.keyId);
    if (jwk === undefined) return undefined;

    try {
      const key = await importPublicSigningJwk(jwk, request.algorithm);
      return { key, identifier };
    } catch {
      // A published key that cannot be imported under the algorithm the
      // assertion declares is not a match. Resolving nothing is the fail-closed
      // answer; the alternative would be verifying under a key published for a
      // different primitive.
      return undefined;
    }
  };
}
