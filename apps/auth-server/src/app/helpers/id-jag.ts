import { randomUUID } from 'node:crypto';

import {
  importPrivateSigningKey,
  type JwsAlgorithm,
  sign,
  type SigningKey,
  verifyWithHeader,
} from '@qauth-labs/core-crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { env } from '../../config/env';
import { REDIS_KEYS } from '../constants/redis-keys';
import { resolveIssuerIdentifier } from './discovery';
import {
  createIdJagIssuerKeyResolver,
  type IdJagIssuerKeyResolver,
  isSupportedIdJagAlgorithm,
} from './id-jag-issuer-keys';

/**
 * Identity Assertion JWT Authorization Grant (ID-JAG) — the credential at the
 * centre of MCP Enterprise-Managed Authorization (EMA, ADR-011).
 *
 * QAuth implements BOTH sides:
 *
 *  - **CONSUME** ({@link validateIdJagAssertion}) — QAuth is the MCP server's
 *    Resource Authorization Server. A client presents an ID-JAG minted by a
 *    trusted enterprise IdP at `/oauth/token` under the RFC 7523 §2.1
 *    `jwt-bearer` grant, and receives an access token audience-restricted to the
 *    MCP server named by the assertion's `resource` claim.
 *  - **MINT** ({@link mintIdJag}) — QAuth is the enterprise IdP. An RFC 8693
 *    token exchange asking for `requested_token_type=...:id-jag` returns an
 *    assertion targeted at a THIRD-PARTY resource authorization server.
 *
 * ## An ID-JAG is not an access token
 *
 * It is a single-use, short-lived, audience-restricted authorization GRANT. It
 * is presented to one authorization server, exactly once, and exchanged. Three
 * properties enforce that here and must not be relaxed:
 *
 *  - the protected header `typ` is {@link ID_JAG_TYP}, distinct from `at+jwt`
 *    (access token) and `JWT` (ID token), so no token QAuth or an IdP signs for
 *    another purpose can be substituted — and vice versa;
 *  - `aud` is a SINGLE authorization-server issuer identifier. A multi-valued
 *    `aud` is rejected: an assertion that authorizes two authorization servers
 *    is one that either of them can redeem;
 *  - `jti` is consumed exactly once ({@link consumeIdJagJti}) inside a window
 *    bounded by `ID_JAG_MAX_ASSERTION_LIFETIME`.
 *
 * ## Fail-closed everywhere
 *
 * `ID_JAG_ENABLED` defaults to false; `ID_JAG_TRUSTED_ISSUERS` defaults to
 * EMPTY, and an empty allowlist rejects every assertion. Nothing in an assertion
 * ever nominates its own trust: keys come only from an OIDC discovery run
 * against an ALREADY ALLOWLISTED issuer (see `id-jag-issuer-keys.ts`).
 */

/**
 * The Internet-Draft revision this implementation targets.
 *
 * ADR-011:420-422 requires the implementation to "pin the revision it targets
 * **in code**" rather than only in prose, so the pin lives here beside the wire
 * constants it governs and moves in the same diff they do.
 *
 * `-04` expires **2026-11-22**, which is this row's `Re-check by` date in
 * `docs/spec-pin-log.md`; that log's freshness check fails the build once the
 * date passes, so the pass cannot be forgotten. Changing this constant without
 * updating the log — or the reverse — is the drift both are there to prevent.
 */
export const ID_JAG_DRAFT = 'draft-ietf-oauth-identity-assertion-authz-grant-04' as const;

/**
 * RFC 8725 / `draft-ietf-oauth-identity-assertion-authz-grant` §3.1 media type
 * for an ID-JAG's protected header, at the revision {@link ID_JAG_DRAFT} pins.
 * Asserted on the VERIFIED header when consuming, and stamped when minting.
 */
export const ID_JAG_TYP = 'oauth-id-jag+jwt';

/**
 * The algorithm QAuth signs the ID-JAGs it MINTS with.
 *
 * Pinned to the same EdDSA key that signs access tokens, so a third-party
 * resource authorization server verifies an ID-JAG from the JWKS it already
 * fetches from `/.well-known/jwks.json` — no second key to publish, rotate or
 * explain. Deliberately NOT the hybrid (ADR-005) signer: the detached ML-DSA
 * component is delivered through RFC 7662 introspection of a QAuth token, and a
 * foreign AS has no introspection relationship with QAuth, so a hybrid ID-JAG
 * would be unverifiable at exactly the party that must verify it.
 */
const ID_JAG_SIGNING_ALGORITHM: JwsAlgorithm = 'EdDSA';

/**
 * Why an inbound assertion was refused.
 *
 * Carried for the AUDIT LOG only. The route maps every one of these to the same
 * bare `invalid_grant` on the wire (RFC 6749 §5.2): a caller learning which
 * check failed learns whether an issuer is allowlisted, whether a `jti` was
 * already burned, and whether a `kid` exists — all of which are oracles.
 */
export type IdJagRejectionReason =
  | 'disabled'
  | 'malformed'
  | 'unsupported_algorithm'
  | 'unsupported_typ'
  | 'unresolvable_key'
  | 'signature_invalid'
  | 'issuer_invalid'
  | 'claims_invalid'
  | 'unsupported_constraint'
  | 'audience_invalid'
  | 'lifetime_invalid'
  | 'client_mismatch'
  | 'replayed'
  | 'replay_store_unavailable';

/**
 * An inbound ID-JAG was refused. Thrown by {@link validateIdJagAssertion} so the
 * caller can audit the precise {@link reason} while returning a uniform OAuth
 * error to the client.
 */
export class IdJagValidationError extends Error {
  readonly reason: IdJagRejectionReason;

  constructor(reason: IdJagRejectionReason, message: string) {
    super(message);
    this.name = 'IdJagValidationError';
    this.reason = reason;
    Object.setPrototypeOf(this, IdJagValidationError.prototype);
  }
}

/**
 * The claim set of a VERIFIED ID-JAG (draft §3.1, MCP EMA §4.3).
 *
 * Every field here survived signature verification against a key resolved from
 * an allowlisted issuer, the `iss`/`aud` assertions, the temporal checks and the
 * single-use `jti` consumption.
 */
export interface ValidatedIdJag {
  /** The CONFIRMED issuer identifier — the allowlist entry, not the raw claim. */
  readonly issuer: string;
  /** `sub` — the end-user, as identified WITHIN the issuer's namespace. */
  readonly subject: string;
  /** `aud` — asserted to be this AS's own issuer identifier. */
  readonly audience: string;
  /** `resource` — the MCP server the issued access token must be restricted to. */
  readonly resource: string;
  /** `client_id` — the client the IdP authorized; must match the authenticated client. */
  readonly clientId: string;
  /** `scope`, split and deduped. Empty when the assertion carried none. */
  readonly scopes: readonly string[];
  /** `jti` — consumed exactly once by the time this is returned. */
  readonly jti: string;
  /** `exp`, epoch seconds. */
  readonly expiresAt: number;
  /** `iat`, epoch seconds. */
  readonly issuedAt: number;
}

/**
 * Claim-shape validation for a SIGNATURE-VERIFIED assertion.
 *
 * `jose` verifies the signature and the registered temporal/issuer/audience
 * claims; it does not assert the SHAPE of anything else. Without this a
 * signed-but-malformed assertion (numeric `sub`, array `resource`, object
 * `scope`) would be cast blindly and mis-typed downstream.
 *
 * `resource` is REQUIRED here even though the underlying draft marks it
 * OPTIONAL. In the MCP profile it is the whole point: EMA §5.1 says the issued
 * access token MUST be audience-restricted to the MCP server the `resource`
 * claim identifies, and an assertion without one gives this AS nothing to
 * restrict to. Accepting it and falling back to some default audience would
 * silently issue a WIDER token than the enterprise authorized, so it is refused.
 */
const idJagClaimsSchema = z.object({
  jti: z.string().min(1).max(256),
  iss: z.string().min(1).max(2048),
  sub: z.string().min(1).max(255),
  aud: z.union([z.string().min(1).max(2048), z.array(z.string().min(1).max(2048)).min(1).max(10)]),
  resource: z.string().min(1).max(2048),
  client_id: z.string().min(1).max(2048),
  exp: z.number().int(),
  iat: z.number().int(),
  scope: z.string().max(2048).optional(),
});

/** Split a space-delimited scope string, dropping empties and duplicates. */
function splitScope(scope: string | undefined): string[] {
  if (!scope) return [];
  return [...new Set(scope.split(/\s+/).filter((s) => s.length > 0))];
}

/**
 * Decode a compact JWS's protected header and payload WITHOUT verifying.
 *
 * Used for exactly two things, both of which are re-established from
 * authenticated data afterwards:
 *
 *   - reading `alg` / `kid` so a key can be SELECTED (there is no way to resolve
 *     a key without them, and the resolver pins the algorithm it imports under);
 *   - reading `iss` so the ALLOWLIST can be consulted before any network call.
 *
 * Nothing read here is trusted. The `iss` is only ever used to find an allowlist
 * entry, and the verified `iss` is then asserted against that entry by
 * `verifyWithHeader`; the header is re-read from the AUTHENTICATED
 * `protectedHeader` for the `typ` check.
 */
function decodeUnverified(
  token: string
): { header: Record<string, unknown>; payload: Record<string, unknown> } | undefined {
  const parts = token.split('.');
  if (parts.length !== 3) return undefined;
  try {
    const header: unknown = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload: unknown = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (typeof header !== 'object' || header === null || Array.isArray(header)) return undefined;
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return undefined;
    return {
      header: header as Record<string, unknown>,
      payload: payload as Record<string, unknown>,
    };
  } catch {
    return undefined;
  }
}

/**
 * Burn an assertion's `jti`, returning `true` only for the FIRST caller.
 *
 * `SET NX EX` is the whole mechanism: atomic, so two concurrent redemptions of
 * the same assertion cannot both win, and TTL-bounded so the store drains on its
 * own. The TTL is `ID_JAG_MAX_ASSERTION_LIFETIME + ID_JAG_CLOCK_SKEW_LEEWAY` —
 * the longest window in which a still-valid assertion could be re-presented —
 * which is precisely what the inbound `exp - iat` bound exists to make finite.
 *
 * FAILS CLOSED on a store error. Every other cache in this module treats an
 * unreachable Redis as a miss, because a miss there only costs a re-fetch. Here
 * a "miss" would mean accepting a possibly-replayed assertion, so an
 * unavailable store must reject instead. Availability is deliberately traded for
 * the single-use property.
 */
async function consumeIdJagJti(
  fastify: FastifyInstance,
  issuer: string,
  jti: string
): Promise<void> {
  const ttl = env.ID_JAG_MAX_ASSERTION_LIFETIME + env.ID_JAG_CLOCK_SKEW_LEEWAY;
  let stored: string | null;
  try {
    stored = await fastify.redis.set(REDIS_KEYS.ID_JAG_JTI(issuer, jti), '1', 'EX', ttl, 'NX');
  } catch (err) {
    fastify.log.error({ err }, 'ID-JAG replay store unavailable; refusing the assertion');
    throw new IdJagValidationError(
      'replay_store_unavailable',
      'replay protection is unavailable for this assertion'
    );
  }
  if (stored === null) {
    throw new IdJagValidationError('replayed', 'assertion has already been redeemed');
  }
}

/** Options for {@link validateIdJagAssertion}. */
export interface ValidateIdJagOptions {
  /** The compact JWS presented as the RFC 7523 §2.1 `assertion` parameter. */
  readonly assertion: string;
  /**
   * The `client_id` of the ALREADY-AUTHENTICATED caller. The assertion's
   * `client_id` claim must equal it (draft §4.4.1).
   *
   * REQUIRED rather than optional so a caller cannot forget the binding and
   * silently accept an assertion minted for someone else.
   */
  readonly expectedClientId: string;
  /**
   * Injection seam for tests and for a future non-fetching backend. Defaults to
   * {@link createIdJagIssuerKeyResolver} over this server instance — production
   * never passes one.
   */
  readonly resolver?: IdJagIssuerKeyResolver;
}

/**
 * Validate an inbound ID-JAG end to end (draft §4.4.1, EMA §5.1).
 *
 * Order is load-bearing — each step is cheaper and less trusting than the next,
 * and no side effect happens before the signature is established:
 *
 *  1. feature flag;
 *  2. structural decode + `alg` in {@link ID_JAG_SIGNING_ALG_VALUES_SUPPORTED}
 *     (no `none`, no `HS*`);
 *  3. `iss` on the operator allowlist — BEFORE any network call;
 *  4. key resolution against that allowlisted issuer only, with ONE bounded
 *     refresh on a `kid` miss so a rotation is picked up promptly;
 *  5. signature + `iss` + `aud` + `exp`/`nbf` (bounded skew) via the crypto
 *     abstraction, with the algorithm pinned to the ONE the header declared;
 *  6. `typ` asserted on the AUTHENTICATED header;
 *  7. claim shape, single-valued `aud`, a bounded `exp - iat`, and the
 *     `client_id` binding to the caller;
 *  8. `jti` burned — the only side effect, and only after everything above.
 *
 * Step 7 includes the `client_id` binding DELIBERATELY, rather than leaving it
 * to the caller after this function returns: burning the `jti` first would let
 * any client that got hold of another client's assertion destroy it — present
 * it, pass every cryptographic check, burn the single-use marker, and only THEN
 * be refused. Checking the binding before the burn means an assertion can only
 * ever be consumed by the client it names.
 *
 * @throws IdJagValidationError for every refusal, carrying an audit reason. The
 *   caller maps them all to one uniform OAuth error.
 */
export async function validateIdJagAssertion(
  fastify: FastifyInstance,
  options: ValidateIdJagOptions
): Promise<ValidatedIdJag> {
  if (!env.ID_JAG_ENABLED) {
    throw new IdJagValidationError('disabled', 'ID-JAG is not enabled on this server');
  }

  const decoded = decodeUnverified(options.assertion);
  if (!decoded) {
    throw new IdJagValidationError('malformed', 'assertion is not a compact JWS');
  }

  // Algorithm gate BEFORE key resolution. `alg: none` has no entry in the
  // supported list, and neither does any `HS*` — so an assertion trying either
  // never reaches a key at all.
  const alg = decoded.header['alg'];
  if (!isSupportedIdJagAlgorithm(alg)) {
    throw new IdJagValidationError(
      'unsupported_algorithm',
      'assertion is signed with an unsupported algorithm'
    );
  }

  // Cheap structural rejection of a wrong-typed token before any I/O. The
  // authoritative check is on the VERIFIED header below — this one only avoids
  // spending a key resolution on an obviously wrong token.
  if (decoded.header['typ'] !== ID_JAG_TYP) {
    throw new IdJagValidationError('unsupported_typ', `assertion typ is not ${ID_JAG_TYP}`);
  }

  const keyId = typeof decoded.header['kid'] === 'string' ? decoded.header['kid'] : undefined;
  const claimedIssuer = decoded.payload['iss'];
  if (typeof claimedIssuer !== 'string' || claimedIssuer.length === 0) {
    throw new IdJagValidationError('malformed', 'assertion has no iss claim');
  }

  const resolver = options.resolver ?? createIdJagIssuerKeyResolver(fastify);

  // The resolver itself enforces the allowlist and returns `undefined` for an
  // untrusted issuer, so an unlisted `iss` never becomes a fetch.
  let resolved = await resolver({ issuer: claimedIssuer, keyId, algorithm: alg });
  if (!resolved) {
    // ONE bounded refresh: an issuer that rotated its keys inside the cache TTL
    // would otherwise fail every verification until the TTL lapsed. Bounded to a
    // single retry per request, and only reachable AFTER the allowlist check,
    // so a forged `kid` cannot be used to drive unbounded outbound traffic.
    resolved = await resolver({
      issuer: claimedIssuer,
      keyId,
      algorithm: alg,
      forceRefresh: true,
    });
  }
  if (!resolved) {
    throw new IdJagValidationError(
      'unresolvable_key',
      'no trusted signing key resolves for the assertion issuer'
    );
  }

  // The expected `aud` is THIS server's published issuer identifier — the exact
  // string discovery advertises — because that is what an IdP allowlists and
  // targets. Byte comparison, no normalisation (RFC 8414 §2).
  const expectedAudience = resolveIssuerIdentifier(fastify.jwtUtils.getIssuer());

  let verified;
  try {
    verified = await verifyWithHeader(options.assertion, resolved.key, {
      // Pinned to the ONE algorithm the header declared and the key was imported
      // under — not the whole supported set — so cross-algorithm substitution is
      // impossible even within the allowed list.
      algorithms: [alg],
      audience: expectedAudience,
      clockTolerance: env.ID_JAG_CLOCK_SKEW_LEEWAY,
      // NOTE: `issuer` is deliberately NOT delegated to the backend here. jose
      // compares `iss` BYTE-for-byte, and the trust rule this feature is built
      // on is byte equality AFTER trailing-slash-only canonicalisation — the
      // same rule the allowlist lookup applied. Delegating would make the two
      // comparisons disagree and would reject real issuers whose identifier
      // genuinely ends in a slash (Auth0's `iss` does) whenever an operator
      // wrote the allowlist entry without one. The equivalent assertion is made
      // explicitly below, on the VERIFIED claims.
    });
  } catch {
    throw new IdJagValidationError(
      'signature_invalid',
      'assertion failed signature, audience or expiry verification'
    );
  }

  // Authoritative `typ` check: read from the header the SIGNATURE covers, so a
  // rewritten header cannot get past it.
  if (verified.protectedHeader['typ'] !== ID_JAG_TYP) {
    throw new IdJagValidationError('unsupported_typ', `assertion typ is not ${ID_JAG_TYP}`);
  }

  // ADR-011 gate 15 — REFUSE an authorization constraint we do not implement;
  // never ignore it. `idJagClaimsSchema` below is deliberately non-strict (a
  // future spec revision may add members we should tolerate), so it would
  // SILENTLY STRIP `authorization_details` — which is precisely the downgrade
  // this gate exists to prevent. The enterprise IdP used RFC 9396 to narrow
  // what the grant authorizes; issuing a token without honouring that narrowing
  // hands the client more authority than the IdP granted.
  //
  // Read from `verified.claims` — the bytes the signature covers — because by
  // the time the schema has parsed, the member is already gone.
  // ADR-011 gate 15 — REFUSE an authorization constraint we do not implement;
  // never ignore it. `idJagClaimsSchema` below is deliberately non-strict (a
  // future spec revision may add members we should tolerate), so it would
  // SILENTLY STRIP `authorization_details` — which is precisely the downgrade
  // this gate exists to prevent. The enterprise IdP used RFC 9396 to narrow
  // what the grant authorizes; issuing a token without honouring that narrowing
  // hands the client more authority than the IdP granted.
  //
  // Read from `verified.claims` — the bytes the signature covers — because by
  // the time the schema has parsed, the member is already gone. Deliberately a
  // TARGETED check rather than `.strict()`: strictness would also reject
  // unrecognised-but-harmless members a later spec revision may add.
  if (
    typeof verified.claims === 'object' &&
    verified.claims !== null &&
    'authorization_details' in verified.claims
  ) {
    throw new IdJagValidationError(
      'unsupported_constraint',
      'assertion carries authorization_details (RFC 9396), which this server does not implement'
    );
  }

  const parsed = idJagClaimsSchema.safeParse(verified.claims);
  if (!parsed.success) {
    throw new IdJagValidationError('claims_invalid', 'assertion is missing required claims');
  }
  const claims = parsed.data;

  // The `iss` binding (RFC 9700 mix-up defence), asserted on the VERIFIED claim
  // against the CONFIRMED allowlist identifier — never against the unverified
  // text the resolver was handed. Same canonicalisation as the allowlist lookup,
  // so the two can never disagree. Without this the only thing tying the
  // assertion to its issuer would be the key, which is one indirection too few.
  if (resolveIssuerIdentifier(claims.iss) !== resolved.identifier) {
    throw new IdJagValidationError(
      'issuer_invalid',
      'assertion iss does not match the issuer whose key verified it'
    );
  }

  // draft §4.4.1: `aud` MUST be a single string or a single-element array. jose
  // asserted that our identifier is IN the audience; this asserts it is the ONLY
  // member. An assertion naming two authorization servers is redeemable at
  // either of them, which is not a grant the enterprise meant to make.
  const audienceValues = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (audienceValues.length !== 1 || audienceValues[0] !== expectedAudience) {
    throw new IdJagValidationError(
      'audience_invalid',
      'assertion aud must be exactly this authorization server'
    );
  }

  // Bound the assertion's own window. This is what makes `jti` retention finite
  // (see `consumeIdJagJti`): an assertion claiming a 30-day lifetime would need
  // a 30-day replay entry, so it is refused instead. A non-positive window and a
  // future `iat` beyond the skew leeway are refused for the same reason a
  // reversed window is — the issuer's clock claim is not usable.
  const lifetime = claims.exp - claims.iat;
  if (lifetime <= 0 || lifetime > env.ID_JAG_MAX_ASSERTION_LIFETIME) {
    throw new IdJagValidationError('lifetime_invalid', 'assertion lifetime is out of bounds');
  }
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (claims.iat > nowSeconds + env.ID_JAG_CLOCK_SKEW_LEEWAY) {
    throw new IdJagValidationError('lifetime_invalid', 'assertion is issued in the future');
  }

  // draft §4.4.1: the assertion must name the client presenting it. Checked
  // BEFORE the burn — see this function's TSDoc for why the ordering matters.
  if (claims.client_id !== options.expectedClientId) {
    throw new IdJagValidationError(
      'client_mismatch',
      'assertion client_id does not match the authenticated client'
    );
  }

  // LAST, and only now: burn the jti. Everything above is side-effect free, so
  // an unverifiable assertion costs no store write.
  await consumeIdJagJti(fastify, resolved.identifier, claims.jti);

  return {
    issuer: resolved.identifier,
    subject: claims.sub,
    audience: expectedAudience,
    resource: claims.resource,
    clientId: claims.client_id,
    scopes: splitScope(claims.scope),
    jti: claims.jti,
    expiresAt: claims.exp,
    issuedAt: claims.iat,
  };
}

/**
 * Provider-type discriminator under which an enterprise IdP's subject is linked
 * to a QAuth user in `user_credentials`.
 *
 * `user_credentials.provider_type` is deliberately plain text with an
 * open-ended `oidc_*` family (see `libs/infra/db` schema), so an issuer needs no
 * migration to become linkable. The issuer identifier is part of the key because
 * `sub` is only unique WITHIN an issuer (draft §6) — two IdPs may both issue
 * `sub: "12345"` and they are not the same person.
 */
export function idJagCredentialProviderType(issuer: string): string {
  return `oidc_${issuer}`;
}

/** Options for {@link mintIdJag}. */
export interface MintIdJagOptions {
  /** `sub` — the QAuth user the assertion is about. */
  readonly subject: string;
  /** `aud` — the TARGET resource authorization server's issuer identifier. */
  readonly audience: string;
  /** `resource` — the MCP server the target AS must restrict its token to. */
  readonly resource: string;
  /** `client_id` — the MCP client the assertion authorizes. */
  readonly clientId: string;
  /** `scope`, space-delimited. Omitted from the assertion when absent. */
  readonly scope?: string;
}

/** A freshly minted ID-JAG and the lifetime advertised alongside it. */
export interface MintedIdJag {
  /** The compact JWS. Returned to the client in the `access_token` member. */
  readonly assertion: string;
  /** Seconds until `exp`; the response's `expires_in`. */
  readonly expiresIn: number;
  /** The assertion's `jti`, for the audit log. */
  readonly jti: string;
}

/**
 * Signing keys imported from PEM, memoised per PEM string.
 *
 * The key is imported once rather than on every mint (`importPKCS8` is not
 * free), and keyed by the PEM itself so a test that boots two servers with
 * different keys never shares one. The map is bounded by the number of distinct
 * configured keys — operator data, never request data — so it cannot grow.
 */
const signingKeyCache = new Map<string, Promise<SigningKey>>();

function idJagSigningKey(): Promise<SigningKey> {
  const pem = env.JWT_PRIVATE_KEY;
  const cached = signingKeyCache.get(pem);
  if (cached) return cached;
  const imported = importPrivateSigningKey(pem, ID_JAG_SIGNING_ALGORITHM);
  signingKeyCache.set(pem, imported);
  return imported;
}

/**
 * Mint an ID-JAG (draft §3.1 / §4.3.4, EMA §4.3).
 *
 * The exact claim set:
 *
 * ```
 * header  { alg: "EdDSA", typ: "oauth-id-jag+jwt" }
 * payload { jti, iss, sub, aud, resource, client_id, iat, exp, scope? }
 * ```
 *
 * Two omissions are deliberate:
 *
 *  - **no `email`** (and no other identity claim), even though the draft
 *    RECOMMENDS one for subject resolution and JIT provisioning at the target.
 *    `iss` + `sub` is already a complete, unambiguous subject identifier, and
 *    emitting an address would release PII into a foreign trust domain on the
 *    strength of no scope decision at all. QAuth's own ID token releases email
 *    only under the `email` scope (#259); an assertion crossing a trust boundary
 *    should not be laxer than that.
 *  - **no `act`** delegation chain. It is not part of the ID-JAG claim set, and
 *    a foreign AS that does not understand it would either ignore it (making it
 *    pointless) or reject the assertion (making it harmful). The delegation
 *    DEPTH bound is still enforced by the caller before minting.
 *
 * Signed with the same EdDSA key as access tokens (see
 * {@link ID_JAG_SIGNING_ALGORITHM}), so the target AS verifies it from QAuth's
 * published JWKS with no extra provisioning. `iss` is the CANONICAL issuer
 * identifier — byte-identical to what discovery publishes — because that is the
 * string the target AS allowlists.
 */
export async function mintIdJag(
  fastify: FastifyInstance,
  options: MintIdJagOptions
): Promise<MintedIdJag> {
  const jti = randomUUID();
  const expiresIn = env.ID_JAG_ISSUED_LIFETIME;

  const claims: Record<string, unknown> = {
    jti,
    sub: options.subject,
    resource: options.resource,
    client_id: options.clientId,
    ...(options.scope !== undefined && options.scope.length > 0 ? { scope: options.scope } : {}),
  };

  const assertion = await sign(claims, await idJagSigningKey(), ID_JAG_SIGNING_ALGORITHM, {
    issuer: resolveIssuerIdentifier(fastify.jwtUtils.getIssuer()),
    expiresIn,
    // Single-valued on purpose: `sign` passes a string straight through to
    // `aud`, and the consume side refuses a multi-valued `aud` for the reason
    // documented there.
    audience: options.audience,
    typ: ID_JAG_TYP,
  });

  return { assertion, expiresIn, jti };
}
