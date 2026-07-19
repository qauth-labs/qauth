import { randomUUID } from 'node:crypto';

import { CryptoVerificationError, sign, verifyWithHeader } from '@qauth-labs/core-crypto';
import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';

import type { JWTPayload, SignAccessTokenPayload, SignIdTokenPayload } from '../types/jwt-service';
import type { KeyLike } from '../types/key-management';
import { accessTokenClaimsSchema } from './access-token-claims';

/**
 * RFC 9068 §2.1 `typ` for a JWT OAuth 2.0 access token.
 *
 * Stamped into the SIGNATURE-PROTECTED header of every access token (#283).
 * This is the standards-defined half of QAuth's cross-token-confusion defence;
 * the `token_use: 'access'` payload claim is the other half. Both are needed:
 * `typ` is what a third-party resource server (and every off-the-shelf RFC 9068
 * verifier) will check, `token_use` is what QAuth's own token-exchange path
 * already asserts.
 *
 * This matters concretely here because ID tokens and access tokens are signed
 * with the SAME key and therefore verify against the same JWKS entry — see
 * `signIdToken` below.
 */
export const ACCESS_TOKEN_TYP = 'at+jwt';

/**
 * RFC 7519 §5.1 `typ` for an OIDC ID token.
 *
 * `JWT` is the generic media type; OIDC Core defines no ID-token-specific one.
 * Its job here is purely to be DISTINCT from {@link ACCESS_TOKEN_TYP}, so a
 * resource server enforcing `at+jwt` rejects an ID token structurally rather
 * than relying on the audience check happening to differ.
 */
export const ID_TOKEN_TYP = 'JWT';

/**
 * Sign an access token
 *
 * Creates a JWT access token with EdDSA algorithm.
 *
 * @param payload - Payload containing sub, email, and email_verified
 * @param privateKey - EdDSA private key for signing
 * @param issuer - JWT issuer (iss claim)
 * @param expiresIn - Expiration time in seconds
 * @returns Promise resolving to signed JWT token string
 *
 * @example
 * ```typescript
 * const token = await signAccessToken(
 *   { sub: 'user-123', email: 'user@example.com', email_verified: true },
 *   privateKey,
 *   'https://auth.example.com',
 *   900
 * );
 * ```
 */
/**
 * Build the access-token claim set + resolved audience (business logic; no
 * signing). Extracted so the classical {@link signAccessToken} and the hybrid
 * signer (#245) share ONE claim-shaping source and can never drift. Each call
 * mints a fresh `jti`.
 */
export function buildAccessTokenClaims(payload: SignAccessTokenPayload): {
  claims: Record<string, unknown>;
  audience: string | string[];
} {
  // Omit email/email_verified for client_credentials tokens where there is no
  // end-user. Include scope only when granted.
  const claims: Record<string, unknown> = {
    sub: payload.sub,
    client_id: payload.clientId,
    // RFC 7519 §4.1.7 `jti` — a unique identifier per access token. Enables
    // targeted revocation (RFC 7009): the auth-server maintains a denylist
    // keyed by `jti` so a specific unexpired token can be invalidated.
    jti: randomUUID(),
    // Token-use marker (token-confusion defence): every token minted by this
    // function is an OAuth access token. Consumers that must accept ONLY access
    // tokens — e.g. RFC 8693 token-exchange subject tokens — assert this so a
    // differently-purposed JWT signed with the same key cannot be substituted.
    token_use: 'access',
  };
  if (payload.email !== undefined) {
    claims['email'] = payload.email;
  }
  if (payload.email_verified !== undefined) {
    claims['email_verified'] = payload.email_verified;
  }
  if (payload.scope !== undefined && payload.scope.length > 0) {
    claims['scope'] = payload.scope;
  }
  // RFC 8693 §4.1: emit the `act` (actor) claim only on delegated tokens minted
  // via token-exchange. It is additive — `sub` stays the end-user; `act`
  // identifies the acting agent (nested for chained delegation).
  if (payload.act !== undefined) {
    claims['act'] = payload.act;
  }

  // `aud` claim: array → multi-audience, string → single, otherwise fall back
  // to the client_id (OAuth 2.1 RFC 8707 light-mode default).
  const audience = payload.aud ?? payload.clientId;
  return { claims, audience };
}

export async function signAccessToken(
  payload: SignAccessTokenPayload,
  privateKey: KeyLike,
  issuer: string,
  expiresIn: number
): Promise<string> {
  const { claims, audience } = buildAccessTokenClaims(payload);
  // The claims shaping above is business logic and stays here; only the JWS
  // signing crosses into the algorithm-agnostic crypto abstraction (ADR-005).
  return sign(claims, privateKey, 'EdDSA', {
    issuer,
    expiresIn,
    audience,
    typ: ACCESS_TOKEN_TYP,
  });
}

/**
 * Sign an OIDC ID token (OpenID Connect Core 1.0 §2).
 *
 * Creates a JWT ID token with the EdDSA algorithm, using the same signing key
 * as access tokens so a single JWKS verifies both. The ID token asserts the
 * authentication of the end-user to the Relying Party (the OAuth client):
 *
 * - `iss` — the authorization server issuer identifier.
 * - `aud` — the client identifier the token was issued for (OIDC Core §2).
 * - `sub` — the stable subject (user) identifier.
 * - `exp` / `iat` — expiry / issued-at, set from `expiresIn`.
 * - `email`, `email_verified`, `name` — identity claims, when available.
 * - `nonce` — echoed verbatim from the authorization request, when supplied
 *   (OIDC Core §3.1.3.6).
 *
 * A `token_use: 'id'` marker is stamped so an ID token can never be mistaken
 * for an access token (token-confusion defence — e.g. it must not be accepted
 * as an RFC 8693 token-exchange `subject_token`, which requires
 * `token_use: 'access'` or the structural access-token markers). Since #283 the
 * SIGNED protected header carries {@link ID_TOKEN_TYP} for the same reason, one
 * layer lower: a resource server can reject this token without parsing a single
 * claim.
 *
 * @param payload - ID token claims (sub, audience, optional identity claims)
 * @param privateKey - EdDSA private key for signing
 * @param issuer - JWT issuer (iss claim)
 * @param expiresIn - Expiration time in seconds
 * @returns Promise resolving to the signed ID token string
 *
 * @example
 * ```typescript
 * const idToken = await signIdToken(
 *   { sub: 'user-123', audience: 'client-abc', email: 'u@example.com',
 *     email_verified: true, nonce: 'n-0S6_WzA2Mj' },
 *   privateKey,
 *   'https://auth.example.com',
 *   900
 * );
 * ```
 */
/**
 * Build the ID-token claim set + audience (business logic; no signing).
 * Shared by the classical {@link signIdToken} and the hybrid signer (#245).
 */
export function buildIdTokenClaims(payload: SignIdTokenPayload): {
  claims: Record<string, unknown>;
  audience: string | string[];
} {
  const claims: Record<string, unknown> = {
    sub: payload.sub,
    // Token-use marker: this is an OIDC ID token, never an access token.
    // Consumers that must accept ONLY access tokens (e.g. the token-exchange
    // subject_token) reject this value, closing the token-confusion gap.
    token_use: 'id',
  };
  if (payload.email !== undefined) {
    claims['email'] = payload.email;
  }
  if (payload.email_verified !== undefined) {
    claims['email_verified'] = payload.email_verified;
  }
  if (payload.name !== undefined) {
    claims['name'] = payload.name;
  }
  // OIDC Core §3.1.3.6: when a `nonce` was present in the authorization request
  // it MUST be echoed unmodified in the ID token. Omitted entirely otherwise.
  if (payload.nonce !== undefined) {
    claims['nonce'] = payload.nonce;
  }
  return { claims, audience: payload.audience };
}

export async function signIdToken(
  payload: SignIdTokenPayload,
  privateKey: KeyLike,
  issuer: string,
  expiresIn: number
): Promise<string> {
  const { claims, audience } = buildIdTokenClaims(payload);
  return sign(claims, privateKey, 'EdDSA', {
    issuer,
    expiresIn,
    audience,
    // #283: `JWT`, never `at+jwt`. Same signing key as the access token, so the
    // protected-header `typ` is the only thing that distinguishes the two
    // before any claim is inspected.
    typ: ID_TOKEN_TYP,
  });
}

/**
 * Verify and decode an access token
 *
 * Verifies the JWT signature and decodes the payload.
 * Throws JWTExpiredError if the token has expired.
 * Throws JWTInvalidError if the token is invalid or malformed.
 *
 * ## RFC 9068 `typ` enforcement (#283) — two-phase, deliberately
 *
 * The `typ` checked here is read from the SIGNATURE-PROTECTED header returned
 * by `verifyWithHeader`, never from an unverified decode: a header member that
 * drives an accept/reject decision must be one the issuer signed, or an
 * attacker simply rewrites it.
 *
 * The two cases are gated differently because only one of them is breaking:
 *
 * - **`typ` present but not `at+jwt`** → ALWAYS rejected. Not a compatibility
 *   risk: no token QAuth issued before #283 carries any `typ` at all, so this
 *   can only fire on a genuinely wrong-typed token — an ID token
 *   ({@link ID_TOKEN_TYP}) being the case that matters, since it is signed with
 *   the same key and verifies against the same JWKS entry.
 * - **`typ` absent** → accepted unless `requireTyp` is set. Turning this on at
 *   the same moment issuance starts stamping `typ` would reject every access
 *   token minted by the previous build that is still inside its lifetime
 *   (`ACCESS_TOKEN_LIFESPAN`, default 900s). Operators flip `requireTyp` on in
 *   a SECOND deploy, at least one access-token lifespan after the first.
 *
 * @param token - JWT token string to verify
 * @param publicKey - EdDSA public key for verification
 * @param options - Verification constraints; `requireTyp` opts into strict
 *   RFC 9068 `typ` enforcement (see above) and defaults to `false`.
 * @returns Promise resolving to decoded JWT payload
 * @throws JWTExpiredError if token has expired
 * @throws JWTInvalidError if token is invalid, or its signed `typ` is not
 *   {@link ACCESS_TOKEN_TYP}
 *
 * @example
 * ```typescript
 * try {
 *   const payload = await verifyAccessToken(token, publicKey);
 *   console.log(payload.sub); // user ID
 * } catch (error) {
 *   if (error instanceof JWTExpiredError) {
 *     // Handle expiration
 *   } else if (error instanceof JWTInvalidError) {
 *     // Handle invalid token
 *   }
 * }
 * ```
 */
/**
 * Assert that a SIGNED protected-header `typ` identifies an RFC 9068 access
 * token (#283).
 *
 * @param signedTyp - The `typ` member of the signature-protected header. MUST
 *   come from a verified header — a value lifted off an unverified decode is
 *   attacker-controlled and asserting on it proves nothing.
 * @param requireTyp - When `true`, an ABSENT `typ` is also rejected. See the
 *   rollout note on {@link verifyAccessToken}.
 * @throws JWTInvalidError when the `typ` is wrong, non-string, or (under
 *   `requireTyp`) missing.
 */
function assertAccessTokenTyp(signedTyp: unknown, requireTyp: boolean): void {
  if (signedTyp === undefined) {
    if (requireTyp) {
      throw new JWTInvalidError('Invalid JWT token: missing typ header (expected at+jwt)');
    }
    return;
  }
  // RFC 9068 §4 lets a verifier accept the `application/` prefix omitted; QAuth
  // only ever issues the bare form, and accepting variants would widen what a
  // wrong-typed token can look like for no benefit. Exact match, no
  // case-folding.
  if (signedTyp !== ACCESS_TOKEN_TYP) {
    throw new JWTInvalidError('Invalid JWT token: not an access token (typ is not at+jwt)');
  }
}

export async function verifyAccessToken(
  token: string,
  publicKey: KeyLike,
  options: { audience?: string | string[]; issuer?: string; requireTyp?: boolean } = {}
): Promise<JWTPayload> {
  let payload: Record<string, unknown>;
  let protectedHeader: Record<string, unknown>;
  try {
    ({ claims: payload, protectedHeader } = await verifyWithHeader(token, publicKey, {
      algorithms: ['EdDSA'],
      // RFC 9700 / mix-up defence: when the caller supplies the expected
      // issuer, the abstraction asserts the `iss` claim matches and rejects
      // otherwise. The alg stays pinned to EdDSA so `none`/alg-confusion is
      // impossible.
      ...(options.issuer !== undefined ? { issuer: options.issuer } : {}),
      ...(options.audience !== undefined ? { audience: options.audience } : {}),
    }));
  } catch (error) {
    // The crypto abstraction normalizes the backend (jose) failure shape into a
    // backend-neutral `CryptoVerificationError`. Mapping that onto QAuth's JWT
    // domain errors is a server-layer concern, so it stays here — the crypto lib
    // never depends on `@qauth-labs/shared-errors`.
    if (error instanceof CryptoVerificationError) {
      if (error.reason === 'expired') {
        throw new JWTExpiredError('JWT token has expired');
      }
      // A backend-supplied diagnostic is surfaced verbatim, preserving the
      // previous `Invalid JWT token: <reason>` message for invalid tokens.
      if (error.detail !== undefined) {
        throw new JWTInvalidError(`Invalid JWT token: ${error.detail}`);
      }
    }

    // Fallback for unknown errors
    throw new JWTInvalidError('Invalid JWT token');
  }

  // #283 RFC 9068 §2.1 `typ`. Read from the AUTHENTICATED header above, and
  // asserted BEFORE the claim-shape parse so a wrong-typed token is rejected on
  // `typ` grounds specifically — an ID token happens to also fail the claim
  // schema, and we do not want that coincidence standing in for this control.
  // See the two-phase rollout note in this function's TSDoc for why an ABSENT
  // `typ` is gated on `requireTyp` but a WRONG one never is.
  assertAccessTokenTyp(protectedHeader['typ'], options.requireTyp === true);

  // `jose` verifies the SIGNATURE and the registered temporal/issuer/audience
  // claims only — it does not assert the SHAPE of application claims. Without
  // this step a signed-but-malformed token (e.g. a numeric `sub` or a non-string
  // `email`) would be blindly cast and silently mis-typed downstream. Validate
  // the claim shape at runtime and reject anything that does not match the token
  // claim model before returning typed claims. Runs OUTSIDE the verify try/catch
  // so the malformed-claims error is not re-wrapped with the jose-error message.
  const result = accessTokenClaimsSchema.safeParse(payload);
  if (!result.success) {
    throw new JWTInvalidError('Invalid JWT token: malformed claims');
  }
  const claims = result.data;

  return {
    sub: claims.sub,
    email: claims.email,
    email_verified: claims.email_verified,
    clientId: claims.client_id as string,
    scope: claims.scope,
    aud: claims.aud,
    // RFC 8693 §4.1: surface any existing `act` chain so a subject token already
    // carrying a delegation can be nested under the new actor.
    act: claims.act,
    iat: claims.iat,
    exp: claims.exp,
    iss: claims.iss,
    // RFC 7009 revocation: surface the unique token id so the auth-server layer
    // can denylist a specific access token. The lib stays pure — it never
    // consults any revocation store itself.
    jti: claims.jti,
    token_use: claims.token_use,
  };
}
