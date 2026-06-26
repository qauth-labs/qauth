import { randomUUID } from 'node:crypto';

import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import { jwtVerify, SignJWT } from 'jose';

import type { JWTPayload, SignAccessTokenPayload, SignIdTokenPayload } from '../types/jwt-service';
import type { KeyLike } from '../types/key-management';

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
export async function signAccessToken(
  payload: SignAccessTokenPayload,
  privateKey: KeyLike,
  issuer: string,
  expiresIn: number
): Promise<string> {
  // Build claims. Omit email/email_verified for client_credentials tokens where
  // there is no end-user. Include scope only when granted.
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

  let jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setExpirationTime(`${expiresIn}s`)
    .setIssuer(issuer);

  // `aud` claim: array → multi-audience, string → single, otherwise fall back
  // to the client_id (OAuth 2.1 RFC 8707 light-mode default).
  const audience = payload.aud ?? payload.clientId;
  jwt = jwt.setAudience(audience);

  return jwt.sign(privateKey);
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
 * `token_use: 'access'` or the structural access-token markers).
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
export async function signIdToken(
  payload: SignIdTokenPayload,
  privateKey: KeyLike,
  issuer: string,
  expiresIn: number
): Promise<string> {
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

  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setExpirationTime(`${expiresIn}s`)
    .setIssuer(issuer)
    .setAudience(payload.audience)
    .sign(privateKey);
}

/**
 * Verify and decode an access token
 *
 * Verifies the JWT signature and decodes the payload.
 * Throws JWTExpiredError if the token has expired.
 * Throws JWTInvalidError if the token is invalid or malformed.
 *
 * @param token - JWT token string to verify
 * @param publicKey - EdDSA public key for verification
 * @returns Promise resolving to decoded JWT payload
 * @throws JWTExpiredError if token has expired
 * @throws JWTInvalidError if token is invalid
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
export async function verifyAccessToken(
  token: string,
  publicKey: KeyLike,
  options: { audience?: string | string[]; issuer?: string } = {}
): Promise<JWTPayload> {
  try {
    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: ['EdDSA'],
      // RFC 9700 / mix-up defence: when the caller supplies the expected
      // issuer, jose asserts the `iss` claim matches and rejects otherwise.
      // The alg stays pinned to EdDSA so `none`/alg-confusion is impossible.
      ...(options.issuer !== undefined ? { issuer: options.issuer } : {}),
      ...(options.audience !== undefined ? { audience: options.audience } : {}),
    });

    return {
      sub: payload.sub as string,
      email: payload['email'] as string | undefined,
      email_verified: payload['email_verified'] as boolean | undefined,
      clientId: payload['client_id'] as string,
      scope: payload['scope'] as string | undefined,
      aud: payload.aud as string | string[] | undefined,
      // RFC 8693 §4.1: surface any existing `act` chain so a subject token
      // already carrying a delegation can be nested under the new actor.
      act: payload['act'] as JWTPayload['act'],
      iat: payload.iat as number | undefined,
      exp: payload.exp as number | undefined,
      iss: payload.iss as string | undefined,
      // RFC 7009 revocation: surface the unique token id so the auth-server
      // layer can denylist a specific access token. The lib stays pure — it
      // never consults any revocation store itself.
      jti: payload.jti as string | undefined,
      token_use: payload['token_use'] as string | undefined,
    };
  } catch (error) {
    if (error instanceof Error) {
      // 'jose' errors have a `code` property, and `JWTExpired` is a specific error name.
      if (error.name === 'JWTExpired') {
        throw new JWTExpiredError('JWT token has expired');
      }

      // Any other error from `jose` can be considered an invalid token error.
      // We can identify them by checking for the `code` property, which is a pattern in `jose`.
      if ('code' in error && typeof error.code === 'string') {
        throw new JWTInvalidError(`Invalid JWT token: ${error.message}`);
      }
    }

    // Fallback for unknown errors
    throw new JWTInvalidError('Invalid JWT token');
  }
}
