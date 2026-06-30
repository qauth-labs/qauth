import { z } from 'zod';

import type { JWTPayload } from '../types/jwt-service';

/**
 * Runtime claim-shape validation for verified access tokens.
 *
 * `jose`'s {@link jwtVerify} verifies the JWT *signature* and the registered
 * temporal/issuer/audience claims — it does NOT assert that application claims
 * have the shape this server expects. A token can therefore be cryptographically
 * valid yet carry, say, a numeric `sub` or an `email` that is not a string. Casting
 * such a payload with `as string` (the previous behaviour) silently mis-types it
 * and pushes the corruption downstream.
 *
 * This schema runs AFTER signature verification and rejects a malformed-but-signed
 * token, so consumers always receive a well-typed {@link JWTPayload}. It is kept
 * intentionally minimal and aligned with the QAuth token claim model:
 *
 * - `sub` is the only always-present claim (RFC 7519 §4.1.2).
 * - `email` / `email_verified` are OMITTED for client_credentials tokens, so they
 *   are optional; when present they must be a well-formed email / boolean.
 * - All registered/optional claims are validated only for type, not presence,
 *   except `sub`.
 *
 * Unknown claims are passed through untouched (`.passthrough()` semantics via
 * `.loose()`) — this validator narrows the claims QAuth consumes, it is not an
 * allowlist of permitted claims.
 */
const actClaimSchema: z.ZodType<NonNullable<JWTPayload['act']>> = z.lazy(() =>
  z.object({
    sub: z.string(),
    act: actClaimSchema.optional(),
  })
);

export const accessTokenClaimsSchema = z.looseObject({
  // RFC 7519 §4.1.2 — subject. Always present on tokens this server mints.
  sub: z.string(),
  // OIDC identity claims. Omitted entirely for client_credentials tokens, so
  // optional; a present-but-malformed value is rejected rather than coerced.
  email: z.email().optional(),
  email_verified: z.boolean().optional(),
  // OAuth client identifier (`client_id` claim).
  client_id: z.string().optional(),
  // Space-separated granted scopes (omitted when none granted).
  scope: z.string().optional(),
  // RFC 8707 audience — single or multiple.
  aud: z.union([z.string(), z.array(z.string())]).optional(),
  // RFC 8693 §4.1 delegation actor (nested chain).
  act: actClaimSchema.optional(),
  // Registered temporal/issuer claims.
  iat: z.number().optional(),
  exp: z.number().optional(),
  iss: z.string().optional(),
  // RFC 7519 §4.1.7 unique token id (RFC 7009 revocation support).
  jti: z.string().optional(),
  // Token-use marker (token-confusion defence).
  token_use: z.string().optional(),
});

export type AccessTokenClaims = z.infer<typeof accessTokenClaimsSchema>;
