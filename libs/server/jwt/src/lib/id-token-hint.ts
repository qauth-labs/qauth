import { CryptoVerificationError, verifyWithHeader } from '@qauth-labs/core-crypto';
import { JWTInvalidError } from '@qauth-labs/shared-errors';
import { decodeJwt } from 'jose';
import { z } from 'zod';

import type { KeyLike } from '../types/key-management';
import { decodeProtectedHeaderUnsafe } from './jose-utils';
import { ID_TOKEN_TYP, type IdTokenSigningAlgorithm } from './jwt-service';

/**
 * The claims of a verified `id_token_hint` (OpenID Connect RP-Initiated
 * Logout 1.0 §2, #675) that the end-session endpoint reads.
 */
export interface IdTokenHint {
  /** The end-user the ID token was issued for. Never empty. */
  readonly sub: string;
  /** The ID token's `aud` as a list: a string `aud` becomes `[aud]`. Never empty. */
  readonly aud: readonly string[];
  /** The browser session the ID token names (#549), when it names one. */
  readonly sid?: string;
  /** `iat`, in epoch seconds, when present. */
  readonly iat?: number;
  /** `exp`, in epoch seconds, when present. */
  readonly exp?: number;
  /**
   * `exp` has passed. The signature, the issuer and the `typ` were verified
   * all the same: an expired hint is accepted (RP-Initiated Logout 1.0 §2).
   */
  readonly expired: boolean;
}

/** Options of {@link verifyIdTokenHint}. */
export interface VerifyIdTokenHintOptions {
  /** The issuer the token's `iss` must equal: the realm's. */
  readonly issuer: string;
  /**
   * The algorithms the key may verify with. Narrows the ID-token algorithms
   * (`RS256`, `EdDSA`); it never widens them. Default: both.
   */
  readonly algorithms?: readonly IdTokenSigningAlgorithm[];
}

/** The algorithms QAuth signs ID tokens with (#309). */
const ID_TOKEN_ALGORITHMS: readonly IdTokenSigningAlgorithm[] = ['RS256', 'EdDSA'];

const nonEmptyString = z.string().min(1);

/**
 * The claims a hint must carry, by shape. Other claims pass through unread.
 * `iat` and `exp` are numbers when present; jose has already refused a
 * non-numeric `exp` or `nbf` by the time this runs.
 */
const idTokenHintClaimsSchema = z.looseObject({
  sub: nonEmptyString,
  aud: z.union([nonEmptyString, z.array(nonEmptyString).min(1)]),
  sid: z.string().optional(),
  iat: z.number().optional(),
  exp: z.number().optional(),
});

/**
 * Verify an `id_token_hint` with one key (OpenID Connect RP-Initiated Logout
 * 1.0 §2, #675): an ID token this server issued, expired or not.
 *
 * - The signature must verify with `publicKey`, under RS256 or EdDSA only:
 *   `none`, HMAC, ES256 and ML-DSA are refused before any key is tried.
 * - `iss` must equal `options.issuer`.
 * - The signed protected header's `typ` must be exactly {@link ID_TOKEN_TYP}.
 *   An access token (`at+jwt`), an ID-JAG, a logout token or a token without
 *   `typ` is refused, expired or not.
 * - An expired token is accepted with `expired: true`. A token whose `nbf`
 *   lies in the future stays refused.
 *
 * The caller resolves the key; the JWT plugin picks it by the header's
 * `(kid, alg)` among the realm's verification keys.
 *
 * @throws JWTInvalidError on every refusal, never `JWTExpiredError`
 */
export async function verifyIdTokenHint(
  token: string,
  publicKey: KeyLike,
  options: VerifyIdTokenHintOptions
): Promise<IdTokenHint> {
  const algorithms = (options.algorithms ?? ID_TOKEN_ALGORITHMS).filter((alg) =>
    ID_TOKEN_ALGORITHMS.includes(alg)
  );
  if (algorithms.length === 0) {
    throw new JWTInvalidError('Invalid ID token hint: no algorithm allowed');
  }

  let claims: Record<string, unknown>;
  let protectedHeader: Record<string, unknown>;
  let expired = false;
  try {
    ({ claims, protectedHeader } = await verifyWithHeader(token, publicKey, {
      algorithms: [...algorithms],
      issuer: options.issuer,
    }));
  } catch (error) {
    if (!(error instanceof CryptoVerificationError) || error.reason !== 'expired') {
      throw new JWTInvalidError('Invalid ID token hint');
    }
    // jose (6.2.12, `jwt/verify.js` + `lib/jwt_claims_set.js`) verifies the
    // signature first, then checks `iss`, then `nbf`, and only then `exp`. So
    // an `expired` failure means the signature, the issuer and `nbf` passed:
    // the header and claims read below are the issuer's, unaltered.
    expired = true;
    protectedHeader = decodeProtectedHeaderUnsafe(token);
    // The raw claims set, not `decodeJwtUnsafe`'s access-token view, which
    // drops `sid`. The token decoded once already, so this cannot throw.
    claims = { ...decodeJwt(token) };
  }

  // Read from the authenticated header. Exact match: an access token, an
  // ID-JAG or a logout token signed by the same key is not an ID token.
  if (protectedHeader['typ'] !== ID_TOKEN_TYP) {
    throw new JWTInvalidError('Invalid ID token hint: not an ID token');
  }

  const result = idTokenHintClaimsSchema.safeParse(claims);
  if (!result.success) {
    throw new JWTInvalidError('Invalid ID token hint: malformed claims');
  }
  const { sub, aud, sid, iat, exp } = result.data;
  return {
    sub,
    aud: typeof aud === 'string' ? [aud] : aud,
    ...(sid === undefined ? {} : { sid }),
    ...(iat === undefined ? {} : { iat }),
    ...(exp === undefined ? {} : { exp }),
    expired,
  };
}
