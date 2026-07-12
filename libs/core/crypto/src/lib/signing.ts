import { jwtVerify, SignJWT } from 'jose';

import type { SignatureAlgorithm } from './algorithms';
import { CryptoVerificationError } from './errors';
import type { SigningKey } from './keys';

/** Registered-claim inputs applied to every signed token. */
export interface SignOptions {
  /** `iss` (issuer) claim value. */
  issuer: string;
  /** Token lifetime in seconds; used to derive `exp` from `iat`. */
  expiresIn: number;
  /** `aud` (audience) claim value — a single audience or a list. */
  audience: string | string[];
}

/** Constraints applied when verifying a token. */
export interface VerifyOptions {
  /**
   * Permitted signature algorithms. A token whose header `alg` is not in this
   * list is rejected (algorithm-confusion defence).
   */
  algorithms: SignatureAlgorithm[];
  /** When set, the token's `iss` must equal this value (RFC 9700 mix-up defence). */
  issuer?: string;
  /** When set, the token's `aud` must include this value. */
  audience?: string | string[];
}

/**
 * Sign a claims set into a compact JWS (JWT) using the given algorithm.
 *
 * This is a pure cryptographic operation. The caller owns all business/claims
 * shaping and passes a ready-to-sign claims record; the abstraction stamps only
 * the registered temporal/issuer/audience claims (`iat`, `exp`, `iss`, `aud`)
 * and the protected header (`alg`).
 *
 * @param claims - Application + registered claims to embed (already shaped by the caller).
 * @param privateKey - Private signing key.
 * @param alg - Signature algorithm (Phase 1: `EdDSA`).
 * @param options - Registered-claim inputs — see {@link SignOptions}.
 * @returns The signed compact JWT.
 */
export async function sign(
  claims: Record<string, unknown>,
  privateKey: SigningKey,
  alg: SignatureAlgorithm,
  options: SignOptions
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .setExpirationTime(`${options.expiresIn}s`)
    .setIssuer(options.issuer)
    .setAudience(options.audience)
    .sign(privateKey);
}

/**
 * Verify a compact JWT's signature and registered claims, returning its raw
 * claims set.
 *
 * The signature, algorithm, and (when supplied) `iss` / `aud` are checked by
 * the backend. Application-level claim-shape validation is intentionally NOT
 * performed here — that is the caller's concern. On any failure a
 * {@link CryptoVerificationError} is thrown, normalizing the backend's error
 * shape into this library's stable vocabulary.
 *
 * @param token - Compact JWT to verify.
 * @param publicKey - Public verification key.
 * @param options - Verification constraints — see {@link VerifyOptions}.
 * @returns The verified raw claims set.
 * @throws CryptoVerificationError if the token is expired or otherwise invalid.
 */
export async function verify(
  token: string,
  publicKey: SigningKey,
  options: VerifyOptions
): Promise<Record<string, unknown>> {
  try {
    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: options.algorithms,
      ...(options.issuer !== undefined ? { issuer: options.issuer } : {}),
      ...(options.audience !== undefined ? { audience: options.audience } : {}),
    });
    return payload;
  } catch (error) {
    throw toCryptoVerificationError(error);
  }
}

/**
 * Normalize a backend (JOSE) verification failure into a
 * {@link CryptoVerificationError}.
 *
 * Preserves the exact classification the JWT layer relied on before this seam
 * existed:
 * - JOSE's `JWTExpired` (error `name`) becomes `reason: 'expired'`.
 * - a JOSE error carrying a string `code` becomes `reason: 'invalid'` with the
 *   backend message retained as `detail`.
 * - anything else becomes `reason: 'invalid'` with no detail.
 */
function toCryptoVerificationError(error: unknown): CryptoVerificationError {
  if (error instanceof Error) {
    if (error.name === 'JWTExpired') {
      return new CryptoVerificationError('expired', { cause: error });
    }
    if ('code' in error && typeof error.code === 'string') {
      return new CryptoVerificationError('invalid', { detail: error.message, cause: error });
    }
  }
  return new CryptoVerificationError('invalid', { cause: error });
}
