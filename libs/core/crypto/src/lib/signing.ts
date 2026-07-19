import { jwtVerify, SignJWT } from 'jose';

import type { JwsAlgorithm } from './algorithms';
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
  /**
   * Extra protected-header members merged in alongside `alg` (#245 hybrid
   * signing uses this to stamp `kid` / `pqc_alg` / `pqc_kid`). Defaults to
   * empty — when omitted the header is exactly `{ alg }`, so existing EdDSA
   * callers emit byte-identical tokens.
   *
   * The RESERVED members {@link RESERVED_PROTECTED_HEADER_MEMBERS} (`alg`,
   * `crit`, `b64`) are REJECTED (#248 F6) — passing any of them throws rather
   * than being silently dropped. `alg` is owned by the `alg` argument (a caller
   * override would be algorithm confusion); `crit` would make a classical
   * verifier reject the token, breaking the hybrid design's compatibility
   * guarantee; `b64` (RFC 7797) would change the signing-input encoding out
   * from under the detached PQC signature.
   */
  header?: Record<string, unknown>;
}

/** Constraints applied when verifying a token. */
export interface VerifyOptions {
  /**
   * Permitted signature algorithms. A token whose header `alg` is not in this
   * list is rejected (algorithm-confusion defence).
   */
  algorithms: JwsAlgorithm[];
  /** When set, the token's `iss` must equal this value (RFC 9700 mix-up defence). */
  issuer?: string;
  /** When set, the token's `aud` must include this value. */
  audience?: string | string[];
  /**
   * Allowed clock skew in seconds when validating temporal claims (`exp`,
   * `nbf`). Defaults to zero — no tolerance.
   */
  clockTolerance?: number;
  /**
   * Reference time used to evaluate temporal claims. Defaults to the current
   * time; primarily useful for deterministic testing of expiry behaviour.
   */
  currentDate?: Date;
}

/**
 * Protected-header members a caller may NEVER supply via
 * {@link SignOptions.header} (#248 F6).
 *
 * Each one, if attacker- or caller-controlled, subverts a signature invariant:
 * `alg` is the algorithm-confusion lever, `crit` breaks classical-verifier
 * compatibility (and can smuggle must-understand semantics past this layer),
 * and `b64` (RFC 7797) redefines the payload encoding the signature covers.
 */
export const RESERVED_PROTECTED_HEADER_MEMBERS = ['alg', 'crit', 'b64'] as const;

/**
 * Reject a caller-supplied protected header that carries a reserved member.
 *
 * Fails CLOSED and LOUDLY: silently dropping a reserved member would leave the
 * caller believing it took effect, which is exactly how a header-injection bug
 * becomes invisible.
 *
 * @throws Error naming the offending member.
 */
function assertNoReservedHeaderMembers(header: Record<string, unknown>): void {
  for (const member of RESERVED_PROTECTED_HEADER_MEMBERS) {
    if (Object.hasOwn(header, member)) {
      throw new Error(
        `Protected-header member '${member}' is reserved and cannot be set via ` +
          `SignOptions.header (reserved: ${RESERVED_PROTECTED_HEADER_MEMBERS.join(', ')}).`
      );
    }
  }
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
 * @throws Error if `options.header` carries a reserved protected-header member
 * ({@link RESERVED_PROTECTED_HEADER_MEMBERS}).
 */
export async function sign(
  claims: Record<string, unknown>,
  privateKey: SigningKey,
  alg: JwsAlgorithm,
  options: SignOptions
): Promise<string> {
  const extraHeader = options.header ?? {};
  assertNoReservedHeaderMembers(extraHeader);
  return (
    new SignJWT(claims)
      // #248 F6: `alg` is spread LAST so the canonical algorithm always wins —
      // belt-and-braces behind the reserved-member rejection above.
      .setProtectedHeader({ ...extraHeader, alg })
      .setIssuedAt()
      .setExpirationTime(`${options.expiresIn}s`)
      .setIssuer(options.issuer)
      .setAudience(options.audience)
      .sign(privateKey)
  );
}

/**
 * A successfully verified compact JWS: its claims set AND the protected header
 * that the signature actually covers.
 *
 * The header is returned SEPARATELY and only after verification succeeds, so a
 * caller can never confuse it with the attacker-controlled, unauthenticated
 * header of an unverified token. Every security decision that depends on a
 * header member (algorithm negotiation, key resolution) MUST read it from here.
 */
export interface VerifiedToken {
  /** The verified raw claims set (JWS payload). */
  claims: Record<string, unknown>;
  /**
   * The JWS PROTECTED header, authenticated by the verified signature. Includes
   * `alg`, `kid`, and any extra members the issuer stamped (e.g. the hybrid
   * `pqc_alg` / `pqc_kid` of ADR-005). Trustworthy: a mutation of any member
   * invalidates the signature, so verification would have thrown first.
   */
  protectedHeader: Record<string, unknown>;
}

/**
 * Verify a compact JWT and return BOTH its claims and its signature-protected
 * header.
 *
 * Identical checking to {@link verify} — this is the full-fidelity form. Use it
 * whenever a downstream decision must be bound to something the ISSUER signed
 * rather than to an unauthenticated transport field (ADR-005 / #248 F1: the
 * hybrid `pqc_alg` downgrade check; #248 F5: ML-DSA key resolution from the
 * signed `pqc_kid`).
 *
 * @param token - Compact JWT to verify.
 * @param publicKey - Public verification key.
 * @param options - Verification constraints — see {@link VerifyOptions}.
 * @returns The verified claims set and the authenticated protected header.
 * @throws CryptoVerificationError if the token is expired or otherwise invalid.
 */
export async function verifyWithHeader(
  token: string,
  publicKey: SigningKey,
  options: VerifyOptions
): Promise<VerifiedToken> {
  try {
    const { payload, protectedHeader } = await jwtVerify(token, publicKey, {
      algorithms: options.algorithms,
      ...(options.issuer !== undefined ? { issuer: options.issuer } : {}),
      ...(options.audience !== undefined ? { audience: options.audience } : {}),
      ...(options.clockTolerance !== undefined ? { clockTolerance: options.clockTolerance } : {}),
      ...(options.currentDate !== undefined ? { currentDate: options.currentDate } : {}),
    });
    return { claims: payload, protectedHeader: { ...protectedHeader } };
  } catch (error) {
    throw toCryptoVerificationError(error);
  }
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
 * Thin wrapper over {@link verifyWithHeader} that discards the protected
 * header; callers needing the signed header must use `verifyWithHeader`.
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
  const { claims } = await verifyWithHeader(token, publicKey, options);
  return claims;
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
