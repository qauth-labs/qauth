/**
 * Why a {@link verify} call rejected a token.
 *
 * - `expired` — the token is structurally and cryptographically acceptable but
 *   past its expiry (`exp`). Callers usually surface this distinctly (e.g. to
 *   prompt a token refresh) rather than as a generic failure.
 * - `invalid` — any other verification failure: bad signature, malformed token,
 *   issuer/audience mismatch, unsupported algorithm, etc.
 *
 * `expired` is exclusively a TOKEN-LAYER reason (it needs temporal claims). The
 * byte-level {@link import('./primitives').SignatureBackend} verify — which has
 * no notion of `exp` — only ever throws with `reason: 'invalid'`.
 */
export type CryptoVerificationErrorReason = 'expired' | 'invalid';

/**
 * Backend-neutral error thrown by {@link verify} when a token fails
 * verification.
 *
 * The crypto abstraction normalizes the concrete backend's failure shape
 * (currently JOSE's error `name` / `code` contract) into this small, stable
 * vocabulary. Consumers branch on {@link reason} — and, for diagnostic
 * failures, {@link detail} — instead of coupling to a specific crypto library's
 * error types. This keeps the seam intact: swapping the backend changes only
 * the normalization inside this library, never the call sites that map these
 * errors onto their own domain errors.
 */
export class CryptoVerificationError extends Error {
  /** Coarse, stable classification of the failure. */
  readonly reason: CryptoVerificationErrorReason;

  /**
   * Optional backend-supplied diagnostic (e.g. `"signature verification
   * failed"`). Present only when the backend reported a specific, safe-to-
   * surface reason; absent for opaque failures.
   */
  readonly detail?: string;

  constructor(
    reason: CryptoVerificationErrorReason,
    options: { detail?: string; cause?: unknown } = {}
  ) {
    // The detail is appended to the message so an unmapped error is still
    // diagnosable from raw logs; consumers branch on `reason` / `detail`.
    super(
      options.detail !== undefined
        ? `Token verification failed (${reason}): ${options.detail}`
        : `Token verification failed (${reason})`,
      options.cause !== undefined ? { cause: options.cause } : undefined
    );
    this.name = 'CryptoVerificationError';
    this.reason = reason;
    this.detail = options.detail;
  }
}

/**
 * The ONLY `message` a {@link CryptoDecryptionError} ever carries.
 *
 * A constant rather than a template, and that is the whole control — see the
 * class docblock. Exported so a test can assert the invariant by identity
 * instead of by comparing two failures that might happen to agree.
 */
export const CRYPTO_DECRYPTION_ERROR_MESSAGE = 'JWE decryption failed';

/**
 * Backend-neutral error thrown when a JWE fails to decrypt (#298).
 *
 * Deliberately has NO `reason` discriminant, unlike
 * {@link CryptoVerificationError}, and its `message` is the FIXED constant
 * {@link CRYPTO_DECRYPTION_ERROR_MESSAGE} — never interpolated with the
 * backend's own text. Every failure, cryptographic or structural, is therefore
 * one indistinguishable outcome: wrong recipient key, tampered ciphertext or
 * authentication tag, a rejected `alg` / `enc`, a `zip` this library refuses, a
 * malformed compact serialization, a plaintext that is not JSON. A caller that
 * could tell "your key is wrong" from "your ciphertext is wrong" is an oracle,
 * and JWE decryption oracles are the origin of the entire Bleichenbacher family.
 * There is nothing to branch on, so nothing can be leaked by branching.
 *
 * Interpolating {@link detail} into the message is precisely what would break
 * that: `jose` reports "decryption operation failed" for both a wrong key and a
 * tampered ciphertext (which collide harmlessly), but "Invalid Compact JWE" for
 * a malformed serialization and `'"alg" (Algorithm) Header Parameter value not
 * allowed'` for a rejected pin — three distinguishable classes, and a caller
 * that logged or echoed `error.message` would publish them.
 *
 * {@link detail} survives as a SEPARATE field for logs. It does distinguish the
 * failure classes, which is exactly why it is off the message and must never be
 * surfaced to a remote party — the OAuth error response for a failed
 * `direct_post.jwt` decryption is a flat `invalid_request`. Same rule for
 * `cause`.
 */
export class CryptoDecryptionError extends Error {
  /**
   * Backend-supplied or library-supplied diagnostic (e.g. `"decryption
   * operation failed"`, `"payload is not valid JSON"`).
   *
   * DIAGNOSTIC ONLY, for local logs — never include it in a response to a
   * remote party, and never let it reach {@link message}.
   */
  readonly detail?: string;

  constructor(options: { detail?: string; cause?: unknown } = {}) {
    // The message is the constant, ALWAYS. `detail` is carried alongside it, so
    // an operator reading logs still gets the diagnostic while a caller reading
    // `error.message` gets one value for every possible failure.
    super(
      CRYPTO_DECRYPTION_ERROR_MESSAGE,
      options.cause !== undefined ? { cause: options.cause } : undefined
    );
    this.name = 'CryptoDecryptionError';
    this.detail = options.detail;
  }
}
