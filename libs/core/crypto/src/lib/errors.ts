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
 * Backend-neutral error thrown when a JWE fails to decrypt (#298).
 *
 * Deliberately has NO `reason` discriminant, unlike
 * {@link CryptoVerificationError}. Every CRYPTOGRAPHIC failure — wrong recipient
 * key, tampered ciphertext or authentication tag, a rejected `alg` / `enc`, a
 * malformed compact serialization — collapses into this ONE outcome with one
 * indistinguishable message. That uniformity is the point: a caller that could
 * tell "your key is wrong" from "your ciphertext is wrong" is an oracle, and JWE
 * decryption oracles are the origin of the entire Bleichenbacher family. There
 * is nothing to branch on, so nothing can be leaked by branching.
 *
 * The two STRUCTURAL failures (a plaintext that is not JSON, or is not a JSON
 * object) do set a distinguishing {@link detail}. They are not an oracle: they
 * are reachable only AFTER the AEAD tag verified, i.e. only by a party that
 * already holds the right key and can read its own plaintext. Telling that party
 * why its payload was rejected reveals nothing it does not already know.
 *
 * {@link detail} and `cause` are for LOGS only. Callers must never surface
 * either to a remote party — the OAuth error response for a failed
 * `direct_post.jwt` decryption is a flat `invalid_request`.
 */
export class CryptoDecryptionError extends Error {
  /**
   * Backend-supplied diagnostic (e.g. `"decryption operation failed"`).
   * DIAGNOSTIC ONLY — never include it in a response to a remote party.
   */
  readonly detail?: string;

  constructor(options: { detail?: string; cause?: unknown } = {}) {
    super(
      options.detail !== undefined
        ? `JWE decryption failed: ${options.detail}`
        : 'JWE decryption failed',
      options.cause !== undefined ? { cause: options.cause } : undefined
    );
    this.name = 'CryptoDecryptionError';
    this.detail = options.detail;
  }
}
