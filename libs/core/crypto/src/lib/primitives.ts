import type { SignatureAlgorithm } from './algorithms';
import type { MlDsaKey, RawSigningKeyPair } from './keys';

/** Options for {@link SignatureBackend.generateKeyPair}. */
export interface GenerateRawKeyPairOptions {
  /**
   * Whether the generated private key may be exported. Defaults to `false`
   * (parity with the jose key layer). Advisory only — raw key bytes in JS
   * memory cannot be hardware-protected.
   */
  extractable?: boolean;
}

/** Options for {@link SignatureBackend.importKey}. */
export interface ImportRawKeyOptions {
  extractable?: boolean;
}

/**
 * A byte-level signing backend (ADR-005, #243) — the swappable seam beneath the
 * crypto abstraction. This is where post-quantum algorithms plug in without
 * touching the jose-based JWT token layer: ML-DSA-65 today (pure-TS
 * `@noble/post-quantum`), the napi-rs native binding next (#244, same
 * interface, byte-for-byte compatible), and hybrid composites later (#245,
 * which builds the JWS carrier on top of these primitives).
 *
 * Backends operate on raw bytes and {@link MlDsaKey} material — NOT on JOSE/JWS.
 * They perform no temporal-claims logic (no `exp`), so verification failure is
 * always `reason: 'invalid'`, never `'expired'` (a token-layer concept).
 */
export interface SignatureBackend {
  /** The algorithm this backend implements. */
  readonly algorithm: SignatureAlgorithm;

  /** Generate a fresh key pair from a CSPRNG-sourced seed. */
  generateKeyPair(options?: GenerateRawKeyPairOptions): RawSigningKeyPair;

  /**
   * Produce a detached signature over `message` with a private key.
   * @throws Error if `privateKey` is not a private key of this algorithm.
   */
  sign(privateKey: MlDsaKey, message: Uint8Array): Uint8Array;

  /**
   * Verify a detached signature. Returns normally on success and throws
   * {@link import('./errors').CryptoVerificationError} (`reason: 'invalid'`) on
   * any failure — a forged/mismatched signature, a malformed input, or a
   * wrong-length key/signature — with one indistinguishable failure vocabulary
   * (no error-shape oracle).
   */
  verify(publicKey: MlDsaKey, message: Uint8Array, signature: Uint8Array): void;

  /**
   * Serialize a key to a compact `base64url` string. For a private key this is
   * the 32-byte seed (the canonical FIPS 204 private form); for a public key
   * the raw key bytes.
   * @throws Error if a private key is not extractable.
   */
  exportKey(key: MlDsaKey): string;

  /** Import a `base64url` key produced by {@link exportKey}. */
  importKey(encoded: string, kind: 'public' | 'private', options?: ImportRawKeyOptions): MlDsaKey;
}
