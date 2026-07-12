import type { CryptoKey } from 'jose';

/**
 * A single asymmetric signing/verification key.
 *
 * Aliases the runtime-agnostic {@link CryptoKey} used by the underlying backend.
 * Higher layers depend on this alias rather than importing a specific crypto
 * library's key type directly, so the backend (native binding, WASM, PQC) can
 * change without rippling through service code.
 */
export type SigningKey = CryptoKey;

/** A generated or imported asymmetric key pair. */
export interface SigningKeyPair {
  /** Private key used to produce signatures. */
  privateKey: SigningKey;
  /** Public key used to verify signatures. */
  publicKey: SigningKey;
}
