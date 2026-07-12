import { generateKeyPair, importPKCS8, importSPKI } from 'jose';

import type { SignatureAlgorithm } from './algorithms';
import type { SigningKey, SigningKeyPair } from './keys';

/** Options for {@link generateSigningKeyPair}. */
export interface GenerateSigningKeyPairOptions {
  /**
   * Whether the generated private key is extractable (exportable to PEM/JWK).
   * Defaults to `false` — a non-extractable key cannot be serialized out of the
   * runtime, which is the safer default for a production signing key.
   */
  extractable?: boolean;
}

/**
 * Generate an asymmetric signing key pair for the given algorithm.
 *
 * @param alg - Signature algorithm (Phase 1: `EdDSA`).
 * @param options - Generation options — see {@link GenerateSigningKeyPairOptions}.
 */
export async function generateSigningKeyPair(
  alg: SignatureAlgorithm,
  options: GenerateSigningKeyPairOptions = {}
): Promise<SigningKeyPair> {
  return generateKeyPair(alg, { extractable: options.extractable ?? false });
}

/**
 * Import a PKCS#8 PEM-encoded private key for the given algorithm.
 *
 * @param pem - PKCS#8 PEM string.
 * @param alg - Signature algorithm the key is used with (Phase 1: `EdDSA`).
 */
export async function importPrivateSigningKey(
  pem: string,
  alg: SignatureAlgorithm
): Promise<SigningKey> {
  return importPKCS8(pem, alg);
}

/**
 * Import an SPKI PEM-encoded public key for the given algorithm.
 *
 * @param pem - SPKI PEM string.
 * @param alg - Signature algorithm the key is used with (Phase 1: `EdDSA`).
 */
export async function importPublicSigningKey(
  pem: string,
  alg: SignatureAlgorithm
): Promise<SigningKey> {
  return importSPKI(pem, alg);
}
