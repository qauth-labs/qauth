import { generateKeyPair, importPKCS8, importSPKI } from 'jose';

import type { KeyLike } from '../types/key-management';

/**
 * Generate an EdDSA key pair
 *
 * Generates a new EdDSA (Ed25519) key pair for JWT signing and verification.
 *
 * @param extractable - Whether keys should be extractable (default: false)
 * @returns Promise resolving to key pair with private and public keys
 *
 * @example
 * ```typescript
 * const { privateKey, publicKey } = await generateEdDSAKeyPair();
 * ```
 */
export async function generateEdDSAKeyPair(extractable = false): Promise<{
  privateKey: KeyLike;
  publicKey: KeyLike;
}> {
  return generateKeyPair('EdDSA', { extractable });
}

/**
 * Import a private key from PEM format
 *
 * Imports an EdDSA private key from PEM format (PKCS#8).
 *
 * @param pem - Private key in PEM format
 * @returns Promise resolving to KeyLike private key
 *
 * @example
 * ```typescript
 * const privateKey = await importPrivateKey(pemString);
 * ```
 */
export async function importPrivateKey(pem: string): Promise<KeyLike> {
  return importPKCS8(pem, 'EdDSA');
}

/**
 * Import a public key from PEM format
 *
 * Imports an EdDSA public key from PEM format (SPKI).
 *
 * @param pem - Public key in PEM format
 * @returns Promise resolving to KeyLike public key
 *
 * @example
 * ```typescript
 * const publicKey = await importPublicKey(pemString);
 * ```
 */
export async function importPublicKey(pem: string): Promise<KeyLike> {
  return importSPKI(pem, 'EdDSA');
}
