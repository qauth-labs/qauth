import { createPublicKey } from 'node:crypto';

import {
  generateSigningKeyPair,
  importPrivateSigningKey,
  importPublicSigningKey,
} from '@qauth-labs/core-crypto';

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
  return generateSigningKeyPair('EdDSA', { extractable });
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
  return importPrivateSigningKey(pem, 'EdDSA');
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
  return importPublicSigningKey(pem, 'EdDSA');
}

/**
 * Import an RS256 (RSASSA-PKCS1-v1_5 + SHA-256) private key from PKCS#8 PEM.
 *
 * RS256 signing (#309) is OPTIONAL and env-provisioned — it exists to satisfy
 * OIDC Basic/Config OP certification (#286), which hard-fails an EdDSA-only OP.
 * When configured, the JWT plugin signs ID tokens with this key by default.
 *
 * @param pem - PKCS#8 PEM string.
 */
export async function importRs256PrivateKey(pem: string): Promise<KeyLike> {
  return importPrivateSigningKey(pem, 'RS256');
}

/**
 * Import an RS256 public key from SPKI PEM (used to build the published RSA JWK
 * and to verify RS256-signed ID tokens).
 *
 * @param pem - SPKI PEM string.
 */
export async function importRs256PublicKey(pem: string): Promise<KeyLike> {
  return importPublicSigningKey(pem, 'RS256');
}

/**
 * Derive the SPKI (public) PEM from a PKCS#8 private-key PEM.
 *
 * Uses `node:crypto`'s {@link createPublicKey}, which computes ONLY the public
 * half — no private material is ever emitted. This is the deliberate path
 * (rather than jose's `exportSPKI`) because jose 6 imports private keys as
 * NON-extractable WebCrypto `CryptoKey`s, from which the public key cannot be
 * re-exported; `createPublicKey` derives it directly from the PEM.
 *
 * Algorithm-agnostic (works for RSA and Ed25519), but its purpose here is to
 * let the JWT plugin publish the RS256 public JWK from a private-key-only
 * configuration, mirroring how the EdDSA key can supply its own public half.
 *
 * @param privatePem - PKCS#8 private-key PEM.
 * @returns SPKI PEM of the corresponding public key.
 */
export function derivePublicKeyPemFromPrivate(privatePem: string): string {
  return createPublicKey(privatePem).export({ type: 'spki', format: 'pem' }).toString();
}
