import { randomBytes } from 'node:crypto';

import {
  type EncryptionKey,
  exportEncryptionPublicJwk,
  exportPublicSigningJwk,
  generateSigningKeyPair,
  getSignatureBackend,
  JOSE_P256_CURVE,
  type JwsAlgorithm,
  PQC_ALG_ML_DSA_65,
  type SignatureAlgorithm,
  type SigningKey,
} from '@qauth-labs/core-crypto';
import { calculateJwkThumbprint, generateKeyPair, type JWK } from 'jose';

import { KeyCreationRefusedError } from './key-creation-errors';
import type { KeyAlgorithm } from './key-purposes';

/**
 * Key generation per algorithm (ADR-019 Decision 9, issue #463), with the
 * crypto libraries the token layer already uses: `@qauth-labs/core-crypto`
 * for the signing keys and the ML-DSA-65 backend, and `jose` for the ECDH-ES
 * pair and the RFC 7638 thumbprint.
 *
 * The private material comes back as bytes for the envelope to seal:
 *
 * - `EdDSA`, `RS256`, `ES256`, `ECDH-ES` — the private key as PKCS#8 DER;
 * - `ML-DSA-65` — the 32-byte FIPS 204 seed, the canonical private form;
 * - `HS256`, `A256GCM` — 32 random bytes.
 *
 * The `kid` of an asymmetric key is its RFC 7638 thumbprint (SHA-256), so the
 * same public key always has the same `kid` and two different keys never
 * share one. A symmetric key has no public half to take a thumbprint of; its
 * `kid` is 128 random bits instead.
 */

/** The length of a symmetric secret: 256 bits. */
export const SYMMETRIC_KEY_BYTES = 32;

/** The length of a symmetric key's random `kid`, before base64url: 128 bits. */
export const RANDOM_KID_BYTES = 16;

/** A freshly generated key. */
export interface GeneratedKeyMaterial {
  readonly algorithm: KeyAlgorithm;
  /** The RFC 7638 thumbprint of {@link publicJwk}, or a random id for a symmetric key. */
  readonly kid: string;
  /**
   * The private material, in the form described above. It belongs to the
   * caller: seal it, then zero it with `material.fill(0)`.
   */
  readonly material: Buffer;
  /**
   * The public half as a fully specified JWK carrying `kid`, `alg` and `use`.
   * Absent for a symmetric key. Never holds a private member.
   */
  readonly publicJwk?: JWK;
}

/** Options for {@link generateKeyMaterial}. */
export interface GenerateKeyMaterialOptions {
  /**
   * The signature algorithms the operator enabled with `SIGNING_ALGORITHM_MODE`
   * (`cryptoEnv.enabledSignatureAlgorithms`). Thread the configured set
   * through; never a literal.
   */
  readonly enabledSignatureAlgorithms: readonly SignatureAlgorithm[];
}

/**
 * The algorithms `SIGNING_ALGORITHM_MODE` names: `ed25519` enables `EdDSA`,
 * and `ed25519+ml-dsa-65` adds `ML-DSA-65`. The mode does not name `RS256`,
 * `ES256`, `ECDH-ES` or the symmetric algorithms (see `JwsAlgorithm` in
 * `@qauth-labs/core-crypto`), so it neither allows nor refuses them; the
 * purpose's own list does.
 */
const MODE_ALGORITHMS: readonly KeyAlgorithm[] = ['EdDSA', 'ML-DSA-65'];

/**
 * Whether the deployment's `SIGNING_ALGORITHM_MODE` allows a key of
 * `algorithm`. See {@link MODE_ALGORITHMS} for which algorithms it governs.
 */
export function isAllowedBySigningMode(
  algorithm: KeyAlgorithm,
  enabledSignatureAlgorithms: readonly SignatureAlgorithm[]
): boolean {
  if (!MODE_ALGORITHMS.includes(algorithm)) return true;
  return (enabledSignatureAlgorithms as readonly string[]).includes(algorithm);
}

/**
 * Refuse an algorithm the deployment's `SIGNING_ALGORITHM_MODE` does not allow.
 *
 * @throws KeyCreationRefusedError (`ALGORITHM_NOT_ENABLED`)
 */
export function assertAllowedBySigningMode(
  algorithm: KeyAlgorithm,
  enabledSignatureAlgorithms: readonly SignatureAlgorithm[]
): void {
  if (!isAllowedBySigningMode(algorithm, enabledSignatureAlgorithms)) {
    throw new KeyCreationRefusedError(
      'ALGORITHM_NOT_ENABLED',
      `Algorithm '${algorithm}' is not enabled by SIGNING_ALGORITHM_MODE ` +
        `(enabled: ${enabledSignatureAlgorithms.join(', ') || 'none'})`
    );
  }
}

/**
 * Generate a new key of `algorithm`.
 *
 * @returns the key's `kid`, its private material and, for an asymmetric key,
 *   its public JWK. Zero `material` once it is sealed.
 * @throws KeyCreationRefusedError (`ALGORITHM_NOT_ENABLED`) when
 *   `SIGNING_ALGORITHM_MODE` does not allow `algorithm`
 */
export async function generateKeyMaterial(
  algorithm: KeyAlgorithm,
  options: GenerateKeyMaterialOptions
): Promise<GeneratedKeyMaterial> {
  assertAllowedBySigningMode(algorithm, options.enabledSignatureAlgorithms);

  switch (algorithm) {
    case 'EdDSA':
    case 'RS256':
    case 'ES256':
      return generateSigningKey(algorithm);
    case 'ML-DSA-65':
      return generateMlDsaKey(options.enabledSignatureAlgorithms);
    case 'ECDH-ES':
      return generateEcdhEsKey();
    case 'HS256':
    case 'A256GCM':
      return generateSymmetricKey(algorithm);
    default:
      return assertNever(algorithm);
  }
}

async function generateSigningKey(algorithm: JwsAlgorithm): Promise<GeneratedKeyMaterial> {
  // Extractable so the private half can be exported once, to be sealed. The
  // key objects are dropped when this function returns.
  const { privateKey, publicKey } = await generateSigningKeyPair(algorithm, { extractable: true });
  const publicJwk = await exportPublicSigningJwk(publicKey, { alg: algorithm });
  return withThumbprintKid(algorithm, await exportPkcs8(privateKey), publicJwk);
}

async function generateEcdhEsKey(): Promise<GeneratedKeyMaterial> {
  const { privateKey, publicKey } = await generateKeyPair('ECDH-ES', {
    crv: JOSE_P256_CURVE,
    extractable: true,
  });
  const material = await exportPkcs8(privateKey);
  // `exportEncryptionPublicJwk` stamps the `kid` it is given, so the
  // thumbprint is taken of the key first.
  const kid = await calculateJwkThumbprint(publicKey, 'sha256');
  const publicJwk = await exportEncryptionPublicJwk({ kid, publicKey });
  return Object.freeze({ algorithm: 'ECDH-ES', kid, material, publicJwk });
}

function generateMlDsaKey(
  enabledSignatureAlgorithms: readonly SignatureAlgorithm[]
): Promise<GeneratedKeyMaterial> {
  // The registry gates the backend on SIGNING_ALGORITHM_MODE as well.
  const backend = getSignatureBackend('ML-DSA-65', enabledSignatureAlgorithms);
  const { privateKey, publicKey } = backend.generateKeyPair({ extractable: true });
  try {
    // `exportKey` of a private key is its 32-byte seed, as base64url.
    const material = Buffer.from(backend.exportKey(privateKey), 'base64url');
    // RFC 9964's AKP public key, in the member order the JWKS uses
    // (`PQC_AKP_PUBLIC_JWK_MEMBERS`).
    const publicJwk: JWK = {
      kty: 'AKP',
      pub: backend.exportKey(publicKey),
      use: 'sig',
      alg: PQC_ALG_ML_DSA_65,
    };
    return withThumbprintKid('ML-DSA-65', material, publicJwk);
  } finally {
    privateKey.destroy();
  }
}

function generateSymmetricKey(algorithm: 'HS256' | 'A256GCM'): Promise<GeneratedKeyMaterial> {
  return Promise.resolve(
    Object.freeze({
      algorithm,
      kid: randomBytes(RANDOM_KID_BYTES).toString('base64url'),
      material: randomBytes(SYMMETRIC_KEY_BYTES),
    })
  );
}

/**
 * The `kid` of an asymmetric key: the RFC 7638 SHA-256 thumbprint of its
 * public JWK, base64url. Only the required members count (`kty`, `crv`, `x`,
 * `y`, `n`, `e`, or `alg` and `pub` for AKP), so `kid`, `use` and `alg` on an
 * OKP, EC or RSA key do not change it.
 */
export function jwkThumbprintKid(publicJwk: JWK): Promise<string> {
  return calculateJwkThumbprint(publicJwk, 'sha256');
}

/** Set the RFC 7638 thumbprint of `publicJwk` as the key's `kid`, on the JWK too. */
async function withThumbprintKid(
  algorithm: KeyAlgorithm,
  material: Buffer,
  publicJwk: JWK
): Promise<GeneratedKeyMaterial> {
  const kid = await jwkThumbprintKid(publicJwk);
  return Object.freeze({ algorithm, kid, material, publicJwk: { ...publicJwk, kid } });
}

/** The private key as PKCS#8 DER, in a buffer the caller owns and zeroes. */
async function exportPkcs8(privateKey: SigningKey | EncryptionKey): Promise<Buffer> {
  return Buffer.from(await crypto.subtle.exportKey('pkcs8', privateKey));
}

function assertNever(value: never): never {
  throw new Error(`Unhandled key algorithm: ${String(value)}`);
}
