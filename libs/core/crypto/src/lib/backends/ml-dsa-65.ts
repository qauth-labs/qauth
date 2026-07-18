import { randomBytes } from 'node:crypto';

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { CryptoVerificationError } from '../errors';
import { ML_DSA_65_LENGTHS, MlDsaKey, type RawSigningKeyPair } from '../keys';
import type {
  GenerateRawKeyPairOptions,
  ImportRawKeyOptions,
  SignatureBackend,
} from '../primitives';

/**
 * ML-DSA-65 (FIPS 204, NIST Level 3) signing backend over the pure-TypeScript
 * `@noble/post-quantum` library (ADR-005, #243). No native code — the AC's
 * "no native dependencies" holds by construction.
 *
 * `@noble/post-quantum` v0.6.1 API used here:
 * - `ml_dsa65.keygen(seed)` → `{ publicKey, secretKey }` (deterministic from a
 *   32-byte seed).
 * - `ml_dsa65.sign(message, secretKey)` → signature. Default signing is HEDGED
 *   (FIPS 204's randomized mode): two signatures over the same input differ.
 *   NEVER assert byte-exact signature output.
 * - `ml_dsa65.verify(signature, message, publicKey)` → boolean.
 *
 * The 32-byte seed (ξ) is treated as the canonical private key: FIPS 204 keys
 * expand deterministically from it, so serialization stores the seed (43
 * base64url chars) and re-expands on import — 126× smaller than the 4032-byte
 * expanded secret key, and the exact shape #246's AKP JWK `priv` member needs.
 */
function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function base64urlDecode(encoded: string): Uint8Array {
  return new Uint8Array(Buffer.from(encoded, 'base64url'));
}

/** Build a private key from a 32-byte seed by re-expanding it. */
function privateKeyFromSeed(seed: Uint8Array, extractable: boolean): MlDsaKey {
  if (seed.length !== ML_DSA_65_LENGTHS.seed) {
    throw new CryptoVerificationError('invalid', {
      detail: `ML-DSA-65 seed must be ${ML_DSA_65_LENGTHS.seed} bytes, got ${seed.length}`,
    });
  }
  const { secretKey } = ml_dsa65.keygen(seed);
  return new MlDsaKey({ kind: 'private', material: secretKey, seed, extractable });
}

export const mlDsa65Backend: SignatureBackend = {
  algorithm: 'ML-DSA-65',

  generateKeyPair(options: GenerateRawKeyPairOptions = {}): RawSigningKeyPair {
    // Fresh CSPRNG seed on every call — NEVER a fixed seed outside tests.
    const seed = new Uint8Array(randomBytes(ML_DSA_65_LENGTHS.seed));
    const { publicKey } = ml_dsa65.keygen(seed);
    const privateKey = privateKeyFromSeed(seed, options.extractable ?? false);
    return {
      privateKey,
      publicKey: new MlDsaKey({ kind: 'public', material: publicKey }),
    };
  },

  sign(privateKey: MlDsaKey, message: Uint8Array): Uint8Array {
    if (privateKey.alg !== 'ML-DSA-65' || privateKey.kind !== 'private') {
      throw new Error('ML-DSA-65 sign requires a private ML-DSA-65 key');
    }
    // noble: sign(message, secretKey).
    return ml_dsa65.sign(message, privateKey.material());
  },

  verify(publicKey: MlDsaKey, message: Uint8Array, signature: Uint8Array): void {
    if (publicKey.alg !== 'ML-DSA-65' || publicKey.kind !== 'public') {
      throw new CryptoVerificationError('invalid', {
        detail: 'ML-DSA-65 verify requires a public ML-DSA-65 key',
      });
    }
    let ok: boolean;
    try {
      // noble: verify(signature, message, publicKey). Throws on malformed
      // lengths; returns false on a well-formed-but-forged signature. Both
      // normalize to the SAME error so no oracle distinguishes them.
      ok = ml_dsa65.verify(signature, message, publicKey.material());
    } catch (cause) {
      throw new CryptoVerificationError('invalid', {
        detail: 'signature verification failed',
        cause,
      });
    }
    if (!ok) {
      throw new CryptoVerificationError('invalid', { detail: 'signature verification failed' });
    }
  },

  exportKey(key: MlDsaKey): string {
    if (key.alg !== 'ML-DSA-65') {
      throw new Error('exportKey requires an ML-DSA-65 key');
    }
    if (key.kind === 'private') {
      if (!key.extractable) {
        throw new Error('Cannot export a non-extractable ML-DSA-65 private key');
      }
      // Canonical private form is the seed, not the expanded secret key.
      return base64urlEncode(key.seed());
    }
    return base64urlEncode(key.material());
  },

  importKey(
    encoded: string,
    kind: 'public' | 'private',
    options: ImportRawKeyOptions = {}
  ): MlDsaKey {
    const bytes = base64urlDecode(encoded);
    if (kind === 'private') {
      // privateKeyFromSeed validates the seed length.
      return privateKeyFromSeed(bytes, options.extractable ?? false);
    }
    if (bytes.length !== ML_DSA_65_LENGTHS.publicKey) {
      throw new CryptoVerificationError('invalid', {
        detail: `ML-DSA-65 public key must be ${ML_DSA_65_LENGTHS.publicKey} bytes, got ${bytes.length}`,
      });
    }
    return new MlDsaKey({ kind: 'public', material: bytes });
  },
};
