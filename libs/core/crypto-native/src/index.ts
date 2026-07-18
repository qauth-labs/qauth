import { randomBytes } from 'node:crypto';

import {
  CryptoVerificationError,
  type GenerateRawKeyPairOptions,
  type ImportRawKeyOptions,
  ML_DSA_65_LENGTHS,
  MlDsaKey,
  type RawSigningKeyPair,
  type SignatureBackend,
} from '@qauth-labs/core-crypto';

import { isNativeAddonAvailable, requireAddon } from './addon';

export { isNativeAddonAvailable } from './addon';

/**
 * Native ML-DSA-65 (FIPS 204) signing backend over `aws-lc-rs` (ADR-005, #244).
 *
 * Implements the SAME {@link SignatureBackend} interface as the pure-TS
 * `@noble/post-quantum` backend (#243) — the whole point of the ADR-005 crypto
 * seam — and is byte-for-byte interoperable with it: both key off the same
 * 32-byte seed (ξ), so keys, exports, and signatures cross-verify. Swapping
 * backends requires ZERO changes to any consumer (the epic's central promise;
 * proven by the shared conformance suite in `index.test.ts`).
 *
 * The native backend, like noble, treats the seed as the canonical private key
 * (aws-lc-rs `from_seed`); it signs directly from the seed and never needs the
 * expanded 4032-byte secret key. A private {@link MlDsaKey} it produces stores
 * the seed in both `seed` and `material` (the native sign path reads `seed()`),
 * while public keys hold the raw 1952-byte key — identical to noble's public
 * representation.
 */
function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function base64urlDecode(encoded: string): Uint8Array {
  return new Uint8Array(Buffer.from(encoded, 'base64url'));
}

function privateKeyFromSeed(seed: Uint8Array, extractable: boolean): MlDsaKey {
  if (seed.length !== ML_DSA_65_LENGTHS.seed) {
    throw new CryptoVerificationError('invalid', {
      detail: `ML-DSA-65 seed must be ${ML_DSA_65_LENGTHS.seed} bytes, got ${seed.length}`,
    });
  }
  // Native signs from the seed (aws-lc-rs from_seed); `material` mirrors the
  // seed so `material()` never throws, but the native sign path reads seed().
  return new MlDsaKey({ kind: 'private', material: seed, seed, extractable });
}

export const mlDsaNativeBackend: SignatureBackend = {
  algorithm: 'ML-DSA-65',

  generateKeyPair(options: GenerateRawKeyPairOptions = {}): RawSigningKeyPair {
    const addon = requireAddon();
    const seed = new Uint8Array(randomBytes(ML_DSA_65_LENGTHS.seed));
    const publicKey = addon.mldsa65PublicKeyFromSeed(seed);
    return {
      privateKey: privateKeyFromSeed(seed, options.extractable ?? false),
      publicKey: new MlDsaKey({ kind: 'public', material: publicKey }),
    };
  },

  sign(privateKey: MlDsaKey, message: Uint8Array): Uint8Array {
    if (privateKey.alg !== 'ML-DSA-65' || privateKey.kind !== 'private') {
      throw new Error('ML-DSA-65 sign requires a private ML-DSA-65 key');
    }
    return requireAddon().mldsa65Sign(privateKey.seed(), message);
  },

  verify(publicKey: MlDsaKey, message: Uint8Array, signature: Uint8Array): void {
    if (publicKey.alg !== 'ML-DSA-65' || publicKey.kind !== 'public') {
      throw new CryptoVerificationError('invalid', {
        detail: 'ML-DSA-65 verify requires a public ML-DSA-65 key',
      });
    }
    let ok: boolean;
    try {
      ok = requireAddon().mldsa65Verify(publicKey.material(), message, signature);
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

/** The native backend if its addon is built for this host, else null. */
export function getNativeBackendIfAvailable(): SignatureBackend | null {
  return isNativeAddonAvailable() ? mlDsaNativeBackend : null;
}
