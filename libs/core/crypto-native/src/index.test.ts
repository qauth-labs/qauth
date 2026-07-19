import { getSignatureBackend, type SignatureBackend } from '@qauth-labs/core-crypto';
import { describe, expect, it } from 'vitest';

import { nativeAddonLoadDiagnostics } from './addon';
import { isNativeAddonAvailable, mlDsaNativeBackend } from './index';

// The native addon is built locally (crypto-native:build-native) but NOT in
// every CI lane — the per-platform prebuild matrix is #244's deferred half.
// Skip the whole suite when it is absent, mirroring the repo's Docker-guarded
// integration tests, so CI stays green without the binary.
const available = isNativeAddonAvailable();
const suite = available ? describe : describe.skip;

const bytes = (s: string) => new TextEncoder().encode(s);
// The noble backend (#243), reached through the gated registry.
const noble = getSignatureBackend('ML-DSA-65', ['ML-DSA-65']);

describe('native ML-DSA-65 backend availability', () => {
  it('reports availability consistently (skips the interop suites when absent)', () => {
    expect(typeof isNativeAddonAvailable()).toBe('boolean');
  });

  // The interop suites below `describe.skip` themselves when the addon is
  // absent, so a green run is NOT by itself proof that noble<->native
  // cross-verification executed. The supply-chain workflow (#277) sets
  // QAUTH_REQUIRE_NATIVE_ADDON=1 after downloading the freshly built,
  // checksum-verified artifact, turning a vacuous pass into a hard failure —
  // which is the gate that must hold on every aws-lc-rs bump.
  it.runIf(process.env['QAUTH_REQUIRE_NATIVE_ADDON'] === '1')(
    'loaded an integrity-verified addon when CI demands one',
    () => {
      const diagnostics = nativeAddonLoadDiagnostics();
      expect(
        isNativeAddonAvailable(),
        `native addon required but not loaded: ${diagnostics.join('; ')}`
      ).toBe(true);
      // A `permissive` unverified load must not satisfy the CI gate either.
      expect(diagnostics.filter((reason) => reason.includes('without provenance'))).toEqual([]);
    }
  );
});

suite('native ML-DSA-65 backend — SignatureBackend conformance', () => {
  it('generates, signs, and verifies a round-trip', () => {
    const { privateKey, publicKey } = mlDsaNativeBackend.generateKeyPair();
    const message = bytes('native round-trip');
    const sig = mlDsaNativeBackend.sign(privateKey, message);
    expect(sig.length).toBe(3309);
    expect(() => mlDsaNativeBackend.verify(publicKey, message, sig)).not.toThrow();
  });

  it('rejects a tampered message and a wrong key', () => {
    const a = mlDsaNativeBackend.generateKeyPair();
    const b = mlDsaNativeBackend.generateKeyPair();
    const message = bytes('authentic');
    const sig = mlDsaNativeBackend.sign(a.privateKey, message);
    expect(() => mlDsaNativeBackend.verify(a.publicKey, bytes('tampered'), sig)).toThrow();
    expect(() => mlDsaNativeBackend.verify(b.publicKey, message, sig)).toThrow();
  });

  it('exports the seed as the canonical private form and re-imports verifiably', () => {
    const { privateKey, publicKey } = mlDsaNativeBackend.generateKeyPair({ extractable: true });
    const seed = mlDsaNativeBackend.exportKey(privateKey);
    expect(seed).toBe(Buffer.from(privateKey.seed()).toString('base64url'));
    const reimported = mlDsaNativeBackend.importKey(seed, 'private');
    const message = bytes('re-imported seed');
    expect(() =>
      mlDsaNativeBackend.verify(publicKey, message, mlDsaNativeBackend.sign(reimported, message))
    ).not.toThrow();
  });
});

suite('native ↔ noble interoperability (the ADR-005 backend-swap promise)', () => {
  it('a native-produced signature verifies under the noble backend', () => {
    const { privateKey, publicKey } = mlDsaNativeBackend.generateKeyPair({ extractable: true });
    const pubEncoded = mlDsaNativeBackend.exportKey(publicKey);
    const message = bytes('native-signed, noble-verified');
    const sig = mlDsaNativeBackend.sign(privateKey, message);
    expect(() => noble.verify(noble.importKey(pubEncoded, 'public'), message, sig)).not.toThrow();
  });

  it('a noble-produced signature verifies under the native backend', () => {
    const { privateKey, publicKey } = noble.generateKeyPair({ extractable: true });
    const pubEncoded = noble.exportKey(publicKey);
    const message = bytes('noble-signed, native-verified');
    const sig = noble.sign(privateKey, message);
    expect(() =>
      mlDsaNativeBackend.verify(mlDsaNativeBackend.importKey(pubEncoded, 'public'), message, sig)
    ).not.toThrow();
  });

  it('a private key exported from one backend re-imports and signs under the other (shared seed)', () => {
    // Native generates + exports the seed; noble imports it and signs; the
    // signature verifies under a public key derived by the NATIVE backend from
    // the same account — proving both backends expand the seed identically.
    const nativePair = mlDsaNativeBackend.generateKeyPair({ extractable: true });
    const seed = mlDsaNativeBackend.exportKey(nativePair.privateKey);
    const nativePubEncoded = mlDsaNativeBackend.exportKey(nativePair.publicKey);

    const noblePriv = noble.importKey(seed, 'private');
    const message = bytes('one seed, both backends');
    const nobleSig = noble.sign(noblePriv, message);
    // Verify noble's signature (from the shared seed) under native's public key.
    expect(() =>
      mlDsaNativeBackend.verify(
        mlDsaNativeBackend.importKey(nativePubEncoded, 'public'),
        message,
        nobleSig
      )
    ).not.toThrow();
  });

  it('runs the identical test body under BOTH backends (zero-change swap)', () => {
    for (const backend of [mlDsaNativeBackend, noble] as SignatureBackend[]) {
      const { privateKey, publicKey } = backend.generateKeyPair();
      const message = bytes('same test, either backend');
      const sig = backend.sign(privateKey, message);
      expect(() => backend.verify(publicKey, message, sig)).not.toThrow();
    }
  });
});
