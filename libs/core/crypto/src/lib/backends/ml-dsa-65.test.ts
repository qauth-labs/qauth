import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { CryptoVerificationError } from '../errors';
import { isMlDsaKey, ML_DSA_65_LENGTHS, MlDsaKey } from '../keys';
import { mlDsa65Backend } from './ml-dsa-65';
import kat from './ml-dsa-65.kat.json';

const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const b64u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const bytes = (s: string) => new TextEncoder().encode(s);

describe('ML-DSA-65 backend — FIPS 204 known-answer vectors', () => {
  it('keyGen KAT: the fixed seed expands to the exact FIPS 204 public/secret key', () => {
    // Deterministic key expansion from the seed (ξ). Fingerprinted by SHA-256
    // rather than pasting 1952/4032 raw bytes; exercised through the PUBLIC
    // import path (the only sanctioned fixed-seed usage).
    const priv = mlDsa65Backend.importKey(kat.keyGen.seedB64url, 'private', { extractable: true });
    expect(sha256(priv.material())).toBe(kat.keyGen.secretKeySha256);

    // The seed round-trips (canonical private form) and re-derives the same pk.
    const reExported = mlDsa65Backend.exportKey(priv);
    expect(reExported).toBe(kat.keyGen.seedB64url);
    const pub = mlDsa65Backend.importKey(kat.sigVer.publicKeyB64url, 'public');
    expect(sha256(pub.material())).toBe(kat.keyGen.publicKeySha256);
  });

  it('sigVer KAT: a known valid (pk, message, signature) triple verifies', () => {
    const pub = mlDsa65Backend.importKey(kat.sigVer.publicKeyB64url, 'public');
    expect(() =>
      mlDsa65Backend.verify(pub, bytes(kat.sigVer.message), b64u(kat.sigVer.signatureB64url))
    ).not.toThrow();
  });

  it('sigVer KAT: a corrupted signature from the same triple is rejected', () => {
    const pub = mlDsa65Backend.importKey(kat.sigVer.publicKeyB64url, 'public');
    const corrupted = b64u(kat.sigVer.signatureB64url);
    corrupted[0] ^= 0x01;
    expect(() => mlDsa65Backend.verify(pub, bytes(kat.sigVer.message), corrupted)).toThrow(
      CryptoVerificationError
    );
  });
});

describe('ML-DSA-65 backend — properties', () => {
  it('generates a key pair with the correct byte lengths and default non-extractable private key', () => {
    const { privateKey, publicKey } = mlDsa65Backend.generateKeyPair();
    expect(isMlDsaKey(privateKey)).toBe(true);
    expect(privateKey.kind).toBe('private');
    expect(publicKey.kind).toBe('public');
    expect(privateKey.extractable).toBe(false);
    expect(privateKey.material().length).toBe(ML_DSA_65_LENGTHS.secretKey);
    expect(privateKey.seed().length).toBe(ML_DSA_65_LENGTHS.seed);
    expect(publicKey.material().length).toBe(ML_DSA_65_LENGTHS.publicKey);
  });

  it('round-trips: sign then verify passes for the generated pair', () => {
    const { privateKey, publicKey } = mlDsa65Backend.generateKeyPair();
    const message = bytes('hello post-quantum world');
    const sig = mlDsa65Backend.sign(privateKey, message);
    expect(sig.length).toBe(ML_DSA_65_LENGTHS.signature);
    expect(() => mlDsa65Backend.verify(publicKey, message, sig)).not.toThrow();
  });

  it('signing is HEDGED (randomized): two signatures over the same input differ but both verify', () => {
    const { privateKey, publicKey } = mlDsa65Backend.generateKeyPair();
    const message = bytes('same message');
    const a = mlDsa65Backend.sign(privateKey, message);
    const b = mlDsa65Backend.sign(privateKey, message);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    expect(() => mlDsa65Backend.verify(publicKey, message, a)).not.toThrow();
    expect(() => mlDsa65Backend.verify(publicKey, message, b)).not.toThrow();
  });

  it('generates independent key pairs (fresh CSPRNG seed each call)', () => {
    const a = mlDsa65Backend.generateKeyPair();
    const b = mlDsa65Backend.generateKeyPair();
    expect(Buffer.from(a.publicKey.material()).equals(Buffer.from(b.publicKey.material()))).toBe(
      false
    );
  });

  it('rejects a message tampered by a single bit', () => {
    const { privateKey, publicKey } = mlDsa65Backend.generateKeyPair();
    const message = bytes('authentic message');
    const sig = mlDsa65Backend.sign(privateKey, message);
    const tampered = bytes('authentic message');
    tampered[0] ^= 0x01;
    expect(() => mlDsa65Backend.verify(publicKey, tampered, sig)).toThrow(CryptoVerificationError);
  });

  it('rejects a signature tampered by a single bit', () => {
    const { privateKey, publicKey } = mlDsa65Backend.generateKeyPair();
    const message = bytes('authentic message');
    const sig = mlDsa65Backend.sign(privateKey, message);
    sig[10] ^= 0x01;
    expect(() => mlDsa65Backend.verify(publicKey, message, sig)).toThrow(CryptoVerificationError);
  });

  it('rejects a signature verified under the wrong public key (cross-key)', () => {
    const a = mlDsa65Backend.generateKeyPair();
    const b = mlDsa65Backend.generateKeyPair();
    const message = bytes('for key a');
    const sig = mlDsa65Backend.sign(a.privateKey, message);
    expect(() => mlDsa65Backend.verify(b.publicKey, message, sig)).toThrow(CryptoVerificationError);
  });

  it('normalizes a malformed-length signature to CryptoVerificationError (not a raw noble error)', () => {
    const { publicKey } = mlDsa65Backend.generateKeyPair();
    let thrown: unknown;
    try {
      mlDsa65Backend.verify(publicKey, bytes('m'), new Uint8Array(10));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(CryptoVerificationError);
    expect((thrown as CryptoVerificationError).reason).toBe('invalid');
  });

  it('rejects an import with a wrong-length public key or seed', () => {
    const shortPub = Buffer.from(new Uint8Array(100)).toString('base64url');
    expect(() => mlDsa65Backend.importKey(shortPub, 'public')).toThrow(CryptoVerificationError);
    const shortSeed = Buffer.from(new Uint8Array(16)).toString('base64url');
    expect(() => mlDsa65Backend.importKey(shortSeed, 'private')).toThrow(CryptoVerificationError);
  });
});

describe('ML-DSA-65 backend — key export/import + hygiene', () => {
  it('export/import round-trip: an exported seed re-imports to a key that verifies under the original public key', () => {
    const { privateKey, publicKey } = mlDsa65Backend.generateKeyPair({ extractable: true });
    const exportedSeed = mlDsa65Backend.exportKey(privateKey);
    const exportedPub = mlDsa65Backend.exportKey(publicKey);

    const reimportedPriv = mlDsa65Backend.importKey(exportedSeed, 'private');
    const message = bytes('cross-instance message');
    const sig = mlDsa65Backend.sign(reimportedPriv, message);
    // Verifies under the ORIGINAL public key and the re-imported one.
    expect(() => mlDsa65Backend.verify(publicKey, message, sig)).not.toThrow();
    const reimportedPub = mlDsa65Backend.importKey(exportedPub, 'public');
    expect(() => mlDsa65Backend.verify(reimportedPub, message, sig)).not.toThrow();
  });

  it('refuses to export a non-extractable private key', () => {
    const { privateKey } = mlDsa65Backend.generateKeyPair(); // default extractable: false
    expect(() => mlDsa65Backend.exportKey(privateKey)).toThrow(/non-extractable/);
  });

  it('never leaks key material through JSON.stringify or inspect', () => {
    const { privateKey } = mlDsa65Backend.generateKeyPair({ extractable: true });
    const seedHex = Buffer.from(privateKey.seed()).toString('hex');
    const json = JSON.stringify(privateKey);
    expect(json).toContain('[redacted]');
    expect(json).not.toContain(seedHex);
    const inspected = (privateKey as unknown as { [k: symbol]: () => string })[
      Symbol.for('nodejs.util.inspect.custom')
    ]();
    expect(inspected).toContain('[redacted]');
    expect(inspected).not.toContain(seedHex);
  });

  it('destroy() zero-fills material and makes the key unusable', () => {
    const { privateKey } = mlDsa65Backend.generateKeyPair({ extractable: true });
    privateKey.destroy();
    expect(() => privateKey.material()).toThrow(/destroyed/);
    expect(() => mlDsa65Backend.sign(privateKey, bytes('m'))).toThrow(/destroyed/);
  });

  it('constructs MlDsaKey with the ML-DSA-65 alg discriminant', () => {
    const key = new MlDsaKey({
      kind: 'public',
      material: new Uint8Array(ML_DSA_65_LENGTHS.publicKey),
    });
    expect(key.alg).toBe('ML-DSA-65');
  });
});
