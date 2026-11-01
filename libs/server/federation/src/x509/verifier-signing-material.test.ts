import { generateKeyPairSync } from 'node:crypto';

import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { createTestCertificate, type TestCertificate } from '../status/test/x509-fixtures';
import { createVerifierSigningMaterial, verifierKeyMatchesLeaf } from './verifier-signing-material';

/**
 * The VERIFIER's own signing identity, validated at boot (issue #377, Phase A).
 *
 * Every case here is an operator mistake whose runtime symptom is identical and
 * useless — a wallet rejects the signed request, so 100% of presentations fail
 * with nothing naming the cause. The point of the suite is that each one is
 * distinguishable HERE, at boot, where an operator can act on it.
 */

/** A certificate's public key as the JWK `realm_public_keys` publishes for it. */
function publishedJwk(certificate: TestCertificate): Record<string, unknown> {
  return {
    ...certificate.keys.publicKey.export({ format: 'jwk' }),
    alg: 'ES256',
    use: 'sig',
    kid: 'thumbprint',
  };
}

/** anchor → intermediate → leaf, the shape a WRPAC deployment configures. */
function buildPki(leafOverrides: { notBefore?: Date; notAfter?: Date } = {}) {
  const anchor = createTestCertificate({
    subject: 'anchor',
    ca: true,
    keyUsage: ['keyCertSign', 'cRLSign'],
  });
  const intermediate = createTestCertificate({
    subject: 'issuing-ca',
    issuer: anchor,
    ca: true,
    keyUsage: ['keyCertSign', 'cRLSign'],
  });
  const leaf = createTestCertificate({
    subject: 'verifier.example',
    issuer: intermediate,
    keyUsage: ['digitalSignature'],
    ...leafOverrides,
  });

  return { anchor, intermediate, leaf };
}

describe('createVerifierSigningMaterial — the happy path', () => {
  const { anchor, intermediate, leaf } = buildPki();

  const material = createVerifierSigningMaterial({
    certificateChainPems: [leaf.pem, intermediate.pem],
    trustAnchorPems: [anchor.pem],
  });

  it('produces an x5c carrying leaf + intermediates, leaf FIRST', () => {
    expect(material.x5c).toEqual([leaf.x5c, intermediate.x5c]);
  });

  it('EXCLUDES the trust anchor from x5c', () => {
    // The property a wallet's own anchor depends on: a chain that shipped its
    // anchor would satisfy a path check against itself.
    expect(material.x5c).not.toContain(anchor.x5c);
  });

  it('carries the leaf DER the x509_hash Client Identifier digests', () => {
    expect(Buffer.from(material.leafDer).equals(leaf.der)).toBe(true);
  });

  it('carries the leaf expiry, so the signing path can refuse a stale chain', () => {
    expect(material.leafNotAfter.getTime()).toBe(leaf.certificate.validToDate.getTime());
  });

  it("carries the leaf's public key and no private key (#546)", () => {
    const jwk = leaf.keys.publicKey.export({ format: 'jwk' });
    expect(material.leafPublicKey).toEqual({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y });
    expect(Object.keys(material).sort()).toEqual([
      'leafDer',
      'leafNotAfter',
      'leafPublicKey',
      'x5c',
    ]);
  });
});

describe('verifierKeyMatchesLeaf (#546)', () => {
  const { anchor, intermediate, leaf } = buildPki();
  const material = createVerifierSigningMaterial({
    certificateChainPems: [leaf.pem, intermediate.pem],
    trustAnchorPems: [anchor.pem],
  });

  it("matches the stored key's published JWK, whatever else it carries", () => {
    expect(verifierKeyMatchesLeaf(material, publishedJwk(leaf))).toBe(true);
  });

  it("refuses another key: another leaf's, the intermediate's, another curve's", () => {
    expect(verifierKeyMatchesLeaf(material, publishedJwk(buildPki().leaf))).toBe(false);
    expect(verifierKeyMatchesLeaf(material, publishedJwk(intermediate))).toBe(false);
    const p384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).publicKey.export({
      format: 'jwk',
    });
    expect(verifierKeyMatchesLeaf(material, p384 as Record<string, unknown>)).toBe(false);
    const own = publishedJwk(leaf);
    expect(verifierKeyMatchesLeaf(material, { ...own, y: own['x'] })).toBe(false);
    expect(verifierKeyMatchesLeaf(material, { ...own, kty: 'OKP' })).toBe(false);
  });

  it('matches by EC coordinates, not by SPKI byte equality', () => {
    // SPKI DER is sensitive to the point CONVERSION FORM — a certificate whose
    // issuer encoded the public point compressed (RFC 5480 §2.2 permits it)
    // re-exports compressed, while the stored key's JWK is uncompressed.
    // Comparing `crv`/`x`/`y` is form-independent, so a legitimate operator PKI
    // cannot be refused for an encoding choice its CA made.
    const { x, y, crv } = leaf.keys.publicKey.export({ format: 'jwk' });
    expect(verifierKeyMatchesLeaf(material, { kty: 'EC', crv, x, y })).toBe(true);
  });
});

describe('createVerifierSigningMaterial — operator mistakes', () => {
  const { anchor, intermediate, leaf } = buildPki();

  it('refuses an empty chain', () => {
    expect(() =>
      createVerifierSigningMaterial({
        certificateChainPems: [],
        trustAnchorPems: [anchor.pem],
      })
    ).toThrow(/certificate chain is empty/);
  });

  it('refuses a chain with no trust anchor', () => {
    expect(() =>
      createVerifierSigningMaterial({
        certificateChainPems: [leaf.pem, intermediate.pem],
        trustAnchorPems: [],
      })
    ).toThrow(/no trust anchor is/);
  });

  it('refuses an unparseable certificate, naming its position', () => {
    try {
      createVerifierSigningMaterial({
        certificateChainPems: [leaf.pem, 'not a certificate'],
        trustAnchorPems: [anchor.pem],
      });
      expect.unreachable('an unparseable certificate must refuse the boot');
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidConfigurationError);
      expect((error as InvalidConfigurationError).details).toMatchObject({ index: 1 });
      // The offending value goes on `details`, never into the message.
      expect((error as Error).message).not.toContain('not a certificate');
    }
  });

  it('refuses a chain that SMUGGLES the anchor into x5c', () => {
    try {
      createVerifierSigningMaterial({
        certificateChainPems: [leaf.pem, intermediate.pem, anchor.pem],
        trustAnchorPems: [anchor.pem],
      });
      expect.unreachable('an anchor inside the chain must refuse the boot');
    } catch (error) {
      expect((error as InvalidConfigurationError).details).toMatchObject({
        reason: 'anchor-in-chain',
      });
    }
  });

  it('refuses a SELF-SIGNED leaf — the certificate x509_hash may never be', () => {
    const selfSigned = createTestCertificate({ subject: 'self', keyUsage: ['digitalSignature'] });

    try {
      createVerifierSigningMaterial({
        certificateChainPems: [selfSigned.pem],
        trustAnchorPems: [anchor.pem],
      });
      expect.unreachable('a self-signed leaf must refuse the boot');
    } catch (error) {
      expect((error as InvalidConfigurationError).details).toMatchObject({
        reason: 'self-signed-leaf',
      });
    }
  });

  it('refuses a chain that reaches a DIFFERENT anchor', () => {
    const stranger = createTestCertificate({ subject: 'stranger', ca: true });

    try {
      createVerifierSigningMaterial({
        certificateChainPems: [leaf.pem, intermediate.pem],
        trustAnchorPems: [stranger.pem],
      });
      expect.unreachable('an unanchored chain must refuse the boot');
    } catch (error) {
      expect((error as InvalidConfigurationError).details).toMatchObject({
        reason: 'no-path-to-anchor',
      });
    }
  });

  it('refuses an EXPIRED chain', () => {
    const expired = buildPki({
      notBefore: new Date(Date.now() - 7_200_000),
      notAfter: new Date(Date.now() - 3_600_000),
    });

    try {
      createVerifierSigningMaterial({
        certificateChainPems: [expired.leaf.pem, expired.intermediate.pem],
        trustAnchorPems: [expired.anchor.pem],
      });
      expect.unreachable('an expired chain must refuse the boot');
    } catch (error) {
      expect((error as InvalidConfigurationError).details).toMatchObject({
        reason: 'certificate-expired',
      });
    }
  });

  it('refuses a chain whose ORDER is reversed rather than reordering it', () => {
    // Guessing an order would be guessing which certificate the operator meant
    // to identify this deployment.
    try {
      createVerifierSigningMaterial({
        certificateChainPems: [intermediate.pem, leaf.pem],
        trustAnchorPems: [anchor.pem],
      });
      expect.unreachable('a reversed chain must refuse the boot');
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidConfigurationError);
    }
  });
});
