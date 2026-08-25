import { generateKeyPairSync } from 'node:crypto';

import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { createTestCertificate, type TestCertificate } from '../status/test/x509-fixtures';
import { createVerifierSigningMaterial } from './verifier-signing-material';

/**
 * The VERIFIER's own signing identity, validated at boot (issue #377, Phase A).
 *
 * Every case here is an operator mistake whose runtime symptom is identical and
 * useless — a wallet rejects the signed request, so 100% of presentations fail
 * with nothing naming the cause. The point of the suite is that each one is
 * distinguishable HERE, at boot, where an operator can act on it.
 */

/** Export a key pair's private half as the PKCS#8 PEM an operator configures. */
function pkcs8(certificate: TestCertificate): string {
  return certificate.keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
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
    privateKeyPem: pkcs8(leaf),
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

  it('keeps the operator key verbatim rather than re-encoding it', () => {
    expect(material.privateKeyPem).toBe(pkcs8(leaf));
  });
});

describe('createVerifierSigningMaterial — operator mistakes', () => {
  const { anchor, intermediate, leaf } = buildPki();
  const validKey = pkcs8(leaf);

  it('refuses a key with no chain', () => {
    expect(() =>
      createVerifierSigningMaterial({
        privateKeyPem: validKey,
        certificateChainPems: [],
        trustAnchorPems: [anchor.pem],
      })
    ).toThrow(/no certificate chain is/);
  });

  it('refuses a chain with no trust anchor', () => {
    expect(() =>
      createVerifierSigningMaterial({
        privateKeyPem: validKey,
        certificateChainPems: [leaf.pem, intermediate.pem],
        trustAnchorPems: [],
      })
    ).toThrow(/no trust anchor is/);
  });

  it('refuses an unparseable certificate, naming its position', () => {
    try {
      createVerifierSigningMaterial({
        privateKeyPem: validKey,
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
        privateKeyPem: validKey,
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
        privateKeyPem: pkcs8(selfSigned),
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
        privateKeyPem: validKey,
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
        privateKeyPem: pkcs8(expired.leaf),
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
        privateKeyPem: pkcs8(intermediate),
        certificateChainPems: [intermediate.pem, leaf.pem],
        trustAnchorPems: [anchor.pem],
      });
      expect.unreachable('a reversed chain must refuse the boot');
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidConfigurationError);
    }
  });

  // The check no amount of chain validation substitutes for.
  it("refuses a key that is not the leaf's own", () => {
    const other = buildPki();

    expect(() =>
      createVerifierSigningMaterial({
        privateKeyPem: pkcs8(other.leaf),
        certificateChainPems: [leaf.pem, intermediate.pem],
        trustAnchorPems: [anchor.pem],
      })
    ).toThrow(/does not belong to the leaf certificate/);
  });

  it('refuses a key that is not EC P-256', () => {
    const ed25519 = generateKeyPairSync('ed25519')
      .privateKey.export({ type: 'pkcs8', format: 'pem' })
      .toString();

    expect(() =>
      createVerifierSigningMaterial({
        privateKeyPem: ed25519,
        certificateChainPems: [leaf.pem, intermediate.pem],
        trustAnchorPems: [anchor.pem],
      })
    ).toThrow(/EC P-256/);
  });

  it('refuses a key that is not a readable PKCS#8 PEM', () => {
    expect(() =>
      createVerifierSigningMaterial({
        privateKeyPem: '-----BEGIN PRIVATE KEY-----\nnot base64\n-----END PRIVATE KEY-----',
        certificateChainPems: [leaf.pem, intermediate.pem],
        trustAnchorPems: [anchor.pem],
      })
    ).toThrow(/not a readable PKCS#8 PEM/);
  });

  it('never puts the operator key into an error message', () => {
    try {
      createVerifierSigningMaterial({
        privateKeyPem: '-----BEGIN PRIVATE KEY-----\nnot base64\n-----END PRIVATE KEY-----',
        certificateChainPems: [leaf.pem, intermediate.pem],
        trustAnchorPems: [anchor.pem],
      });
      expect.unreachable('an unreadable key must refuse the boot');
    } catch (error) {
      expect((error as Error).message).not.toContain('BEGIN PRIVATE KEY');
    }
  });
});
