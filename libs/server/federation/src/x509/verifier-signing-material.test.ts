import { execSync } from 'node:child_process';
import { createPrivateKey, generateKeyPairSync } from 'node:crypto';

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

  it('hands back the key as PKCS#8, the one form the signing path can import', () => {
    expect(material.privateKeyPem.startsWith('-----BEGIN PRIVATE KEY-----')).toBe(true);
    expect(material.privateKeyPem).toBe(pkcs8(leaf));
  });
});

describe('createVerifierSigningMaterial — key ENCODING (#377)', () => {
  const { anchor, intermediate, leaf } = buildPki();

  it('accepts a SEC1 key and normalises it, because that is what openssl emits', () => {
    // The failure this closes: `openssl ecparam -name prime256v1 -genkey` — the
    // way most operators produce a P-256 key — emits SEC1 (`BEGIN EC PRIVATE
    // KEY`). `node:crypto` parses it happily, so a boot check written around
    // `createPrivateKey` alone passes, while `jose`'s `importPKCS8` (what the
    // signing path uses) refuses it with `"pkcs8" must be PKCS#8 formatted
    // string`. Boot would validate one form and the request path import another,
    // and the symptom would be every wallet login failing with nothing in the
    // logs naming the cause.
    const sec1 = leaf.keys.privateKey.export({ type: 'sec1', format: 'pem' }).toString();

    expect(sec1.startsWith('-----BEGIN EC PRIVATE KEY-----')).toBe(true);

    const material = createVerifierSigningMaterial({
      privateKeyPem: sec1,
      certificateChainPems: [leaf.pem, intermediate.pem],
      trustAnchorPems: [anchor.pem],
    });

    expect(material.privateKeyPem.startsWith('-----BEGIN PRIVATE KEY-----')).toBe(true);
    // The normalised bytes are the SAME KEY, not merely a well-formed one.
    expect(material.privateKeyPem).toBe(pkcs8(leaf));
  });

  it('accepts what `openssl ecparam -genkey` actually writes', () => {
    // Belt and braces on the assertion above: the SEC1 export used there is
    // Node's, and the claim is about openssl's. This runs the real command, and
    // asserts only that the encoding is accepted — the key is a stranger's, so
    // the leaf match is what refuses it.
    const openssl = execSync('openssl ecparam -name prime256v1 -genkey -noout', {
      encoding: 'utf8',
    });

    expect(openssl.startsWith('-----BEGIN EC PRIVATE KEY-----')).toBe(true);
    expect(createPrivateKey(openssl).asymmetricKeyDetails?.namedCurve).toBe('prime256v1');
    expect(
      () =>
        createVerifierSigningMaterial({
          privateKeyPem: openssl,
          certificateChainPems: [leaf.pem, intermediate.pem],
          trustAnchorPems: [anchor.pem],
        })
      // Refused for belonging to the wrong leaf, NOT for its encoding.
    ).toThrow(/does not belong to the leaf certificate/);
  });

  it('matches the key to the leaf by EC coordinates, not by SPKI byte equality', () => {
    // SPKI DER is sensitive to the point CONVERSION FORM — a certificate whose
    // issuer encoded the public point compressed (RFC 5480 §2.2 permits it)
    // re-exports compressed, while a key derived from PKCS#8 exports
    // uncompressed. Comparing `crv`/`x`/`y` is form-independent, so a legitimate
    // operator PKI cannot be refused for an encoding choice its CA made.
    const jwk = leaf.keys.publicKey.export({ format: 'jwk' });
    const material = createVerifierSigningMaterial({
      privateKeyPem: pkcs8(leaf),
      certificateChainPems: [leaf.pem, intermediate.pem],
      trustAnchorPems: [anchor.pem],
    });

    expect(jwk.crv).toBe('P-256');
    expect(material.x5c[0]).toBe(leaf.x5c);
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

  it('refuses a key that is not a readable PEM at all', () => {
    expect(() =>
      createVerifierSigningMaterial({
        privateKeyPem: '-----BEGIN PRIVATE KEY-----\nnot base64\n-----END PRIVATE KEY-----',
        certificateChainPems: [leaf.pem, intermediate.pem],
        trustAnchorPems: [anchor.pem],
      })
    ).toThrow(/not a readable PEM private key/);
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
