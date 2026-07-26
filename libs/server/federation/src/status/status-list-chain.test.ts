import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import {
  certificateBindsIssuer,
  createStatusListTrustAnchors,
  NO_STATUS_LIST_TRUST_ANCHORS,
  resolveStatusListSigningCertificate,
  type StatusListTrustAnchors,
} from './status-list-chain';
import { createTestCertificate, generateEd25519TestKeyPair } from './test/x509-fixtures';

// Built at module scope, not in `beforeAll`: the `it.each` tables below are
// evaluated while the suite is being collected, which happens before any hook
// has run.
const now = new Date('2026-07-26T12:00:00.000Z');
const valid = {
  notBefore: new Date('2026-07-01T00:00:00.000Z'),
  notAfter: new Date('2026-08-31T00:00:00.000Z'),
};

const root = createTestCertificate({ subject: 'QAuth Test Root', ca: true, ...valid });
const intermediate = createTestCertificate({
  subject: 'QAuth Test Intermediate',
  ca: true,
  issuer: root,
  ...valid,
});
const leaf = createTestCertificate({
  subject: 'status.issuer.example',
  issuer: intermediate,
  dnsNames: ['status.issuer.example'],
  ...valid,
});
const otherRoot = createTestCertificate({ subject: 'Unrelated Root', ca: true, ...valid });
const anchors: StatusListTrustAnchors = createStatusListTrustAnchors([root.pem]);

describe('createStatusListTrustAnchors (#297)', () => {
  it('compiles PEM anchors', () => {
    expect(createStatusListTrustAnchors([root.pem, otherRoot.pem]).size).toBe(2);
  });

  it('yields the deny-all set for an empty configuration', () => {
    expect(createStatusListTrustAnchors([])).toBe(NO_STATUS_LIST_TRUST_ANCHORS);
    expect(NO_STATUS_LIST_TRUST_ANCHORS.size).toBe(0);
  });

  it.each([
    ['a non-PEM string', ['not a certificate']],
    ['a non-string entry', [42]],
    ['an empty string', ['']],
  ])('throws InvalidConfigurationError for %s', (_label, entries) => {
    expect(() => createStatusListTrustAnchors(entries as string[])).toThrow(
      InvalidConfigurationError
    );
  });

  it('reports the offending anchor on details, never in the message', () => {
    try {
      createStatusListTrustAnchors(['-----BEGIN CERTIFICATE----- nope']);
      expect.unreachable('should have refused');
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidConfigurationError);
      expect((error as InvalidConfigurationError).message).not.toContain('nope');
      expect((error as InvalidConfigurationError).details?.['index']).toBe(0);
    }
  });

  it('rejects a non-array configuration', () => {
    expect(() => createStatusListTrustAnchors(root.pem as never)).toThrow(
      InvalidConfigurationError
    );
  });
});

describe('resolveStatusListSigningCertificate (#297, HAIP §6.1.1)', () => {
  it('resolves a leaf that chains to a configured anchor', () => {
    const resolution = resolveStatusListSigningCertificate(
      [leaf.x5c, intermediate.x5c],
      anchors,
      now
    );

    expect(resolution.outcome).toBe('resolved');
    if (resolution.outcome !== 'resolved') return;
    expect(resolution.leaf.subject).toContain('status.issuer.example');
    expect(resolution.publicKeyPem).toContain('BEGIN PUBLIC KEY');
  });

  it('resolves a single-certificate chain issued directly by the anchor', () => {
    const direct = createTestCertificate({
      subject: 'direct.issuer.example',
      issuer: root,
      dnsNames: ['direct.issuer.example'],
      ...valid,
    });
    expect(resolveStatusListSigningCertificate([direct.x5c], anchors, now).outcome).toBe(
      'resolved'
    );
  });

  it('refuses a chain that reaches no configured anchor', () => {
    const foreignRoot = createTestCertificate({ subject: 'Attacker Root', ca: true, ...valid });
    const foreignLeaf = createTestCertificate({
      subject: 'status.issuer.example',
      issuer: foreignRoot,
      dnsNames: ['status.issuer.example'],
      ...valid,
    });

    expect(resolveStatusListSigningCertificate([foreignLeaf.x5c], anchors, now)).toEqual({
      outcome: 'rejected',
      reason: 'no-path-to-anchor',
    });
  });

  it('refuses everything when no anchors are configured', () => {
    expect(
      resolveStatusListSigningCertificate(
        [leaf.x5c, intermediate.x5c],
        NO_STATUS_LIST_TRUST_ANCHORS,
        now
      )
    ).toEqual({ outcome: 'rejected', reason: 'no-path-to-anchor' });
  });

  it('refuses a chain that carries the trust anchor (HAIP: anchor EXCLUDED)', () => {
    // Without this, a self-signed root shipped inside `x5c` would satisfy the
    // path check against itself — "chains to an anchor" would degrade into
    // "carries a copy of an anchor".
    expect(
      resolveStatusListSigningCertificate([leaf.x5c, intermediate.x5c, root.x5c], anchors, now)
    ).toEqual({ outcome: 'rejected', reason: 'anchor-in-chain' });
  });

  it('refuses a self-signed leaf', () => {
    const selfSigned = createTestCertificate({
      subject: 'status.issuer.example',
      dnsNames: ['status.issuer.example'],
      ...valid,
    });
    expect(resolveStatusListSigningCertificate([selfSigned.x5c], anchors, now)).toEqual({
      outcome: 'rejected',
      reason: 'self-signed-leaf',
    });
  });

  it('refuses an expired certificate anywhere in the chain', () => {
    const expiredLeaf = createTestCertificate({
      subject: 'status.issuer.example',
      issuer: intermediate,
      dnsNames: ['status.issuer.example'],
      notBefore: new Date('2026-01-01T00:00:00.000Z'),
      notAfter: new Date('2026-02-01T00:00:00.000Z'),
    });
    expect(
      resolveStatusListSigningCertificate([expiredLeaf.x5c, intermediate.x5c], anchors, now)
    ).toEqual({ outcome: 'rejected', reason: 'certificate-expired' });
  });

  it('refuses a certificate that is not yet valid', () => {
    const futureLeaf = createTestCertificate({
      subject: 'status.issuer.example',
      issuer: intermediate,
      dnsNames: ['status.issuer.example'],
      notBefore: new Date('2027-01-01T00:00:00.000Z'),
      notAfter: new Date('2027-02-01T00:00:00.000Z'),
    });
    expect(
      resolveStatusListSigningCertificate([futureLeaf.x5c, intermediate.x5c], anchors, now)
    ).toEqual({ outcome: 'rejected', reason: 'certificate-expired' });
  });

  it('refuses when the anchor itself has expired', () => {
    const expiredRoot = createTestCertificate({
      subject: 'Expired Root',
      ca: true,
      notBefore: new Date('2020-01-01T00:00:00.000Z'),
      notAfter: new Date('2021-01-01T00:00:00.000Z'),
    });
    const child = createTestCertificate({
      subject: 'status.issuer.example',
      issuer: expiredRoot,
      dnsNames: ['status.issuer.example'],
      ...valid,
    });
    expect(
      resolveStatusListSigningCertificate(
        [child.x5c],
        createStatusListTrustAnchors([expiredRoot.pem]),
        now
      )
    ).toEqual({ outcome: 'rejected', reason: 'no-path-to-anchor' });
  });

  it('refuses a non-CA intermediate', () => {
    // Otherwise any leaf legitimately issued under the anchor could mint
    // certificates for every other status issuer under it.
    const notACa = createTestCertificate({
      subject: 'Not A CA',
      ca: false,
      issuer: root,
      ...valid,
    });
    const forged = createTestCertificate({
      subject: 'status.issuer.example',
      issuer: notACa,
      dnsNames: ['status.issuer.example'],
      ...valid,
    });
    expect(resolveStatusListSigningCertificate([forged.x5c, notACa.x5c], anchors, now)).toEqual({
      outcome: 'rejected',
      reason: 'broken-link',
    });
  });

  it('refuses a chain whose links do not actually verify', () => {
    const unrelated = createTestCertificate({
      subject: 'Unrelated Intermediate',
      ca: true,
      issuer: otherRoot,
      ...valid,
    });
    expect(resolveStatusListSigningCertificate([leaf.x5c, unrelated.x5c], anchors, now)).toEqual({
      outcome: 'rejected',
      reason: 'broken-link',
    });
  });

  it('refuses a leaf whose key cannot produce an ES256 signature', () => {
    const edLeaf = createTestCertificate({
      subject: 'status.issuer.example',
      issuer: intermediate,
      dnsNames: ['status.issuer.example'],
      keys: generateEd25519TestKeyPair(),
      ...valid,
    });
    expect(
      resolveStatusListSigningCertificate([edLeaf.x5c, intermediate.x5c], anchors, now)
    ).toEqual({ outcome: 'rejected', reason: 'unsupported-leaf-key' });
  });

  it.each([
    ['a non-array x5c', leaf.x5c],
    ['an empty x5c', []],
    ['a non-string entry', [42]],
    ['base64url instead of base64', ['a-b_c']],
    ['unpadded base64', ['AAA']],
    ['garbage that is valid base64', ['AAAA']],
    ['an over-long chain', Array.from({ length: 9 }, () => 'AAAA')],
  ])('refuses %s as malformed', (_label, x5c) => {
    expect(resolveStatusListSigningCertificate(x5c, anchors, now)).toEqual({
      outcome: 'rejected',
      reason: 'malformed-x5c',
    });
  });

  it('refuses an over-long single entry without parsing it', () => {
    expect(resolveStatusListSigningCertificate(['A'.repeat(20_000)], anchors, now)).toEqual({
      outcome: 'rejected',
      reason: 'malformed-x5c',
    });
  });
});

describe('certificateBindsIssuer (#297)', () => {
  it('accepts an iss whose host matches a dNSName SAN', () => {
    expect(certificateBindsIssuer(leaf.certificate, 'https://status.issuer.example')).toBe(true);
    expect(certificateBindsIssuer(leaf.certificate, 'https://status.issuer.example/lists/1')).toBe(
      true
    );
  });

  it('refuses an iss the certificate does not cover', () => {
    // The attack this closes: any holder of an anchored certificate signing a
    // status list that claims to be a DIFFERENT issuer under the same anchor.
    expect(certificateBindsIssuer(leaf.certificate, 'https://other.issuer.example')).toBe(false);
  });

  it('does not fall back to the subject CN', () => {
    // RFC 2818 §3.1 deprecated CN-as-hostname; a CA that is not checking CN
    // makes it a free-text field.
    const cnOnly = createTestCertificate({
      subject: 'cn-only.issuer.example',
      issuer: intermediate,
      ...valid,
    });
    expect(certificateBindsIssuer(cnOnly.certificate, 'https://cn-only.issuer.example')).toBe(
      false
    );
  });

  it.each([
    ['a non-HTTPS iss', 'http://status.issuer.example'],
    ['a non-URL iss', 'status.issuer.example'],
    ['an empty iss', ''],
    ['a URN', 'urn:example:issuer'],
  ])('refuses %s', (_label, issuer) => {
    expect(certificateBindsIssuer(leaf.certificate, issuer)).toBe(false);
  });
});
