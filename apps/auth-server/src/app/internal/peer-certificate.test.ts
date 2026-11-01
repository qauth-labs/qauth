import { X509Certificate } from 'node:crypto';

import { internalListenerEnvSchema } from '@qauth-labs/server-config';
import { describe, expect, it } from 'vitest';

import { createTestCertificate } from '../../testing/x509-der';
import {
  certificateSans,
  holdsSan,
  loggableSans,
  resolvePeerRole,
  splitSubjectAltName,
} from './peer-certificate';

/** How the internal listener and client read a certificate's SANs (#496). */

const PEER_ROLES = internalListenerEnvSchema.parse({
  INTERNAL_PEER_ROLES: JSON.stringify({
    'spiffe://qauth.test/web': 'web',
    'api.qauth.internal': 'api',
    'spiffe://qauth.test/admin': 'admin',
  }),
}).INTERNAL_PEER_ROLES;

/** The `subjectAltName` text Node.js writes for a certificate with these SANs. */
function subjectAltNameOf(options: { dnsNames?: string[]; uris?: string[] }): string | undefined {
  const certificate = createTestCertificate({ subject: 'peer', ...options });
  return new X509Certificate(certificate.der).subjectAltName;
}

describe('certificateSans', () => {
  it('reads the DNS and URI SANs Node.js lists', () => {
    expect(
      certificateSans(
        subjectAltNameOf({
          dnsNames: ['api.qauth.internal', 'other.internal'],
          uris: ['spiffe://qauth.test/web'],
        })
      )
    ).toEqual([
      { type: 'dns', value: 'api.qauth.internal' },
      { type: 'dns', value: 'other.internal' },
      { type: 'uri', value: 'spiffe://qauth.test/web' },
    ]);
  });

  it('never splits one SAN that holds ", " into two (CVE-2021-44532)', () => {
    // A DNS SAN whose text reads as two entries: Node.js quotes it.
    const text = subjectAltNameOf({ dnsNames: ['x, URI:spiffe://qauth.test/admin'] });
    expect(text).toBe('DNS:"x' + String.fromCharCode(92) + 'u002c URI:spiffe://qauth.test/admin"');
    const sans = certificateSans(text);
    expect(sans).toEqual([{ type: 'dns', value: 'x, URI:spiffe://qauth.test/admin' }]);
    expect(resolvePeerRole(sans, PEER_ROLES)).toEqual({ refused: 'unknown' });
  });

  it('reads an escaped value and the entries after it', () => {
    expect(splitSubjectAltName('DNS:"a\\"b, c", URI:spiffe://x/y')).toEqual([
      'DNS:a"b, c',
      'URI:spiffe://x/y',
    ]);
  });

  it('reads nothing from a text it cannot parse, and nothing from no text', () => {
    expect(certificateSans('DNS:"unterminated')).toEqual([]);
    expect(certificateSans(undefined)).toEqual([]);
    expect(certificateSans('')).toEqual([]);
  });

  it('leaves out the kinds no peer is known by', () => {
    expect(
      certificateSans('IP Address:10.0.0.1, email:peer@example.com, DNS:api.qauth.internal')
    ).toEqual([{ type: 'dns', value: 'api.qauth.internal' }]);
  });
});

describe('resolvePeerRole', () => {
  it('maps a URI SAN exactly and a DNS SAN without regard to case', () => {
    expect(
      resolvePeerRole([{ type: 'uri', value: 'spiffe://qauth.test/web' }], PEER_ROLES)
    ).toEqual({ role: 'web' });
    expect(resolvePeerRole([{ type: 'dns', value: 'API.Qauth.Internal' }], PEER_ROLES)).toEqual({
      role: 'api',
    });
    expect(
      resolvePeerRole([{ type: 'uri', value: 'spiffe://qauth.test/WEB' }], PEER_ROLES)
    ).toEqual({ refused: 'unknown' });
  });

  it('never reads a DNS SAN as the URI of the same text, or the reverse', () => {
    expect(
      resolvePeerRole([{ type: 'dns', value: 'spiffe://qauth.test/web' }], PEER_ROLES)
    ).toEqual({ refused: 'unknown' });
    expect(resolvePeerRole([{ type: 'uri', value: 'api.qauth.internal' }], PEER_ROLES)).toEqual({
      refused: 'unknown',
    });
  });

  it('gives no wildcard a meaning', () => {
    expect(resolvePeerRole([{ type: 'dns', value: '*.qauth.internal' }], PEER_ROLES)).toEqual({
      refused: 'unknown',
    });
  });

  it('refuses a certificate whose SANs map to two roles, and admits two SANs of one role', () => {
    expect(
      resolvePeerRole(
        [
          { type: 'uri', value: 'spiffe://qauth.test/web' },
          { type: 'uri', value: 'spiffe://qauth.test/admin' },
        ],
        PEER_ROLES
      )
    ).toEqual({ refused: 'ambiguous' });
    expect(
      resolvePeerRole(
        [
          { type: 'dns', value: 'api.qauth.internal' },
          { type: 'dns', value: 'unknown.internal' },
        ],
        PEER_ROLES
      )
    ).toEqual({ role: 'api' });
  });

  it('refuses a certificate with no SAN', () => {
    expect(resolvePeerRole([], PEER_ROLES)).toEqual({ refused: 'unknown' });
  });
});

describe('holdsSan', () => {
  it('finds a DNS SAN without regard to case and a URI exactly', () => {
    const sans = certificateSans('DNS:Signer.qauth.internal, URI:spiffe://qauth.test/signer');
    expect(holdsSan(sans, { type: 'dns', value: 'signer.QAUTH.internal' })).toBe(true);
    expect(holdsSan(sans, { type: 'uri', value: 'spiffe://qauth.test/signer' })).toBe(true);
    expect(holdsSan(sans, { type: 'uri', value: 'spiffe://qauth.test/Signer' })).toBe(false);
    expect(holdsSan(sans, { type: 'uri', value: 'Signer.qauth.internal' })).toBe(false);
  });
});

describe('loggableSans', () => {
  it('bounds what a certificate puts in a log line', () => {
    const many = Array.from({ length: 20 }, (_, index) => ({
      type: 'dns' as const,
      value: `${'a'.repeat(300)}${index}`,
    }));
    const logged = loggableSans(many);
    expect(logged).toHaveLength(8);
    expect(logged[0]?.length).toBe('dns:'.length + 256);
  });
});
