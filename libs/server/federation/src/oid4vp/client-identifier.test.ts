import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { createTestCertificate } from '../status/test/x509-fixtures';
import {
  buildClientId,
  buildRedirectUriClientId,
  buildX509HashClientId,
  CLIENT_ID_PREFIX_SEPARATOR,
  UNSIGNED_CLIENT_ID_PREFIX,
  X509_HASH_CLIENT_ID_PREFIX,
} from './client-identifier';

/**
 * Client Identifier Prefix rendering (OID4VP 1.0 §5.9, issues #233 and #377).
 *
 * The `x509_hash` value is the one string in this codebase a wallet recomputes
 * for itself and compares byte for byte. Everything about it is therefore an
 * interoperability assertion rather than a formatting one, and the digest below
 * is computed independently of the implementation for exactly that reason.
 */

const RESPONSE_URI = 'https://auth.example.com/oid4vp/response';

describe('buildClientId', () => {
  it('joins a prefix and its value with the §5.9 separator', () => {
    expect(buildClientId('redirect_uri', RESPONSE_URI)).toBe(
      `redirect_uri${CLIENT_ID_PREFIX_SEPARATOR}${RESPONSE_URI}`
    );
    expect(CLIENT_ID_PREFIX_SEPARATOR).toBe(':');
  });
});

describe('buildRedirectUriClientId', () => {
  it('renders the response_uri under the unsigned prefix (§5.9.3)', () => {
    expect(buildRedirectUriClientId(RESPONSE_URI)).toBe(`redirect_uri:${RESPONSE_URI}`);
    expect(UNSIGNED_CLIENT_ID_PREFIX).toBe('redirect_uri');
  });
});

describe('buildX509HashClientId (#377)', () => {
  const anchor = createTestCertificate({ subject: 'anchor', ca: true });
  const leaf = createTestCertificate({ subject: 'verifier.example', issuer: anchor });

  it('is the base64url SHA-256 of the DER-encoded leaf certificate (§5.9.3)', () => {
    // Recomputed here from `raw` rather than read back from the implementation:
    // a wallet does exactly this, so a test that reused the same helper would
    // agree with a wrong answer.
    const expected = createHash('sha256').update(leaf.der).digest('base64url');

    expect(buildX509HashClientId(leaf.der)).toBe(`x509_hash:${expected}`);
    expect(X509_HASH_CLIENT_ID_PREFIX).toBe('x509_hash');
  });

  it('emits UNPADDED base64url — no +, / or = survives a query parameter', () => {
    const value = buildX509HashClientId(leaf.der).slice('x509_hash:'.length);

    expect(value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(value).not.toContain('=');
    expect(value).not.toContain('+');
    expect(value).not.toContain('/');
  });

  it('digests the DER, not the PEM', () => {
    // The mistake that produces a `client_id` no wallet can ever match: `pem` is
    // a base64 text WRAPPING of `der`, so hashing it yields a different digest
    // for the same certificate.
    const overPem = createHash('sha256').update(leaf.pem).digest('base64url');

    expect(buildX509HashClientId(leaf.der)).not.toBe(`x509_hash:${overPem}`);
  });

  it('identifies the LEAF, never another certificate in the chain', () => {
    expect(buildX509HashClientId(leaf.der)).not.toBe(buildX509HashClientId(anchor.der));
  });

  it('is stable for one certificate and distinct across certificates', () => {
    const other = createTestCertificate({ subject: 'other.example', issuer: anchor });

    expect(buildX509HashClientId(leaf.der)).toBe(buildX509HashClientId(leaf.der));
    expect(buildX509HashClientId(leaf.der)).not.toBe(buildX509HashClientId(other.der));
  });
});
