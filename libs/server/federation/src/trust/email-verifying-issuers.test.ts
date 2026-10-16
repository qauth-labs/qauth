import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import {
  assertEmailVerifyingIssuersUsable,
  issuerVouchesForEmail,
} from './email-verifying-issuers';
import { ValidatedIssuer } from './issuer-identity';

/**
 * `OID4VP_EMAIL_VERIFYING_ISSUERS` (ANT-2026-BGP7XCR2): the issuers whose
 * `email` claim the OPERATOR accepts as verified without a disclosed
 * `email_verified: true`. Absent means none, which is the safe default.
 */

const ISSUER = ValidatedIssuer.fromValidatedPresentation({
  identifier: 'https://pid.issuer.example',
  keyResolution: 'issuer-metadata',
});

describe('issuerVouchesForEmail', () => {
  it('is false when nothing is configured', () => {
    expect(issuerVouchesForEmail(ISSUER, undefined)).toBe(false);
    expect(issuerVouchesForEmail(ISSUER, [])).toBe(false);
  });

  it('is true for a listed issuer, compared after canonicalization', () => {
    expect(issuerVouchesForEmail(ISSUER, ['https://PID.issuer.example/'])).toBe(true);
  });

  it('is false for an issuer that is not listed', () => {
    expect(issuerVouchesForEmail(ISSUER, ['https://other.issuer.example'])).toBe(false);
  });

  it('is false for an issuer that is not a branded ValidatedIssuer', () => {
    expect(
      issuerVouchesForEmail({ identifier: 'https://pid.issuer.example' }, [
        'https://pid.issuer.example',
      ])
    ).toBe(false);
  });
});

describe('assertEmailVerifyingIssuersUsable', () => {
  it('accepts nothing configured, and a list of https issuer identifiers', () => {
    expect(() => assertEmailVerifyingIssuersUsable(undefined)).not.toThrow();
    expect(() =>
      assertEmailVerifyingIssuersUsable(['https://pid.issuer.example', 'https://b.example'])
    ).not.toThrow();
  });

  it.each([
    ['an http URL', 'http://pid.issuer.example'],
    ['a URL with a query', 'https://pid.issuer.example/?a=b'],
    ['not a URL', 'pid.issuer.example'],
  ])('refuses to start on %s', (_label, entry) => {
    expect(() => assertEmailVerifyingIssuersUsable([entry])).toThrow(InvalidConfigurationError);
  });
});
