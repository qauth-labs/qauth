import { InvalidCredentialsError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { ISSUER_TRUST_REJECTION_MESSAGE } from '../trust/issuer-trust-rejection';
import {
  CREDENTIAL_STATUS_REJECTION_MESSAGE,
  credentialStatusRejection,
  type CredentialStatusRejectionReason,
} from './credential-status-rejection';

const ALL_REASONS: readonly CredentialStatusRejectionReason[] = [
  'status-required-but-absent',
  'malformed-status-claim',
  'uri-not-permitted',
  'endpoint-unavailable',
  'circuit-open',
  'token-unverifiable',
  'issuer-untrusted',
  'list-unreadable',
  'index-out-of-range',
  'revoked',
  'suspended',
  'status-unknown',
];

describe('credentialStatusRejection (#297)', () => {
  it('is the SAME refusal the issuer-trust path throws', () => {
    // The moment these two differ, "this credential is revoked" becomes
    // distinguishable from "this issuer is not trusted", and the
    // non-enumeration property #236 built is gone at this seam.
    expect(CREDENTIAL_STATUS_REJECTION_MESSAGE).toBe(ISSUER_TRUST_REJECTION_MESSAGE);
  });

  it('produces an InvalidCredentialsError for every reason', () => {
    for (const reason of ALL_REASONS) {
      expect(credentialStatusRejection(reason)).toBeInstanceOf(InvalidCredentialsError);
    }
  });

  it('is INDISTINGUISHABLE across every failure mode', () => {
    const shapes = ALL_REASONS.map((reason) => {
      const error = credentialStatusRejection(reason);
      return {
        name: error.name,
        message: error.message,
        statusCode: (error as unknown as { statusCode?: number }).statusCode,
        code: (error as unknown as { code?: string }).code,
        keys: Object.keys(error).sort(),
      };
    });

    for (const shape of shapes) expect(shape).toEqual(shapes[0]);
  });

  it('never leaks the reason into the error', () => {
    for (const reason of ALL_REASONS) {
      const serialized = JSON.stringify({
        ...credentialStatusRejection(reason),
        message: credentialStatusRejection(reason).message,
      });
      expect(serialized).not.toContain(reason);
    }
  });

  it('returns a fresh instance so each throw carries its own stack', () => {
    const first = credentialStatusRejection('revoked');
    const second = credentialStatusRejection('revoked');
    expect(first).not.toBe(second);
  });

  it('says nothing about revocation, issuers, or status lists', () => {
    const message = CREDENTIAL_STATUS_REJECTION_MESSAGE.toLowerCase();
    for (const word of ['revok', 'suspend', 'status', 'issuer', 'list', 'expired']) {
      expect(message).not.toContain(word);
    }
  });
});
