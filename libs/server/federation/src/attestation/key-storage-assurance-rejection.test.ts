import { InvalidCredentialsError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { CREDENTIAL_STATUS_REJECTION_MESSAGE } from '../status/credential-status-rejection';
import {
  ISSUER_TRUST_REJECTION_MESSAGE,
  issuerTrustRejection,
} from '../trust/issuer-trust-rejection';
import {
  KEY_STORAGE_ASSURANCE_REJECTION_MESSAGE,
  keyStorageAssuranceRejection,
  type KeyStorageAssuranceRejectionReason,
} from './key-storage-assurance-rejection';

/** Every reason the gate can name. Listed so a new one must be added here too. */
const EVERY_REASON: readonly KeyStorageAssuranceRejectionReason[] = [
  'assurance-required-but-absent',
  'issuer-does-not-attest-key-storage',
  'attestation-malformed',
  'attestation-certificate-self-signed',
  'attestation-anchor-in-chain',
  'attestation-chain-unanchored',
  'attestation-signature-invalid',
  'attested-key-mismatch',
  'attack-potential-below-minimum',
];

describe('keyStorageAssuranceRejection (#308) — distinct outcomes, one wire shape', () => {
  it('carries the issuer-trust message VERBATIM', () => {
    // The moment these differ, the key-storage path becomes distinguishable from
    // the trust path and the non-enumeration guarantee #236 built is lost at the
    // seam #308 introduces.
    expect(KEY_STORAGE_ASSURANCE_REJECTION_MESSAGE).toBe(ISSUER_TRUST_REJECTION_MESSAGE);
  });

  it('is indistinguishable from the credential-status refusal too (#297)', () => {
    expect(KEY_STORAGE_ASSURANCE_REJECTION_MESSAGE).toBe(CREDENTIAL_STATUS_REJECTION_MESSAGE);
  });

  it.each(EVERY_REASON)('renders reason %s as the one non-enumerating error', (reason) => {
    const error = keyStorageAssuranceRejection(reason);

    expect(error).toBeInstanceOf(InvalidCredentialsError);
    expect(error.message).toBe(ISSUER_TRUST_REJECTION_MESSAGE);
  });

  it('never leaks the reason into the error it builds', () => {
    // The reason describes the holder's DEVICE — whether their key is in
    // certified hardware, at what grade, and whether their wallet vendor's chain
    // is anchored here. A client able to read it learns facts about a stranger's
    // hardware from a login attempt.
    for (const reason of EVERY_REASON) {
      const error = keyStorageAssuranceRejection(reason);

      expect(error.message).not.toContain(reason);
      expect(JSON.stringify(error)).not.toContain(reason);
      expect(error).not.toHaveProperty('reason');
    }
  });

  it('produces one error per call, so no stack is shared between requests', () => {
    const first = keyStorageAssuranceRejection('assurance-required-but-absent');
    const second = keyStorageAssuranceRejection('assurance-required-but-absent');

    expect(first).not.toBe(second);
  });

  it('is byte-identical to what an untrusted issuer produces', () => {
    const fromTrust = issuerTrustRejection();
    const fromAssurance = keyStorageAssuranceRejection('attested-key-mismatch');

    expect(fromAssurance.message).toBe(fromTrust.message);
    expect(fromAssurance.constructor).toBe(fromTrust.constructor);
    expect(fromAssurance.statusCode).toBe(fromTrust.statusCode);
  });
});
