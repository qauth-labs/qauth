import { describe, expect, it, vi } from 'vitest';

import type { ValidatedCredential } from '../oid4vp/validated-credential';
import type { CredentialStatusChecker } from '../status/credential-status-checker';
import { ValidatedIssuer } from '../trust/issuer-identity';
import { createStaticIssuerAllowlist, DENY_ALL_TRUST_REGISTRY } from '../trust/trust-registry';
import {
  buildWalletAttributeProvenance,
  isWalletAttributeIssuerTrusted,
  isWalletAttributeStatusValid,
  readWalletAttributeProvenance,
} from './wallet-attribute-provenance';

/**
 * What stands behind a `source='wallet'` attribute row (ANT-2026-ULJIA4P4).
 *
 * The issuer-trust and credential-status gates run when a credential is
 * presented. The rows it leaves behind are emitted on every later token, so
 * each row records the issuer and the issuer-signed `status` reference it
 * rests on, and those can be asked about again without the holder.
 */

const ISSUER = 'https://issuer.example.com';
const STATUS = { status_list: { idx: 7, uri: 'https://status.example.com/lists/1' } };

function credentialFor(claims: Record<string, unknown>, issuer = ISSUER): ValidatedCredential {
  return {
    queryId: 'pid',
    format: 'dc+sd-jwt',
    credentialType: 'https://credentials.example.com/pid',
    issuer: ValidatedIssuer.fromValidatedPresentation({
      identifier: issuer,
      keyResolution: 'issuer-metadata',
    }),
    claims,
    validity: {},
    assurance: {
      credentialType: 'https://credentials.example.com/pid',
      issuerKeyResolution: 'issuer-metadata',
      issuerSignatureAlgorithm: 'ES256',
      keyBindingAlgorithm: 'ES256',
      disclosedClaimCount: Object.keys(claims).length,
      statusChecked: 'not-required',
      keyStorageAssurance: { assurance: 'none' },
    },
  };
}

function checkerAnswering(decision: 'valid' | 'rejected'): CredentialStatusChecker {
  return {
    resolveCredentialStatus: vi.fn(async () =>
      decision === 'valid'
        ? ({ decision: 'valid' } as const)
        : ({ decision: 'rejected', reason: 'revoked' } as const)
    ),
    assertCredentialNotRevoked: vi.fn(),
  } as unknown as CredentialStatusChecker;
}

describe('buildWalletAttributeProvenance', () => {
  it('records the validated issuer and the issuer-signed status reference verbatim', () => {
    expect(
      buildWalletAttributeProvenance(credentialFor({ email: 'a@b.c', status: STATUS }))
    ).toEqual({ issuer: ISSUER, issuer_key_resolution: 'issuer-metadata', status: STATUS });
  });

  it('records no status when the credential carried none', () => {
    expect(buildWalletAttributeProvenance(credentialFor({ email: 'a@b.c' }))).toEqual({
      issuer: ISSUER,
      issuer_key_resolution: 'issuer-metadata',
    });
  });

  it('refuses a credential whose issuer is not a branded ValidatedIssuer', () => {
    const forged = { ...credentialFor({}), issuer: { identifier: ISSUER } } as never;
    expect(() => buildWalletAttributeProvenance(forged)).toThrow();
  });
});

describe('readWalletAttributeProvenance', () => {
  it.each([
    ['null (a row written before provenance was recorded)', null],
    ['a string', 'https://issuer.example.com'],
    ['an object with no issuer', { issuer_key_resolution: 'x5c' }],
    ['an unknown key-resolution method', { issuer: ISSUER, issuer_key_resolution: 'jwks' }],
  ])('reads nothing from %s', (_label, raw) => {
    expect(readWalletAttributeProvenance(raw)).toBeUndefined();
  });
});

describe('isWalletAttributeIssuerTrusted', () => {
  const provenance = buildWalletAttributeProvenance(credentialFor({ status: STATUS }));

  it('is true while the realm still trusts the recorded issuer', () => {
    expect(isWalletAttributeIssuerTrusted(provenance, createStaticIssuerAllowlist([ISSUER]))).toBe(
      true
    );
  });

  it('is false once the issuer is no longer on the allowlist', () => {
    expect(
      isWalletAttributeIssuerTrusted(
        provenance,
        createStaticIssuerAllowlist(['https://other.example.com'])
      )
    ).toBe(false);
    expect(isWalletAttributeIssuerTrusted(provenance, DENY_ALL_TRUST_REGISTRY)).toBe(false);
  });

  it('is false for a row with no readable provenance, whatever the registry', () => {
    expect(isWalletAttributeIssuerTrusted(null, createStaticIssuerAllowlist([ISSUER]))).toBe(false);
    expect(
      isWalletAttributeIssuerTrusted(
        { issuer: 'not a url', issuer_key_resolution: 'x5c' },
        createStaticIssuerAllowlist([ISSUER])
      )
    ).toBe(false);
  });
});

describe('isWalletAttributeStatusValid', () => {
  it('asks the checker about the recorded status reference', async () => {
    const checker = checkerAnswering('valid');
    const provenance = buildWalletAttributeProvenance(credentialFor({ status: STATUS }));

    await expect(isWalletAttributeStatusValid(provenance, checker)).resolves.toBe(true);
    expect(checker.resolveCredentialStatus).toHaveBeenCalledWith(STATUS, {
      statusRequired: false,
    });
  });

  it('is false when the checker no longer reads VALID', async () => {
    const provenance = buildWalletAttributeProvenance(credentialFor({ status: STATUS }));
    await expect(
      isWalletAttributeStatusValid(provenance, checkerAnswering('rejected'))
    ).resolves.toBe(false);
  });

  it('has nothing to ask when the credential carried no status, or none is configured', async () => {
    const checker = checkerAnswering('rejected');
    await expect(
      isWalletAttributeStatusValid(buildWalletAttributeProvenance(credentialFor({})), checker)
    ).resolves.toBe(true);
    expect(checker.resolveCredentialStatus).not.toHaveBeenCalled();

    await expect(
      isWalletAttributeStatusValid(
        buildWalletAttributeProvenance(credentialFor({ status: STATUS })),
        undefined
      )
    ).resolves.toBe(true);
  });

  it('is false for a row with no readable provenance', async () => {
    await expect(isWalletAttributeStatusValid(null, checkerAnswering('valid'))).resolves.toBe(
      false
    );
  });
});
