import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import type { CredentialFormat } from '../profiles/verifier-profile.types';
import { extractWalletAttributes, WALLET_SOURCE } from '../providers/wallet.provider';
import {
  CREDENTIAL_CLAIM_ADAPTERS,
  resolveCredentialClaimAdapter,
} from './credential-claim-adapters';
import type {
  CredentialClaimAdapter,
  CredentialClaimAdapterRegistry,
  CredentialClaimSet,
  NormalizedCredentialClaim,
} from './credential-claims.types';
import { SD_JWT_VC_ATTRIBUTE_CLAIMS } from './sd-jwt-vc-claims';

/**
 * The acceptance criterion of #235, asserted rather than described:
 *
 * > `mso_mdoc` is not implemented, but the format-adapter seam exists so it can
 * > be added without modifying the SD-JWT path.
 *
 * The proof is a HYPOTHETICAL mdoc claim adapter — deliberately not the real
 * one, which needs ISO/IEC 18013-5 and a COSE/CBOR stack QAuth does not have —
 * registered alongside the shipped SD-JWT VC adapter and run through the whole
 * mapping path. If `extractWalletAttributes`, the `UserAttribute` assembly or
 * the adapter contract knew anything format-specific, this file could not pass
 * without editing one of them.
 *
 * The mdoc adapter therefore lands as ONE new module plus ONE line in
 * `CREDENTIAL_CLAIM_ADAPTERS`. If a future change makes this test require more
 * than that, the boundary has regressed — do not soften it to make it pass.
 */

const MSO_MDOC: CredentialFormat = 'mso_mdoc';

/**
 * A stand-in mdoc claim adapter.
 *
 * It maps the ISO/EUDI data-identifier vocabulary — `birth_date`, singular
 * `nationality` — onto the SAME canonical attribute keys the SD-JWT VC adapter
 * produces from `birthdate`. That divergence is not decoration: it is the reason
 * the mapping has to be per-format (ADR-009 Finding 1 records both spellings for
 * the same PID), and it is what makes a shared code path wrong rather than
 * merely inelegant.
 */
const hypotheticalMdocClaimAdapter: CredentialClaimAdapter = {
  format: MSO_MDOC,

  normalizeClaims(claimSet: CredentialClaimSet): readonly NormalizedCredentialClaim[] {
    const mdocVocabulary: Readonly<Record<string, string>> = {
      birth_date: 'birthdate',
      family_name: 'family_name',
      nationality: 'nationality',
    };

    const normalized: NormalizedCredentialClaim[] = [];

    for (const [element, attrKey] of Object.entries(mdocVocabulary)) {
      const value = claimSet.claims[element];
      if (typeof value === 'string' && value.length > 0)
        normalized.push({ attrKey, attrValue: value });
    }

    return normalized;
  },
};

/** The registry a future release would ship, one entry richer. */
const REGISTRY_WITH_MDOC: CredentialClaimAdapterRegistry = Object.freeze({
  ...CREDENTIAL_CLAIM_ADAPTERS,
  [MSO_MDOC]: hypotheticalMdocClaimAdapter,
});

describe('registering a second Credential Format for claim normalization (#235)', () => {
  it('is refused today: haip-1.0 permits mso_mdoc but QAuth normalizes no mdoc claims', () => {
    expect(() => resolveCredentialClaimAdapter(MSO_MDOC)).toThrow(
      /No credential claim adapter is implemented/
    );
  });

  it('refuses rather than silently returning no attributes', () => {
    // An empty list would be indistinguishable from a credential that disclosed
    // nothing — silent claim loss, which is #232's stated reason for making the
    // provider fail loudly in the first place.
    expect(() =>
      extractWalletAttributes({
        format: MSO_MDOC,
        credentialType: 'org.iso.18013.5.1.mDL',
        claims: { birth_date: '1990-01-01' },
      })
    ).toThrow(/No credential claim adapter is implemented/);
  });

  it('needs no change to the attribute assembly once registered', () => {
    const attributes = extractWalletAttributes(
      {
        format: MSO_MDOC,
        credentialType: 'org.iso.18013.5.1.mDL',
        claims: { birth_date: '1990-01-01', nationality: 'DE' },
        validity: { expiresAt: 4_102_444_800 },
      },
      REGISTRY_WITH_MDOC
    );

    expect(attributes).toEqual([
      {
        source: WALLET_SOURCE,
        attrKey: 'birthdate',
        attrValue: '1990-01-01',
        verified: true,
        expiresAt: new Date(4_102_444_800 * 1000),
      },
      {
        source: WALLET_SOURCE,
        attrKey: 'nationality',
        attrValue: 'DE',
        verified: true,
        expiresAt: new Date(4_102_444_800 * 1000),
      },
    ]);
  });

  it('leaves the SD-JWT VC path completely untouched', () => {
    // Same canonical keys out of a different vocabulary in. Registering mdoc
    // must not make the SD-JWT adapter start accepting `birth_date`.
    const sdJwt = extractWalletAttributes(
      {
        format: 'dc+sd-jwt',
        credentialType: 'https://credentials.example.com/pid',
        claims: { birthdate: '1990-01-01', birth_date: '2000-02-02' },
      },
      REGISTRY_WITH_MDOC
    );

    expect(sdJwt.map((attr) => [attr.attrKey, attr.attrValue])).toEqual([
      ['birthdate', '1990-01-01'],
    ]);
  });

  it('keeps the shipped registry frozen and SD-JWT VC only', () => {
    expect(Object.isFrozen(CREDENTIAL_CLAIM_ADAPTERS)).toBe(true);
    expect(Object.keys(CREDENTIAL_CLAIM_ADAPTERS)).toEqual(['dc+sd-jwt']);
    expect(resolveCredentialClaimAdapter('dc+sd-jwt').format).toBe('dc+sd-jwt');
  });

  it('leaves the mapping consumer naming no Credential Format at all', () => {
    // The structural half of the claim: the module that turns normalized claims
    // into `user_attributes` rows cannot special-case a format, because it does
    // not mention one. Only the adapter itself and the registry table may.
    for (const module of [
      path.join(__dirname, 'credential-claims.types.ts'),
      path.join(__dirname, '..', 'providers', 'wallet.provider.ts'),
    ]) {
      const code = readFileSync(module, 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/^\s*\/\/.*$/gm, '');

      expect(code, `${module} names a Credential Format`).not.toContain('dc+sd-jwt');
      expect(code, `${module} names a Credential Format`).not.toContain('mso_mdoc');
      expect(code, `${module} reaches past the registry`).not.toContain('sdJwtVcClaimAdapter');
    }
  });

  it('proves the two vocabularies actually differ (or this whole seam is ceremony)', () => {
    // If SD-JWT VC and mdoc used one vocabulary, one adapter would do and every
    // argument above would be wrong. ADR-009 Finding 1 says they do not.
    expect(Object.keys(SD_JWT_VC_ATTRIBUTE_CLAIMS)).toContain('birthdate');
    expect(Object.keys(SD_JWT_VC_ATTRIBUTE_CLAIMS)).not.toContain('birth_date');
  });
});
