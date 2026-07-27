import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { NO_KEY_STORAGE_ASSURANCE } from '../attestation/key-storage-assurance';
import type { CredentialFormat } from '../profiles/verifier-profile.types';
import { ValidatedIssuer } from '../trust/issuer-identity';
import type {
  CredentialFormatAdapter,
  CredentialFormatAdapterRegistry,
  CredentialRequestSpec,
  PresentedCredential,
} from './credential-format';
import {
  CREDENTIAL_FORMAT_ADAPTERS,
  resolveCredentialFormatAdapter,
  SD_JWT_VC_FORMAT,
} from './credential-format';
import { assertValidDcqlQuery, type DcqlCredentialQuery, type DcqlQuery } from './dcql';
import { parseVpToken } from './direct-post';
import { validatePresentations } from './presentation-validation';
import type { ValidatedCredential } from './validated-credential';

/**
 * The acceptance criterion of #234, asserted rather than described:
 *
 * > The format-adapter boundary is real: registering `mso_mdoc` later requires
 * > no change to intake/dispatch, only a new adapter.
 *
 * The proof is a HYPOTHETICAL `mso_mdoc` adapter — deliberately not the real
 * one, which needs ISO/IEC 18013-5 and a COSE/CBOR stack QAuth does not have —
 * placed into a registry alongside the shipped SD-JWT VC adapter. If the request
 * builder, the `direct_post` intake or the validation dispatcher needed to know
 * anything format-specific, this file could not compile or could not pass
 * without editing one of them.
 *
 * The real `mso_mdoc` adapter therefore lands as ONE new module plus ONE line in
 * `CREDENTIAL_FORMAT_ADAPTERS`. If a future change makes this test require more
 * than that, the boundary has regressed.
 */

const MSO_MDOC: CredentialFormat = 'mso_mdoc';

const MDOC_QUERY: DcqlCredentialQuery = {
  id: 'mdl',
  format: MSO_MDOC,
  meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
};

/**
 * A stand-in mdoc adapter.
 *
 * It satisfies {@link CredentialFormatAdapter} in full and nothing else: the
 * point is that IMPLEMENTING THE INTERFACE is sufficient to be registered, which
 * is exactly what "adding a format is a registration" has to mean.
 */
const hypotheticalMdocAdapter: CredentialFormatAdapter = {
  format: MSO_MDOC,

  buildCredentialQuery(spec: CredentialRequestSpec): DcqlCredentialQuery {
    return { id: spec.id, format: MSO_MDOC, meta: { doctype_value: spec.typeValues[0] } };
  },

  parsePresentation(queryId: string, value: unknown): PresentedCredential {
    if (typeof value !== 'string') throw new Error('mdoc Presentations are base64url strings');
    return { queryId, format: MSO_MDOC, presentation: value };
  },

  async validatePresentation(
    entry: PresentedCredential,
    query: DcqlCredentialQuery
  ): Promise<ValidatedCredential> {
    return {
      queryId: entry.queryId,
      format: MSO_MDOC,
      credentialType: String(query.meta?.['doctype_value']),
      issuer: ValidatedIssuer.fromValidatedPresentation({
        identifier: 'https://mdl-issuer.example.gov',
        keyResolution: 'x5c',
      }),
      claims: { family_name: 'Doe' },
      validity: {},
      assurance: {
        credentialType: String(query.meta?.['doctype_value']),
        issuerKeyResolution: 'x5c',
        issuerSignatureAlgorithm: 'ES256',
        keyBindingAlgorithm: 'ES256',
        disclosedClaimCount: 1,
        // An mdoc's device-binding and key-attestation model is COSE/MSO-shaped
        // and structurally different (#308), so this hypothetical adapter states
        // the only honest thing: it established nothing.
        keyStorageAssurance: NO_KEY_STORAGE_ASSURANCE,
        statusChecked: false,
      },
    };
  },
};

/** The registry a future release would ship, one entry richer. */
const REGISTRY_WITH_MDOC: CredentialFormatAdapterRegistry = Object.freeze({
  ...CREDENTIAL_FORMAT_ADAPTERS,
  [MSO_MDOC]: hypotheticalMdocAdapter,
});

describe('registering a second Credential Format', () => {
  it('is refused today: haip-1.0 permits mso_mdoc but QAuth ships no adapter', () => {
    expect(() => resolveCredentialFormatAdapter(MSO_MDOC, [MSO_MDOC])).toThrow(
      /No credential format adapter is implemented/
    );
  });

  it('needs no change to the request builder', () => {
    const query: DcqlQuery = {
      credentials: [
        resolveCredentialFormatAdapter(
          SD_JWT_VC_FORMAT,
          [SD_JWT_VC_FORMAT, MSO_MDOC],
          REGISTRY_WITH_MDOC
        ).buildCredentialQuery({
          id: 'pid',
          format: SD_JWT_VC_FORMAT,
          typeValues: ['https://credentials.example.com/pid'],
        }),
        resolveCredentialFormatAdapter(
          MSO_MDOC,
          [SD_JWT_VC_FORMAT, MSO_MDOC],
          REGISTRY_WITH_MDOC
        ).buildCredentialQuery({
          id: 'mdl',
          format: MSO_MDOC,
          typeValues: ['org.iso.18013.5.1.mDL'],
        }),
      ],
    };

    expect(() => assertValidDcqlQuery(query)).not.toThrow();
    expect(query.credentials.map((credential) => credential.format)).toEqual([
      'dc+sd-jwt',
      'mso_mdoc',
    ]);
  });

  it('needs no change to the direct_post intake', () => {
    const parsed = parseVpToken(
      JSON.stringify({ mdl: ['omdkb2NUeXBl'] }),
      { credentials: [MDOC_QUERY] },
      [MSO_MDOC],
      REGISTRY_WITH_MDOC
    );

    expect(parsed).toEqual([{ queryId: 'mdl', format: 'mso_mdoc', presentation: 'omdkb2NUeXBl' }]);
  });

  it('needs no change to the validation dispatcher', async () => {
    const parsed = parseVpToken(
      JSON.stringify({ mdl: ['omdkb2NUeXBl'] }),
      { credentials: [MDOC_QUERY] },
      [MSO_MDOC],
      REGISTRY_WITH_MDOC
    );

    const validated = await validatePresentations(
      parsed,
      { credentials: [MDOC_QUERY] },
      {
        clientId: 'https://auth.example.com',
        nonce: 'irrelevant-to-this-adapter',
        signatureAlgorithms: ['ES256'],
        permittedFormats: [MSO_MDOC],
        resolveIssuerKey: async () => undefined,
      },
      REGISTRY_WITH_MDOC
    );

    expect(validated).toHaveLength(1);
    expect(validated[0].format).toBe('mso_mdoc');
    expect(validated[0].credentialType).toBe('org.iso.18013.5.1.mDL');
    expect(ValidatedIssuer.isValidated(validated[0].issuer)).toBe(true);
  });

  it('still refuses a registered format the active profile forbids', async () => {
    // Registration is not permission. The profile check runs FIRST, so widening
    // the registry cannot widen what a deployment accepts.
    expect(() =>
      resolveCredentialFormatAdapter(MSO_MDOC, [SD_JWT_VC_FORMAT], REGISTRY_WITH_MDOC)
    ).toThrow(/not permitted by the active verifier profile/);
  });

  it('leaves intake and dispatch naming no Credential Format at all', () => {
    // The structural half of the claim: neither module can special-case a
    // format, because neither module mentions one.
    for (const module of ['direct-post.ts', 'presentation-validation.ts']) {
      const source = readFileSync(path.join(__dirname, module), 'utf8');
      const code = source.replace(/\/\*[\s\S]*?\*\//g, '');

      expect(code, `${module} names a Credential Format`).not.toContain('dc+sd-jwt');
      expect(code, `${module} names a Credential Format`).not.toContain('mso_mdoc');
      expect(code, `${module} reaches past the registry`).not.toContain('sdJwtVcAdapter');
    }
  });

  it('keeps the shipped registry frozen and SD-JWT VC only', () => {
    expect(Object.isFrozen(CREDENTIAL_FORMAT_ADAPTERS)).toBe(true);
    expect(Object.keys(CREDENTIAL_FORMAT_ADAPTERS)).toEqual(['dc+sd-jwt']);
  });
});
