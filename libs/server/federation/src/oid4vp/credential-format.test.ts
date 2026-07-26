import { describe, expect, it } from 'vitest';

import {
  MAX_PRESENTATION_LENGTH,
  resolveCredentialFormatAdapter,
  SD_JWT_VC_FORMAT,
  sdJwtVcAdapter,
} from './credential-format';

/** A structurally valid SD-JWT VC Presentation: JWT ~ disclosure ~ KB-JWT. */
const ISSUER_JWT = 'eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJwaWQifQ.c2ln';
const PRESENTATION = `${ISSUER_JWT}~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0~eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6Im4ifQ.a2I`;

describe('sdJwtVcAdapter.buildCredentialQuery', () => {
  it('renders vct_values into the DCQL meta object', () => {
    const built = sdJwtVcAdapter.buildCredentialQuery({
      id: 'pid',
      format: SD_JWT_VC_FORMAT,
      typeValues: ['https://credentials.example.com/pid'],
      claims: [{ path: ['given_name'] }],
    });

    expect(built).toEqual({
      id: 'pid',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['https://credentials.example.com/pid'] },
      claims: [{ path: ['given_name'] }],
    });
  });

  it("omits 'multiple' unless explicitly requested", () => {
    const single = sdJwtVcAdapter.buildCredentialQuery({
      id: 'pid',
      format: SD_JWT_VC_FORMAT,
      typeValues: ['vct'],
    });
    const many = sdJwtVcAdapter.buildCredentialQuery({
      id: 'pid',
      format: SD_JWT_VC_FORMAT,
      typeValues: ['vct'],
      multiple: true,
    });

    expect(single).not.toHaveProperty('multiple');
    expect(many.multiple).toBe(true);
  });

  it('refuses an unconstrained query (no vct values)', () => {
    expect(() =>
      sdJwtVcAdapter.buildCredentialQuery({ id: 'pid', format: SD_JWT_VC_FORMAT, typeValues: [] })
    ).toThrow(/no accepted 'vct' value/);
  });
});

describe('sdJwtVcAdapter.parsePresentation — structure only', () => {
  it('accepts a compact SD-JWT VC Presentation and returns it verbatim', () => {
    const parsed = sdJwtVcAdapter.parsePresentation('pid', PRESENTATION);

    expect(parsed).toEqual({
      queryId: 'pid',
      format: 'dc+sd-jwt',
      presentation: PRESENTATION,
    });
  });

  it('accepts an Issuer-signed JWT with no disclosures and no KB-JWT', () => {
    expect(() => sdJwtVcAdapter.parsePresentation('pid', `${ISSUER_JWT}~`)).not.toThrow();
    expect(() => sdJwtVcAdapter.parsePresentation('pid', ISSUER_JWT)).not.toThrow();
  });

  // The safety boundary: parsing is NOT validation. A garbage signature is
  // structurally fine here and must be rejected later, by #234.
  it('accepts a Presentation whose signature is obviously bogus (validation is #234)', () => {
    const forged = 'eyJhbGciOiJub25lIn0.eyJ2Y3QiOiJhbnl0aGluZyJ9.AAAA~';

    expect(() => sdJwtVcAdapter.parsePresentation('pid', forged)).not.toThrow();
  });

  it('returns no subject, claims or issuer', () => {
    const parsed = sdJwtVcAdapter.parsePresentation('pid', PRESENTATION);

    expect(Object.keys(parsed).sort()).toEqual(['format', 'presentation', 'queryId']);
  });

  it.each([
    ['a number', 1],
    ['null', null],
    ['an object', { jwt: ISSUER_JWT }],
    ['an array', [ISSUER_JWT]],
    ['an empty string', ''],
  ])('rejects %s', (_label, value) => {
    expect(() => sdJwtVcAdapter.parsePresentation('pid', value)).toThrow();
  });

  it('rejects a value whose first segment is not a compact JWS', () => {
    expect(() => sdJwtVcAdapter.parsePresentation('pid', 'not-a-jwt~disclosure')).toThrow(
      /compact-serialized Issuer-signed JWT/
    );
  });

  it('rejects an oversized Presentation before walking it', () => {
    const huge = `${ISSUER_JWT}~${'A'.repeat(MAX_PRESENTATION_LENGTH)}`;

    expect(() => sdJwtVcAdapter.parsePresentation('pid', huge)).toThrow(/exceeds/);
  });
});

describe('resolveCredentialFormatAdapter — fail-closed', () => {
  it('resolves the SD-JWT VC adapter when the profile permits it', () => {
    expect(resolveCredentialFormatAdapter('dc+sd-jwt', ['dc+sd-jwt'])).toBe(sdJwtVcAdapter);
  });

  it('refuses a format the profile forbids, even though QAuth ships an adapter', () => {
    expect(() => resolveCredentialFormatAdapter('dc+sd-jwt', ['mso_mdoc'])).toThrow(
      /not permitted by the active verifier profile/
    );
  });

  it('refuses mso_mdoc: permitted by haip-1.0, but no adapter ships yet', () => {
    expect(() => resolveCredentialFormatAdapter('mso_mdoc', ['mso_mdoc'])).toThrow(
      /No credential format adapter is implemented/
    );
  });

  it('refuses everything when the profile permits nothing', () => {
    expect(() => resolveCredentialFormatAdapter('dc+sd-jwt', [])).toThrow(/permitted: none/);
  });
});
