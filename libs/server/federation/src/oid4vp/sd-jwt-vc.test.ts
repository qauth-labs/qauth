import { describe, expect, it } from 'vitest';

import { ValidatedIssuer } from '../trust/issuer-identity';
import { SD_JWT_VC_FORMAT } from './credential-format';
import { createStaticIssuerKeyResolver } from './issuer-key-resolution';
import {
  isPresentationValidationRejection,
  type PresentationRejectionReason,
  type PresentationValidationRejection,
} from './presentation-rejection';
import {
  MAX_CLAIM_DEPTH,
  MAX_DISCLOSURES,
  SD_JWT_VC_TYP,
  validateSdJwtVcPresentation,
} from './sd-jwt-vc';
import {
  arrayDisclosure,
  digestDisclosure,
  encodeDisclosure,
  fixtureValidationContext,
  generateFixtureKeys,
  issueSdJwtVc,
  objectDisclosure,
  presentSdJwtVc,
  randomSalt,
  signCompactJws,
  TEST_CLIENT_ID,
  TEST_CREDENTIAL_QUERY,
  TEST_ISSUER,
  TEST_VCT,
} from './sd-jwt-vc.fixture';
import type { PresentationValidationContext } from './validated-credential';

const NONCE = 'RRUxJfoAg1x5aQdBnhL3vjqZ4wMDx3iQ0K7ZaB0R0jU';

/** Validate with the fixture's clean context unless the test says otherwise. */
async function validate(
  presentation: string,
  context: PresentationValidationContext,
  query = TEST_CREDENTIAL_QUERY
) {
  return validateSdJwtVcPresentation(presentation, query.id, query, context);
}

/**
 * Assert a refusal and return it, so a test can name the exact outcome.
 *
 * `.rejects.toThrow(/message/)` would be far weaker here: every rejection path
 * throws the same class, so matching on anything but {@link
 * PresentationValidationRejection.reason} lets a test pass because the WRONG
 * check fired first.
 */
async function rejectionOf(promise: Promise<unknown>): Promise<PresentationValidationRejection> {
  const settled = await promise.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error })
  );

  if (settled.ok) {
    expect.fail(
      `expected a rejection, but validation RESOLVED with ${JSON.stringify(settled.value)}`
    );
  }

  if (!isPresentationValidationRejection(settled.error)) {
    expect.fail(
      `expected a PresentationValidationRejection, got ${String(settled.error)}. An escaping non-domain error would surface as a 500 on the response endpoint, which is an oracle.`
    );
  }

  return settled.error;
}

/** Assert both the rejection and its distinct server-side reason. */
async function expectRejection(
  promise: Promise<unknown>,
  reason: PresentationRejectionReason
): Promise<PresentationValidationRejection> {
  const rejection = await rejectionOf(promise);
  expect(rejection.reason).toBe(reason);
  return rejection;
}

describe('validateSdJwtVcPresentation — the credential validates', () => {
  it('accepts a well-formed Presentation and returns the disclosed claims', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const validated = await validate(presentation, fixtureValidationContext(issued, NONCE));

    expect(validated.queryId).toBe('pid');
    expect(validated.format).toBe(SD_JWT_VC_FORMAT);
    expect(validated.credentialType).toBe(TEST_VCT);
    expect(validated.claims).toMatchObject({ given_name: 'Alice', family_name: 'Doe' });
  });

  it('surfaces the VALIDATED issuer identity for #236 without deciding trust', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const validated = await validate(presentation, fixtureValidationContext(issued, NONCE));

    // Nominal, not structural: this is the only thing #236's gate accepts, and a
    // hand-built object with the same fields would fail its brand check.
    expect(ValidatedIssuer.isValidated(validated.issuer)).toBe(true);
    expect(validated.issuer.identifier).toBe(TEST_ISSUER);
    expect(validated.issuer.keyResolution).toBe('issuer-metadata');
  });

  it('reports an assurance SIGNAL, not an assurance level', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const { assurance } = await validate(presentation, fixtureValidationContext(issued, NONCE));

    expect(assurance).toEqual({
      credentialType: TEST_VCT,
      issuerKeyResolution: 'issuer-metadata',
      issuerSignatureAlgorithm: 'ES256',
      keyBindingAlgorithm: 'ES256',
      disclosedClaimCount: 2,
      statusChecked: false,
    });
    // #237 derives the eIDAS LoA; #297 flips `statusChecked`. Neither happens here.
    expect(assurance).not.toHaveProperty('assuranceLevel');
  });

  it('reports the credential validity window', async () => {
    const now = Math.floor(Date.now() / 1000);
    const issued = await issueSdJwtVc({ iat: now - 10, nbf: now - 5, exp: now + 3600 });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const { validity } = await validate(presentation, fixtureValidationContext(issued, NONCE));

    expect(validity).toEqual({ issuedAt: now - 10, notBefore: now - 5, expiresAt: now + 3600 });
  });

  it('keeps undisclosed claims hidden while accepting the ones revealed', async () => {
    const issued = await issueSdJwtVc({
      selectiveClaims: { given_name: 'Alice', birthdate: '1990-01-01' },
    });
    // The holder reveals only the first Disclosure.
    const presentation = await presentSdJwtVc(issued, {
      nonce: NONCE,
      disclosures: [issued.disclosures[0]],
    });

    const validated = await validate(presentation, fixtureValidationContext(issued, NONCE));

    expect(validated.claims).toHaveProperty('given_name', 'Alice');
    expect(validated.claims).not.toHaveProperty('birthdate');
    expect(validated.assurance.disclosedClaimCount).toBe(1);
  });

  it('accepts a Presentation with no Disclosures at all', async () => {
    const issued = await issueSdJwtVc({
      selectiveClaims: {},
      plainClaims: { nationalities: ['DE'] },
    });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const validated = await validate(presentation, fixtureValidationContext(issued, NONCE));

    expect(validated.claims).toHaveProperty('nationalities', ['DE']);
  });

  it('strips the SD machinery, the holder key and the raw iss from the claims', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const validated = await validate(presentation, fixtureValidationContext(issued, NONCE));

    // `cnf` is linkability-sensitive (OID4VP §15.5–§15.6) and ADR-009 forbids
    // keying an account on it; `iss` must be read from the branded issuer.
    expect(validated.claims).not.toHaveProperty('cnf');
    expect(validated.claims).not.toHaveProperty('iss');
    expect(validated.claims).not.toHaveProperty('_sd');
    expect(validated.claims).not.toHaveProperty('_sd_alg');
    expect(JSON.stringify(validated.claims)).not.toContain('kty');
  });

  it('resolves nested and array-element Disclosures', async () => {
    const nested = objectDisclosure('locality', 'Berlin');
    const element = arrayDisclosure('DE');

    const issued = await issueSdJwtVc({
      selectiveClaims: {},
      extraDisclosures: [nested.encoded, element.encoded],
      payloadOverrides: {
        // Both digests live INSIDE the structure, so the top-level `_sd` the
        // fixture would otherwise emit is cleared — a digest may be claimed once.
        _sd: undefined,
        address: { country: 'DE', _sd: [nested.digest] },
        nationalities: [{ '...': element.digest }, 'FR'],
      },
    });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const validated = await validate(presentation, fixtureValidationContext(issued, NONCE));

    expect(validated.claims).toHaveProperty('address', { country: 'DE', locality: 'Berlin' });
    expect(validated.claims).toHaveProperty('nationalities', ['DE', 'FR']);
  });

  it('omits an array element whose Disclosure the holder withheld', async () => {
    const element = arrayDisclosure('DE');
    const issued = await issueSdJwtVc({
      selectiveClaims: {},
      extraDisclosures: [element.encoded],
      payloadOverrides: { _sd: undefined, nationalities: [{ '...': element.digest }, 'FR'] },
    });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE, disclosures: [] });

    const validated = await validate(presentation, fixtureValidationContext(issued, NONCE));

    expect(validated.claims).toHaveProperty('nationalities', ['FR']);
  });

  it.each(['sha-256', 'sha-384', 'sha-512'])('accepts _sd_alg %s', async (sdAlg) => {
    const issued = await issueSdJwtVc({ sdAlg });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const validated = await validate(presentation, fixtureValidationContext(issued, NONCE));

    expect(validated.claims).toHaveProperty('given_name', 'Alice');
  });

  it('defaults _sd_alg to sha-256 when the credential omits it', async () => {
    const issued = await issueSdJwtVc({ sdAlg: null });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const validated = await validate(presentation, fixtureValidationContext(issued, NONCE));

    expect(validated.claims).toHaveProperty('given_name', 'Alice');
  });

  it('accepts an EdDSA credential when the deployment permits EdDSA', async () => {
    const issued = await issueSdJwtVc({ algorithm: 'EdDSA', holderAlgorithm: 'EdDSA' });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE, algorithm: 'EdDSA' });

    const validated = await validate(presentation, fixtureValidationContext(issued, NONCE));

    expect(validated.assurance.issuerSignatureAlgorithm).toBe('EdDSA');
    expect(validated.assurance.keyBindingAlgorithm).toBe('EdDSA');
  });

  it('selects the issuer key by kid when the issuer publishes several', async () => {
    const issued = await issueSdJwtVc({ kid: 'issuer-key-2' });
    const rotatedOut = await generateFixtureKeys('ES256', 'issuer-key-1');
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const validated = await validate(
      presentation,
      fixtureValidationContext(issued, NONCE, {
        resolveIssuerKey: createStaticIssuerKeyResolver([
          { issuer: TEST_ISSUER, jwks: [rotatedOut.jwk, issued.issuerKeys.jwk] },
        ]),
      })
    );

    expect(validated.issuer.identifier).toBe(TEST_ISSUER);
  });
});

describe('validateSdJwtVcPresentation — issuer signature', () => {
  it('rejects a tampered signature', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });
    const [header, payload, signature] = issued.issuerSignedJwt.split('.');
    const forgedSignature = `${signature.slice(0, -2)}${signature.endsWith('AA') ? 'BB' : 'AA'}`;
    const forged = presentation.replace(
      issued.issuerSignedJwt,
      `${header}.${payload}.${forgedSignature}`
    );

    await expectRejection(
      validate(forged, fixtureValidationContext(issued, NONCE)),
      'issuer-signature-invalid'
    );
  });

  it('rejects a credential re-signed by an unrelated key', async () => {
    const issued = await issueSdJwtVc();
    const attacker = await generateFixtureKeys('ES256');
    const forgedJwt = await signCompactJws(
      {
        iss: TEST_ISSUER,
        vct: TEST_VCT,
        iat: Math.floor(Date.now() / 1000),
        cnf: { jwk: issued.holderKeys.jwk },
      },
      attacker.keyPair,
      { alg: 'ES256', typ: SD_JWT_VC_TYP }
    );
    const forged = await presentSdJwtVc(
      { ...issued, issuerSignedJwt: forgedJwt, disclosures: [] },
      { nonce: NONCE }
    );

    await expectRejection(
      validate(forged, fixtureValidationContext(issued, NONCE)),
      'issuer-signature-invalid'
    );
  });

  it('rejects an issuer whose key cannot be resolved', async () => {
    const issued = await issueSdJwtVc({ issuer: 'https://unknown-issuer.example.org' });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const context = fixtureValidationContext(issued, NONCE, {
      resolveIssuerKey: async () => undefined,
    });

    await expectRejection(validate(presentation, context), 'issuer-key-unresolvable');
  });

  it('CONTAINS a resolver that throws instead of letting it escape as a 500', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const context = fixtureValidationContext(issued, NONCE, {
      resolveIssuerKey: async () => {
        throw new Error('backend exploded');
      },
    });

    const rejection = await expectRejection(
      validate(presentation, context),
      'issuer-key-unresolvable'
    );
    expect(rejection.toClientError().message).toBe('Verifiable Presentation rejected');
  });

  it('rejects a resolver that confirms an unusable issuer identity', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const context = fixtureValidationContext(issued, NONCE, {
      // http:, not https: — `canonicalizeIssuerIdentifier` refuses it, so the
      // confirmed identity cannot be shown to be the credential's issuer and no
      // ValidatedIssuer can be asserted from it either.
      resolveIssuerKey: async () => ({
        key: issued.issuerKeys.keyPair.publicKey,
        identifier: 'http://issuer.example.com',
        keyResolution: 'issuer-metadata' as const,
      }),
    });

    await expectRejection(validate(presentation, context), 'issuer-signature-invalid');
  });

  it('rejects a resolver reporting a key-resolution method this library does not know', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const context = fixtureValidationContext(issued, NONCE, {
      resolveIssuerKey: async () => ({
        key: issued.issuerKeys.keyPair.publicKey,
        identifier: TEST_ISSUER,
        // Re-checked at run time even though the type forbids it: a resolver is
        // pluggable code and `as` casts are routine at JOSE boundaries.
        keyResolution: 'trust-me' as unknown as 'x5c',
      }),
    });

    await expectRejection(validate(presentation, context), 'issuer-key-unresolvable');
  });

  it('accepts an x5c-resolving backend with no change to the validator', async () => {
    // The HAIP §6.1.1 path: a resolver that validates the credential's `x5c`
    // chain to an operator-provisioned trust anchor. That backend does not ship
    // here (it needs anchors this library has no configuration for), but the
    // port carries the chain and the resolution method flows through to #236 —
    // which is what makes adding it a resolver change and nothing else.
    const chain = ['MIIBleafcertificate', 'MIIBintermediate'];
    const issued = await issueSdJwtVc({ headerOverrides: { x5c: chain } });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });
    const seen: (readonly string[] | undefined)[] = [];

    const validated = await validate(
      presentation,
      fixtureValidationContext(issued, NONCE, {
        resolveIssuerKey: async (request) => {
          seen.push(request.x5c);
          return {
            key: issued.issuerKeys.keyPair.publicKey,
            identifier: TEST_ISSUER,
            keyResolution: 'x5c',
          };
        },
      })
    );

    expect(seen).toEqual([chain]);
    expect(validated.issuer.keyResolution).toBe('x5c');
    expect(validated.assurance.issuerKeyResolution).toBe('x5c');
  });

  it('refuses a resolver that confirms a DIFFERENT issuer than the credential claims', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const context = fixtureValidationContext(issued, NONCE, {
      // The signature verifies — the key is genuinely this credential's — but
      // the resolver confirmed an unrelated identity. #236 would then decide
      // trust about an issuer that signed nothing here.
      resolveIssuerKey: async () => ({
        key: issued.issuerKeys.keyPair.publicKey,
        identifier: 'https://some-other-issuer.example.net',
        keyResolution: 'issuer-metadata' as const,
      }),
    });

    await expectRejection(validate(presentation, context), 'issuer-signature-invalid');
  });

  it('refuses an algorithm the deployment did not permit', async () => {
    const issued = await issueSdJwtVc({ algorithm: 'EdDSA', holderAlgorithm: 'EdDSA' });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE, algorithm: 'EdDSA' });

    const context = fixtureValidationContext(issued, NONCE, { signatureAlgorithms: ['ES256'] });

    await expectRejection(validate(presentation, context), 'malformed-presentation');
  });

  it('refuses every Presentation when no algorithm is permitted', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const context = fixtureValidationContext(issued, NONCE, { signatureAlgorithms: [] });

    await expectRejection(validate(presentation, context), 'malformed-presentation');
  });

  it("refuses an Issuer-signed JWT whose typ is not 'dc+sd-jwt'", async () => {
    const issued = await issueSdJwtVc({ typ: 'vc+sd-jwt' });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'malformed-presentation'
    );
  });

  it("refuses a credential carrying no 'iss'", async () => {
    const issued = await issueSdJwtVc({ payloadOverrides: { iss: undefined } });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'malformed-presentation'
    );
  });

  it("refuses a credential carrying no 'vct'", async () => {
    const issued = await issueSdJwtVc({ payloadOverrides: { vct: undefined } });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'malformed-presentation'
    );
  });

  it('refuses a credential type the Credential Query never asked for', async () => {
    const issued = await issueSdJwtVc({ vct: 'https://credentials.example.com/loyalty-card' });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'malformed-presentation'
    );
  });

  it('fails CLOSED when the Credential Query constrains no vct_values', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE), {
        id: 'pid',
        format: 'dc+sd-jwt',
      }),
      'malformed-presentation'
    );
  });
});

describe('validateSdJwtVcPresentation — validity window', () => {
  it('rejects an expired credential', async () => {
    const issued = await issueSdJwtVc({ exp: Math.floor(Date.now() / 1000) - 3600 });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'credential-expired'
    );
  });

  it('rejects a not-yet-valid credential DISTINCTLY from an expired one', async () => {
    const issued = await issueSdJwtVc({ nbf: Math.floor(Date.now() / 1000) + 3600 });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'credential-not-yet-valid'
    );
  });

  it('accepts a credential that expires within the clock tolerance', async () => {
    const issued = await issueSdJwtVc({ exp: Math.floor(Date.now() / 1000) - 5 });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const validated = await validate(presentation, fixtureValidationContext(issued, NONCE));

    expect(validated.credentialType).toBe(TEST_VCT);
  });

  it('evaluates the window against the injected clock', async () => {
    const now = Math.floor(Date.now() / 1000);
    const issued = await issueSdJwtVc({ exp: now + 60 });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(
        presentation,
        fixtureValidationContext(issued, NONCE, { now: new Date((now + 7200) * 1000) })
      ),
      'credential-expired'
    );
  });

  it("rejects a non-numeric 'exp'", async () => {
    const issued = await issueSdJwtVc({ payloadOverrides: { exp: 'soon' } });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'malformed-presentation'
    );
  });
});

describe('validateSdJwtVcPresentation — selective disclosure digests', () => {
  it('rejects a Disclosure the issuer never signed a digest for', async () => {
    const issued = await issueSdJwtVc();
    const injected = objectDisclosure('is_over_18', true);
    const presentation = await presentSdJwtVc(issued, {
      nonce: NONCE,
      disclosures: [...issued.disclosures, injected.encoded],
    });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'disclosure-digest-mismatch'
    );
  });

  it('rejects an ALTERED Disclosure', async () => {
    const issued = await issueSdJwtVc({ selectiveClaims: { given_name: 'Alice' } });
    const altered = encodeDisclosure([randomSalt(), 'given_name', 'Mallory']);
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE, disclosures: [altered] });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'disclosure-digest-mismatch'
    );
  });

  it('rejects the same Disclosure presented twice', async () => {
    const issued = await issueSdJwtVc({ selectiveClaims: { given_name: 'Alice' } });
    const presentation = await presentSdJwtVc(issued, {
      nonce: NONCE,
      disclosures: [issued.disclosures[0], issued.disclosures[0]],
    });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'disclosure-digest-mismatch'
    );
  });

  it("rejects a digest repeated inside one '_sd' array", async () => {
    const disclosure = objectDisclosure('given_name', 'Alice');
    const issued = await issueSdJwtVc({
      selectiveClaims: {},
      extraDisclosures: [disclosure.encoded],
      payloadOverrides: { _sd: [disclosure.digest, disclosure.digest] },
    });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'disclosure-digest-mismatch'
    );
  });

  it('rejects one digest claimed in two different places', async () => {
    const disclosure = objectDisclosure('given_name', 'Alice');
    const issued = await issueSdJwtVc({
      selectiveClaims: {},
      extraDisclosures: [disclosure.encoded],
      payloadOverrides: {
        _sd: [disclosure.digest],
        address: { _sd: [disclosure.digest] },
      },
    });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'disclosure-digest-mismatch'
    );
  });

  it('rejects an array-element Disclosure presented against an object digest', async () => {
    const element = arrayDisclosure('Alice');
    const issued = await issueSdJwtVc({
      selectiveClaims: {},
      extraDisclosures: [element.encoded],
      payloadOverrides: { _sd: [element.digest] },
    });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'disclosure-digest-mismatch'
    );
  });

  it('rejects an object-property Disclosure presented as an array element', async () => {
    const property = objectDisclosure('given_name', 'Alice');
    const issued = await issueSdJwtVc({
      selectiveClaims: {},
      extraDisclosures: [property.encoded],
      payloadOverrides: { nationalities: [{ '...': property.digest }] },
    });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'disclosure-digest-mismatch'
    );
  });

  it('rejects a Disclosure that would overwrite an already-present claim', async () => {
    const disclosure = objectDisclosure('given_name', 'Mallory');
    const issued = await issueSdJwtVc({
      selectiveClaims: {},
      plainClaims: { given_name: 'Alice' },
      extraDisclosures: [disclosure.encoded],
      payloadOverrides: { _sd: [disclosure.digest] },
    });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'disclosure-digest-mismatch'
    );
  });

  it.each(['_sd', '...'])("rejects a Disclosure of the reserved claim '%s'", async (name) => {
    const disclosure = objectDisclosure(name, ['forged']);
    const issued = await issueSdJwtVc({
      selectiveClaims: {},
      extraDisclosures: [disclosure.encoded],
      payloadOverrides: { _sd: [disclosure.digest] },
    });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'disclosure-digest-mismatch'
    );
  });

  it('rejects an unsupported _sd_alg', async () => {
    const issued = await issueSdJwtVc({ payloadOverrides: { _sd_alg: 'sha-1' } });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'malformed-presentation'
    );
  });

  it("rejects a non-array '_sd'", async () => {
    const issued = await issueSdJwtVc({ selectiveClaims: {}, payloadOverrides: { _sd: 'nope' } });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'malformed-presentation'
    );
  });

  it('rejects a Disclosure that is not a 2- or 3-element array', async () => {
    const malformed = encodeDisclosure([randomSalt()]);
    const issued = await issueSdJwtVc({
      selectiveClaims: {},
      extraDisclosures: [malformed],
      payloadOverrides: { _sd: [digestDisclosure(malformed)] },
    });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'malformed-presentation'
    );
  });

  it('rejects a Disclosure with a non-string salt', async () => {
    const malformed = encodeDisclosure([1, 'given_name', 'Alice']);
    const issued = await issueSdJwtVc({
      selectiveClaims: {},
      extraDisclosures: [malformed],
      payloadOverrides: { _sd: [digestDisclosure(malformed)] },
    });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'malformed-presentation'
    );
  });

  it('rejects more Disclosures than the DoS bound allows', async () => {
    const issued = await issueSdJwtVc();
    const filler = Array.from({ length: MAX_DISCLOSURES + 1 }, (_, index) =>
      encodeDisclosure([randomSalt(), `claim_${index}`, index])
    );
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE, disclosures: filler });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'malformed-presentation'
    );
  });

  it('rejects a claim structure nested past the depth bound', async () => {
    let deep: Record<string, unknown> = { bottom: true };
    for (let level = 0; level <= MAX_CLAIM_DEPTH + 1; level += 1) {
      deep = { nested: deep };
    }

    const issued = await issueSdJwtVc({ selectiveClaims: {}, payloadOverrides: { deep } });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'malformed-presentation'
    );
  });
});

describe('validateSdJwtVcPresentation — holder binding', () => {
  it('rejects a Presentation with no Key Binding JWT', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE, omitKeyBinding: true });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });

  it("rejects a Key Binding JWT carrying another request's nonce", async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: 'a-different-request-nonce' });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });

  it('rejects a Presentation made for a different Verifier', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, {
      nonce: NONCE,
      audience: 'https://another-verifier.example.net',
    });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });

  it('rejects a Key Binding JWT signed by a key the credential is not bound to', async () => {
    const issued = await issueSdJwtVc();
    const attacker = await generateFixtureKeys('ES256');
    const presentation = await presentSdJwtVc(issued, {
      nonce: NONCE,
      signingKeys: attacker.keyPair,
    });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });

  it('rejects a mismatched sd_hash', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE, sdHash: 'not-the-digest' });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });

  it('rejects Disclosures appended AFTER the sd_hash was computed', async () => {
    const issued = await issueSdJwtVc();
    const injected = objectDisclosure('is_over_18', true);
    const presentation = await presentSdJwtVc(issued, {
      nonce: NONCE,
      appendAfterBinding: [injected.encoded],
    });

    // The digest check fires first here — either outcome is a refusal, and both
    // are non-enumerating. What matters is that the mutation cannot pass.
    const rejection = await rejectionOf(
      validate(presentation, fixtureValidationContext(issued, NONCE))
    );
    expect(['disclosure-digest-mismatch', 'holder-binding-invalid']).toContain(rejection.reason);
  });

  it("rejects a Key Binding JWT whose typ is not 'kb+jwt'", async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE, typ: 'JWT' });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });

  it('rejects a stale Key Binding JWT', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, {
      nonce: NONCE,
      issuedAt: Math.floor(Date.now() / 1000) - 7200,
    });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });

  it('rejects a Key Binding JWT issued in the future', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, {
      nonce: NONCE,
      issuedAt: Math.floor(Date.now() / 1000) + 7200,
    });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });

  it("rejects a Key Binding JWT with no numeric 'iat'", async () => {
    const issued = await issueSdJwtVc();
    const prefix = `${issued.issuerSignedJwt}~${issued.disclosures.join('~')}~`;
    const sdHash = digestDisclosure(prefix);
    const keyBindingJwt = await signCompactJws(
      { aud: TEST_CLIENT_ID, nonce: NONCE, sd_hash: sdHash },
      issued.holderKeys.keyPair,
      { alg: 'ES256', typ: 'kb+jwt' }
    );

    await expectRejection(
      validate(`${prefix}${keyBindingJwt}`, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });

  it("rejects a credential carrying no 'cnf'", async () => {
    const issued = await issueSdJwtVc({ cnf: null });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });

  it("rejects a 'cnf' that carries no jwk", async () => {
    const issued = await issueSdJwtVc({ cnf: { kid: 'some-holder-key' } });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });

  it('rejects a confirmation key that cannot carry the KB-JWT algorithm', async () => {
    const eddsaHolder = await generateFixtureKeys('EdDSA');
    const issued = await issueSdJwtVc({ cnf: { jwk: eddsaHolder.jwk } });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE, algorithm: 'ES256' });

    await expectRejection(
      validate(presentation, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });

  it('rejects a Key Binding JWT that is not a compact JWS', async () => {
    const issued = await issueSdJwtVc();
    const prefix = `${issued.issuerSignedJwt}~${issued.disclosures.join('~')}~`;

    await expectRejection(
      validate(`${prefix}not-a-jws`, fixtureValidationContext(issued, NONCE)),
      'holder-binding-invalid'
    );
  });
});

describe('validateSdJwtVcPresentation — structural refusals', () => {
  it.each([
    ['no tilde separator at all', 'eyJhbGciOiJFUzI1NiJ9.e30.sig'],
    ['an empty Disclosure segment', 'eyJhbGciOiJFUzI1NiJ9.e30.sig~~kb'],
    ['a non-JWS Issuer-signed segment', 'not-a-jws~kb'],
    ['a base64url header that is not JSON', 'bm90LWpzb24.e30.sig~kb'],
  ])('rejects %s', async (_label, presentation) => {
    const issued = await issueSdJwtVc();

    const rejection = await rejectionOf(
      validate(presentation, fixtureValidationContext(issued, NONCE))
    );

    expect(['malformed-presentation', 'holder-binding-invalid']).toContain(rejection.reason);
  });

  it('renders the SAME client error for every distinct reason', async () => {
    const issued = await issueSdJwtVc({ exp: Math.floor(Date.now() / 1000) - 3600 });
    const expiredPresentation = await presentSdJwtVc(issued, { nonce: NONCE });
    const replayed = await presentSdJwtVc(await issueSdJwtVc(), { nonce: 'stale-nonce' });

    const expired = await rejectionOf(
      validate(expiredPresentation, fixtureValidationContext(issued, NONCE))
    );
    const unbound = await rejectionOf(validate(replayed, fixtureValidationContext(issued, NONCE)));

    expect(expired.reason).not.toBe(unbound.reason);
    // Distinct server-side, INDISTINGUISHABLE on the wire — the #236 lane rule.
    expect(expired.toClientError().message).toBe(unbound.toClientError().message);
    expect(expired.toClientError().constructor).toBe(unbound.toClientError().constructor);
  });

  it('never leaks the server-side reason into the client error', async () => {
    const issued = await issueSdJwtVc({ exp: Math.floor(Date.now() / 1000) - 3600 });
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const rejection = await rejectionOf(
      validate(presentation, fixtureValidationContext(issued, NONCE))
    );
    const clientError = rejection.toClientError();

    expect(JSON.stringify(clientError.message)).not.toContain('expired');
    expect(clientError.message).not.toContain(TEST_ISSUER);
    expect(clientError.message).not.toContain('exp');
  });
});

describe('SD_JWT_VC_TYP', () => {
  it('equals the Credential Format identifier', () => {
    // The media type and the OID4VP format identifier are the same string;
    // `sd-jwt-vc.ts` declares its own constant to avoid depending on the
    // registry that dispatches to it, so the two are pinned equal here.
    expect(SD_JWT_VC_TYP).toBe(SD_JWT_VC_FORMAT);
  });
});
