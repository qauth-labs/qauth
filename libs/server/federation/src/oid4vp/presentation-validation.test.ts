import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { VERIFIER_PROFILES } from '../profiles/verifier-profiles';
import { buildOid4vpAuthorizationRequest } from './authorization-request';
import { SD_JWT_VC_FORMAT, sdJwtVcAdapter } from './credential-format';
import type { DcqlQuery } from './dcql';
import { parseVpToken } from './direct-post';
import { isPresentationValidationRejection } from './presentation-rejection';
import { validatePresentations } from './presentation-validation';
import {
  fixtureValidationContext,
  generateFixtureKeys,
  issueSdJwtVc,
  presentSdJwtVc,
  TEST_CREDENTIAL_QUERY,
  TEST_VCT,
} from './sd-jwt-vc.fixture';

const NONCE = 'Xb1s2v9QpM4rT7kLwZ0nCyHgEfDaUiOj3lRqSt8mVzY';

const QUERY: DcqlQuery = { credentials: [TEST_CREDENTIAL_QUERY] };

describe('validatePresentations — dispatch', () => {
  it('validates a vp_token end to end, from intake to ValidatedCredential', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    // Exactly the path a `direct_post` route walks: #233 parses, #234 validates.
    const parsed = parseVpToken(
      JSON.stringify({ pid: [presentation] }),
      QUERY,
      VERIFIER_PROFILES['oid4vp-1.0-base'].credentialFormats
    );

    const validated = await validatePresentations(
      parsed,
      QUERY,
      fixtureValidationContext(issued, NONCE)
    );

    expect(validated).toHaveLength(1);
    expect(validated[0].queryId).toBe('pid');
    expect(validated[0].credentialType).toBe(TEST_VCT);
    expect(validated[0].claims).toMatchObject({ given_name: 'Alice' });
  });

  it('validates several Presentations for one query when the query allows it', async () => {
    const query: DcqlQuery = { credentials: [{ ...TEST_CREDENTIAL_QUERY, multiple: true }] };
    const issuerKeys = await generateFixtureKeys('ES256');
    const first = await issueSdJwtVc({ issuerKeys, selectiveClaims: { given_name: 'Alice' } });
    const second = await issueSdJwtVc({ issuerKeys, selectiveClaims: { given_name: 'Bob' } });

    const parsed = parseVpToken(
      JSON.stringify({
        pid: [
          await presentSdJwtVc(first, { nonce: NONCE }),
          await presentSdJwtVc(second, { nonce: NONCE }),
        ],
      }),
      query,
      ['dc+sd-jwt']
    );

    const validated = await validatePresentations(
      parsed,
      query,
      fixtureValidationContext(first, NONCE)
    );

    expect(validated.map((credential) => credential.claims['given_name'])).toEqual([
      'Alice',
      'Bob',
    ]);
  });

  it('rejects a Presentation whose Credential Query id was never requested', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const settled = await validatePresentations(
      [{ queryId: 'not-requested', format: SD_JWT_VC_FORMAT, presentation }],
      QUERY,
      fixtureValidationContext(issued, NONCE)
    ).then(
      () => null,
      (error: unknown) => error
    );

    expect(isPresentationValidationRejection(settled)).toBe(true);
    expect(isPresentationValidationRejection(settled) && settled.reason).toBe(
      'malformed-presentation'
    );
  });

  it('rejects a format the active profile does not permit', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const settled = await validatePresentations(
      [{ queryId: 'pid', format: SD_JWT_VC_FORMAT, presentation }],
      QUERY,
      fixtureValidationContext(issued, NONCE, { permittedFormats: [] })
    ).then(
      () => null,
      (error: unknown) => error
    );

    expect(isPresentationValidationRejection(settled) && settled.reason).toBe(
      'unsupported-credential-format'
    );
  });

  it('rejects a Presentation arriving in a different format than its query asked for', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const settled = await validatePresentations(
      [{ queryId: 'pid', format: 'mso_mdoc', presentation }],
      QUERY,
      fixtureValidationContext(issued, NONCE, { permittedFormats: ['dc+sd-jwt', 'mso_mdoc'] })
    ).then(
      () => null,
      (error: unknown) => error
    );

    expect(isPresentationValidationRejection(settled) && settled.reason).toBe(
      'unsupported-credential-format'
    );
  });

  it('aborts the batch on the first refusal rather than returning a partial result', async () => {
    const good = await issueSdJwtVc();
    const query: DcqlQuery = { credentials: [{ ...TEST_CREDENTIAL_QUERY, multiple: true }] };

    const settled = await validatePresentations(
      [
        { queryId: 'pid', format: SD_JWT_VC_FORMAT, presentation: 'garbage~kb' },
        {
          queryId: 'pid',
          format: SD_JWT_VC_FORMAT,
          presentation: await presentSdJwtVc(good, { nonce: NONCE }),
        },
      ],
      query,
      fixtureValidationContext(good, NONCE)
    ).then(
      (value) => value,
      (error: unknown) => error
    );

    expect(Array.isArray(settled)).toBe(false);
    expect(isPresentationValidationRejection(settled)).toBe(true);
  });

  it('selects by DCQL Credential Query id and by nothing else', () => {
    // OID4VP 1.0 §8.1: the `vp_token` object is keyed by Credential Query id.
    // A submission descriptor / `presentation_definition` path is superseded
    // (DIF Presentation Exchange, OID4VP Draft 22) and must never reappear —
    // two ways to decide which query a Presentation answers means the weaker
    // one becomes the attack.
    // Block comments stripped: the superseded path is NAMED in the module JSDoc
    // on purpose, so that a reader knows it was considered and refused.
    const source = readFileSync(path.join(__dirname, 'presentation-validation.ts'), 'utf8').replace(
      /\/\*[\s\S]*?\*\//g,
      ''
    );

    for (const forbidden of [
      'presentation_definition',
      'presentation_submission',
      'descriptor_map',
      'input_descriptor',
    ]) {
      expect(source).not.toContain(forbidden);
    }
  });
});

describe('validatePresentations — the request → response round trip', () => {
  it('binds the Presentation to the nonce the request was built with', async () => {
    const request = buildOid4vpAuthorizationRequest({
      profile: VERIFIER_PROFILES['oid4vp-1.0-base'],
      responseUri: 'https://auth.example.com/oid4vp/response',
      credentials: [{ id: 'pid', format: 'dc+sd-jwt', typeValues: [TEST_VCT] }],
      state: 'state-value',
      nonce: NONCE,
    });

    const issued = await issueSdJwtVc();
    const parsed = parseVpToken(
      JSON.stringify({ pid: [await presentSdJwtVc(issued, { nonce: request.nonce })] }),
      request.dcql_query,
      VERIFIER_PROFILES['oid4vp-1.0-base'].credentialFormats
    );

    const validated = await validatePresentations(
      parsed,
      request.dcql_query,
      fixtureValidationContext(issued, request.nonce)
    );

    expect(validated[0].claims).toMatchObject({ given_name: 'Alice' });
  });

  it("refuses a Presentation minted for a DIFFERENT request's nonce", async () => {
    const issued = await issueSdJwtVc();
    const replayed = await presentSdJwtVc(issued, { nonce: 'a-previous-request-nonce' });

    const parsed = parseVpToken(JSON.stringify({ pid: [replayed] }), QUERY, ['dc+sd-jwt']);

    const settled = await validatePresentations(
      parsed,
      QUERY,
      fixtureValidationContext(issued, NONCE)
    ).then(
      () => null,
      (error: unknown) => error
    );

    expect(isPresentationValidationRejection(settled) && settled.reason).toBe(
      'holder-binding-invalid'
    );
  });
});

describe('the SD-JWT VC adapter satisfies the whole boundary', () => {
  it('exposes query building, intake parsing and validation on one object', () => {
    expect(typeof sdJwtVcAdapter.buildCredentialQuery).toBe('function');
    expect(typeof sdJwtVcAdapter.parsePresentation).toBe('function');
    expect(typeof sdJwtVcAdapter.validatePresentation).toBe('function');
  });

  it('validates through the adapter exactly as through the module function', async () => {
    const issued = await issueSdJwtVc();
    const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

    const validated = await sdJwtVcAdapter.validatePresentation(
      { queryId: 'pid', format: SD_JWT_VC_FORMAT, presentation },
      TEST_CREDENTIAL_QUERY,
      fixtureValidationContext(issued, NONCE)
    );

    expect(validated.credentialType).toBe(TEST_VCT);
  });
});
