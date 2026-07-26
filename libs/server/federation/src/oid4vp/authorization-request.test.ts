import { describe, expect, it } from 'vitest';

import type { VerifierProfile } from '../profiles/verifier-profile.types';
import { VERIFIER_PROFILES } from '../profiles/verifier-profiles';
import {
  assertNoRedirectUriParameter,
  assertValidResponseUri,
  buildOid4vpAuthorizationRequest,
  DIRECT_POST_RESPONSE_MODE,
  encodeOid4vpRequestUri,
  OID4VP_RESPONSE_TYPE,
} from './authorization-request';
import type { CredentialRequestSpec } from './credential-format';

const BASE = VERIFIER_PROFILES['oid4vp-1.0-base'];
const HAIP = VERIFIER_PROFILES['haip-1.0'];

const RESPONSE_URI = 'https://auth.example.com/oid4vp/response';

const PID: CredentialRequestSpec = {
  id: 'pid',
  format: 'dc+sd-jwt',
  typeValues: ['https://credentials.example.com/identity_credential'],
  claims: [{ path: ['given_name'] }],
};

function build(overrides: Partial<Parameters<typeof buildOid4vpAuthorizationRequest>[0]> = {}) {
  return buildOid4vpAuthorizationRequest({
    profile: BASE,
    responseUri: RESPONSE_URI,
    credentials: [PID],
    state: 'state-value',
    nonce: 'nonce-value',
    ...overrides,
  });
}

describe('buildOid4vpAuthorizationRequest — oid4vp-1.0-base', () => {
  it('emits the OID4VP 1.0 request shape', () => {
    const request = build();

    expect(request.response_type).toBe(OID4VP_RESPONSE_TYPE);
    expect(request.response_type).toBe('vp_token');
    expect(request.response_mode).toBe(DIRECT_POST_RESPONSE_MODE);
    expect(request.response_uri).toBe(RESPONSE_URI);
    expect(request.nonce).toBe('nonce-value');
    expect(request.state).toBe('state-value');
    expect(request.dcql_query.credentials).toHaveLength(1);
    expect(request.client_metadata.vp_formats_supported).toHaveProperty('dc+sd-jwt');
  });

  it("carries a 'redirect_uri'-prefixed client_id equal to the response_uri (§5.9.3)", () => {
    expect(build().client_id).toBe(`redirect_uri:${RESPONSE_URI}`);
  });

  // OID4VP 1.0 §8.2 — the acceptance criterion this issue names explicitly.
  it('NEVER emits a redirect_uri parameter alongside response_uri (§8.2)', () => {
    const request = build();

    expect(Object.prototype.hasOwnProperty.call(request, 'redirect_uri')).toBe(false);
    expect(Object.keys(request)).not.toContain('redirect_uri');
    expect(request.response_uri).toBeDefined();
    expect(() => assertNoRedirectUriParameter(request)).not.toThrow();

    // The prefix inside client_id is the ONLY surviving occurrence of the
    // string, and it must not be mistaken for the forbidden parameter.
    expect(request.client_id.startsWith('redirect_uri:')).toBe(true);

    const encoded = encodeOid4vpRequestUri('openid4vp://', request);
    expect(new URL(encoded).searchParams.has('redirect_uri')).toBe(false);
    expect(new URL(encoded).searchParams.get('response_uri')).toBe(RESPONSE_URI);
  });

  it('refuses a request object that acquired a redirect_uri through an untyped path', () => {
    const smuggled = { ...build(), redirect_uri: 'https://evil.example.com/cb' };

    expect(() => assertNoRedirectUriParameter(smuggled)).toThrow(/MUST NOT carry a 'redirect_uri'/);
    expect(() =>
      encodeOid4vpRequestUri('openid4vp://', smuggled as ReturnType<typeof build>)
    ).toThrow(/MUST NOT carry a 'redirect_uri'/);
  });

  it('builds a DCQL query (never a presentation_definition)', () => {
    const request = build();

    expect(request).not.toHaveProperty('presentation_definition');
    expect(request.dcql_query.credentials[0]).toMatchObject({
      id: 'pid',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['https://credentials.example.com/identity_credential'] },
    });
  });

  it('serializes JSON-valued parameters as JSON strings in the wallet URI (§5)', () => {
    const request = build();
    const params = new URL(encodeOid4vpRequestUri('openid4vp://', request)).searchParams;

    expect(JSON.parse(params.get('dcql_query') ?? '')).toEqual(request.dcql_query);
    expect(JSON.parse(params.get('client_metadata') ?? '')).toEqual(request.client_metadata);
    expect(params.get('response_type')).toBe('vp_token');
    expect(params.get('response_mode')).toBe('direct_post');
  });

  it('appends to a wallet endpoint that already carries a query string', () => {
    const encoded = encodeOid4vpRequestUri('https://wallet.example.com/authorize?x=1', build());

    expect(encoded).toContain('?x=1&');
    expect(new URL(encoded).searchParams.get('x')).toBe('1');
  });

  it('includes client_name only when the deployment configured one', () => {
    expect(build().client_metadata.client_name).toBeUndefined();
    expect(build({ clientName: 'QAuth' }).client_metadata.client_name).toBe('QAuth');
  });
});

describe('buildOid4vpAuthorizationRequest — profile gating (fail-closed)', () => {
  it('refuses a profile that does not permit direct_post (haip-1.0 requires direct_post.jwt)', () => {
    expect(() => build({ profile: HAIP })).toThrow(
      /does not permit the 'direct_post' Response Mode/
    );
  });

  it('refuses a profile that requires response encryption', () => {
    const encryptedBase: VerifierProfile = { ...BASE, responseEncryption: 'required' };

    expect(() => build({ profile: encryptedBase })).toThrow(/no JWE stack/);
  });

  it('refuses a profile that requires signed requests, since this build cannot sign', () => {
    const signingRequired: VerifierProfile = { ...BASE, requestSigning: 'required' };

    expect(() => build({ profile: signingRequired })).toThrow(
      /requires signed Authorization Requests/
    );
  });

  it('refuses a credential format the profile does not permit', () => {
    expect(() =>
      build({
        credentials: [{ ...PID, format: 'mso_mdoc', typeValues: ['org.iso.18013.5.1.mDL'] }],
      })
    ).toThrow(/not permitted by the active verifier profile/);
  });

  it('refuses a format the profile permits but QAuth ships no adapter for', () => {
    const mdocBase: VerifierProfile = { ...BASE, credentialFormats: ['mso_mdoc'] };

    expect(() =>
      build({
        profile: mdocBase,
        credentials: [{ ...PID, format: 'mso_mdoc', typeValues: ['org.iso.18013.5.1.mDL'] }],
      })
    ).toThrow(/No credential format adapter is implemented/);
  });

  it('refuses an empty credential list', () => {
    expect(() => build({ credentials: [] })).toThrow(/at least one Credential/);
  });
});

describe('buildOid4vpAuthorizationRequest — Client Identifier Prefixes', () => {
  it('defaults to the profile-preferred prefix', () => {
    expect(BASE.verifierIdentity.presentedPrefixes[0].prefix).toBe('redirect_uri');
    expect(build().client_id.startsWith('redirect_uri:')).toBe(true);
  });

  it('refuses a prefix the profile does not present', () => {
    expect(() => build({ clientIdPrefix: 'x509_hash' })).toThrow(
      /does not present the 'x509_hash' Client Identifier Prefix/
    );
  });

  it('refuses x509_san_dns when no leaf certificate is provisioned (#299)', () => {
    expect(() => build({ clientIdPrefix: 'x509_san_dns' })).toThrow(/leaf-cert/);
  });

  // The DEFERRAL this issue records: even fully provisioned, the signed prefix
  // cannot be used until #298 lands ES256.
  it('refuses x509_san_dns even when provisioned, because signing needs #298', () => {
    expect(() =>
      build({
        clientIdPrefix: 'x509_san_dns',
        provisioned: { available: ['leaf-cert'] },
      })
    ).toThrow(/#298/);
  });

  it('never silently downgrades a signed prefix to the unsigned one', () => {
    let built: ReturnType<typeof build> | undefined;

    try {
      built = build({ clientIdPrefix: 'x509_san_dns', provisioned: { available: ['leaf-cert'] } });
    } catch {
      built = undefined;
    }

    expect(built).toBeUndefined();
  });
});

describe('assertValidResponseUri', () => {
  it('accepts an https URI', () => {
    expect(() => assertValidResponseUri(RESPONSE_URI)).not.toThrow();
  });

  it('accepts loopback http for local development', () => {
    expect(() => assertValidResponseUri('http://localhost:3000/oid4vp/response')).not.toThrow();
    expect(() => assertValidResponseUri('http://127.0.0.1:3000/oid4vp/response')).not.toThrow();
  });

  it('rejects plaintext http on a real host', () => {
    expect(() => assertValidResponseUri('http://auth.example.com/oid4vp/response')).toThrow(
      /must use https/
    );
  });

  it('rejects a relative URI', () => {
    expect(() => assertValidResponseUri('/oid4vp/response')).toThrow(/absolute URI/);
  });

  it('rejects a fragment', () => {
    expect(() => assertValidResponseUri('https://auth.example.com/cb#frag')).toThrow(/fragment/);
  });

  it('is enforced by the builder', () => {
    expect(() => build({ responseUri: 'http://auth.example.com/oid4vp/response' })).toThrow(
      /must use https/
    );
  });
});
