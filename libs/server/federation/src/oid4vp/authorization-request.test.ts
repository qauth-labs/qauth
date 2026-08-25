import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type { VerifierProfile } from '../profiles/verifier-profile.types';
import { VERIFIER_PROFILES } from '../profiles/verifier-profiles';
import { createTestCertificate } from '../status/test/x509-fixtures';
import {
  createVerifierSigningMaterial,
  verifierMaterialProvisionedBy,
  type VerifierSigningMaterial,
} from '../x509/verifier-signing-material';
import {
  assertNoRedirectUriParameter,
  assertValidResponseUri,
  buildOid4vpAuthorizationRequest,
  DIRECT_POST_RESPONSE_MODE,
  encodeOid4vpRequestUri,
  OID4VP_RESPONSE_TYPE,
  QUERY_PARAMETER_DELIVERY,
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

    expect(() => build({ profile: encryptedBase })).toThrow(/no wired JWE path/);
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

  // #377 builds ONE signed verifier identity, not two: HAIP §5 mandates
  // `x509_hash` and nothing else, so the other signed prefix is refused
  // explicitly rather than silently downgraded. The refusal no longer blames
  // #298 — ES256 exists now, and pointing at a landed issue would send an
  // operator looking for a crypto gap that is not there.
  it('refuses x509_san_dns even when provisioned, because QAuth implements only x509_hash', () => {
    expect(() =>
      build({
        clientIdPrefix: 'x509_san_dns',
        provisioned: { available: ['leaf-cert'] },
      })
    ).toThrow(/does not implement/);
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

/**
 * The SIGNED path (issue #377, Phase B).
 *
 * ## Why the profile below is a HAIP posture rather than `haip-1.0` itself
 *
 * `VERIFIER_PROFILES['haip-1.0']` also declares `direct_post.jwt` and
 * `responseEncryption: 'required'`, and the builder refuses BOTH — correctly:
 * they are Phase C of #377, which lands the encrypted response mode, the
 * published encryption key and the decrypting intake together. Relaxing exactly
 * those two members and nothing else is what isolates the signing half; every
 * other mandate — `clientIdPrefixes: ['x509_hash']`, `requestSigning:
 * 'required'`, `signingAlgs: ['ES256']` — is the shipped table's own.
 */
const HAIP_SIGNING_POSTURE: VerifierProfile = {
  ...HAIP,
  responseModes: ['direct_post'],
  responseEncryption: 'permitted',
};

/** anchor → intermediate → leaf, and the material a boot would have validated. */
function buildSigningMaterial(): {
  readonly material: VerifierSigningMaterial;
  readonly leafDer: Buffer;
  readonly anchorX5c: string;
  readonly intermediateX5c: string;
} {
  const anchor = createTestCertificate({ subject: 'anchor', ca: true });
  const intermediate = createTestCertificate({ subject: 'issuing-ca', issuer: anchor, ca: true });
  const leaf = createTestCertificate({
    subject: 'verifier.example',
    issuer: intermediate,
    keyUsage: ['digitalSignature'],
  });

  return {
    leafDer: leaf.der,
    anchorX5c: anchor.x5c,
    intermediateX5c: intermediate.x5c,
    material: createVerifierSigningMaterial({
      privateKeyPem: leaf.keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      certificateChainPems: [leaf.pem, intermediate.pem],
      trustAnchorPems: [anchor.pem],
    }),
  };
}

function buildSigned(
  overrides: Partial<Parameters<typeof buildOid4vpAuthorizationRequest>[0]> = {}
) {
  const { material } = buildSigningMaterial();

  return buildOid4vpAuthorizationRequest({
    profile: HAIP_SIGNING_POSTURE,
    responseUri: RESPONSE_URI,
    credentials: [PID],
    state: 'state-value',
    nonce: 'nonce-value',
    provisioned: verifierMaterialProvisionedBy(material),
    signingMaterial: material,
    ...overrides,
  });
}

describe('buildOid4vpAuthorizationRequest — the x509_hash prefix (#377)', () => {
  it('presents x509_hash as the profile-preferred prefix', () => {
    expect(HAIP.verifierIdentity.presentedPrefixes[0].prefix).toBe('x509_hash');
    expect(buildSigned().client_id.startsWith('x509_hash:')).toBe(true);
  });

  it("renders the base64url SHA-256 of the deployment's own leaf certificate", () => {
    const { material, leafDer } = buildSigningMaterial();
    const request = buildSigned({
      provisioned: verifierMaterialProvisionedBy(material),
      signingMaterial: material,
    });

    expect(request.client_id).toBe(
      `x509_hash:${createHash('sha256').update(leafDer).digest('base64url')}`
    );
  });

  it('does NOT fall back to the response_uri identifier', () => {
    // The downgrade #299 forbids: a request that named a weaker verifier
    // identity than the profile demands.
    expect(buildSigned().client_id).not.toContain(RESPONSE_URI);
  });

  it('refuses the signed prefix when no signing material is threaded through', () => {
    expect(() =>
      buildOid4vpAuthorizationRequest({
        profile: HAIP_SIGNING_POSTURE,
        responseUri: RESPONSE_URI,
        credentials: [PID],
        state: 'state-value',
        nonce: 'nonce-value',
        provisioned: { available: ['non-self-signed-chain'] },
      })
    ).toThrow(/no verifier signing material was passed to the builder/);
  });

  it('refuses the signed prefix when the chain is not provisioned at all', () => {
    const { material } = buildSigningMaterial();

    expect(() =>
      buildOid4vpAuthorizationRequest({
        profile: HAIP_SIGNING_POSTURE,
        responseUri: RESPONSE_URI,
        credentials: [PID],
        state: 'state-value',
        nonce: 'nonce-value',
        signingMaterial: material,
      })
    ).toThrow(/non-self-signed-chain/);
  });

  it('refuses a profile that FORBIDS signing from presenting x509_hash', () => {
    const { material } = buildSigningMaterial();
    const forbidden: VerifierProfile = { ...HAIP_SIGNING_POSTURE, requestSigning: 'forbidden' };

    expect(() =>
      buildOid4vpAuthorizationRequest({
        profile: forbidden,
        responseUri: RESPONSE_URI,
        credentials: [PID],
        state: 'state-value',
        nonce: 'nonce-value',
        provisioned: verifierMaterialProvisionedBy(material),
        signingMaterial: material,
      })
    ).toThrow(/forbids request signing/);
  });

  it('refuses an unsigned request under a profile that REQUIRES signing', () => {
    // The `redirect_uri` prefix can never be signed (§5.9.3), so a profile that
    // both permits it and requires signing is a contradiction the posture check
    // catches rather than one the builder resolves.
    const contradictory: VerifierProfile = { ...BASE, requestSigning: 'required' };

    expect(() => build({ profile: contradictory })).toThrow(
      /requires signed Authorization Requests/
    );
  });

  it('still refuses haip-1.0 itself, on the Phase C response-mode count', () => {
    // The control for HAIP_SIGNING_POSTURE: the shipped table entry is NOT
    // buildable yet, and this asserts it fails on the count Phase C owns rather
    // than on anything #377 Phase B was supposed to clear.
    const { material } = buildSigningMaterial();

    expect(() =>
      buildOid4vpAuthorizationRequest({
        profile: HAIP,
        responseUri: RESPONSE_URI,
        credentials: [PID],
        state: 'state-value',
        nonce: 'nonce-value',
        provisioned: verifierMaterialProvisionedBy(material),
        signingMaterial: material,
      })
    ).toThrow(/does not permit the 'direct_post' Response Mode/);
  });

  it('leaves the unsigned base profile bit-for-bit unchanged', () => {
    // Provisioning verifier material must not change what the base profile
    // emits: its preferred prefix needs no certificate and its requests stay
    // unsigned.
    const { material } = buildSigningMaterial();

    expect(
      build({ provisioned: verifierMaterialProvisionedBy(material), signingMaterial: material })
    ).toEqual(build());
  });
});

describe('verifierMaterialProvisionedBy (#377)', () => {
  it('declares a non-self-signed chain for real material', () => {
    expect(verifierMaterialProvisionedBy(buildSigningMaterial().material).available).toEqual([
      'non-self-signed-chain',
    ]);
  });

  it('declares NOTHING for an unprovisioned deployment', () => {
    expect(verifierMaterialProvisionedBy(undefined).available).toEqual([]);
  });

  it('never declares leaf-cert, which x509_san_dns would need a SAN match for', () => {
    expect(verifierMaterialProvisionedBy(buildSigningMaterial().material).available).not.toContain(
      'leaf-cert'
    );
  });
});

describe('encodeOid4vpRequestUri — delivery follows the prefix (#377)', () => {
  const REQUEST_URI = 'https://auth.example.com/oid4vp/request/abc';

  it('emits only client_id and request_uri for a signed request', () => {
    const params = new URL(
      encodeOid4vpRequestUri('openid4vp://', buildSigned(), {
        mode: 'request-uri',
        requestUri: REQUEST_URI,
      })
    ).searchParams;

    expect(params.get('request_uri')).toBe(REQUEST_URI);
    expect(params.get('client_id')?.startsWith('x509_hash:')).toBe(true);
    expect([...params.keys()].sort()).toEqual(['client_id', 'request_uri']);
  });

  it('keeps the request parameters OUT of the wire under request_uri', () => {
    // A second, unsigned copy of `dcql_query` or `nonce` on the wire is a value
    // an attacker could steer while the signature covered a different one.
    const encoded = encodeOid4vpRequestUri('openid4vp://', buildSigned(), {
      mode: 'request-uri',
      requestUri: REQUEST_URI,
    });

    expect(encoded).not.toContain('dcql_query');
    expect(encoded).not.toContain('nonce');
    expect(encoded).not.toContain('state=');
    expect(encoded).not.toContain('client_metadata');
  });

  it('REFUSES to flatten a signed request into query parameters (HAIP §5.1)', () => {
    // The mandate is that the unsigned form is UNREACHABLE, not unpreferred.
    expect(() => encodeOid4vpRequestUri('openid4vp://', buildSigned())).toThrow(
      /MUST be delivered by 'request_uri'/
    );
    expect(() =>
      encodeOid4vpRequestUri('openid4vp://', buildSigned(), QUERY_PARAMETER_DELIVERY)
    ).toThrow(/MUST be delivered by 'request_uri'/);
  });

  it('refuses request_uri delivery for an unsigned request', () => {
    // There is no request object to fetch: §5.9.3 makes a `redirect_uri`
    // request unverifiable, so QAuth never signs one.
    expect(() =>
      encodeOid4vpRequestUri('openid4vp://', build(), {
        mode: 'request-uri',
        requestUri: REQUEST_URI,
      })
    ).toThrow(/cannot be delivered by 'request_uri'/);
  });

  it('appends to a wallet endpoint that already carries a query string', () => {
    const encoded = encodeOid4vpRequestUri(
      'https://wallet.example.com/authorize?x=1',
      buildSigned(),
      { mode: 'request-uri', requestUri: REQUEST_URI }
    );

    expect(encoded).toContain('?x=1&');
    expect(new URL(encoded).searchParams.get('x')).toBe('1');
  });

  it('still refuses a smuggled redirect_uri on the signed path', () => {
    const smuggled = { ...buildSigned(), redirect_uri: 'https://evil.example.com/cb' };

    expect(() =>
      encodeOid4vpRequestUri('openid4vp://', smuggled as ReturnType<typeof buildSigned>, {
        mode: 'request-uri',
        requestUri: REQUEST_URI,
      })
    ).toThrow(/MUST NOT carry a 'redirect_uri'/);
  });
});
