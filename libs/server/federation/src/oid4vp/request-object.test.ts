import { X509Certificate } from 'node:crypto';

import { compactVerify, decodeJwt, decodeProtectedHeader, importSPKI } from 'jose';
import { describe, expect, it } from 'vitest';

import type { VerifierProfile } from '../profiles/verifier-profile.types';
import { VERIFIER_PROFILES } from '../profiles/verifier-profiles';
import { createTestCertificate, type TestCertificate } from '../status/test/x509-fixtures';
import {
  createVerifierSigningMaterial,
  verifierMaterialProvisionedBy,
  type VerifierSigningMaterial,
} from '../x509/verifier-signing-material';
import { buildOid4vpAuthorizationRequest } from './authorization-request';
import type { CredentialRequestSpec } from './credential-format';
import {
  DEFAULT_REQUEST_OBJECT_LIFETIME_SECONDS,
  OID4VP_REQUEST_OBJECT_MEDIA_TYPE,
  OID4VP_REQUEST_OBJECT_TYP,
  signOid4vpRequestObject,
} from './request-object';

/**
 * The signed request object (JAR) a wallet fetches by `request_uri`
 * (issue #377, Phase B; RFC 9101; HAIP 1.0 §5.1).
 *
 * ## Why the profile here is a HAIP posture rather than `haip-1.0` itself
 *
 * `VERIFIER_PROFILES['haip-1.0']` also declares `direct_post.jwt` and
 * `responseEncryption: 'required'`, and the builder refuses BOTH — correctly:
 * they are Phase C of #377, which lands the encrypted response mode, the
 * published encryption key and the decrypting intake together. Relaxing exactly
 * those two members and nothing else is what isolates the signing half. When
 * Phase C lands, the literal table entry flows through this path unchanged.
 */
const HAIP_SIGNING_POSTURE: VerifierProfile = {
  ...VERIFIER_PROFILES['haip-1.0'],
  responseModes: ['direct_post'],
  responseEncryption: 'permitted',
};

const RESPONSE_URI = 'https://auth.example.com/oid4vp/response';

const PID: CredentialRequestSpec = {
  id: 'pid',
  format: 'dc+sd-jwt',
  typeValues: ['https://credentials.example.com/pid'],
  claims: [{ path: ['given_name'] }],
};

/** anchor → intermediate → leaf, plus the material the builder consumes. */
function buildMaterial(leafOverrides: { notBefore?: Date; notAfter?: Date } = {}): {
  readonly material: VerifierSigningMaterial;
  readonly anchor: TestCertificate;
  readonly intermediate: TestCertificate;
  readonly leaf: TestCertificate;
} {
  const anchor = createTestCertificate({ subject: 'anchor', ca: true });
  const intermediate = createTestCertificate({ subject: 'issuing-ca', issuer: anchor, ca: true });
  const leaf = createTestCertificate({
    subject: 'verifier.example',
    issuer: intermediate,
    keyUsage: ['digitalSignature'],
    ...leafOverrides,
  });

  return {
    anchor,
    intermediate,
    leaf,
    material: createVerifierSigningMaterial({
      privateKeyPem: leaf.keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      certificateChainPems: [leaf.pem, intermediate.pem],
      trustAnchorPems: [anchor.pem],
      // The chain is minted seconds ago; validation is at "now" either way.
      now: new Date(),
    }),
  };
}

function buildRequest(material: VerifierSigningMaterial) {
  return buildOid4vpAuthorizationRequest({
    profile: HAIP_SIGNING_POSTURE,
    responseUri: RESPONSE_URI,
    credentials: [PID],
    state: 'state-value',
    nonce: 'nonce-value',
    provisioned: verifierMaterialProvisionedBy(material),
    signingMaterial: material,
  });
}

describe('signOid4vpRequestObject — the protected header', () => {
  const { material, anchor, intermediate, leaf } = buildMaterial();

  it('signs with ES256 and stamps the JAR media type as typ', async () => {
    const header = decodeProtectedHeader(
      await signOid4vpRequestObject({
        request: buildRequest(material),
        material,
      })
    );

    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe(OID4VP_REQUEST_OBJECT_TYP);
    expect(OID4VP_REQUEST_OBJECT_MEDIA_TYPE).toBe(`application/${OID4VP_REQUEST_OBJECT_TYP}`);
  });

  it('carries leaf + intermediates in x5c, leaf FIRST, anchor EXCLUDED', async () => {
    const header = decodeProtectedHeader(
      await signOid4vpRequestObject({ request: buildRequest(material), material })
    );

    expect(header.x5c).toEqual([leaf.x5c, intermediate.x5c]);
    expect(header.x5c).not.toContain(anchor.x5c);
  });

  it('emits an x5c a plain X509Certificate parser can read back', async () => {
    // `x5c` is standard-alphabet base64 of DER (RFC 7515 §4.1.6), not base64url
    // and not PEM. A wallet decodes it exactly this way.
    const header = decodeProtectedHeader(
      await signOid4vpRequestObject({ request: buildRequest(material), material })
    );
    const entries = header.x5c as string[];

    expect(new X509Certificate(Buffer.from(entries[0] as string, 'base64')).subject).toContain(
      'verifier.example'
    );
  });
});

describe('signOid4vpRequestObject — the claims', () => {
  const { material } = buildMaterial();

  it('carries every request parameter as a claim (RFC 9101 §4)', async () => {
    const request = buildRequest(material);
    const claims = decodeJwt(await signOid4vpRequestObject({ request, material }));

    expect(claims['client_id']).toBe(request.client_id);
    expect(claims['response_type']).toBe('vp_token');
    expect(claims['response_mode']).toBe('direct_post');
    expect(claims['response_uri']).toBe(RESPONSE_URI);
    expect(claims['nonce']).toBe('nonce-value');
    expect(claims['state']).toBe('state-value');
    expect(claims['dcql_query']).toEqual(request.dcql_query);
    expect(claims['client_metadata']).toEqual(request.client_metadata);
  });

  it('sets iss to the client_id, so the header and the claim name one identity', async () => {
    const request = buildRequest(material);
    const claims = decodeJwt(await signOid4vpRequestObject({ request, material }));

    expect(claims.iss).toBe(request.client_id);
    expect(request.client_id.startsWith('x509_hash:')).toBe(true);
  });

  it('bounds the lifetime, defaulting to the request state TTL', async () => {
    const claims = decodeJwt(
      await signOid4vpRequestObject({ request: buildRequest(material), material })
    );

    expect(claims.exp).toBe((claims.iat as number) + DEFAULT_REQUEST_OBJECT_LIFETIME_SECONDS);
  });

  it('OMITS aud by default — OID4VP names no universal wallet audience', async () => {
    const claims = decodeJwt(
      await signOid4vpRequestObject({ request: buildRequest(material), material })
    );

    expect(claims.aud).toBeUndefined();
  });

  it('carries aud when an ecosystem states one', async () => {
    const claims = decodeJwt(
      await signOid4vpRequestObject({
        request: buildRequest(material),
        material,
        audience: 'https://wallet.example/authorize',
      })
    );

    expect(claims.aud).toBe('https://wallet.example/authorize');
  });

  it('never carries a redirect_uri parameter (§8.2)', async () => {
    const claims = decodeJwt(
      await signOid4vpRequestObject({ request: buildRequest(material), material })
    );

    expect(Object.keys(claims)).not.toContain('redirect_uri');
  });
});

describe('signOid4vpRequestObject — the signature', () => {
  it("verifies under the leaf's public key and no other", async () => {
    const { material, leaf, intermediate } = buildMaterial();
    const jwt = await signOid4vpRequestObject({ request: buildRequest(material), material });

    const leafKey = await importSPKI(
      leaf.keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      'ES256'
    );
    await expect(compactVerify(jwt, leafKey, { algorithms: ['ES256'] })).resolves.toBeDefined();

    const wrongKey = await importSPKI(
      intermediate.keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      'ES256'
    );
    await expect(compactVerify(jwt, wrongKey, { algorithms: ['ES256'] })).rejects.toThrow();
  });

  it('is rejected by a verifier pinned to another algorithm', async () => {
    const { material, leaf } = buildMaterial();
    const jwt = await signOid4vpRequestObject({ request: buildRequest(material), material });
    const leafKey = await importSPKI(
      leaf.keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      'ES256'
    );

    await expect(compactVerify(jwt, leafKey, { algorithms: ['EdDSA'] })).rejects.toThrow();
  });
});

describe('signOid4vpRequestObject — an expired certificate', () => {
  it('refuses to sign once the leaf is outside its validity window', async () => {
    // The one check boot-time validation structurally cannot make: a process
    // that started while the leaf was valid is still running after it expired.
    const { material } = buildMaterial();
    const request = buildRequest(material);

    await expect(
      signOid4vpRequestObject({
        request,
        material,
        now: new Date(material.leafNotAfter.getTime() + 1_000),
      })
    ).rejects.toThrow(/leaf certificate has expired/);
  });

  it('still signs a moment before expiry', async () => {
    const { material } = buildMaterial();

    await expect(
      signOid4vpRequestObject({
        request: buildRequest(material),
        material,
        now: new Date(material.leafNotAfter.getTime() - 1_000),
      })
    ).resolves.toBeTypeOf('string');
  });
});
