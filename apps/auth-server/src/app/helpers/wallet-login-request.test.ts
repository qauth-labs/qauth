import {
  decryptJwe,
  importEncryptionPrivateJwk,
  JWE_CONTENT_ENCRYPTION_ALGORITHMS,
  JWE_KEY_AGREEMENT_ALGORITHMS,
} from '@qauth-labs/core-crypto';
import {
  createVerifierSigningMaterial,
  VERIFIER_PROFILES,
  type VerifierProfile,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';
import { CompactEncrypt, importJWK, type JWK } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { envMock } = vi.hoisted(() => ({
  envMock: {
    JWT_ISSUER: 'https://auth.example.com/',
    WALLET_FEDERATION_ENABLED: true,
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' as string | undefined,
    OID4VP_REQUESTED_VCT: ['urn:example:pid'] as readonly string[] | undefined,
    OID4VP_WALLET_INVOCATION_ENDPOINT: 'openid4vp://',
    // The verifier identity (#377). Kept UNSET here: these tests drive the
    // signed path through an explicit capability rather than through the cached
    // env-backed resolver, so the gate's "nothing provisioned" branch is what
    // this env describes.
    OID4VP_VERIFIER_SIGNING_KEY: undefined as string | undefined,
    OID4VP_VERIFIER_SIGNING_KEY_PATH: undefined as string | undefined,
    OID4VP_VERIFIER_CERTIFICATE_CHAIN: [] as readonly string[],
    OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: [] as readonly string[],
    OID4VP_VERIFIER_TRUST_ANCHORS: [] as readonly string[],
    OID4VP_VERIFIER_TRUST_ANCHORS_PATH: [] as readonly string[],
    // The at-rest secret for the per-request decryption key (#377 Phase C).
    // Unset is the default posture — the private half is stored in the clear —
    // and it is what the encrypted-path tests below assert on.
    OID4VP_RESPONSE_KEY_SECRET: undefined as string | undefined,
  },
}));

vi.mock('../../config/env', () => ({ env: envMock }));

import { createMockVerifierPki } from '../../testing/mock-verifier-pki';
import { parseOid4vpRequestReference, verifyOid4vpRequestObject } from '../../testing/mock-wallet';
import {
  buildWalletLoginInvocation,
  OID4VP_REQUEST_OBJECT_PATH_PREFIX,
  OID4VP_RESPONSE_PATH,
  resolveWalletLoginCapability,
  type WalletLoginCapability,
} from './wallet-login-request';

/**
 * The availability gate (#296 LOCKED: no permissive fallback) and the request it
 * builds. Every `undefined` below is a wallet-login entry point that must not be
 * rendered — the login page asks this question to decide whether the button
 * exists at all.
 *
 * ## The signed half (#377)
 *
 * Driven through an explicit {@link WalletLoginCapability} rather than through
 * `resolveWalletLoginCapability`, because the env-backed material is resolved
 * once per process and these tests need several deployments. What the signed
 * cases assert is the DELIVERY: a signed request must reach the wallet as a
 * `request_uri` reference to a parked object, and the object must survive an
 * independent wallet's chain check against an anchor the request did not carry.
 */
function fakeFastify() {
  const store = new Map<string, unknown>();

  return {
    log: { debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
    sessionUtils: {
      setSession: vi.fn(async (key: string, value: unknown) => {
        store.set(key, value);
      }),
      getSession: vi.fn(async (key: string) => store.get(key) ?? null),
      deleteSession: vi.fn(async (key: string) => {
        store.delete(key);
      }),
    },
  } as unknown as FastifyInstance;
}

/** Split a concatenated PEM bundle the way the env schema does. */
function blocks(bundle: string): readonly string[] {
  return (bundle.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []).map(
    (pem) => pem.trim()
  );
}

beforeEach(() => {
  envMock.WALLET_FEDERATION_ENABLED = true;
  envMock.OID4VP_VERIFIER_PROFILE = 'oid4vp-1.0-base';
  envMock.OID4VP_REQUESTED_VCT = ['urn:example:pid'];
  envMock.OID4VP_WALLET_INVOCATION_ENDPOINT = 'openid4vp://';
});

describe('resolveWalletLoginCapability', () => {
  it('resolves when the flag, the profile and a credential type are all present', () => {
    const capability = resolveWalletLoginCapability(fakeFastify());
    expect(capability?.profile.id).toBe('oid4vp-1.0-base');
    // The trailing slash on JWT_ISSUER is canonicalised away, so the
    // `response_uri` matches the endpoint the wallet actually posts to.
    expect(capability?.responseUri).toBe(`https://auth.example.com${OID4VP_RESPONSE_PATH}`);
    expect(capability?.requestObjectBaseUri).toBe(
      `https://auth.example.com${OID4VP_REQUEST_OBJECT_PATH_PREFIX}`
    );
    expect(capability?.credentials[0].typeValues).toEqual(['urn:example:pid']);
  });

  it('carries no signing material for a deployment that provisioned none', () => {
    expect(resolveWalletLoginCapability(fakeFastify())?.signingMaterial).toBeUndefined();
  });

  it('refuses when wallet federation is switched off', () => {
    envMock.WALLET_FEDERATION_ENABLED = false;
    expect(resolveWalletLoginCapability(fakeFastify())).toBeUndefined();
  });

  it('refuses when no VerifierProfile is selected', () => {
    envMock.OID4VP_VERIFIER_PROFILE = undefined;
    expect(resolveWalletLoginCapability(fakeFastify())).toBeUndefined();
  });

  it('refuses when the operator has not said which credential to ask for', () => {
    envMock.OID4VP_REQUESTED_VCT = undefined;
    expect(resolveWalletLoginCapability(fakeFastify())).toBeUndefined();
  });

  it('refuses haip-1.0 on a deployment that provisioned no verifier identity', () => {
    // Not the encryption posture — #377 Phase C cleared that, and encryption
    // needs nothing provisioned. What this env lacks is the X.509 identity the
    // `x509_hash` prefix needs, so the profile does not resolve at all.
    envMock.OID4VP_VERIFIER_PROFILE = 'haip-1.0';
    expect(resolveWalletLoginCapability(fakeFastify())).toBeUndefined();
  });

  it('refuses a profile whose response posture contradicts its permitted modes', () => {
    // A table that requires encryption while permitting only the plain mode is
    // a refusal at the gate, never a downgrade to whichever half is buildable.
    // Driven through the builder's own selector on a capability, since the env
    // cannot express a profile the table does not ship.
    const fastify = fakeFastify();
    const contradictory: WalletLoginCapability = {
      ...resolveWalletLoginCapability(fastify)!,
      profile: { ...VERIFIER_PROFILES['oid4vp-1.0-base'], responseEncryption: 'required' },
    };

    return expect(buildWalletLoginInvocation(fastify, contradictory)).rejects.toThrow(
      /does not permit the 'direct_post.jwt' Response Mode/
    );
  });

  it('does not throw when the selected profile is not provisioned', () => {
    envMock.OID4VP_VERIFIER_PROFILE = 'haip-1.0';
    const fastify = fakeFastify();
    expect(() => resolveWalletLoginCapability(fastify)).not.toThrow();
  });
});

describe('buildWalletLoginInvocation — the unsigned base path', () => {
  it('builds a direct_post request and encodes it as an opaque invocation URI', async () => {
    const fastify = fakeFastify();
    const capability = resolveWalletLoginCapability(fastify)!;
    const invocation = await buildWalletLoginInvocation(fastify, capability);

    expect(invocation.request.response_type).toBe('vp_token');
    expect(invocation.request.response_mode).toBe('direct_post');
    expect(invocation.request.response_uri).toBe(capability.responseUri);
    // OID4VP 1.0 §8.2: `redirect_uri` MUST NOT be a parameter of a direct_post
    // request. It survives only as the Client Identifier Prefix.
    expect(Object.keys(invocation.request)).not.toContain('redirect_uri');
    expect(invocation.request.client_id).toBe(`redirect_uri:${capability.responseUri}`);

    expect(invocation.invocationUri.startsWith('openid4vp://?')).toBe(true);
    expect(invocation.invocationUri).toContain(`state=${invocation.request.state}`);
  });

  it('parks no request object — there is nothing to sign', async () => {
    const fastify = fakeFastify();
    const capability = resolveWalletLoginCapability(fastify)!;
    const invocation = await buildWalletLoginInvocation(fastify, capability);

    expect(invocation.requestObjectHandle).toBeUndefined();
    expect(fastify.sessionUtils.setSession).not.toHaveBeenCalled();
  });

  it('stores only the digest of the state, and the nonce verbatim', async () => {
    const fastify = fakeFastify();
    const capability = resolveWalletLoginCapability(fastify)!;
    const invocation = await buildWalletLoginInvocation(fastify, capability);

    expect(invocation.stateHash).toMatch(/^[0-9a-f]{64}$/);
    expect(invocation.stateHash).not.toContain(invocation.request.state);
    expect(invocation.nonce).toBe(invocation.request.nonce);
  });

  it('mints a fresh state and nonce for every request', async () => {
    const fastify = fakeFastify();
    const capability = resolveWalletLoginCapability(fastify)!;
    const first = await buildWalletLoginInvocation(fastify, capability);
    const second = await buildWalletLoginInvocation(fastify, capability);

    expect(first.stateHash).not.toBe(second.stateHash);
    expect(first.nonce).not.toBe(second.nonce);
  });

  it('bounds the request lifetime', async () => {
    const fastify = fakeFastify();
    const capability = resolveWalletLoginCapability(fastify)!;
    const invocation = await buildWalletLoginInvocation(fastify, capability);

    expect(invocation.expiresAt).toBeGreaterThan(Date.now());
    expect(invocation.expiresAt).toBeLessThanOrEqual(Date.now() + 15 * 60 * 1000);
  });

  // The regression this suite exists for. A deployment may run
  // `oid4vp-1.0-base` AND provision a verifier identity — the boot validates the
  // material whatever profile is selected — and that profile's preferred prefix
  // is the unsigned one. A delivery decision made from "do we hold a key" rather
  // than from "is this request signed" breaks every wallet login on the base
  // profile the moment an operator configures a chain.
  it('still delivers INLINE when material is provisioned but the profile is unsigned', async () => {
    const pki = createMockVerifierPki();
    const fastify = fakeFastify();
    const capability: WalletLoginCapability = {
      ...resolveWalletLoginCapability(fastify)!,
      signingMaterial: createVerifierSigningMaterial({
        privateKeyPem: pki.signingKeyPem,
        certificateChainPems: blocks(pki.certificateChainPem),
        trustAnchorPems: blocks(pki.trustAnchorPem),
      }),
    };

    expect(capability.profile.id).toBe('oid4vp-1.0-base');

    const invocation = await buildWalletLoginInvocation(fastify, capability);

    expect(invocation.request.client_id.startsWith('redirect_uri:')).toBe(true);
    expect(invocation.invocationUri.startsWith('openid4vp://?')).toBe(true);
    expect(invocation.invocationUri).toContain('dcql_query');
    expect(invocation.invocationUri).not.toContain('request_uri');
    expect(invocation.requestObjectHandle).toBeUndefined();
    expect(fastify.sessionUtils.setSession).not.toHaveBeenCalled();
  });

  it('honours a custom wallet invocation endpoint', async () => {
    envMock.OID4VP_WALLET_INVOCATION_ENDPOINT = 'https://wallet.example/authorize?v=1';
    const fastify = fakeFastify();
    const capability = resolveWalletLoginCapability(fastify)!;
    const invocation = await buildWalletLoginInvocation(fastify, capability);

    expect(invocation.invocationUri.startsWith('https://wallet.example/authorize?v=1&')).toBe(true);
  });
});

/**
 * The HAIP signing posture with the encrypted response relaxed away.
 *
 * `haip-1.0` also declares `direct_post.jwt` and `responseEncryption:
 * 'required'`, which #377 Phase C made buildable — see the describe block
 * after the signed one for the shipped table entry driven whole. Relaxing
 * exactly those two here isolates the signing half, so a signed-delivery
 * regression cannot hide behind an encryption one; every other mandate is the
 * shipped table's own.
 */
const HAIP_SIGNING_POSTURE: VerifierProfile = {
  ...VERIFIER_PROFILES['haip-1.0'],
  responseModes: ['direct_post'],
  responseEncryption: 'permitted',
};

describe('buildWalletLoginInvocation — the signed request_uri path (#377)', () => {
  const pki = createMockVerifierPki();

  function signingCapability(): WalletLoginCapability {
    return {
      profile: HAIP_SIGNING_POSTURE,
      responseUri: `https://auth.example.com${OID4VP_RESPONSE_PATH}`,
      requestObjectBaseUri: `https://auth.example.com${OID4VP_REQUEST_OBJECT_PATH_PREFIX}`,
      walletInvocationEndpoint: 'openid4vp://',
      credentials: [
        { id: 'qauth_wallet_login', format: 'dc+sd-jwt', typeValues: ['urn:example:pid'] },
      ],
      signingMaterial: createVerifierSigningMaterial({
        privateKeyPem: pki.signingKeyPem,
        certificateChainPems: blocks(pki.certificateChainPem),
        trustAnchorPems: blocks(pki.trustAnchorPem),
      }),
    };
  }

  it('identifies the Verifier by x509_hash', async () => {
    const fastify = fakeFastify();
    const invocation = await buildWalletLoginInvocation(fastify, signingCapability());

    expect(invocation.request.client_id.startsWith('x509_hash:')).toBe(true);
  });

  it('delivers a request_uri reference, never the inline parameters', async () => {
    const fastify = fakeFastify();
    const invocation = await buildWalletLoginInvocation(fastify, signingCapability());
    const reference = parseOid4vpRequestReference(invocation.invocationUri);

    expect(reference.clientId).toBe(invocation.request.client_id);
    expect(
      reference.requestUri.startsWith(
        `https://auth.example.com${OID4VP_REQUEST_OBJECT_PATH_PREFIX}`
      )
    ).toBe(true);
    expect(invocation.invocationUri).not.toContain('dcql_query');
  });

  it('parks the signed object under the handle the reference names', async () => {
    const fastify = fakeFastify();
    const invocation = await buildWalletLoginInvocation(fastify, signingCapability());
    const reference = parseOid4vpRequestReference(invocation.invocationUri);

    expect(invocation.requestObjectHandle).toBeDefined();
    expect(reference.requestUri.endsWith(invocation.requestObjectHandle as string)).toBe(true);
    expect(fastify.sessionUtils.setSession).toHaveBeenCalledTimes(1);
  });

  // The #377 acceptance criterion, end to end through the app's own builder.
  it('produces an object an INDEPENDENT wallet validates against an out-of-band anchor', async () => {
    const fastify = fakeFastify();
    const invocation = await buildWalletLoginInvocation(fastify, signingCapability());
    const reference = parseOid4vpRequestReference(invocation.invocationUri);

    const stored = (await fastify.sessionUtils.getSession<{ requestObject: string }>(
      `wallet-request-object:${invocation.requestObjectHandle as string}`
    )) as { requestObject: string };

    const verified = await verifyOid4vpRequestObject(stored.requestObject, {
      // Out of band, from the wallet's own trust list. The request never carries
      // this and must never be able to.
      trustAnchorPem: pki.walletTrustAnchorPem,
    });

    expect(verified.request.clientId).toBe(reference.clientId);
    expect(verified.request.nonce).toBe(invocation.nonce);
    expect(verified.request.state).toBe(invocation.request.state);
    expect(verified.request.responseUri).toBe(invocation.request.response_uri);
    expect(verified.request.dcqlQuery).toEqual(invocation.request.dcql_query);
  });

  it('ships leaf + intermediate in x5c and NOT the anchor', async () => {
    const fastify = fakeFastify();
    const invocation = await buildWalletLoginInvocation(fastify, signingCapability());
    const stored = (await fastify.sessionUtils.getSession<{ requestObject: string }>(
      `wallet-request-object:${invocation.requestObjectHandle as string}`
    )) as { requestObject: string };

    const verified = await verifyOid4vpRequestObject(stored.requestObject, {
      trustAnchorPem: pki.walletTrustAnchorPem,
    });

    expect(verified.x5c).toEqual([pki.leaf.x5c, pki.intermediate.x5c]);
    expect(verified.x5c).not.toContain(pki.anchor.x5c);
  });

  it('is refused by a wallet holding a DIFFERENT trust anchor', async () => {
    // The control that makes the assertion above mean something: the chain check
    // is real, not a shape check that any anchor would satisfy.
    const fastify = fakeFastify();
    const invocation = await buildWalletLoginInvocation(fastify, signingCapability());
    const stored = (await fastify.sessionUtils.getSession<{ requestObject: string }>(
      `wallet-request-object:${invocation.requestObjectHandle as string}`
    )) as { requestObject: string };

    await expect(
      verifyOid4vpRequestObject(stored.requestObject, {
        trustAnchorPem: createMockVerifierPki({ name: 'stranger.example' }).walletTrustAnchorPem,
      })
    ).rejects.toThrow(/does not terminate at the trust anchor/);
  });
});

/**
 * The encrypted response (#377 Phase C, HAIP 1.0 §5 / §5.1).
 *
 * Driven through the shipped `haip-1.0` entry WHOLE — signed prefix, encrypted
 * mode — so what is asserted is the request an EU deployment actually sends.
 * The decryption round trip below is the property that matters: the private
 * half the helper hands back for storage must open a JWE encrypted to the
 * public half it published, or the row would be a correlator for an exchange
 * that can never complete.
 */
describe('buildWalletLoginInvocation — the encrypted direct_post.jwt path (#377 Phase C)', () => {
  const pki = createMockVerifierPki();

  function haipCapability(): WalletLoginCapability {
    return {
      profile: VERIFIER_PROFILES['haip-1.0'],
      responseUri: `https://auth.example.com${OID4VP_RESPONSE_PATH}`,
      requestObjectBaseUri: `https://auth.example.com${OID4VP_REQUEST_OBJECT_PATH_PREFIX}`,
      walletInvocationEndpoint: 'openid4vp://',
      credentials: [
        { id: 'qauth_wallet_login', format: 'dc+sd-jwt', typeValues: ['urn:example:pid'] },
      ],
      signingMaterial: createVerifierSigningMaterial({
        privateKeyPem: pki.signingKeyPem,
        certificateChainPems: blocks(pki.certificateChainPem),
        trustAnchorPems: blocks(pki.trustAnchorPem),
      }),
    };
  }

  it('asks for direct_post.jwt under haip-1.0', async () => {
    const invocation = await buildWalletLoginInvocation(fakeFastify(), haipCapability());

    expect(invocation.request.response_mode).toBe('direct_post.jwt');
  });

  it('publishes ONE per-request key in client_metadata, and hands back its private half for the row', async () => {
    const invocation = await buildWalletLoginInvocation(fakeFastify(), haipCapability());
    const keys = invocation.request.client_metadata.jwks?.keys ?? [];

    expect(keys).toHaveLength(1);
    expect(keys[0]?.kty).toBe('EC');
    expect(keys[0]?.crv).toBe('P-256');
    expect(keys[0]?.use).toBe('enc');
    expect(keys[0]?.alg).toBe('ECDH-ES');
    // The PUBLIC half is published: no private scalar on the wire.
    expect(keys[0]).not.toHaveProperty('d');

    // The three columns, all present, and the kid is THE kid — the same value
    // the wallet will echo in the JWE header and the intake will look up by.
    expect(invocation.responseEncryption).toBeDefined();
    expect(invocation.responseEncryption?.kid).toBe(keys[0]?.kid);
    expect(invocation.responseEncryption?.protection).toBe('plain');
    expect(invocation.request.client_metadata.encrypted_response_enc_values_supported).toContain(
      'A128GCM'
    );
  });

  it('stores the private half in the clear by default, as a JWK document', async () => {
    // The default posture: no `OID4VP_RESPONSE_KEY_SECRET` in this env, so the
    // column holds the JWK itself, `d` included, under the `plain` marker.
    const invocation = await buildWalletLoginInvocation(fakeFastify(), haipCapability());
    const stored = JSON.parse(invocation.responseEncryption?.privateJwk as string) as JWK;

    expect(stored.kty).toBe('EC');
    expect(typeof stored.d).toBe('string');
    expect(stored.kid).toBe(invocation.responseEncryption?.kid);
  });

  it('hands back a private half that opens a JWE encrypted to the published public half', async () => {
    // The round trip, with the WALLET side written against `jose` directly —
    // no import of the code under test — and the VERIFIER side using the
    // crypto layer's own pinned decrypt.
    const invocation = await buildWalletLoginInvocation(fakeFastify(), haipCapability());
    const published = invocation.request.client_metadata.jwks?.keys[0] as JWK;
    const stored = JSON.parse(invocation.responseEncryption?.privateJwk as string) as JWK;

    const jwe = await new CompactEncrypt(
      new TextEncoder().encode(JSON.stringify({ state: invocation.request.state, vp_token: {} }))
    )
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', kid: published.kid as string })
      .encrypt(await importJWK(published, 'ECDH-ES'));

    const { payload } = await decryptJwe(jwe, await importEncryptionPrivateJwk(stored), {
      keyManagementAlgorithms: JWE_KEY_AGREEMENT_ALGORITHMS,
      contentEncryptionAlgorithms: JWE_CONTENT_ENCRYPTION_ALGORITHMS,
    });

    expect(payload['state']).toBe(invocation.request.state);
  });

  it('mints a fresh pair and kid for every request (HAIP §5: specific to each request)', async () => {
    const fastify = fakeFastify();
    const first = await buildWalletLoginInvocation(fastify, haipCapability());
    const second = await buildWalletLoginInvocation(fastify, haipCapability());

    expect(first.responseEncryption?.kid).not.toBe(second.responseEncryption?.kid);
    expect(first.request.client_metadata.jwks?.keys[0]?.x).not.toBe(
      second.request.client_metadata.jwks?.keys[0]?.x
    );
  });

  it('carries the encryption key set INSIDE the signed request object, not on the wire', async () => {
    // Under haip-1.0 the request is delivered by reference, so the wallet reads
    // `client_metadata` — key set included — out of the JAR it fetched and
    // verified. The invocation URI itself carries neither.
    const fastify = fakeFastify();
    const invocation = await buildWalletLoginInvocation(fastify, haipCapability());
    const reference = parseOid4vpRequestReference(invocation.invocationUri);
    const stored = (await fastify.sessionUtils.getSession<{ requestObject: string }>(
      `wallet-request-object:${invocation.requestObjectHandle as string}`
    )) as { requestObject: string };

    const verified = await verifyOid4vpRequestObject(stored.requestObject, {
      trustAnchorPem: pki.walletTrustAnchorPem,
    });

    expect(reference.requestUri).toContain(invocation.requestObjectHandle);
    expect(invocation.invocationUri).not.toContain('jwks');
    expect(verified.request.responseMode).toBe('direct_post.jwt');
    expect((verified.request.clientMetadata['jwks'] as { keys: JWK[] }).keys[0]?.kid).toBe(
      invocation.responseEncryption?.kid
    );
  });

  it('mints nothing for the base profile, whose posture forbids encryption', async () => {
    const fastify = fakeFastify();
    const invocation = await buildWalletLoginInvocation(
      fastify,
      resolveWalletLoginCapability(fastify)!
    );

    expect(invocation.request.response_mode).toBe('direct_post');
    expect(invocation.responseEncryption).toBeUndefined();
    expect(invocation.request.client_metadata).not.toHaveProperty('jwks');
  });
});
