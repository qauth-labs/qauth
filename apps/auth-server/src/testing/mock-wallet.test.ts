import { compactDecrypt, decodeProtectedHeader, exportJWK, generateKeyPair, type JWK } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  createMockIssuer,
  createMockWallet,
  DEFAULT_VCT,
  encryptAuthorizationResponse,
  issuerJwksConfig,
  MOCK_WALLET_SD_JWT_VC_FORMAT,
  parseOid4vpRequest,
  presentCredential,
  selectResponseEncryptionKey,
  type VpToken,
  WALLET_PRESENTATION_BUILDERS,
} from './mock-wallet';

/**
 * The reference/mock wallet itself (#240).
 *
 * A test fixture that is wrong produces E2E failures that look like product
 * bugs, so the wallet's own contract is pinned here — cheaply, without
 * containers. The CORRECTNESS of what it emits is proven elsewhere and can only
 * be proven elsewhere: the shipping #234 validator inside the running server
 * accepts these presentations in `app/wallet-federation.integration.test.ts`.
 * What this file pins is the seam and the refusals.
 */

const CLIENT_ID = 'redirect_uri:https://auth.example.com/oid4vp/response';

/** A request URI shaped exactly as `encodeOid4vpRequestUri` produces one. */
function invocationUri(dcqlQuery: unknown, overrides: Record<string, string> = {}): string {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: 'vp_token',
    response_mode: 'direct_post',
    response_uri: 'https://auth.example.com/oid4vp/response',
    nonce: 'n-0S6_WzA2Mj',
    state: 'state-value',
    dcql_query: JSON.stringify(dcqlQuery),
    client_metadata: JSON.stringify({ client_name: 'QAuth' }),
    ...overrides,
  });
  return `openid4vp://?${params.toString()}`;
}

const LOGIN_QUERY = {
  credentials: [
    {
      id: 'qauth_wallet_login',
      format: MOCK_WALLET_SD_JWT_VC_FORMAT,
      meta: { vct_values: [DEFAULT_VCT] },
    },
  ],
};

/** The single presentation the login query's entry carries. */
function presentationOf(vpToken: VpToken): string {
  const entry = vpToken['qauth_wallet_login'];
  // OID4VP 1.0 §8.1: every entry is an ARRAY, even for a single credential.
  expect(Array.isArray(entry)).toBe(true);
  expect(entry).toHaveLength(1);
  const presentation = entry?.[0];
  if (presentation === undefined) throw new Error('vp_token entry carried no presentation');
  return presentation;
}

describe('parseOid4vpRequest — a wallet reads the request off the WIRE', () => {
  it('parses every parameter the base profile sends', () => {
    const request = parseOid4vpRequest(invocationUri(LOGIN_QUERY));

    expect(request.clientId).toBe(CLIENT_ID);
    expect(request.responseType).toBe('vp_token');
    expect(request.responseMode).toBe('direct_post');
    expect(request.nonce).toBe('n-0S6_WzA2Mj');
    expect(request.state).toBe('state-value');
    expect(request.dcqlQuery.credentials[0]?.id).toBe('qauth_wallet_login');
  });

  it.each([
    ['client_id'],
    ['response_type'],
    ['response_mode'],
    ['response_uri'],
    ['nonce'],
    ['state'],
    ['dcql_query'],
  ] as const)('refuses a request missing %s rather than guessing a default', (parameter) => {
    // A wallet that defaulted a missing parameter would hide the exact
    // regression this fixture exists to catch: QAuth silently stopping sending
    // one. The E2E must fail loudly at the wallet, not pass on a guess.
    const params = new URLSearchParams(invocationUri(LOGIN_QUERY).split('?')[1]);
    params.delete(parameter);

    expect(() => parseOid4vpRequest(`openid4vp://?${params.toString()}`)).toThrow(parameter);
  });
});

describe('the format seam — one builder per DCQL credential format', () => {
  it('ships dc+sd-jwt and NOT mso_mdoc', () => {
    // Mirrors the verifier's `CREDENTIAL_FORMAT_ADAPTERS`. `mso_mdoc` is a
    // tracked fast-follow; a wallet that answered an mdoc query with an SD-JWT
    // VC would make the E2E pass for a credential the verifier can never
    // receive in production.
    expect(Object.keys(WALLET_PRESENTATION_BUILDERS)).toEqual([MOCK_WALLET_SD_JWT_VC_FORMAT]);
    expect(WALLET_PRESENTATION_BUILDERS['mso_mdoc']).toBeUndefined();
  });

  it('refuses to present a credential in a format it has no builder for', async () => {
    const issuer = await createMockIssuer('https://issuer.example.com');
    const credential = await issuer.issue();

    await expect(
      presentCredential({ ...credential, format: 'mso_mdoc' }, { nonce: 'n', audience: CLIENT_ID })
    ).rejects.toThrow('mso_mdoc');
  });
});

describe('answering a DCQL query', () => {
  it('keys the vp_token by Credential Query id, not by format or index', async () => {
    // OID4VP 1.0 §8.1. The endpoint reads presentations by DCQL id; a wallet
    // keying on anything else would be refused, so the E2E's happy path depends
    // on this being right.
    const issuer = await createMockIssuer('https://issuer.example.com');
    const wallet = createMockWallet([await issuer.issue()]);

    const response = await wallet.buildResponse(invocationUri(LOGIN_QUERY));

    expect(Object.keys(response.vpToken)).toEqual(['qauth_wallet_login']);
    expect(response.formBody['state']).toBe('state-value');
    expect(JSON.parse(response.formBody['vp_token'] as string)).toEqual(response.vpToken);
  });

  it('produces a presentation with disclosures and a Key Binding JWT', async () => {
    const issuer = await createMockIssuer('https://issuer.example.com');
    const wallet = createMockWallet([await issuer.issue({ claims: { given_name: 'Alice' } })]);

    const response = await wallet.buildResponse(invocationUri(LOGIN_QUERY));
    const presentation = presentationOf(response.vpToken);
    const segments = presentation.split('~');

    // issuer-signed JWT ~ one Disclosure ~ Key Binding JWT
    expect(segments).toHaveLength(3);
    expect(segments[2]).not.toBe('');
    expect(JSON.parse(Buffer.from(segments[1] as string, 'base64url').toString())).toEqual([
      expect.any(String),
      'given_name',
      'Alice',
    ]);
  });

  it('binds the Key Binding JWT to the request nonce and the PREFIXED client_id', async () => {
    // OID4VP 1.0 §5.9: the Client Identifier Prefix is part of the Verifier's
    // identity. A wallet that stripped `redirect_uri:` would produce a binding
    // QAuth refuses, and the E2E would fail somewhere far from the cause.
    const issuer = await createMockIssuer('https://issuer.example.com');
    const wallet = createMockWallet([await issuer.issue()]);

    const response = await wallet.buildResponse(invocationUri(LOGIN_QUERY));
    const presentation = presentationOf(response.vpToken);
    const keyBindingJwt = presentation.slice(presentation.lastIndexOf('~') + 1);
    const claims = JSON.parse(
      Buffer.from(keyBindingJwt.split('.')[1] as string, 'base64url').toString()
    ) as Record<string, unknown>;

    expect(claims['aud']).toBe(CLIENT_ID);
    expect(claims['nonce']).toBe('n-0S6_WzA2Mj');
    expect(typeof claims['sd_hash']).toBe('string');
  });

  it('refuses a query it holds no credential for, rather than sending an empty token', async () => {
    const issuer = await createMockIssuer('https://issuer.example.com');
    const wallet = createMockWallet([await issuer.issue({ credentialType: 'https://other/type' })]);

    await expect(wallet.buildResponse(invocationUri(LOGIN_QUERY))).rejects.toThrow(
      'qauth_wallet_login'
    );
  });

  it('matches on vct as well as format', async () => {
    const issuer = await createMockIssuer('https://issuer.example.com');
    const wallet = createMockWallet([
      await issuer.issue({ credentialType: 'https://other/type' }),
      await issuer.issue({ credentialType: DEFAULT_VCT, claims: { given_name: 'Wanted' } }),
    ]);

    const response = await wallet.buildResponse(invocationUri(LOGIN_QUERY));
    const disclosure = JSON.parse(
      Buffer.from(presentationOf(response.vpToken).split('~')[1] as string, 'base64url').toString()
    ) as unknown[];

    expect(disclosure[2]).toBe('Wanted');
  });

  it('signs the `status` claim IN THE CLEAR and never as a Disclosure (#297)', async () => {
    // SD-JWT VC §3.2.2.2 forbids `status` from being selectively disclosable,
    // and QAuth refuses a credential that makes it so. A wallet harness that got
    // this wrong would make the revocation E2E fail for the wrong reason —
    // `forbidden-selective-disclosure` rather than a bit that says revoked.
    const issuer = await createMockIssuer('https://issuer.example.com');
    const status = { status_list: { idx: 7, uri: 'https://status.issuer.example/lists/1' } };
    const wallet = createMockWallet([
      await issuer.issue({ claims: { given_name: 'Alice' }, status }),
    ]);

    const presentation = presentationOf(
      (await wallet.buildResponse(invocationUri(LOGIN_QUERY))).vpToken
    );
    const [issuerSignedJwt, disclosure] = presentation.split('~');
    const payload = JSON.parse(
      Buffer.from((issuerSignedJwt as string).split('.')[1] as string, 'base64url').toString()
    ) as Record<string, unknown>;

    expect(payload['status']).toEqual(status);
    expect(
      JSON.parse(Buffer.from(disclosure as string, 'base64url').toString()) as unknown[]
    ).not.toContain('status');
  });

  it('omits `status` entirely when the issuer publishes no revocation mechanism', async () => {
    const issuer = await createMockIssuer('https://issuer.example.com');
    const wallet = createMockWallet([await issuer.issue()]);

    const presentation = presentationOf(
      (await wallet.buildResponse(invocationUri(LOGIN_QUERY))).vpToken
    );
    const payload = JSON.parse(
      Buffer.from(
        (presentation.split('~')[0] as string).split('.')[1] as string,
        'base64url'
      ).toString()
    ) as Record<string, unknown>;

    expect('status' in payload).toBe(false);
  });

  it('can answer with a wallet error instead of a vp_token (§8.2)', async () => {
    const wallet = createMockWallet();
    const response = await wallet.buildErrorResponse(invocationUri(LOGIN_QUERY));

    expect(response.formBody).toEqual({ state: 'state-value', error: 'access_denied' });
    expect(response.formBody['vp_token']).toBeUndefined();
  });
});

/**
 * The encrypted-response seam (#377 Phase C, OID4VP 1.0 §8.3, HAIP §5).
 *
 * The "Verifier" here is a bare `jose` key pair standing in for the one QAuth
 * publishes per request. Decrypting on this side with `jose` too — never with
 * QAuth's helper — keeps the fixture's own contract independent of the code
 * the E2E then checks it against.
 */
describe('the encrypted-response seam — direct_post.jwt (#377 Phase C)', () => {
  /** A per-request Verifier key pair, as QAuth would publish and hold it. */
  async function verifierKey(
    kid = 'req-kid-1'
  ): Promise<{ published: JWK; privateKey: CryptoKey }> {
    const { publicKey, privateKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256' });
    const published = { ...(await exportJWK(publicKey)), alg: 'ECDH-ES', use: 'enc', kid };
    return { published, privateKey };
  }

  function encryptedInvocation(published: JWK, metadata: Record<string, unknown> = {}): string {
    return invocationUri(LOGIN_QUERY, {
      response_mode: 'direct_post.jwt',
      client_metadata: JSON.stringify({
        client_name: 'QAuth',
        jwks: { keys: [published] },
        encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
        ...metadata,
      }),
    });
  }

  it('posts ONE response parameter and no cleartext state under direct_post.jwt', async () => {
    const issuer = await createMockIssuer('https://issuer.example.com');
    const wallet = createMockWallet([await issuer.issue()]);
    const { published } = await verifierKey();

    const response = await wallet.buildResponse(encryptedInvocation(published));

    expect(Object.keys(response.formBody)).toEqual(['response']);
    expect(response.formBody['response']?.split('.')).toHaveLength(5);
  });

  it('echoes the published kid in the JWE protected header, with ECDH-ES and the advertised enc (§8.3)', async () => {
    const issuer = await createMockIssuer('https://issuer.example.com');
    const wallet = createMockWallet([await issuer.issue()]);
    const { published } = await verifierKey('the-kid');

    const response = await wallet.buildResponse(encryptedInvocation(published));
    const header = decodeProtectedHeader(response.formBody['response'] as string);

    expect(header.alg).toBe('ECDH-ES');
    // Both advertised, so HAIP §5's SHOULD: A256GCM.
    expect(header.enc).toBe('A256GCM');
    expect(header.kid).toBe('the-kid');
    expect(header.zip).toBeUndefined();
  });

  it('encrypts the state and the vp_token as a JSON OBJECT to the published key', async () => {
    const issuer = await createMockIssuer('https://issuer.example.com');
    const wallet = createMockWallet([await issuer.issue()]);
    const { published, privateKey } = await verifierKey();

    const response = await wallet.buildResponse(encryptedInvocation(published));
    const { plaintext } = await compactDecrypt(response.formBody['response'] as string, privateKey);
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;

    expect(payload['state']).toBe('state-value');
    // §8.3: the payload is JSON, so vp_token is the object itself, not a string.
    expect(payload['vp_token']).toEqual(response.vpToken);
    expect(typeof payload['vp_token']).toBe('object');
  });

  it('falls back to A128GCM when the Verifier advertised no enc values (HAIP §5 floor)', async () => {
    const { published } = await verifierKey();
    const request = parseOid4vpRequest(
      invocationUri(LOGIN_QUERY, {
        response_mode: 'direct_post.jwt',
        client_metadata: JSON.stringify({ jwks: { keys: [published] } }),
      })
    );

    const jwe = await encryptAuthorizationResponse(request, { state: 'state-value' });

    expect(decodeProtectedHeader(jwe).enc).toBe('A128GCM');
  });

  it('PREFERS A256GCM whenever it is advertised, wherever it sits in the list (HAIP §5)', async () => {
    // "If both are supported, the Wallet SHOULD use A256GCM for the JWE enc."
    // A wallet that took the first advertised value would post an enc a real
    // HAIP wallet never produces against a Verifier listing both.
    const { published } = await verifierKey();
    const request = parseOid4vpRequest(
      encryptedInvocation(published, {
        encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
      })
    );

    const jwe = await encryptAuthorizationResponse(request, { state: 'state-value' });

    expect(decodeProtectedHeader(jwe).enc).toBe('A256GCM');
  });

  it('takes the first advertised enc value when A256GCM is not among them', async () => {
    const { published } = await verifierKey();
    const request = parseOid4vpRequest(
      encryptedInvocation(published, {
        encrypted_response_enc_values_supported: ['A128GCM', 'A192GCM'],
      })
    );

    const jwe = await encryptAuthorizationResponse(request, { state: 'state-value' });

    expect(decodeProtectedHeader(jwe).enc).toBe('A128GCM');
  });

  it('encrypts a wallet error too — a refusal is not a downgrade to plaintext', async () => {
    const wallet = createMockWallet();
    const { published, privateKey } = await verifierKey();

    const response = await wallet.buildErrorResponse(encryptedInvocation(published));
    const { plaintext } = await compactDecrypt(response.formBody['response'] as string, privateKey);

    expect(Object.keys(response.formBody)).toEqual(['response']);
    expect(JSON.parse(new TextDecoder().decode(plaintext))).toEqual({
      state: 'state-value',
      error: 'access_denied',
    });
  });

  it('refuses to answer an encrypted request that publishes no key, rather than posting plaintext', async () => {
    const issuer = await createMockIssuer('https://issuer.example.com');
    const wallet = createMockWallet([await issuer.issue()]);

    await expect(
      wallet.buildResponse(invocationUri(LOGIN_QUERY, { response_mode: 'direct_post.jwt' }))
    ).rejects.toThrow(/publishes no encryption key/);
  });

  it('refuses a published key that carries no kid (§5.1)', async () => {
    const { published } = await verifierKey();
    const unnamed: JWK = { ...published, kid: undefined };

    expect(() => selectResponseEncryptionKey({ jwks: { keys: [unnamed] } })).toThrow(
      /carries no kid/
    );
  });

  it('still posts in the clear under plain direct_post, exactly as before', async () => {
    const issuer = await createMockIssuer('https://issuer.example.com');
    const wallet = createMockWallet([await issuer.issue()]);

    const response = await wallet.buildResponse(invocationUri(LOGIN_QUERY));

    expect(Object.keys(response.formBody).sort()).toEqual(['state', 'vp_token']);
    expect(response.formBody).not.toHaveProperty('response');
  });
});

describe('issuerJwksConfig', () => {
  it('publishes each issuer under its own identifier, with its own key', async () => {
    const first = await createMockIssuer('https://a.example.com', 'k1');
    const second = await createMockIssuer('https://b.example.com', 'k2');

    const parsed = JSON.parse(issuerJwksConfig([first, second])) as Record<
      string,
      Record<string, unknown>[]
    >;

    expect(Object.keys(parsed).sort()).toEqual(['https://a.example.com', 'https://b.example.com']);
    expect(parsed['https://a.example.com']?.[0]?.['kid']).toBe('k1');
    // PUBLIC keys only — a private member here would fail the server's boot, and
    // silently weaken every test that configured it.
    for (const jwks of Object.values(parsed)) {
      for (const jwk of jwks) {
        for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k']) {
          expect(jwk[member]).toBeUndefined();
        }
      }
    }
  });
});
