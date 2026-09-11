import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { decodeProtectedHeader, exportJWK, generateKeyPair } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  decodeHtmlEntities,
  type E2eInfrastructure,
  followRedirect,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  REQUIRED_TEST_ENVIRONMENT,
  resetE2eState,
  startE2eInfrastructure,
  type StartedWalletFlow,
  startWalletLogin,
  type StartWalletLoginOptions,
  withoutNonces,
} from '../testing/e2e-harness';
import { createMockStatusList, installMockStatusEndpoints } from '../testing/mock-status-list';
import { createMockVerifierPki, verifierIdentityEnvironment } from '../testing/mock-verifier-pki';
import {
  createMockIssuer,
  createMockWallet,
  DEFAULT_VCT,
  encryptAuthorizationResponse,
  issuerJwksConfig,
  type MockCredentialIssuer,
  type MockWallet,
  type Oid4vpRequestView,
  parseOid4vpRequestReference,
  parseOid4vpResponseAck,
  verifyOid4vpRequestObject,
  type WalletAuthorizationResponse,
} from '../testing/mock-wallet';

/**
 * WALLET FEDERATION under `haip-1.0` — the second E2E suite issue #240 asks for
 * (HAIP 1.0, #377 Phases A–C, #379).
 *
 * ## What is asserted, and in what order
 *
 * `createConfiguredProviders` refused `haip-1.0` on four independent counts.
 * #377 cleared the first three and #379 gave the fourth an operator surface:
 *
 *  1. ~~no WRPAC / X.509 verifier material is provisioned~~ — **CLEARED**
 *     (Phase A). `OID4VP_VERIFIER_SIGNING_KEY` and its chain/anchor siblings
 *     provision it, and this suite configures them.
 *  2. ~~`signingAlgs: ['ES256']` unmet~~ — **CLEARED** (Phase A).
 *     `deriveCryptoCapabilities` claims ES256 for a deployment that provisioned
 *     both halves.
 *  3. ~~`responseEncryption: 'required'` unmet~~ — **CLEARED** (Phase C). The
 *     response mode, the per-request key in `client_metadata` and the
 *     decrypting intake ship together, and the capability is a property of the
 *     build — no operator material.
 *  4. `keyStorageAssurance: 'required'` (#308) — provisionable through
 *     `OID4VP_ATTESTING_ISSUERS` (#379), and `requireCredentialStatus` through
 *     the `OID4VP_STATUS_LIST_*` pair (#297).
 *
 * So the first block below holds the boot gate to the NEW truth: a deployment
 * that provisioned the verifier identity and nothing else refuses on count 4
 * SPECIFICALLY — not on any count #377 cleared — and the same deployment with
 * count 4 provisioned BOOTS. A test matching any `/haip-1\.0/` message would
 * keep passing for the cleared counts, which is exactly the false green this
 * ordering discipline exists to prevent.
 *
 * The second block is the E2E itself, against real containers: a signed JAR
 * fetched by `request_uri`, verified by an independent wallet against an
 * out-of-band anchor, answered with a `direct_post.jwt` response encrypted to
 * the per-request key the JAR published, decrypted at the intake by the private
 * half the request-state row carried, and carried through to a session. And
 * the property the encrypted mode adds: a replayed `response` is refused,
 * because the row it names was consumed by the first one.
 *
 * ## What is covered elsewhere
 *
 * The signed-request half of #377 is proven without containers in
 * `helpers/wallet-login-request.test.ts`, which hands the app's own JAR to
 * `testing/mock-wallet.ts` for chain validation; the encrypted intake's refusal
 * matrix — unknown kid, wrong key, tampered ciphertext, mismatched state,
 * downgrade to cleartext — is `routes/oid4vp/response.test.ts`. What only this
 * suite can prove is that the pieces agree with each other across the seams:
 * the key the JAR publishes is the key the row stores, and the row the wallet's
 * `kid` finds is the row the browser's flow record is waiting on.
 *
 * The same-device return leg (#405) is asserted here as well as in the base
 * suite, on purpose: HAIP 1.0 §5.1 is where the `redirect_uri` MUST lives, and
 * under this profile the Response Code is minted for a row the intake found by
 * a JWE `kid` and consumed BEFORE decrypting — a different redemption path from
 * the cleartext `state` one, and the one that has to carry `same_device`
 * through for the acknowledgement to be right.
 *
 * ## Docker
 *
 * The boot-gate block needs no containers — registration throws or completes
 * before anything opens a connection. The E2E block skips locally when no
 * daemon is reachable and FAILS on CI (`requireDockerOrSkip`).
 *
 * @see https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html
 */

const REALM = 'master';
const TRUSTED_ISSUER = 'https://issuer.example.com';

const CLIENT_ID = 'e2e-haip-client';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email', 'profile'];

const CREDENTIAL_CLAIMS = {
  given_name: 'Alice',
  family_name: 'Doe',
  email: 'alice@example.com',
} as const;

const BINDING_CLAIMS = 'given_name,family_name';

/**
 * The verifier-identity half of a HAIP deployment, plus what every enabled
 * deployment needs. Shared by both blocks so the boot-gate refusal and the E2E
 * boot differ only in what count 4 needs.
 */
function haipVerifierEnvironment(pki: ReturnType<typeof createMockVerifierPki>) {
  return {
    WALLET_FEDERATION_ENABLED: 'true',
    OID4VP_VERIFIER_PROFILE: 'haip-1.0',
    OID4VP_REQUESTED_VCT: DEFAULT_VCT,
    // Subject resolution, stated because #379 made it a BOOT gate: an enabled
    // deployment that names no binding claims refuses to start (ADR-010 §6).
    OID4VP_SUBJECT_RESOLUTION: 'asserted-lookup',
    OID4VP_SUBJECT_BINDING_CLAIMS: BINDING_CLAIMS,
    // The verifier identity #377 made provisionable. Without it every refusal
    // below would fire on the CERTIFICATE count, and the assertions would pass
    // for the state that existed before any of this work.
    ...verifierIdentityEnvironment(pki),
  };
}

describe('wallet federation — haip-1.0 boot gate after #377 Phase C', () => {
  it('refuses on the key-storage assurance count, NOT on any count #377 cleared', async () => {
    const jwt = await generateJwtPem();
    const pki = createMockVerifierPki();

    const environment = {
      ...REQUIRED_TEST_ENVIRONMENT,
      // Syntactically valid and never dialled: registration decides first.
      DATABASE_URL: 'postgresql://unused:unused@127.0.0.1:1/unused',
      REDIS_URL: 'redis://127.0.0.1:1/0',
      JWT_PRIVATE_KEY: jwt.privateKey,
      JWT_PUBLIC_KEY: jwt.publicKey,
      ...haipVerifierEnvironment(pki),
    };

    // The control: the same deployment on the BASE profile boots. Without it
    // the assertion below would pass for any configuration mistake at all. It
    // is also what proves the provisioned chain VALIDATED: an unusable one
    // would take this boot down too, since the material is checked whatever
    // profile is selected.
    const base = await bootAuthServer({
      ...environment,
      OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
    });
    await base.close();

    const refusal = await bootAuthServer(environment).then(
      async (server) => {
        await server.close();
        return undefined;
      },
      (error: unknown) => (error instanceof Error ? error.message : String(error))
    );

    expect(refusal).toBeDefined();
    expect(refusal).toContain('haip-1.0');
    // Count 4, named: the next refusal after Phase C.
    expect(refusal).toMatch(/requires key-storage assurance for every presentation/);
    // NOT count 3: the encrypted-response path ships now (Phase C).
    expect(refusal).not.toMatch(/requires encrypted Authorization Responses/);
    // NOT count 2: ES256 is producible (Phase A).
    expect(refusal).not.toMatch(/for request signing, but this deployment's crypto layer/);
    // NOT count 1: the certificate material is provisioned (Phase A).
    expect(refusal).not.toMatch(/X\.509 material that is not configured/);
  }, 60_000);

  it('BOOTS once key-storage assurance and credential status are provisioned too', async () => {
    // The end state: every count cleared by real configuration, nothing forced.
    // `haip-1.0` also mandates credential status (#297), so a deployment that
    // clears count 4 alone would refuse on that next; both are provisioned here
    // and the boot completes.
    const jwt = await generateJwtPem();
    const pki = createMockVerifierPki();
    const statusList = createMockStatusList();

    const server = await bootAuthServer({
      ...REQUIRED_TEST_ENVIRONMENT,
      DATABASE_URL: 'postgresql://unused:unused@127.0.0.1:1/unused',
      REDIS_URL: 'redis://127.0.0.1:1/0',
      JWT_PRIVATE_KEY: jwt.privateKey,
      JWT_PUBLIC_KEY: jwt.publicKey,
      ...haipVerifierEnvironment(pki),
      OID4VP_ATTESTING_ISSUERS: JSON.stringify({ [TRUSTED_ISSUER]: 'iso_18045_high' }),
      OID4VP_STATUS_LIST_TRUST_ANCHORS: statusList.anchorPem,
      OID4VP_STATUS_LIST_URI_ALLOWLIST: statusList.uriAllowlistPrefix,
    });

    try {
      expect(server.app.providerRegistry.has('wallet')).toBe(true);
    } finally {
      await server.close();
    }
  }, 60_000);

  it('refuses to boot on a misconfigured OID4VP_RESPONSE_KEY_SECRET, whatever the profile', async () => {
    // The one operator knob Phase C added is OPTIONAL — but a value that is set
    // and is not a 32-byte key must fail the boot rather than the first
    // sign-in. Asserted on the BASE profile on purpose: the secret is checked
    // whether or not the selected profile would ever use it, like every other
    // OID4VP_* boot gate.
    const jwt = await generateJwtPem();

    await expect(
      bootAuthServer({
        ...REQUIRED_TEST_ENVIRONMENT,
        DATABASE_URL: 'postgresql://unused:unused@127.0.0.1:1/unused',
        REDIS_URL: 'redis://127.0.0.1:1/0',
        JWT_PRIVATE_KEY: jwt.privateKey,
        JWT_PUBLIC_KEY: jwt.publicKey,
        WALLET_FEDERATION_ENABLED: 'false',
        OID4VP_RESPONSE_KEY_SECRET: 'dG9vLXNob3J0',
      })
    ).rejects.toThrow(/OID4VP_RESPONSE_KEY_SECRET must decode to exactly 32 bytes/);
  }, 60_000);
});

describe('wallet federation E2E — haip-1.0 with direct_post.jwt (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;

  /** One verifier PKI per file; the wallet holds its anchor out of band. */
  const pki = createMockVerifierPki();

  let statusList = createMockStatusList();
  let restoreFetch: (() => void) | undefined;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
    // A fresh status list per test: `haip-1.0` requires credential status, and
    // the checker caches a verified list per process.
    statusList = createMockStatusList();
    restoreFetch = installMockStatusEndpoints([statusList]);
  });

  afterEach(() => {
    restoreFetch?.();
    restoreFetch = undefined;
  });

  /** A HAIP deployment that can serve wallet flows end to end. */
  function haipEnv(
    issuers: readonly MockCredentialIssuer[],
    overrides: Record<string, string> = {}
  ): Record<string, string> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    return {
      ...baseEnvironment(infra, jwt),
      ...haipVerifierEnvironment(pki),
      OID4VP_ISSUER_JWKS: issuerJwksConfig(issuers),
      OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
      // Count 4 (#308/#379): the transitive path, at the profile's floor.
      OID4VP_ATTESTING_ISSUERS: JSON.stringify({ [TRUSTED_ISSUER]: 'iso_18045_high' }),
      // Credential status (#297): the two things a checker cannot be built
      // without.
      OID4VP_STATUS_LIST_TRUST_ANCHORS: statusList.anchorPem,
      OID4VP_STATUS_LIST_URI_ALLOWLIST: statusList.uriAllowlistPrefix,
      ...overrides,
    };
  }

  // ---------------------------------------------------------------- helpers

  async function seedClient(app: FastifyInstance): Promise<{ realmId: string; clientId: string }> {
    const realm =
      (await app.repositories.realms.findByName(REALM)) ??
      (await app.repositories.realms.create({ name: REALM, enabled: true }));

    const client = await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'E2E HAIP client',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      enabled: true,
      requirePkce: true,
    });

    return { realmId: realm.id, clientId: client.id };
  }

  /** A started wallet sign-in — the harness's shape, named for the reader. */
  type StartedFlow = StartedWalletFlow;

  /**
   * The session cookie's name — `SESSION_COOKIE_NAME` in
   * `helpers/session-cookie.ts`, which reads `env` at load and so cannot be
   * imported by a file that boots deployments with different environments.
   */
  const SESSION_COOKIE = '__Host-qauth_session';

  /** The one refusal page `/ui/wallet-login/return` renders, by its title. */
  const RETURN_REFUSAL_TITLE = 'Finish signing in where you started';

  /**
   * Whether a browser holding this jar can obtain an authorization code — the
   * strongest available statement of "no session was created".
   */
  async function canMintAuthorizationCode(app: FastifyInstance, jar: CookieJar): Promise<boolean> {
    const pkce = pkcePair();
    const authorize = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'e2e-state',
      }).toString()}`,
      headers: { ...(jar.header() === undefined ? {} : { cookie: jar.header() as string }) },
    });

    const location = authorize.headers['location'];
    if (typeof location !== 'string') return false;
    if (!location.startsWith(REDIRECT_URI)) return false;
    return new URL(location).searchParams.get('code') !== null;
  }

  /**
   * Do what a HAIP wallet does with the invocation URI: follow the
   * `request_uri` reference, fetch the JAR from the running server, and verify
   * it against the anchor the wallet holds out of band. The request the wallet
   * acts on is the one INSIDE the signature — nothing off the URI.
   */
  async function fetchAndVerifyRequest(
    app: FastifyInstance,
    invocationUri: string
  ): Promise<Oid4vpRequestView> {
    const reference = parseOid4vpRequestReference(invocationUri);
    const fetched = await app.inject({
      method: 'GET',
      url: new URL(reference.requestUri).pathname,
    });
    expect(fetched.statusCode).toBe(200);

    const verified = await verifyOid4vpRequestObject(fetched.body, {
      trustAnchorPem: pki.walletTrustAnchorPem,
    });
    expect(verified.request.clientId).toBe(reference.clientId);
    return verified.request;
  }

  /**
   * POST a wallet response to the `direct_post` endpoint.
   *
   * @returns the status code AND the parsed JSON body — since #405 the body
   * tells the wallet whether to bring the user agent back (OID4VP 1.0 §8.2).
   */
  async function postWalletResponse(
    app: FastifyInstance,
    formBody: Record<string, string>
  ): Promise<{ statusCode: number; body: unknown }> {
    const response = await app.inject({
      method: 'POST',
      url: '/oid4vp/response',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams(formBody).toString(),
    });
    return { statusCode: response.statusCode, body: JSON.parse(response.body) as unknown };
  }

  /** The one request-state row's encryption columns, as the TABLE holds them. */
  async function storedEncryptionColumns(app: FastifyInstance): Promise<{
    redeemed: boolean;
    response_encryption_kid: string | null;
    response_encryption_private_jwk: string | null;
    response_encryption_key_protection: string | null;
  }> {
    const { rows } = await app.dbPool.query<{
      redeemed_at: string | null;
      response_encryption_kid: string | null;
      response_encryption_private_jwk: string | null;
      response_encryption_key_protection: string | null;
    }>(
      'select redeemed_at, response_encryption_kid, response_encryption_private_jwk, response_encryption_key_protection from oid4vp_request_states'
    );
    expect(rows).toHaveLength(1);
    const { redeemed_at, ...columns } = rows[0] as NonNullable<(typeof rows)[0]>;
    return { redeemed: redeemed_at !== null, ...columns };
  }

  async function pollStatus(
    app: FastifyInstance,
    flow: StartedFlow
  ): Promise<{ status: string; redirect_to?: string }> {
    const response = await app.inject({
      method: 'GET',
      url: `/ui/wallet-login/${flow.handle}/status`,
      headers: {
        ...(flow.jar.header() === undefined ? {} : { cookie: flow.jar.header() as string }),
      },
    });
    flow.jar.absorb(response.headers['set-cookie']);
    return response.json() as { status: string; redirect_to?: string };
  }

  /** Boot a deployment, seed it, and hand it to the body — then close it. */
  async function withDeployment<T>(
    environment: Record<string, string>,
    body: (context: {
      app: FastifyInstance;
      ids: { realmId: string; clientId: string };
    }) => Promise<T>
  ): Promise<T> {
    let booted: BootedAuthServer | undefined;
    try {
      booted = await bootAuthServer(environment);
      await resetE2eState(booted.app);
      const ids = await seedClient(booted.app);
      return await body({ app: booted.app, ids });
    } finally {
      await booted?.close();
    }
  }

  /** A wallet holding one live, status-bearing credential from `issuer`. */
  async function walletHolding(issuer: MockCredentialIssuer): Promise<MockWallet> {
    const credential = await issuer.issue({
      claims: { ...CREDENTIAL_CLAIMS },
      status: statusList.statusClaimFor(0),
    });
    return createMockWallet([credential]);
  }

  /**
   * Start a flow, let the wallet read the JAR and build its (encrypted) answer.
   *
   * `options.device` is the sign-in form's choice (#405); omitted, the flow is
   * cross-device, as every scenario written before #405 expects.
   */
  async function walletAnswers(
    app: FastifyInstance,
    wallet: MockWallet,
    identifier: string,
    options: StartWalletLoginOptions = {}
  ): Promise<{
    flow: StartedFlow;
    request: Oid4vpRequestView;
    answer: WalletAuthorizationResponse;
  }> {
    const flow = await startWalletLogin(app, identifier, options);
    const request = await fetchAndVerifyRequest(app, flow.invocationUri);
    const answer = await wallet.buildResponseForRequest(request);
    return { flow, request, answer };
  }

  /**
   * Post an answer and read the acknowledgement as the wallet does: a 200 with
   * a body the wallet's own parser accepts (OID4VP 1.0 §8.2).
   */
  async function acknowledged(
    app: FastifyInstance,
    formBody: Record<string, string>
  ): Promise<{ redirectUri?: string; responseCode?: string }> {
    const posted = await postWalletResponse(app, formBody);
    expect(posted.statusCode).toBe(200);
    return parseOid4vpResponseAck(posted.body);
  }

  // ------------------------------------------------------- the scenarios

  it('completes a wallet login end to end over a signed JAR and an encrypted direct_post.jwt response', async () => {
    const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
    const wallet = await walletHolding(issuer);

    await withDeployment(haipEnv([issuer]), async ({ app, ids }) => {
      const asserted = 'haip-newcomer@example.com';
      const { flow, request, answer } = await walletAnswers(app, wallet, asserted);

      // What the JAR asked for: the whole HAIP shape at once.
      expect(request.clientId.startsWith('x509_hash:')).toBe(true);
      expect(request.responseMode).toBe('direct_post.jwt');
      const published = (request.clientMetadata['jwks'] as { keys: { kid?: string }[] }).keys;
      expect(published).toHaveLength(1);
      expect(request.clientMetadata['encrypted_response_enc_values_supported']).toContain(
        'A128GCM'
      );

      // What the wallet sent: one JWE, its header naming the published key —
      // under the `enc` HAIP §5 has a wallet prefer when both are advertised.
      expect(Object.keys(answer.formBody)).toEqual(['response']);
      const header = decodeProtectedHeader(answer.formBody['response'] as string);
      expect(header.alg).toBe('ECDH-ES');
      expect(header.enc).toBe('A256GCM');
      expect(header.kid).toBe(published[0]?.kid);

      // Cross-device (no device choice): acknowledged with exactly `{}` —
      // OID4VP 1.0 §14.2, the Response Code technique "is not applicable to
      // cross-device scenarios" — and completed by polling.
      const posted = await postWalletResponse(app, answer.formBody);
      expect(posted.statusCode).toBe(200);
      expect(posted.body).toEqual({});
      expect((await pollStatus(app, flow)).status).toBe('complete');

      // The row was consumed — and its key went with it. The private half's
      // only job ended with the response it opened; a key that outlived it
      // would decrypt this login again from a later dump of the table plus a
      // retained copy of the POST body.
      expect(await storedEncryptionColumns(app)).toEqual({
        redeemed: true,
        response_encryption_kid: null,
        response_encryption_private_jwk: null,
        response_encryption_key_protection: null,
      });

      // The login is real: an account, keyed on the ASSERTED identifier
      // (ADR-009 §1), with its wallet credential and verified attributes.
      const rows = await app.repositories.userCredentials.findAllByRealmAndExternalSub(
        ids.realmId,
        asserted
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]?.providerType).toBe('wallet');
    });
  }, 180_000);

  it('refuses a REPLAYED response — the row its kid names was consumed by the first', async () => {
    const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
    const wallet = await walletHolding(issuer);

    await withDeployment(haipEnv([issuer]), async ({ app }) => {
      const { flow, answer } = await walletAnswers(app, wallet, 'haip-replay@example.com');

      expect((await postWalletResponse(app, answer.formBody)).statusCode).toBe(200);
      expect((await pollStatus(app, flow)).status).toBe('complete');

      // The identical ciphertext, again. The kid finds no live row — the
      // single guarded UPDATE consumed it — and the refusal is the uniform one.
      const replay = await app.inject({
        method: 'POST',
        url: '/oid4vp/response',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: new URLSearchParams(answer.formBody).toString(),
      });
      expect(replay.statusCode).toBe(400);
      expect(replay.json()).toMatchObject({ error: 'invalid_request' });
    });
  }, 180_000);

  it('refuses a response encrypted to a key it never published — after consuming the row', async () => {
    // The attack §14.5 warns about, at the wire: anyone can name a live kid in
    // a JWE header, so a wrong-key ciphertext must find the row, SPEND it, and
    // fail — never leave it live for a second try, and never decrypt.
    const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
    const wallet = await walletHolding(issuer);

    await withDeployment(haipEnv([issuer]), async ({ app }) => {
      const { flow, request, answer } = await walletAnswers(
        app,
        wallet,
        'haip-wrongkey@example.com'
      );
      const published = (request.clientMetadata['jwks'] as { keys: { kid: string }[] }).keys[0];

      // A JWE to a key the Verifier never published, echoing the real kid.
      const rogue = await generateKeyPair('ECDH-ES', { crv: 'P-256' });
      const forged = await encryptAuthorizationResponse(
        request,
        { state: request.state, vp_token: answer.vpToken },
        { recipient: { ...(await exportJWK(rogue.publicKey)), kid: published?.kid } }
      );

      expect((await postWalletResponse(app, { response: forged })).statusCode).toBe(400);

      // The row is spent: the GENUINE response now fails too. That is the
      // price of "consume before decrypt", and it is the right price — the
      // alternative is a retry oracle against a key QAuth itself published.
      expect((await postWalletResponse(app, answer.formBody)).statusCode).toBe(400);
      expect((await pollStatus(app, flow)).status).not.toBe('complete');
    });
  }, 180_000);

  it('refuses the same response posted in the CLEAR — required encryption is not preferred encryption', async () => {
    // Whoever fetched the JAR holds its `state`. Under haip-1.0 the plaintext
    // form must not consume the request as a success.
    const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
    const wallet = await walletHolding(issuer);

    await withDeployment(haipEnv([issuer]), async ({ app }) => {
      const { flow, request, answer } = await walletAnswers(
        app,
        wallet,
        'haip-downgrade@example.com'
      );

      const plaintext = await postWalletResponse(app, {
        state: request.state,
        vp_token: JSON.stringify(answer.vpToken),
      });

      expect(plaintext.statusCode).toBe(400);
      expect((await pollStatus(app, flow)).status).not.toBe('complete');
    });
  }, 180_000);

  it('completes the login when the JWE arrives with a stray cleartext state beside it', async () => {
    // OID4VP 1.0 is silent on whether `state` may ride beside `response`, so a
    // conformant wallet MAY send both. The body has to be routed by the JWE —
    // a cleartext-first parse stripped the `response`, consumed the row by the
    // stray `state`, and refused the login as a mode downgrade.
    const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
    const wallet = await walletHolding(issuer);

    await withDeployment(haipEnv([issuer]), async ({ app, ids }) => {
      const asserted = 'haip-stray-state@example.com';
      const { flow, request, answer } = await walletAnswers(app, wallet, asserted);

      expect(
        (await postWalletResponse(app, { ...answer.formBody, state: request.state })).statusCode
      ).toBe(200);
      expect((await pollStatus(app, flow)).status).toBe('complete');

      const rows = await app.repositories.userCredentials.findAllByRealmAndExternalSub(
        ids.realmId,
        asserted
      );
      expect(rows).toHaveLength(1);
    });
  }, 180_000);

  it('tells the browser the wallet declined when the refusal arrives unencrypted (§8.3.1)', async () => {
    // OID4VP 1.0 §8.3.1: a wallet unable to encrypt MAY send its error
    // response in the clear. Refusing that refusal left the browser polling
    // until the request expired, never learning the wallet said no.
    const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
    const wallet = await walletHolding(issuer);

    await withDeployment(haipEnv([issuer]), async ({ app, ids }) => {
      const asserted = 'haip-declined-clear@example.com';
      const { flow, request } = await walletAnswers(app, wallet, asserted);

      const declined = await postWalletResponse(app, {
        state: request.state,
        error: 'access_denied',
      });
      expect(declined.statusCode).toBe(200);
      // Cross-device: nothing to follow, even for an error (§14.2).
      expect(declined.body).toEqual({});
      expect((await pollStatus(app, flow)).status).toBe('rejected');

      // Consumed, key erased, and nobody was created.
      expect((await storedEncryptionColumns(app)).response_encryption_private_jwk).toBeNull();
      expect(
        await app.repositories.userCredentials.findAllByRealmAndExternalSub(ids.realmId, asserted)
      ).toHaveLength(0);

      // A replay of the same unencrypted refusal finds nothing.
      expect(
        (await postWalletResponse(app, { state: request.state, error: 'access_denied' })).statusCode
      ).toBe(400);
    });
  }, 180_000);

  it('still refuses an untrusted issuer under the encrypted mode, creating nothing', async () => {
    // Decryption establishes nothing about the credential: the trust gate
    // (#236) runs on the decrypted presentation exactly as on a cleartext one.
    const trusted = await createMockIssuer(TRUSTED_ISSUER, 'k1');
    const rogue = await createMockIssuer('https://rogue-issuer.example.net', 'r1');
    const wallet = await walletHolding(rogue);

    await withDeployment(
      haipEnv([trusted, rogue], {
        OID4VP_ATTESTING_ISSUERS: JSON.stringify({
          [TRUSTED_ISSUER]: 'iso_18045_high',
          'https://rogue-issuer.example.net': 'iso_18045_high',
        }),
      }),
      async ({ app, ids }) => {
        const asserted = 'haip-nobody@example.com';
        const { flow, answer } = await walletAnswers(app, wallet, asserted);

        // The transport accepts it — it is well-formed and correlated — and
        // the verification seam refuses it.
        expect((await postWalletResponse(app, answer.formBody)).statusCode).toBe(200);
        expect((await pollStatus(app, flow)).status).toBe('rejected');
        expect(
          await app.repositories.userCredentials.findAllByRealmAndExternalSub(ids.realmId, asserted)
        ).toEqual([]);
      }
    );
  }, 180_000);

  it('decrypts a row whose key was stored under OID4VP_RESPONSE_KEY_SECRET', async () => {
    // The opt-in at-rest envelope, end to end: the request helper wraps the
    // private half under the configured secret, the intake unwraps it by the
    // marker the ROW carries, and the login completes.
    const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
    const wallet = await walletHolding(issuer);
    const secret = Buffer.alloc(32, 7).toString('base64');

    await withDeployment(
      haipEnv([issuer], { OID4VP_RESPONSE_KEY_SECRET: secret }),
      async ({ app }) => {
        const { flow, answer } = await walletAnswers(app, wallet, 'haip-wrapped@example.com');

        // The row holds an ENVELOPE, not a JWK: the private scalar is not in the
        // column in the clear, and the marker says which scheme wrote it.
        const stored = await app.dbPool
          .query<{
            response_encryption_key_protection: string;
            response_encryption_private_jwk: string;
          }>(
            'select response_encryption_key_protection, response_encryption_private_jwk from oid4vp_request_states'
          )
          .then((result) => result.rows[0]);
        expect(stored?.response_encryption_key_protection).toBe('aes-256-gcm');
        expect(stored?.response_encryption_private_jwk.startsWith('1.')).toBe(true);
        expect(stored?.response_encryption_private_jwk).not.toContain('"d"');

        expect((await postWalletResponse(app, answer.formBody)).statusCode).toBe(200);
        expect((await pollStatus(app, flow)).status).toBe('complete');
      }
    );
  }, 180_000);

  it('refuses — and still consumes — a row written under a secret the process no longer holds', async () => {
    // The bounded consequence the env doc names: rotate the secret with a
    // sign-in in flight and that sign-in is lost, nothing else. The row is
    // found by kid and SPENT before the envelope is opened, so the refusal is
    // the uniform one and the correlator does not survive to be retried under
    // the right secret later.
    if (infra === undefined) throw new Error('infrastructure not started');
    const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
    const wallet = await walletHolding(issuer);
    const written = Buffer.alloc(32, 7).toString('base64');
    const rotated = Buffer.alloc(32, 9).toString('base64');

    // Written under one secret...
    const first = await bootAuthServer(haipEnv([issuer], { OID4VP_RESPONSE_KEY_SECRET: written }));
    let flow: StartedFlow;
    let answer: WalletAuthorizationResponse;
    try {
      await resetE2eState(first.app);
      await seedClient(first.app);
      ({ flow, answer } = await walletAnswers(first.app, wallet, 'haip-rotated@example.com'));
    } finally {
      await first.close();
    }

    // ...and posted to a process holding another. Same Postgres and Redis —
    // the row and the browser's flow record are both still there — so this is
    // a rotation mid-flight, not a fresh deployment.
    const second = await bootAuthServer(haipEnv([issuer], { OID4VP_RESPONSE_KEY_SECRET: rotated }));
    try {
      const refused = await second.app.inject({
        method: 'POST',
        url: '/oid4vp/response',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: new URLSearchParams(answer.formBody).toString(),
      });
      expect(refused.statusCode).toBe(400);
      expect(refused.json()).toMatchObject({ error: 'invalid_request' });

      // Consumed — and the envelope the rotated secret could not open is gone
      // with it: erased by the redemption itself, whether or not the decrypt
      // that followed succeeded.
      expect(await storedEncryptionColumns(second.app)).toEqual({
        redeemed: true,
        response_encryption_kid: null,
        response_encryption_private_jwk: null,
        response_encryption_key_protection: null,
      });
      expect((await pollStatus(second.app, flow)).status).not.toBe('complete');
    } finally {
      await second.close();
    }
  }, 240_000);

  // ------------------------------------ the same-device return leg (#405)

  it('(HAIP 1.0 §5.1) completes a same-device login on the return leg — the redirect_uri rides in the acknowledgement of the ENCRYPTED response, never in the poll', async () => {
    const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
    const wallet = await walletHolding(issuer);

    await withDeployment(haipEnv([issuer]), async ({ app, ids }) => {
      const asserted = 'haip-same-device@example.com';
      const { flow, request, answer } = await walletAnswers(app, wallet, asserted, {
        device: 'this',
      });

      // The same JAR, the same JWE — the device choice changes nothing the
      // wallet sees on the request side.
      expect(request.responseMode).toBe('direct_post.jwt');
      expect(Object.keys(answer.formBody)).toEqual(['response']);
      // And exactly one affordance on the page: the deep link, no QR.
      expect(flow.page).toMatch(/href="openid4vp:/);
      expect(flow.page).not.toContain('<svg');

      // The acknowledgement of the JWE carries the return leg: an absolute
      // URI under the issuer with a fresh Response Code (OID4VP 1.0 §8.2).
      const ack = await acknowledged(app, answer.formBody);
      if (ack.redirectUri === undefined) throw new Error('no redirect_uri in the ack');
      const target = new URL(ack.redirectUri);
      expect(target.origin).toBe(new URL(REQUIRED_TEST_ENVIRONMENT['JWT_ISSUER'] as string).origin);
      expect(target.pathname).toBe('/ui/wallet-login/return');
      expect(ack.responseCode).toMatch(/^[A-Za-z0-9_-]{43}$/);

      // The row was consumed by the kid path — the key erased — and the
      // digest of the code is what remains to be spent by the return route.
      expect(await storedEncryptionColumns(app)).toEqual({
        redeemed: true,
        response_encryption_kid: null,
        response_encryption_private_jwk: null,
        response_encryption_key_protection: null,
      });

      // §14.2: the poll never completes a same-device flow.
      expect((await pollStatus(app, flow)).status).toBe('pending');
      expect(await canMintAuthorizationCode(app, flow.jar)).toBe(false);

      // The wallet brings the same browser back; the landing signs it in and
      // the original tab's poll consumes the marker once.
      const landed = await followRedirect(app, flow.jar, ack.redirectUri);
      expect(landed.statusCode).toBe(200);
      expect(decodeHtmlEntities(landed.body)).toContain("You're signed in");
      expect(landed.body).toContain('history.replaceState');
      expect(landed.headers['cache-control']).toBe('no-store');
      expect(landed.headers['referrer-policy']).toBe('no-referrer');
      expect(flow.jar.get(SESSION_COOKIE)).toBeDefined();

      expect(await pollStatus(app, flow)).toEqual({ status: 'complete', redirect_to: '/' });
      expect((await pollStatus(app, flow)).status).toBe('expired');

      // A real login, keyed on the asserted identifier, with a session that
      // the authorization endpoint honours. Consent is pre-granted so this
      // drives the code-mint path rather than the consent screen.
      const rows = await app.repositories.userCredentials.findAllByRealmAndExternalSub(
        ids.realmId,
        asserted
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]?.providerType).toBe('wallet');
      const userId = rows[0]?.userId;
      if (userId === undefined) throw new Error('the same-device login enrolled no account');
      await app.repositories.oauthConsents.upsertGrant(userId, ids.clientId, ids.realmId, SCOPES);
      expect(await canMintAuthorizationCode(app, flow.jar)).toBe(true);
    });
  }, 180_000);

  it('(HAIP 1.0 §5.1) rejects an encrypted presentation whose redirect back arrives in a different user session', async () => {
    const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
    const wallet = await walletHolding(issuer);

    await withDeployment(haipEnv([issuer]), async ({ app, ids }) => {
      const asserted = 'haip-foreign@example.com';
      const { flow, answer } = await walletAnswers(app, wallet, asserted, { device: 'this' });
      const ack = await acknowledged(app, answer.formBody);
      if (ack.redirectUri === undefined) throw new Error('no redirect_uri in the ack');

      // A browser holding none of the flow's cookies: the refusal page, no
      // session, and the code is now spent.
      const elsewhere = new CookieJar();
      const landed = await followRedirect(app, elsewhere, ack.redirectUri);
      expect(landed.statusCode).toBe(200);
      expect(landed.body).toContain(RETURN_REFUSAL_TITLE);
      expect(elsewhere.get(SESSION_COOKIE)).toBeUndefined();

      // The initiating tab is told; the presentation was discarded, so no
      // account exists for it and neither browser can mint a code.
      expect((await pollStatus(app, flow)).status).toBe('rejected');
      expect(await canMintAuthorizationCode(app, elsewhere)).toBe(false);
      expect(await canMintAuthorizationCode(app, flow.jar)).toBe(false);
      expect(
        await app.repositories.userCredentials.findAllByRealmAndExternalSub(ids.realmId, asserted)
      ).toEqual([]);

      // The right browser, too late: the same page, byte for byte.
      const late = await followRedirect(app, flow.jar, ack.redirectUri);
      expect(withoutNonces(late.body)).toBe(withoutNonces(landed.body));
      expect(flow.jar.get(SESSION_COOKIE)).toBeUndefined();
    });
  }, 180_000);

  it('(OID4VP 1.0 §8.2) hands a same-device wallet a redirect_uri even for an UNENCRYPTED refusal, and a cross-device one nothing', async () => {
    // §8.2 permits the redirect_uri "in response to […] Error Responses" and
    // HAIP §5.1's MUST carries no success qualifier, so a wallet that declined
    // is still brought back — and what it is brought back to is the existing
    // refusal, never a session. The cross-device twin of this case is the
    // §8.3.1 scenario above, which asserts the empty acknowledgement.
    const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
    const wallet = await walletHolding(issuer);

    await withDeployment(haipEnv([issuer]), async ({ app, ids }) => {
      // (a) The original tab polls first: a wallet error reaches it ungated,
      // and the redirect arriving afterwards finds no flow to advance.
      const polledFirst = await walletAnswers(app, wallet, 'haip-declined-poll@example.com', {
        device: 'this',
      });
      const ackA = await acknowledged(app, {
        state: polledFirst.request.state,
        error: 'access_denied',
      });
      expect(ackA.redirectUri).toBeDefined();
      expect(ackA.responseCode).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect((await pollStatus(app, polledFirst.flow)).status).toBe('rejected');

      const lateLanding = await followRedirect(
        app,
        polledFirst.flow.jar,
        ackA.redirectUri as string
      );
      expect(lateLanding.statusCode).toBe(200);
      expect(lateLanding.body).toContain(RETURN_REFUSAL_TITLE);
      expect(polledFirst.flow.jar.get(SESSION_COOKIE)).toBeUndefined();

      // (b) The wallet brings the browser back first: the landing renders the
      // existing "not completed" refusal (401), and the original tab then
      // finds the flow gone.
      const returnedFirst = await walletAnswers(app, wallet, 'haip-declined-return@example.com', {
        device: 'this',
      });
      const ackB = await acknowledged(app, {
        state: returnedFirst.request.state,
        error: 'access_denied',
      });
      if (ackB.redirectUri === undefined)
        throw new Error('no redirect_uri for a same-device error');

      const landed = await followRedirect(app, returnedFirst.flow.jar, ackB.redirectUri);
      expect(landed.statusCode).toBe(401);
      expect(landed.body).toContain('Sign-in was not completed');
      expect(landed.headers['cache-control']).toBe('no-store');
      expect(landed.headers['referrer-policy']).toBe('no-referrer');
      expect(returnedFirst.flow.jar.get(SESSION_COOKIE)).toBeUndefined();
      expect((await pollStatus(app, returnedFirst.flow)).status).toBe('expired');

      // Nobody was created, nobody can mint, on either path.
      for (const asserted of [
        'haip-declined-poll@example.com',
        'haip-declined-return@example.com',
      ]) {
        expect(
          await app.repositories.userCredentials.findAllByRealmAndExternalSub(ids.realmId, asserted)
        ).toEqual([]);
      }
      expect(await canMintAuthorizationCode(app, polledFirst.flow.jar)).toBe(false);
      expect(await canMintAuthorizationCode(app, returnedFirst.flow.jar)).toBe(false);
    });
  }, 180_000);
});
