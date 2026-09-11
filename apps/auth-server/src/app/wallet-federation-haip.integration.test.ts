import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { decodeProtectedHeader, exportJWK, generateKeyPair } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  type E2eInfrastructure,
  extractCsrfToken,
  extractFlowHandle,
  extractInvocationUri,
  generateJwtPem,
  type PemKeyPair,
  REQUIRED_TEST_ENVIRONMENT,
  resetE2eState,
  startE2eInfrastructure,
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

  interface StartedFlow {
    readonly jar: CookieJar;
    readonly handle: string;
    readonly invocationUri: string;
  }

  async function startWalletLogin(app: FastifyInstance, identifier: string): Promise<StartedFlow> {
    const jar = new CookieJar();

    const form = await app.inject({ method: 'GET', url: '/ui/wallet-login' });
    expect(form.statusCode).toBe(200);
    jar.absorb(form.headers['set-cookie']);

    const started = await app.inject({
      method: 'POST',
      url: '/ui/wallet-login',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        ...(jar.header() === undefined ? {} : { cookie: jar.header() as string }),
      },
      payload: new URLSearchParams({
        identifier,
        csrf_token: extractCsrfToken(form.body),
      }).toString(),
    });
    expect(started.statusCode).toBe(200);
    jar.absorb(started.headers['set-cookie']);

    return {
      jar,
      handle: extractFlowHandle(started.body),
      invocationUri: extractInvocationUri(started.body),
    };
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

  async function postWalletResponse(
    app: FastifyInstance,
    formBody: Record<string, string>
  ): Promise<number> {
    const response = await app.inject({
      method: 'POST',
      url: '/oid4vp/response',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams(formBody).toString(),
    });
    return response.statusCode;
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

  /** Start a flow, let the wallet read the JAR and build its (encrypted) answer. */
  async function walletAnswers(
    app: FastifyInstance,
    wallet: MockWallet,
    identifier: string
  ): Promise<{
    flow: StartedFlow;
    request: Oid4vpRequestView;
    answer: WalletAuthorizationResponse;
  }> {
    const flow = await startWalletLogin(app, identifier);
    const request = await fetchAndVerifyRequest(app, flow.invocationUri);
    const answer = await wallet.buildResponseForRequest(request);
    return { flow, request, answer };
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

      // What the wallet sent: one JWE, its header naming the published key.
      expect(Object.keys(answer.formBody)).toEqual(['response']);
      const header = decodeProtectedHeader(answer.formBody['response'] as string);
      expect(header.alg).toBe('ECDH-ES');
      expect(header.kid).toBe(published[0]?.kid);

      expect(await postWalletResponse(app, answer.formBody)).toBe(200);
      expect((await pollStatus(app, flow)).status).toBe('complete');

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

      expect(await postWalletResponse(app, answer.formBody)).toBe(200);
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

      expect(await postWalletResponse(app, { response: forged })).toBe(400);

      // The row is spent: the GENUINE response now fails too. That is the
      // price of "consume before decrypt", and it is the right price — the
      // alternative is a retry oracle against a key QAuth itself published.
      expect(await postWalletResponse(app, answer.formBody)).toBe(400);
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

      expect(plaintext).toBe(400);
      expect((await pollStatus(app, flow)).status).not.toBe('complete');
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
        expect(await postWalletResponse(app, answer.formBody)).toBe(200);
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

        expect(await postWalletResponse(app, answer.formBody)).toBe(200);
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

      const redeemedAt = await second.app.dbPool
        .query<{ redeemed_at: string | null }>('select redeemed_at from oid4vp_request_states')
        .then((result) => result.rows[0]?.redeemed_at);
      expect(redeemedAt).not.toBeNull();
      expect((await pollStatus(second.app, flow)).status).not.toBe('complete');
    } finally {
      await second.close();
    }
  }, 240_000);
});
