import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  backdateWalletPresentationSignal,
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  decodeHtmlEntities,
  decodeJwtClaims,
  type E2eInfrastructure,
  extractCsrfToken,
  extractFlowHandle,
  followRedirect,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  readInvocationUriFromPendingPage,
  REQUIRED_TEST_ENVIRONMENT,
  resetE2eState,
  startE2eInfrastructure,
  type StartedWalletFlow,
  startWalletLogin,
  type WalletDeviceChoice,
  withoutNonces,
} from '../testing/e2e-harness';
import {
  createMockIssuer,
  createMockWallet,
  DEFAULT_VCT,
  type HeldCredential,
  issuerJwksConfig,
  type MockCredentialIssuer,
  type MockWallet,
  parseOid4vpRequest,
  parseOid4vpResponseAck,
} from '../testing/mock-wallet';
import { WALLET_RETURN_CODE_TTL_MS } from './constants';

/**
 * WALLET FEDERATION, END TO END (issue #240, ADR-004 / ADR-009 / ADR-010).
 *
 * The whole T4 stack against a real Postgres, a real Redis and a mock wallet
 * that speaks OID4VP 1.0 over the wire: an unsigned authorization request under
 * the `oid4vp-1.0-base` profile with a `redirect_uri` Client Identifier Prefix,
 * a DCQL query, a `vp_token` keyed by DCQL Credential Query id, and an
 * unencrypted `direct_post` form response.
 *
 * ## Why this suite exists at all
 *
 * Every sibling issue in T4 is unit-tested inside its own library, and each of
 * those suites necessarily stubs its neighbours. The properties that matter to a
 * deployment are the ones that only exist ACROSS the seams:
 *
 * - a first-time wallet login creates a user, its `user_credentials` row and its
 *   `user_attributes` rows — and keys the credential on the ASSERTED identifier,
 *   never on a wallet key (ADR-009 Finding 1);
 * - a linked wallet credential and the account's password credential mint tokens
 *   with the IDENTICAL `sub` (#238);
 * - an untrusted issuer is refused before any account is touched, with a refusal
 *   byte-identical to every other (#236);
 * - `acr` reaches the ID token on the wallet path (#237) and NEVER on the
 *   password path — the invariant most likely to break silently;
 * - a deployment with no `VerifierProfile` serves no wallet flow at all
 *   (#296 Q1, LOCKED);
 * - a flow started for a wallet on THIS device completes only on the return
 *   leg, in the browser that started it, and a cross-device flow completes by
 *   polling exactly as before (#405, OID4VP 1.0 §8.2 / §14.2, HAIP 1.0 §5.1) —
 *   the Response Code is minted by the response endpoint, spent by the return
 *   route and matched against the browser's binder cookie, three seams no
 *   unit test holds at once.
 *
 * ## The wallet is not the code under test
 *
 * `src/testing/mock-wallet.ts` is built on `@qauth-labs/core-crypto` and `jose`
 * and imports nothing from the verifier. Its presentations are validated by the
 * shipping #234 validator inside the running server, so an encoding divergence
 * fails here rather than being absorbed by a shared helper. See that module for
 * why it does not reuse `libs/server/federation/testing/sd-jwt-vc.fixture.ts`.
 *
 * ## Docker
 *
 * Locally the suite skips when no daemon is reachable; on CI it FAILS
 * (`requireDockerOrSkip`), because a silent skip here is indistinguishable from
 * a pass while asserting nothing.
 */

/** The realm every deployment in this suite uses. `OID4VP_*` maps key on it. */
const REALM = 'master';

/** The issuer a realm trusts, and the one it does not. */
const TRUSTED_ISSUER = 'https://issuer.example.com';
const UNTRUSTED_ISSUER = 'https://rogue-issuer.example.net';

/** The OAuth client the E2E exchanges an authorization code with. */
const CLIENT_ID = 'e2e-wallet-client';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email', 'profile'];

/** Selectively disclosable claims the mock credential carries. */
const CREDENTIAL_CLAIMS = {
  given_name: 'Alice',
  family_name: 'Doe',
  email: 'alice@example.com',
} as const;

/** The claim set `asserted-lookup` derives its entitlement binding from. */
const BINDING_CLAIMS = 'given_name,family_name';

describe('wallet federation E2E (oid4vp-1.0-base, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;

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
  });

  /** Environment for a deployment that CAN serve wallet flows. */
  function walletEnabledEnv(overrides: Record<string, string> = {}): Record<string, string> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    return {
      ...baseEnvironment(infra, jwt),
      WALLET_FEDERATION_ENABLED: 'true',
      OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
      OID4VP_REQUESTED_VCT: DEFAULT_VCT,
      OID4VP_SUBJECT_RESOLUTION: 'asserted-lookup',
      OID4VP_SUBJECT_BINDING_CLAIMS: BINDING_CLAIMS,
      ...overrides,
    };
  }

  // ---------------------------------------------------------------- helpers

  /** Seed the realm and a public PKCE client, returning their ids. */
  async function seedClient(app: FastifyInstance): Promise<{ realmId: string; clientId: string }> {
    const realm =
      (await app.repositories.realms.findByName(REALM)) ??
      (await app.repositories.realms.create({ name: REALM, enabled: true }));

    const client = await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CLIENT_ID,
      // A PUBLIC client (`none`) with mandatory PKCE — the posture OAuth 2.1
      // prescribes for a browser client, and the one that needs no secret here.
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'E2E wallet client',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      enabled: true,
      requirePkce: true,
    });

    return { realmId: realm.id, clientId: client.id };
  }

  /** Register a password account through the real registration route. */
  async function registerPasswordUser(
    app: FastifyInstance,
    email: string,
    password = 'Correct-Horse-Battery-Staple-42!'
  ): Promise<string> {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password },
    });
    expect(response.statusCode).toBe(201);
    const body = response.json() as { user?: { id?: string }; id?: string };
    const userId = body.user?.id ?? body.id;
    if (typeof userId !== 'string') {
      throw new Error(`registration returned no user id: ${response.body}`);
    }
    return userId;
  }

  /** A started wallet sign-in — the harness's shape, named for the reader. */
  type StartedFlow = StartedWalletFlow;

  /**
   * POST a wallet response to the `direct_post` endpoint.
   *
   * @returns the status code AND the parsed JSON body: since #405 the body
   * is the wallet's next instruction — `{}` to stop, `{ redirect_uri }` to
   * bring the user agent back (OID4VP 1.0 §8.2) — so a suite has to read it.
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

  /**
   * The session cookie's name — `SESSION_COOKIE_NAME` in
   * `helpers/session-cookie.ts`, which reads `env` at load and so cannot be
   * imported by a file that boots deployments with different environments.
   */
  const SESSION_COOKIE = '__Host-qauth_session';

  /** The one refusal page `/ui/wallet-login/return` renders, by its title. */
  const RETURN_REFUSAL_TITLE = 'Finish signing in where you started';

  /**
   * Whether a browser holding this jar can obtain an authorization code.
   *
   * The strongest available statement of "no session was created": not that a
   * cookie is absent, but that the OAuth authorization endpoint will not mint
   * a code for whatever the browser is holding.
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

  /** Poll the flow's status endpoint once, absorbing any cookie it sets. */
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

  /**
   * Run a complete CROSS-DEVICE wallet sign-in: start the flow with no device
   * choice (the pre-#405 default), let the wallet answer, poll.
   *
   * Asserts on the way that the response endpoint acknowledged with exactly
   * `{}` — OID4VP 1.0 §14.2: the Response Code technique "is not applicable to
   * cross-device scenarios", so a `redirect_uri` here would be a wallet sent
   * to a browser that does not hold the flow.
   *
   * @returns the terminal status and the browser's cookie jar (which carries the
   * session cookie on success).
   */
  async function signInWithWallet(
    app: FastifyInstance,
    wallet: MockWallet,
    identifier: string
  ): Promise<{ status: string; jar: CookieJar; flow: StartedFlow }> {
    const flow = await startWalletLogin(app, identifier);
    const response = await wallet.buildResponse(flow.invocationUri);
    const posted = await postWalletResponse(app, response.formBody);
    expect(posted.statusCode).toBe(200);
    expect(posted.body).toEqual({});
    const outcome = await pollStatus(app, flow);
    return { status: outcome.status, jar: flow.jar, flow };
  }

  /**
   * Start a SAME-DEVICE flow and let the wallet answer it, returning the
   * `redirect_uri` the response endpoint handed the wallet — the leg every
   * #405 scenario begins with. The user agent has NOT followed it yet.
   */
  async function presentOnThisDevice(
    app: FastifyInstance,
    wallet: MockWallet,
    identifier: string
  ): Promise<{ flow: StartedFlow; redirectUri: string; responseCode: string }> {
    const flow = await startWalletLogin(app, identifier, { device: 'this' });
    const response = await wallet.buildResponse(flow.invocationUri);
    const posted = await postWalletResponse(app, response.formBody);
    expect(posted.statusCode).toBe(200);

    // What the wallet does with the body (HAIP 1.0 §5.1: "Wallets MUST follow
    // the redirect to redirect_uri") — read by the wallet's own parser, which
    // refuses every shape but the two the spec allows.
    const ack = parseOid4vpResponseAck(posted.body);
    if (ack.redirectUri === undefined || ack.responseCode === undefined) {
      throw new Error(`a same-device presentation was acknowledged without a redirect_uri`);
    }
    return { flow, redirectUri: ack.redirectUri, responseCode: ack.responseCode };
  }

  /** The `users.id` behind the wallet credential enrolled for `asserted`, if any. */
  async function enrolledUserId(
    app: FastifyInstance,
    realmId: string,
    asserted: string
  ): Promise<string | undefined> {
    const rows = await app.repositories.userCredentials.findAllByRealmAndExternalSub(
      realmId,
      asserted
    );
    return rows[0]?.userId;
  }

  /**
   * Exchange a browser session for an ID token, through the REAL
   * `/oauth/authorize` → `/oauth/token` path.
   *
   * Consent is pre-granted at the repository so this drives the code-mint path
   * rather than the consent screen — the consent UI is #150's, and what #237
   * needs asserted is that `authorization_codes.assurance_level` survives from
   * the session to the ID token.
   */
  async function idTokenFor(
    app: FastifyInstance,
    jar: CookieJar,
    ids: { realmId: string; clientId: string },
    userId: string
  ): Promise<Record<string, unknown>> {
    await app.repositories.oauthConsents.upsertGrant(userId, ids.clientId, ids.realmId, SCOPES);

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

    expect(authorize.statusCode).toBe(302);
    const location = authorize.headers['location'];
    if (typeof location !== 'string') throw new Error('authorize did not redirect');
    const code = new URL(location).searchParams.get('code');
    if (code === null) {
      throw new Error(`authorize returned no code: ${location}`);
    }

    const token = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: pkce.verifier,
      }).toString(),
    });

    expect(token.statusCode).toBe(200);
    const body = token.json() as { id_token?: string };
    if (typeof body.id_token !== 'string') {
      throw new Error(`token response carried no id_token: ${token.body}`);
    }
    return decodeJwtClaims(body.id_token);
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

  /** An issuer plus a wallet holding one credential from it. */
  async function walletHolding(
    issuer: MockCredentialIssuer,
    overrides: Parameters<MockCredentialIssuer['issue']>[0] = {}
  ): Promise<{ wallet: MockWallet; credential: HeldCredential }> {
    const credential = await issuer.issue({ claims: { ...CREDENTIAL_CLAIMS }, ...overrides });
    return { wallet: createMockWallet([credential]), credential };
  }

  // ------------------------------------------------------- the scenarios

  describe('first-time wallet login (asserted-lookup, new user)', () => {
    it('creates the account, its wallet credential and its verified attributes', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet } = await walletHolding(issuer);

      await withDeployment(
        walletEnabledEnv({
          OID4VP_ISSUER_JWKS: issuerJwksConfig([issuer]),
          OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
        }),
        async ({ app, ids }) => {
          const asserted = 'newcomer@example.com';

          const outcome = await signInWithWallet(app, wallet, asserted);
          expect(outcome.status).toBe('complete');

          // ADR-009 §1: `external_sub` is the ASSERTED, normalized identifier —
          // the same column `PasswordProvider` fills. Never a wallet key, a JWK
          // thumbprint or a DID.
          const rows = await app.repositories.userCredentials.findAllByRealmAndExternalSub(
            ids.realmId,
            asserted
          );
          expect(rows).toHaveLength(1);
          expect(rows[0]?.providerType).toBe('wallet');
          expect(rows[0]?.externalSub).toBe(asserted);

          const stored = JSON.stringify(rows[0]?.credentialData ?? {});
          expect(stored).not.toContain('cnf');
          expect(stored).not.toContain('"kty"');
          expect(stored).not.toContain('did:');

          // #235: the credential's claims land as `source='wallet'` attributes.
          const userId = rows[0]?.userId;
          if (userId === undefined) throw new Error('no user id on the wallet credential row');
          const email = await app.repositories.userAttributes.findVerifiedByUserIdAndKey(
            userId,
            'email'
          );
          expect(email.map((row) => row.source)).toContain('wallet');
          expect(email.find((row) => row.source === 'wallet')?.attrValue).toBe(
            CREDENTIAL_CLAIMS.email
          );
        }
      );
    }, 120_000);

    it('signs the same wallet in again without creating a second account', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet } = await walletHolding(issuer);

      await withDeployment(
        walletEnabledEnv({
          OID4VP_ISSUER_JWKS: issuerJwksConfig([issuer]),
          OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
        }),
        async ({ app, ids }) => {
          const asserted = 'returning@example.com';

          expect((await signInWithWallet(app, wallet, asserted)).status).toBe('complete');
          expect((await signInWithWallet(app, wallet, asserted)).status).toBe('complete');

          // The entitlement check (ADR-009 §1) matched the stored binding rather
          // than enrolling a duplicate — the property that makes the second
          // login a LOGIN.
          const rows = await app.repositories.userCredentials.findAllByRealmAndExternalSub(
            ids.realmId,
            asserted
          );
          expect(rows).toHaveLength(1);
        }
      );
    }, 120_000);

    it('refuses a different person holding a credential from the same trusted issuer', async () => {
      // The attack ADR-009 §1 names: a genuine, valid, trusted credential
      // asserting somebody else's account. Everything about the presentation is
      // correct except whose it is.
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet: alice } = await walletHolding(issuer);
      const { wallet: mallory } = await walletHolding(issuer, {
        claims: { given_name: 'Mallory', family_name: 'Vane', email: 'mallory@example.com' },
      });

      await withDeployment(
        walletEnabledEnv({
          OID4VP_ISSUER_JWKS: issuerJwksConfig([issuer]),
          OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
        }),
        async ({ app, ids }) => {
          const victim = 'victim@example.com';
          expect((await signInWithWallet(app, alice, victim)).status).toBe('complete');

          const attempt = await signInWithWallet(app, mallory, victim);
          expect(attempt.status).toBe('rejected');

          // No second row, and nothing rebound: the refusal wrote nothing.
          const rows = await app.repositories.userCredentials.findAllByRealmAndExternalSub(
            ids.realmId,
            victim
          );
          expect(rows).toHaveLength(1);
        }
      );
    }, 120_000);
  });

  describe('untrusted issuer (#236)', () => {
    it('refuses a validly signed credential from an unlisted issuer, creating nothing', async () => {
      const trusted = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const rogue = await createMockIssuer(UNTRUSTED_ISSUER, 'r1');
      const { wallet } = await walletHolding(rogue);

      await withDeployment(
        walletEnabledEnv({
          // The rogue issuer's KEY is configured — so the signature verifies and
          // the refusal can only come from the trust gate, not from an
          // unresolvable key. That separation is the whole point of #236 keeping
          // `OID4VP_ISSUER_JWKS` and `OID4VP_TRUSTED_ISSUERS` apart.
          OID4VP_ISSUER_JWKS: issuerJwksConfig([trusted, rogue]),
          OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
        }),
        async ({ app, ids }) => {
          const asserted = 'nobody@example.com';
          const outcome = await signInWithWallet(app, wallet, asserted);

          expect(outcome.status).toBe('rejected');
          expect(
            await app.repositories.userCredentials.findAllByRealmAndExternalSub(
              ids.realmId,
              asserted
            )
          ).toEqual([]);
        }
      );
    }, 120_000);

    it('refuses identically whether the issuer is untrusted or the account unknown', async () => {
      // #236's rule: an untrusted issuer must be indistinguishable from every
      // other refusal. Asserted on the wire, where an anonymous caller sees it.
      const trusted = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const rogue = await createMockIssuer(UNTRUSTED_ISSUER, 'r1');
      const { wallet: rogueWallet } = await walletHolding(rogue);
      const { wallet: trustedWallet } = await walletHolding(trusted);

      await withDeployment(
        walletEnabledEnv({
          OID4VP_ISSUER_JWKS: issuerJwksConfig([trusted, rogue]),
          OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
        }),
        async ({ app }) => {
          // Untrusted issuer, and a trusted issuer asserting an account that
          // exists only as a password account (ADR-009 bootstrap case 2).
          await registerPasswordUser(app, 'existing@example.com');

          const untrusted = await signInWithWallet(app, rogueWallet, 'nobody@example.com');
          const unbound = await signInWithWallet(app, trustedWallet, 'existing@example.com');

          expect(untrusted.status).toBe('rejected');
          expect(unbound.status).toBe(untrusted.status);
        }
      );
    }, 120_000);
  });

  describe('account linking (#238)', () => {
    /** Sign a password account in through the real login form; returns its jar. */
    async function passwordSession(
      app: FastifyInstance,
      email: string,
      password: string
    ): Promise<CookieJar> {
      const jar = new CookieJar();
      const loginPage = await app.inject({ method: 'GET', url: '/ui/login' });
      jar.absorb(loginPage.headers['set-cookie']);
      const login = await app.inject({
        method: 'POST',
        url: '/ui/login',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          ...(jar.header() === undefined ? {} : { cookie: jar.header() as string }),
        },
        payload: new URLSearchParams({
          email,
          password,
          csrf_token: extractCsrfToken(loginPage.body),
        }).toString(),
      });
      expect(login.statusCode).toBe(302);
      jar.absorb(login.headers['set-cookie']);
      return jar;
    }

    /**
     * Start a linking flow through the server-rendered screen, as the signed-in
     * browser holding `jar`, choosing where the wallet is (#405) — or not
     * choosing, which is the cross-device default every pre-#405 client gets.
     */
    async function startWalletLink(
      app: FastifyInstance,
      jar: CookieJar,
      device?: WalletDeviceChoice
    ): Promise<{ handle: string; invocationUri: string; page: string }> {
      const confirm = await app.inject({
        method: 'GET',
        url: '/ui/wallet-link',
        headers: { cookie: jar.header() as string },
      });
      expect(confirm.statusCode).toBe(200);
      jar.absorb(confirm.headers['set-cookie']);

      const started = await app.inject({
        method: 'POST',
        url: '/ui/wallet-link',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          cookie: jar.header() as string,
        },
        payload: new URLSearchParams({
          csrf_token: extractCsrfToken(confirm.body),
          ...(device === undefined ? {} : { device }),
        }).toString(),
      });
      expect(started.statusCode).toBe(200);
      jar.absorb(started.headers['set-cookie']);

      return {
        handle: extractFlowHandle(started.body),
        invocationUri: await readInvocationUriFromPendingPage(app, started.body, device === 'this'),
        page: started.body,
      };
    }

    /** Poll the JSON linking status once, as the signed-in browser. */
    async function pollLink(
      app: FastifyInstance,
      jar: CookieJar,
      handle: string
    ): Promise<{ status: string; message?: string }> {
      const response = await app.inject({
        method: 'GET',
        url: `/auth/link/wallet/${handle}`,
        headers: { cookie: jar.header() as string },
      });
      jar.absorb(response.headers['set-cookie']);
      expect(response.statusCode).toBe(200);
      return response.json() as { status: string; message?: string };
    }

    it('links a wallet to a password account, and both mint the identical sub', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet } = await walletHolding(issuer);

      await withDeployment(
        walletEnabledEnv({
          OID4VP_ISSUER_JWKS: issuerJwksConfig([issuer]),
          OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
        }),
        async ({ app, ids }) => {
          const email = 'linked@example.com';
          const password = 'Correct-Horse-Battery-Staple-42!';
          const userId = await registerPasswordUser(app, email, password);

          // (1) Sign in with the password so the linking flow has a session.
          const jar = await passwordSession(app, email, password);

          // (2) Link the wallet through the server-rendered linking screen —
          // CROSS-device, the path that existed before #405: no device field,
          // a QR, and completion by polling.
          const link = await startWalletLink(app, jar);
          const walletResponse = await wallet.buildResponse(link.invocationUri);
          const posted = await postWalletResponse(app, walletResponse.formBody);
          expect(posted.statusCode).toBe(200);
          expect(posted.body).toEqual({});

          const linked = await app.inject({
            method: 'GET',
            url: `/ui/wallet-link/${link.handle}`,
            headers: { cookie: jar.header() as string },
          });
          jar.absorb(linked.headers['set-cookie']);
          expect(linked.statusCode).toBe(200);

          // (3) The account now holds two credentials under one users.id.
          const rows = await app.repositories.userCredentials.findAllByRealmAndExternalSub(
            ids.realmId,
            email
          );
          expect(rows.map((row) => row.providerType).sort()).toEqual(['password', 'wallet']);
          expect(new Set(rows.map((row) => row.userId))).toEqual(new Set([userId]));

          // (4) #238 AC3, on real tokens: the password session and a fresh
          // WALLET sign-in produce ID tokens with the identical `sub`.
          const passwordClaims = await idTokenFor(app, jar, ids, userId);

          const walletSession = await signInWithWallet(app, wallet, email);
          expect(walletSession.status).toBe('complete');
          const walletClaims = await idTokenFor(app, walletSession.jar, ids, userId);

          expect(walletClaims['sub']).toBe(passwordClaims['sub']);
          expect(walletClaims['sub']).toBe(userId);
        }
      );
    }, 180_000);

    it('(HAIP 1.0 §5.1) links a wallet on THIS device via the return leg, and the original tab learns it once (#405)', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet } = await walletHolding(issuer);

      await withDeployment(
        walletEnabledEnv({
          OID4VP_ISSUER_JWKS: issuerJwksConfig([issuer]),
          OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
        }),
        async ({ app, ids }) => {
          const email = 'linked-same-device@example.com';
          const password = 'Correct-Horse-Battery-Staple-42!';
          const userId = await registerPasswordUser(app, email, password);
          const jar = await passwordSession(app, email, password);

          // `device=this`: the pending page offers the deep link and no QR.
          const link = await startWalletLink(app, jar, 'this');
          expect(link.page).toMatch(/href="openid4vp:/);
          expect(link.page).not.toContain('<svg');

          // The wallet answers; the acknowledgement carries the return leg.
          const walletResponse = await wallet.buildResponse(link.invocationUri);
          const posted = await postWalletResponse(app, walletResponse.formBody);
          expect(posted.statusCode).toBe(200);
          const ack = parseOid4vpResponseAck(posted.body);
          if (ack.redirectUri === undefined)
            throw new Error('no redirect_uri for a same-device link');

          // Until the browser comes back, the link poll must NOT complete it
          // (OID4VP 1.0 §14.2) — and nothing has been written.
          expect(await pollLink(app, jar, link.handle)).toEqual({ status: 'pending' });
          expect(
            (
              await app.repositories.userCredentials.findAllByRealmAndExternalSub(
                ids.realmId,
                email
              )
            ).map((row) => row.providerType)
          ).toEqual(['password']);

          // The wallet brings the SAME browser back: session cookie + binder.
          const landed = await followRedirect(app, jar, ack.redirectUri);
          expect(landed.statusCode).toBe(200);
          expect(landed.body).toContain('Wallet credential linked');
          expect(landed.body).toContain('history.replaceState');
          expect(landed.headers['cache-control']).toBe('no-store');
          expect(landed.headers['referrer-policy']).toBe('no-referrer');

          // The original tab's poll finds the done-marker: `linked` ONCE, then
          // the flow is gone.
          expect(await pollLink(app, jar, link.handle)).toEqual({
            status: 'linked',
            message: 'Your wallet credential is now linked to this account.',
          });
          expect((await pollLink(app, jar, link.handle)).status).toBe('expired');

          // The account holds two credentials under one users.id — exactly as
          // the cross-device link leaves it.
          const rows = await app.repositories.userCredentials.findAllByRealmAndExternalSub(
            ids.realmId,
            email
          );
          expect(rows.map((row) => row.providerType).sort()).toEqual(['password', 'wallet']);
          expect(new Set(rows.map((row) => row.userId))).toEqual(new Set([userId]));

          // The spent code buys nothing a second time.
          const replay = await followRedirect(app, jar, ack.redirectUri);
          expect(replay.statusCode).toBe(200);
          expect(replay.body).toContain(RETURN_REFUSAL_TITLE);
        }
      );
    }, 180_000);
  });

  describe('acr on the wallet path, and never on the password path (#237)', () => {
    it('emits the configured eIDAS acr for an assured issuer', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet } = await walletHolding(issuer);

      await withDeployment(
        walletEnabledEnv({
          OID4VP_ISSUER_JWKS: issuerJwksConfig([issuer]),
          OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
          OID4VP_ISSUER_ASSURANCE: JSON.stringify({
            [REALM]: { [TRUSTED_ISSUER]: { level: 'high', credentialTypes: [DEFAULT_VCT] } },
          }),
        }),
        async ({ app, ids }) => {
          const asserted = 'assured@example.com';
          const outcome = await signInWithWallet(app, wallet, asserted);
          expect(outcome.status).toBe('complete');

          const rows = await app.repositories.userCredentials.findAllByRealmAndExternalSub(
            ids.realmId,
            asserted
          );
          const userId = rows[0]?.userId;
          if (userId === undefined) throw new Error('wallet login created no credential row');

          const claims = await idTokenFor(app, outcome.jar, ids, userId);
          expect(claims['acr']).toBe('http://eidas.europa.eu/LoA/high');
        }
      );
    }, 120_000);

    it('emits NO acr for a trusted issuer the realm assures nothing about', async () => {
      // Trust and assurance are separate variables (#236 vs #237). An issuer a
      // realm accepts but has stated no level for is `'low'`, and `'low'` emits
      // nothing — the same shape as a password login.
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet } = await walletHolding(issuer);

      await withDeployment(
        walletEnabledEnv({
          OID4VP_ISSUER_JWKS: issuerJwksConfig([issuer]),
          OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
        }),
        async ({ app, ids }) => {
          const asserted = 'unassured@example.com';
          const outcome = await signInWithWallet(app, wallet, asserted);
          expect(outcome.status).toBe('complete');

          const rows = await app.repositories.userCredentials.findAllByRealmAndExternalSub(
            ids.realmId,
            asserted
          );
          const userId = rows[0]?.userId;
          if (userId === undefined) throw new Error('wallet login created no credential row');

          const claims = await idTokenFor(app, outcome.jar, ids, userId);
          expect('acr' in claims).toBe(false);
        }
      );
    }, 120_000);
  });

  describe('password login is unaffected by the wallet code paths', () => {
    it('still works, and its ID token carries NO acr — with wallet federation ON', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');

      await withDeployment(
        walletEnabledEnv({
          OID4VP_ISSUER_JWKS: issuerJwksConfig([issuer]),
          OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
          // Assurance IS configured. A password login must still emit nothing:
          // the level is a property of a presented credential, and there is no
          // presentation on this path.
          OID4VP_ISSUER_ASSURANCE: JSON.stringify({
            [REALM]: { [TRUSTED_ISSUER]: { level: 'high' } },
          }),
        }),
        async ({ app, ids }) => {
          const email = 'password-only@example.com';
          const password = 'Correct-Horse-Battery-Staple-42!';
          const userId = await registerPasswordUser(app, email, password);

          const jar = new CookieJar();
          const page = await app.inject({ method: 'GET', url: '/ui/login' });
          jar.absorb(page.headers['set-cookie']);
          const login = await app.inject({
            method: 'POST',
            url: '/ui/login',
            headers: {
              'content-type': 'application/x-www-form-urlencoded',
              cookie: jar.header() as string,
            },
            payload: new URLSearchParams({
              email,
              password,
              csrf_token: extractCsrfToken(page.body),
            }).toString(),
          });
          expect(login.statusCode).toBe(302);
          jar.absorb(login.headers['set-cookie']);

          const claims = await idTokenFor(app, jar, ids, userId);
          expect(claims['sub']).toBe(userId);
          expect('acr' in claims).toBe(false);
          // `auth_time` IS emitted, which is what makes the absence above a
          // statement about `acr` rather than about the whole claim set.
          expect(typeof claims['auth_time']).toBe('number');
        }
      );
    }, 120_000);

    it('still works with wallet federation OFF, and the wallet routes 404', async () => {
      if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');

      await withDeployment(
        { ...baseEnvironment(infra, jwt), WALLET_FEDERATION_ENABLED: 'false' },
        async ({ app, ids }) => {
          expect((await app.inject({ method: 'GET', url: '/ui/wallet-login' })).statusCode).toBe(
            404
          );
          expect(
            (
              await app.inject({
                method: 'POST',
                url: '/oid4vp/response',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                payload: 'state=x',
              })
            ).statusCode
          ).toBe(404);

          const email = 'no-wallet@example.com';
          const password = 'Correct-Horse-Battery-Staple-42!';
          const userId = await registerPasswordUser(app, email, password);

          const jar = new CookieJar();
          const page = await app.inject({ method: 'GET', url: '/ui/login' });
          jar.absorb(page.headers['set-cookie']);
          const login = await app.inject({
            method: 'POST',
            url: '/ui/login',
            headers: {
              'content-type': 'application/x-www-form-urlencoded',
              cookie: jar.header() as string,
            },
            payload: new URLSearchParams({
              email,
              password,
              csrf_token: extractCsrfToken(page.body),
            }).toString(),
          });
          expect(login.statusCode).toBe(302);
          jar.absorb(login.headers['set-cookie']);

          const claims = await idTokenFor(app, jar, ids, userId);
          expect(claims['sub']).toBe(userId);
          expect('acr' in claims).toBe(false);
        }
      );
    }, 120_000);
  });

  describe('fail-closed: no VerifierProfile selected (#296 Q1, LOCKED)', () => {
    it('refuses to start rather than serving wallet flows under a default profile', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');

      const environment = walletEnabledEnv({
        OID4VP_ISSUER_JWKS: issuerJwksConfig([issuer]),
        OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
      });

      // The control: with the profile named, this exact deployment boots. So the
      // refusal below is about the profile and not about anything else.
      const control = await bootAuthServer(environment);
      await control.close();

      // #296 Q1 is LOCKED: "There is never a permissive fallback to the more
      // capable profile." QAuth goes further than refusing the flow — it refuses
      // to START, so a deployment cannot be running for weeks believing it
      // serves wallet logins under some default posture.
      await expect(bootAuthServer({ ...environment, OID4VP_VERIFIER_PROFILE: '' })).rejects.toThrow(
        /no VerifierProfile is selected/i
      );
    }, 120_000);

    it('serves no wallet surface at all when wallet federation is off', async () => {
      // The other half of fail-closed, and the default: the routes are not
      // REGISTERED, so the paths do not exist rather than existing and refusing.
      if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');

      await withDeployment(
        { ...baseEnvironment(infra, jwt), WALLET_FEDERATION_ENABLED: 'false' },
        async ({ app }) => {
          for (const url of ['/ui/wallet-login', '/ui/wallet-link']) {
            expect((await app.inject({ method: 'GET', url })).statusCode).toBe(404);
          }
          const posted = await app.inject({
            method: 'POST',
            url: '/oid4vp/response',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: 'state=whatever',
          });
          expect(posted.statusCode).toBe(404);
        }
      );
    }, 120_000);
  });

  describe('the response is read only as a vp_token keyed by DCQL Credential Query id', () => {
    it('accepts a vp_token keyed by the query id and refuses a Presentation Exchange shape', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet } = await walletHolding(issuer);

      await withDeployment(
        walletEnabledEnv({
          OID4VP_ISSUER_JWKS: issuerJwksConfig([issuer]),
          OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
        }),
        async ({ app }) => {
          const flow = await startWalletLogin(app, 'dcql@example.com');
          const request = parseOid4vpRequest(flow.invocationUri);

          // OID4VP 1.0 §5: the Response Type is `vp_token`, and the request is
          // an unsigned `direct_post` under the `redirect_uri` prefix.
          expect(request.responseType).toBe('vp_token');
          expect(request.responseMode).toBe('direct_post');
          expect(request.clientId.startsWith('redirect_uri:')).toBe(true);

          const queryIds = request.dcqlQuery.credentials.map((query) => query.id);
          expect(queryIds).toHaveLength(1);

          // A legacy Presentation Exchange submission — a `presentation_submission`
          // envelope with a descriptor map instead of DCQL keys — is refused.
          const legacy = await postWalletResponse(app, {
            state: request.state,
            vp_token: JSON.stringify({
              presentation_submission: {
                id: 'x',
                definition_id: 'y',
                descriptor_map: [{ id: queryIds[0], format: 'dc+sd-jwt', path: '$' }],
              },
            }),
          });
          expect(legacy.statusCode).toBe(400);

          // The `state` is single-use, so the legacy attempt consumed it. Start a
          // fresh flow to prove the DCQL-keyed shape IS accepted.
          const second = await startWalletLogin(app, 'dcql@example.com');
          const response = await wallet.buildResponse(second.invocationUri);
          expect(Object.keys(response.vpToken)).toEqual(queryIds);
          expect((await postWalletResponse(app, response.formBody)).statusCode).toBe(200);
          expect((await pollStatus(app, second)).status).toBe('complete');
        }
      );
    }, 120_000);
  });

  describe('same-device return leg (#405 — OID4VP 1.0 §8.2 / §14.2, HAIP 1.0 §5.1)', () => {
    /**
     * Every scenario here runs the SAME deployment shape as the first-time
     * login above; what varies is only the `device` the user chose at the
     * sign-in form, and therefore how the flow is allowed to end.
     */
    function sameDeviceEnv(issuer: MockCredentialIssuer): Record<string, string> {
      return walletEnabledEnv({
        OID4VP_ISSUER_JWKS: issuerJwksConfig([issuer]),
        OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
      });
    }

    it('(HAIP 1.0 §5.1) completes a same-device login on the return leg, in the browser that started it — never by polling', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet } = await walletHolding(issuer);

      await withDeployment(sameDeviceEnv(issuer), async ({ app, ids }) => {
        const asserted = 'same-device@example.com';
        const flow = await startWalletLogin(app, asserted, { device: 'this' });

        // Exactly one affordance: the deep link, and no QR.
        expect(flow.page).toMatch(/href="openid4vp:/);
        expect(flow.page).not.toContain('<svg');
        expect(flow.page).toContain('Opening your wallet on this device');

        // The wallet answers, and is told where to bring the user agent
        // (OID4VP 1.0 §8.2). The URI is absolute and under the ISSUER, not
        // under whatever `Host` the wallet's POST carried.
        const response = await wallet.buildResponse(flow.invocationUri);
        const posted = await postWalletResponse(app, response.formBody);
        expect(posted.statusCode).toBe(200);
        const ack = parseOid4vpResponseAck(posted.body);
        if (ack.redirectUri === undefined) throw new Error('no redirect_uri in the ack');
        const target = new URL(ack.redirectUri);
        expect(target.origin).toBe(
          new URL(REQUIRED_TEST_ENVIRONMENT['JWT_ISSUER'] as string).origin
        );
        expect(target.pathname).toBe('/ui/wallet-login/return');
        // §8.2 "fresh, cryptographically random"; RECOMMENDED ≥ 128 bits — QAuth
        // mints 32 bytes, base64url: 43 characters.
        expect(ack.responseCode).toMatch(/^[A-Za-z0-9_-]{43}$/);

        // §14.2: the Verifier "MUST require the frontend to pass the respective
        // Response Code" — so the poll, which never sees one, cannot finish it.
        expect((await pollStatus(app, flow)).status).toBe('pending');
        expect(await canMintAuthorizationCode(app, flow.jar)).toBe(false);

        // The wallet brings the SAME browser back. The landing signs it in.
        const landed = await followRedirect(app, flow.jar, ack.redirectUri);
        expect(landed.statusCode).toBe(200);
        expect(decodeHtmlEntities(landed.body)).toContain("You're signed in");
        expect(landed.body).toContain('history.replaceState');
        expect(landed.headers['cache-control']).toBe('no-store');
        expect(landed.headers['referrer-policy']).toBe('no-referrer');
        const setCookie = landed.headers['set-cookie'];
        const cookiesSet = Array.isArray(setCookie)
          ? setCookie
          : typeof setCookie === 'string'
            ? [setCookie]
            : [];
        expect(cookiesSet.some((header) => header.startsWith(`${SESSION_COOKIE}=`))).toBe(true);
        expect(flow.jar.get(SESSION_COOKIE)).toBeDefined();

        // The ORIGINAL tab's poll consumes the done-marker: `complete` with the
        // flow's `redirect_to`, ONCE; then the flow is gone.
        expect(await pollStatus(app, flow)).toEqual({ status: 'complete', redirect_to: '/' });
        expect((await pollStatus(app, flow)).status).toBe('expired');

        // The session is real, in that jar, for the enrolled account — proven
        // through the real authorize → token path like every login above.
        const userId = await enrolledUserId(app, ids.realmId, asserted);
        if (userId === undefined) throw new Error('the same-device login enrolled no account');
        const claims = await idTokenFor(app, flow.jar, ids, userId);
        expect(claims['sub']).toBe(userId);
      });
    }, 120_000);

    it('refuses a tampered, a malformed and a replayed Response Code with ONE identical page, and mints nothing for them', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet } = await walletHolding(issuer);

      await withDeployment(sameDeviceEnv(issuer), async ({ app, ids }) => {
        const asserted = 'same-device-codes@example.com';
        const { flow, redirectUri, responseCode } = await presentOnThisDevice(
          app,
          wallet,
          asserted
        );
        const returnPath = new URL(redirectUri).pathname;

        // A well-formed code that was never minted, and one that is not a
        // code at all. Neither touches the flow: it is still pending after.
        const other = Buffer.from(responseCode, 'base64url').map((byte) => byte ^ 0xff);
        const tampered = await followRedirect(
          app,
          flow.jar,
          redirectUri.replace(responseCode, Buffer.from(other).toString('base64url'))
        );
        expect(tampered.statusCode).toBe(200);
        expect(tampered.body).toContain(RETURN_REFUSAL_TITLE);
        expect(decodeHtmlEntities(tampered.body)).not.toContain("You're signed in");

        const malformed = await followRedirect(
          app,
          flow.jar,
          `${new URL(redirectUri).origin}${returnPath}?response_code=not-a-code`
        );
        expect(withoutNonces(malformed.body)).toBe(withoutNonces(tampered.body));
        expect((await pollStatus(app, flow)).status).toBe('pending');
        expect(flow.jar.get(SESSION_COOKIE)).toBeUndefined();

        // The genuine code, once: signed in.
        const landed = await followRedirect(app, flow.jar, redirectUri);
        expect(decodeHtmlEntities(landed.body)).toContain("You're signed in");
        expect((await pollStatus(app, flow)).status).toBe('complete');

        // Replayed — from a browser that never held the flow, and from the
        // one that did — the spent code renders the SAME refusal page, and
        // the stranger's jar ends up with nothing an authorization endpoint
        // will honour.
        const stranger = new CookieJar();
        const replayed = await followRedirect(app, stranger, redirectUri);
        expect(withoutNonces(replayed.body)).toBe(withoutNonces(tampered.body));
        expect(stranger.get(SESSION_COOKIE)).toBeUndefined();
        expect(await canMintAuthorizationCode(app, stranger)).toBe(false);

        const replayedAtHome = await followRedirect(app, flow.jar, redirectUri);
        expect(withoutNonces(replayedAtHome.body)).toBe(withoutNonces(tampered.body));

        // One account, from the one genuine landing.
        expect(
          await app.repositories.userCredentials.findAllByRealmAndExternalSub(ids.realmId, asserted)
        ).toHaveLength(1);
      });
    }, 120_000);

    it('(HAIP 1.0 §5.1) rejects a presentation whose redirect back arrives in a different user session — the code is spent, the initiating tab learns it, nobody is signed in', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet } = await walletHolding(issuer);

      await withDeployment(sameDeviceEnv(issuer), async ({ app, ids }) => {
        const asserted = 'same-device-foreign@example.com';
        const { flow, redirectUri } = await presentOnThisDevice(app, wallet, asserted);

        // The wallet opens a DIFFERENT browser: an in-app webview, a private
        // window, a non-default browser — or an attacker who read the URL. A
        // fresh jar holds none of the flow's cookies.
        const elsewhere = new CookieJar();
        const landed = await followRedirect(app, elsewhere, redirectUri);
        expect(landed.statusCode).toBe(200);
        expect(landed.body).toContain(RETURN_REFUSAL_TITLE);
        expect(decodeHtmlEntities(landed.body)).toContain(
          'go back to where you started and try again'
        );
        expect(elsewhere.get(SESSION_COOKIE)).toBeUndefined();

        // The tab that started the flow is told promptly, not at the deadline.
        expect((await pollStatus(app, flow)).status).toBe('rejected');

        // Neither browser can obtain a code, and nobody was enrolled: the
        // presentation was DISCARDED, not parked for a later landing.
        expect(await canMintAuthorizationCode(app, elsewhere)).toBe(false);
        expect(await canMintAuthorizationCode(app, flow.jar)).toBe(false);
        expect(await enrolledUserId(app, ids.realmId, asserted)).toBeUndefined();

        // Even the right browser, arriving afterwards with the same code,
        // finds it spent — the burn is the hard guarantee, the discard only
        // made the refusal prompt.
        const late = await followRedirect(app, flow.jar, redirectUri);
        expect(withoutNonces(late.body)).toBe(withoutNonces(landed.body));
        expect(flow.jar.get(SESSION_COOKIE)).toBeUndefined();
        expect((await pollStatus(app, flow)).status).toBe('expired');
      });
    }, 120_000);

    it('(HAIP 1.0 §5.1) rejects a same-device presentation whose redirect was never followed, once the Response Code deadline passes', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet } = await walletHolding(issuer);

      await withDeployment(sameDeviceEnv(issuer), async ({ app, ids }) => {
        const asserted = 'same-device-unfollowed@example.com';
        const { flow, redirectUri } = await presentOnThisDevice(app, wallet, asserted);

        // The wallet posted and stopped. However often the original tab asks,
        // the presentation is parked, not accepted: pending, no session.
        for (let attempt = 0; attempt < 3; attempt += 1) {
          expect((await pollStatus(app, flow)).status).toBe('pending');
        }
        expect(await canMintAuthorizationCode(app, flow.jar)).toBe(false);

        // Age the wallet-side signal past the deadline — in the server's own
        // store, so the decision below is the server's — and the next poll
        // rejects it ACTIVELY: the user is not left watching a spinner until
        // the flow expires.
        await backdateWalletPresentationSignal(app, flow.handle, WALLET_RETURN_CODE_TTL_MS + 1);
        expect((await pollStatus(app, flow)).status).toBe('rejected');
        expect((await pollStatus(app, flow)).status).toBe('expired');
        expect(await canMintAuthorizationCode(app, flow.jar)).toBe(false);
        expect(await enrolledUserId(app, ids.realmId, asserted)).toBeUndefined();

        // A late return cannot revive it: the flow is gone, so the landing is
        // a landing nobody holds — refused, and still no session.
        const late = await followRedirect(app, flow.jar, redirectUri);
        expect(late.statusCode).toBe(200);
        expect(late.body).toContain(RETURN_REFUSAL_TITLE);
        expect(flow.jar.get(SESSION_COOKIE)).toBeUndefined();
        expect(await enrolledUserId(app, ids.realmId, asserted)).toBeUndefined();
      });
    }, 120_000);

    it('(OID4VP 1.0 §14.2) a cross-device flow is acknowledged with exactly {} and completes by polling, as before', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const { wallet } = await walletHolding(issuer);

      await withDeployment(sameDeviceEnv(issuer), async ({ app, ids }) => {
        const asserted = 'cross-device@example.com';

        // No device field at all — every client built before #405.
        const flow = await startWalletLogin(app, asserted);
        expect(flow.page).toContain('<svg');
        expect(flow.page).not.toMatch(/href="openid4vp:/);
        expect(flow.page).toContain('Scan this code with the wallet on your other device');

        const response = await wallet.buildResponse(flow.invocationUri);
        const posted = await postWalletResponse(app, response.formBody);
        expect(posted.statusCode).toBe(200);
        expect(posted.body).toEqual({});
        expect(parseOid4vpResponseAck(posted.body)).toEqual({});

        expect(await pollStatus(app, flow)).toEqual({ status: 'complete', redirect_to: '/' });
        expect(flow.jar.get(SESSION_COOKIE)).toBeDefined();

        // The explicit choice lands on the identical path.
        const explicit = await startWalletLogin(app, asserted, { device: 'other' });
        expect(explicit.page).toContain('<svg');
        expect(explicit.page).not.toMatch(/href="openid4vp:/);
        const again = await postWalletResponse(
          app,
          (await wallet.buildResponse(explicit.invocationUri)).formBody
        );
        expect(again.body).toEqual({});
        expect((await pollStatus(app, explicit)).status).toBe('complete');

        const userId = await enrolledUserId(app, ids.realmId, asserted);
        if (userId === undefined) throw new Error('the cross-device login enrolled no account');
        expect((await idTokenFor(app, flow.jar, ids, userId))['sub']).toBe(userId);
      });
    }, 120_000);
  });
});
