import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
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
  pkcePair,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import {
  createMockStatusList,
  installMockStatusEndpoints,
  MOCK_STATUS,
  type MockStatusEndpointBehaviour,
  type MockStatusList,
} from '../testing/mock-status-list';
import {
  createMockIssuer,
  createMockWallet,
  DEFAULT_VCT,
  issuerJwksConfig,
  type MockCredentialIssuer,
  type MockWallet,
} from '../testing/mock-wallet';

/**
 * CREDENTIAL REVOCATION, END TO END (issues #297, #378).
 *
 * The defect #378 reports, closed at the only layer that can prove it is closed.
 * The Token Status List checker shipped complete and tested in #297 and had ZERO
 * production call sites: `validateSdJwtVcPresentation` hardcoded
 * `statusChecked: false`, `VerifierProfile.requireCredentialStatus` was read by
 * nothing, and a revoked verifiable credential authenticated a user exactly like
 * a live one.
 *
 * Every assertion below therefore runs through the REAL flow — the rendered
 * login form, the wallet invocation URI, an OID4VP `direct_post`, the flow
 * poll, and the account store behind it — against a real Postgres and a real
 * Redis. A unit test cannot distinguish "the gate is wired" from "the gate
 * exists"; that is the whole lesson of #378.
 *
 * ## What is faked, and what is not
 *
 * Only the socket. The status list issuer (`src/testing/mock-status-list.ts`) is
 * an independent implementation: it mints its own X.509 CA, signs a real Status
 * List Token with a real ES256 signature, and publishes a real deflate-packed
 * 2-bit list. QAuth verifies that chain against the anchor the deployment was
 * configured with, exactly as it would in production. `installMockStatusEndpoints`
 * intercepts the transport rather than binding a loopback listener because the
 * SSRF allowlist refuses `localhost` and IP literals outright — a correctly
 * configured deployment could not reach a loopback endpoint at all, so a suite
 * built on one would be testing a configuration nobody can ship.
 *
 * ## Fail-CLOSED, asserted by omission as well as by assertion
 *
 * There is deliberately no test here in which a status endpoint that is down, or
 * 500ing, or serving the wrong media type, lets a login through. Each of those
 * is a REJECTION. `status-endpoint-breaker.ts`, verbatim: *"an open circuit is
 * an immediate REJECTION … It makes the failure cheaper, never more
 * permissive."*
 *
 * ## One deployment per scenario
 *
 * A verified status list is cached for up to 300 s inside the checker INSTANCE,
 * and that instance is a per-process singleton (it owns the cache, the in-flight
 * coalescing map and the endpoint breaker). Mutating the list or the endpoint's
 * behaviour inside a running deployment would be answered from that cache, so
 * each scenario boots its own — which is also the honest shape, since a
 * revocation state is a property of the world the deployment runs in.
 */

/** The realm every deployment in this suite uses. `OID4VP_*` maps key on it. */
const REALM = 'master';

const TRUSTED_ISSUER = 'https://issuer.example.com';
const UNTRUSTED_ISSUER = 'https://rogue-issuer.example.net';

const CLIENT_ID = 'e2e-status-client';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email', 'profile'];

const CREDENTIAL_CLAIMS = {
  given_name: 'Alice',
  family_name: 'Doe',
  email: 'alice@example.com',
} as const;

const BINDING_CLAIMS = 'given_name,family_name';

/** Indices into the published list, named so the tests read as intent. */
const IDX = Object.freeze({ live: 0, revoked: 1, suspended: 2, unspecified: 3 });

describe('credential revocation E2E (Token Status List, #297/#378)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;

  /** The status list this suite publishes; re-created per test. */
  let statusList: MockStatusList;
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
    // A fresh issuer, CA and list per test: nothing leaks between scenarios,
    // and no anchor outlives the deployment it was configured into.
    statusList = createMockStatusList();
    statusList.setStatus(IDX.revoked, MOCK_STATUS.INVALID);
    statusList.setStatus(IDX.suspended, MOCK_STATUS.SUSPENDED);
    statusList.setStatus(IDX.unspecified, MOCK_STATUS.UNSPECIFIED);
    restoreFetch = installMockStatusEndpoints([statusList]);
  });

  afterEach(() => {
    restoreFetch?.();
    restoreFetch = undefined;
  });

  // ------------------------------------------------------------ environment

  /** A deployment that serves wallet flows AND checks revocation. */
  function statusCheckingEnv(
    issuers: readonly MockCredentialIssuer[],
    overrides: Record<string, string> = {}
  ): Record<string, string> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    return {
      ...baseEnvironment(infra, jwt),
      WALLET_FEDERATION_ENABLED: 'true',
      OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
      OID4VP_REQUESTED_VCT: DEFAULT_VCT,
      OID4VP_SUBJECT_RESOLUTION: 'asserted-lookup',
      OID4VP_SUBJECT_BINDING_CLAIMS: BINDING_CLAIMS,
      OID4VP_ISSUER_JWKS: issuerJwksConfig(issuers),
      OID4VP_TRUSTED_ISSUERS: JSON.stringify({ [REALM]: [TRUSTED_ISSUER] }),
      // The two things a `CredentialStatusChecker` cannot be built without.
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
      name: 'E2E status client',
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

  /** Everything a caller could observe about one sign-in attempt. */
  interface SignInObservation {
    /** HTTP status of the `direct_post` response endpoint. */
    readonly directPostStatus: number;
    /** HTTP status of the flow poll. */
    readonly pollStatus: number;
    /** The poll body, verbatim — this is the whole client-visible outcome. */
    readonly pollBody: string;
    readonly jar: CookieJar;
  }

  /** Run a complete wallet sign-in and record everything a caller sees. */
  async function signInWithWallet(
    app: FastifyInstance,
    wallet: MockWallet,
    identifier: string
  ): Promise<SignInObservation> {
    const flow = await startWalletLogin(app, identifier);
    const response = await wallet.buildResponse(flow.invocationUri);

    const posted = await app.inject({
      method: 'POST',
      url: '/oid4vp/response',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams(response.formBody).toString(),
    });

    const polled = await app.inject({
      method: 'GET',
      url: `/ui/wallet-login/${flow.handle}/status`,
      headers: {
        ...(flow.jar.header() === undefined ? {} : { cookie: flow.jar.header() as string }),
      },
    });
    flow.jar.absorb(polled.headers['set-cookie']);

    return {
      directPostStatus: posted.statusCode,
      pollStatus: polled.statusCode,
      pollBody: polled.body,
      jar: flow.jar,
    };
  }

  /** The terminal status word the poll reported. */
  function statusOf(observation: SignInObservation): string {
    return (JSON.parse(observation.pollBody) as { status: string }).status;
  }

  /**
   * Whether a browser holding this jar can obtain an authorization code.
   *
   * The strongest available statement of "no session was created": not that a
   * cookie is absent, but that the OAuth authorization endpoint will not mint a
   * code for whatever the browser is holding.
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

  /** Boot a deployment, seed it, hand it to the body — then close it. */
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

  /** A wallet holding one credential from `issuer`, at a given list index. */
  async function walletHolding(issuer: MockCredentialIssuer, idx?: number): Promise<MockWallet> {
    const credential = await issuer.issue({
      claims: { ...CREDENTIAL_CLAIMS },
      ...(idx === undefined ? {} : { status: statusList.statusClaimFor(idx) }),
    });
    return createMockWallet([credential]);
  }

  // ------------------------------------------------------- the acceptance

  describe('a revoked credential does not authenticate anybody', () => {
    it('refuses a REVOKED credential identically to an untrusted issuer, creating nothing', async () => {
      // #378's headline acceptance criterion, on the wire. The control matters
      // as much as the assertion: the SAME wallet, issuer and deployment sign in
      // successfully when the bit says VALID, so the refusal is about the bit
      // and about nothing else.
      const trusted = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const rogue = await createMockIssuer(UNTRUSTED_ISSUER, 'r1');

      const live = await walletHolding(trusted, IDX.live);
      const revoked = await walletHolding(trusted, IDX.revoked);
      const untrusted = await walletHolding(rogue, IDX.live);

      await withDeployment(statusCheckingEnv([trusted, rogue]), async ({ app, ids }) => {
        // (1) The control: a live bit authenticates.
        const good = await signInWithWallet(app, live, 'live@example.com');
        expect(statusOf(good)).toBe('complete');

        // (2) The revoked credential, and (3) a credential from an issuer this
        // realm does not trust — the refusal #236 already produced.
        const refusedForStatus = await signInWithWallet(app, revoked, 'revoked@example.com');
        const refusedForTrust = await signInWithWallet(app, untrusted, 'rogue@example.com');

        expect(statusOf(refusedForStatus)).toBe('rejected');

        // BYTE-IDENTICAL, not merely "both rejected". "Is my credential revoked
        // yet?" must be unanswerable from the outside, and a difference in
        // status code, body or shape would answer it.
        expect(refusedForStatus.pollBody).toBe(refusedForTrust.pollBody);
        expect(refusedForStatus.pollStatus).toBe(refusedForTrust.pollStatus);
        expect(refusedForStatus.directPostStatus).toBe(refusedForTrust.directPostStatus);

        // NO account was enrolled and NO credential row written.
        for (const asserted of ['revoked@example.com', 'rogue@example.com']) {
          expect(
            await app.repositories.userCredentials.findAllByRealmAndExternalSub(
              ids.realmId,
              asserted
            )
          ).toEqual([]);
        }

        // NO session: the browser that presented the revoked credential cannot
        // obtain an authorization code, while the one that presented the live
        // credential can. Consent is pre-granted for the live account so the
        // control drives the code-mint path rather than the consent screen.
        const liveRows = await app.repositories.userCredentials.findAllByRealmAndExternalSub(
          ids.realmId,
          'live@example.com'
        );
        const liveUserId = liveRows[0]?.userId;
        if (liveUserId === undefined) throw new Error('the live login enrolled no account');
        await app.repositories.oauthConsents.upsertGrant(
          liveUserId,
          ids.clientId,
          ids.realmId,
          SCOPES
        );

        expect(await canMintAuthorizationCode(app, refusedForStatus.jar)).toBe(false);
        expect(await canMintAuthorizationCode(app, good.jar)).toBe(true);

        // The status endpoint really was dialled — otherwise "rejected" could be
        // any of a dozen unrelated refusals and this suite would prove nothing.
        expect(statusList.requestCount).toBeGreaterThan(0);
      });
    }, 180_000);

    it.each([
      ['SUSPENDED', IDX.suspended],
      ['an application-specific value this deployment has no meaning for', IDX.unspecified],
    ])(
      'refuses a credential whose bit is %s',
      async (_label, idx) => {
        const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
        const wallet = await walletHolding(issuer, idx);

        await withDeployment(statusCheckingEnv([issuer]), async ({ app, ids }) => {
          const outcome = await signInWithWallet(app, wallet, 'suspended@example.com');

          expect(statusOf(outcome)).toBe('rejected');
          expect(
            await app.repositories.userCredentials.findAllByRealmAndExternalSub(
              ids.realmId,
              'suspended@example.com'
            )
          ).toEqual([]);
          expect(statusList.requestCount).toBeGreaterThan(0);
        });
      },
      180_000
    );

    it('refuses a credential whose `status` is present but not a usable status_list', async () => {
      // HAIP §6.1: a credential carrying `status` MUST carry `status_list`. A
      // mechanism this verifier cannot evaluate is a status it has not
      // established — refused even though the base profile requires none.
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const credential = await issuer.issue({
        claims: { ...CREDENTIAL_CLAIMS },
        status: { some_other_mechanism: { list: 'https://elsewhere.example/crl', index: 4 } },
      });
      const wallet = createMockWallet([credential]);

      await withDeployment(statusCheckingEnv([issuer]), async ({ app, ids }) => {
        const outcome = await signInWithWallet(app, wallet, 'unusable@example.com');

        expect(statusOf(outcome)).toBe('rejected');
        expect(
          await app.repositories.userCredentials.findAllByRealmAndExternalSub(
            ids.realmId,
            'unusable@example.com'
          )
        ).toEqual([]);
        // Nothing was dialled: the claim is unusable before any URI exists.
        expect(statusList.requestCount).toBe(0);
      });
    }, 180_000);

    it('refuses a status list URI outside the operator allowlist, without dialling it', async () => {
      // The SSRF boundary, from configuration. The URI is bytes the credential
      // ISSUER chose; the allowlist is the only thing between it and whatever
      // host it names.
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const elsewhere = createMockStatusList({ host: 'status.elsewhere.example' });
      const restoreElsewhere = installMockStatusEndpoints([statusList, elsewhere]);

      try {
        const credential = await issuer.issue({
          claims: { ...CREDENTIAL_CLAIMS },
          status: elsewhere.statusClaimFor(IDX.live),
        });
        const wallet = createMockWallet([credential]);

        await withDeployment(statusCheckingEnv([issuer]), async ({ app, ids }) => {
          const outcome = await signInWithWallet(app, wallet, 'ssrf@example.com');

          expect(statusOf(outcome)).toBe('rejected');
          expect(
            await app.repositories.userCredentials.findAllByRealmAndExternalSub(
              ids.realmId,
              'ssrf@example.com'
            )
          ).toEqual([]);
          // The point: refused BEFORE a socket was opened to the host the
          // credential named.
          expect(elsewhere.requestCount).toBe(0);
        });
      } finally {
        restoreElsewhere();
      }
    }, 180_000);
  });

  // ------------------------------------------------------------ fail-closed

  describe('an endpoint that cannot answer refuses the login (fail-closed)', () => {
    /**
     * Each case is a REJECTION. There is intentionally no companion test
     * asserting a pass-through under any of them: a status endpoint outage
     * blocking logins for that issuer's users is a cost #297 accepts
     * deliberately, because the alternative lets anyone who can degrade a third
     * party's availability un-revoke credentials.
     */
    it.each([
      ['500s', { kind: 'http-error', status: 500 } as MockStatusEndpointBehaviour],
      ['404s', { kind: 'http-error', status: 404 } as MockStatusEndpointBehaviour],
      ['serves the wrong media type', { kind: 'wrong-media-type' } as MockStatusEndpointBehaviour],
      ['is unreachable', { kind: 'unreachable' } as MockStatusEndpointBehaviour],
    ])(
      'refuses the login when the status endpoint %s',
      async (_label, behaviour) => {
        const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
        const wallet = await walletHolding(issuer, IDX.live);
        statusList.setBehaviour(behaviour);

        await withDeployment(statusCheckingEnv([issuer]), async ({ app, ids }) => {
          const outcome = await signInWithWallet(app, wallet, 'outage@example.com');

          expect(statusOf(outcome)).toBe('rejected');
          expect(
            await app.repositories.userCredentials.findAllByRealmAndExternalSub(
              ids.realmId,
              'outage@example.com'
            )
          ).toEqual([]);
          expect(await canMintAuthorizationCode(app, outcome.jar)).toBe(false);
          // It was attempted — the refusal is the endpoint's answer, not a
          // configuration mistake that skipped the fetch.
          expect(statusList.requestCount).toBeGreaterThan(0);
        });
      },
      180_000
    );

    it('refuses when the Status List Token chains to an anchor this deployment did not configure', async () => {
      // A genuine-looking status answer from a party the operator never trusted
      // to give one: the token verifies against ITS OWN CA, which is exactly the
      // point — anchoring is what makes that insufficient.
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const wallet = await walletHolding(issuer, IDX.live);
      const strangerAnchor = createMockStatusList({ host: 'unrelated.example' }).anchorPem;

      await withDeployment(
        statusCheckingEnv([issuer], { OID4VP_STATUS_LIST_TRUST_ANCHORS: strangerAnchor }),
        async ({ app, ids }) => {
          const outcome = await signInWithWallet(app, wallet, 'unanchored@example.com');

          expect(statusOf(outcome)).toBe('rejected');
          expect(
            await app.repositories.userCredentials.findAllByRealmAndExternalSub(
              ids.realmId,
              'unanchored@example.com'
            )
          ).toEqual([]);
        }
      );
    }, 180_000);
  });

  // -------------------------------------------------------------- postures

  describe('the base profile still permits a credential naming no status mechanism', () => {
    it('signs in a credential with NO status claim under oid4vp-1.0-base', async () => {
      // Base OID4VP 1.0 mandates no revocation mechanism, so a credential
      // carrying none is accepted unchecked — `requireCredentialStatus` is
      // `false` for this profile. #378's fix must not break every existing
      // base-profile deployment.
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const wallet = await walletHolding(issuer);

      await withDeployment(statusCheckingEnv([issuer]), async ({ app, ids }) => {
        const outcome = await signInWithWallet(app, wallet, 'no-status@example.com');

        expect(statusOf(outcome)).toBe('complete');
        expect(
          await app.repositories.userCredentials.findAllByRealmAndExternalSub(
            ids.realmId,
            'no-status@example.com'
          )
        ).toHaveLength(1);
        // Nothing to consult, so nothing was dialled.
        expect(statusList.requestCount).toBe(0);
      });
    }, 180_000);

    it('signs in with a live bit and enrols the account exactly once', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const wallet = await walletHolding(issuer, IDX.live);

      await withDeployment(statusCheckingEnv([issuer]), async ({ app, ids }) => {
        expect(statusOf(await signInWithWallet(app, wallet, 'live-twice@example.com'))).toBe(
          'complete'
        );
        expect(statusOf(await signInWithWallet(app, wallet, 'live-twice@example.com'))).toBe(
          'complete'
        );

        expect(
          await app.repositories.userCredentials.findAllByRealmAndExternalSub(
            ids.realmId,
            'live-twice@example.com'
          )
        ).toHaveLength(1);
        // The verified list is cached on the checker INSTANCE, which is a
        // per-process singleton — so two logins cost one outbound request. This
        // is why it is built at bootstrap and never per request.
        expect(statusList.requestCount).toBe(1);
      });
    }, 180_000);
  });

  // ------------------------------------------------------------- boot gate

  describe('a half-configured status path refuses to START (#297)', () => {
    it('refuses anchors with no URI allowlist, naming what is missing', async () => {
      if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');

      // The control: the same deployment with BOTH halves boots. Without it this
      // assertion would pass for any configuration mistake at all.
      const control = await bootAuthServer(statusCheckingEnv([issuer]));
      await control.close();

      const environment = statusCheckingEnv([issuer]);
      delete environment['OID4VP_STATUS_LIST_URI_ALLOWLIST'];

      await expect(bootAuthServer(environment)).rejects.toThrow(
        /OID4VP_STATUS_LIST_URI_ALLOWLIST is not/
      );
    }, 180_000);

    it('refuses a URI allowlist with no anchors, naming what is missing', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');
      const environment = statusCheckingEnv([issuer]);
      delete environment['OID4VP_STATUS_LIST_TRUST_ANCHORS'];

      await expect(bootAuthServer(environment)).rejects.toThrow(/OID4VP_STATUS_LIST_TRUST_ANCHORS/);
    }, 180_000);

    it('refuses an anchor that will not parse, rather than rejecting every login', async () => {
      // The failure this exists to prevent: a dropped anchor is a trust decision
      // the operator wrote and the server did not apply, and it surfaces as a
      // 100% login-failure rate nobody can explain.
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');

      await expect(
        bootAuthServer(
          statusCheckingEnv([issuer], {
            OID4VP_STATUS_LIST_TRUST_ANCHORS:
              '-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----',
          })
        )
      ).rejects.toThrow();
    }, 180_000);

    it('refuses an allowlist entry that is not a usable https prefix', async () => {
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');

      await expect(
        bootAuthServer(
          statusCheckingEnv([issuer], {
            OID4VP_STATUS_LIST_URI_ALLOWLIST: 'http://status.issuer.example/lists',
          })
        )
      ).rejects.toThrow();
    }, 180_000);

    it('still boots a deployment that configured neither half', async () => {
      if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
      const issuer = await createMockIssuer(TRUSTED_ISSUER, 'k1');

      const environment = statusCheckingEnv([issuer]);
      delete environment['OID4VP_STATUS_LIST_TRUST_ANCHORS'];
      delete environment['OID4VP_STATUS_LIST_URI_ALLOWLIST'];

      const booted = await bootAuthServer(environment);
      await booted.close();
    }, 180_000);
  });
});
