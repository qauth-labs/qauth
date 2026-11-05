import { createTestEgressClient } from '@qauth-labs/fastify-plugin-egress';
import {
  type LocalHttpsFixture,
  startLocalHttpsFixture,
} from '@qauth-labs/fastify-plugin-egress/src/testing/egress-fixtures';
import {
  createFakeProvider,
  type FakeProvider,
  type FakeSignIn,
  sealUpstreamOidcConfig,
  type UpstreamOidcConfigInput,
} from '@qauth-labs/fastify-plugin-federation/src/testing/upstream-oidc-fixtures';
import {
  CEREMONY_PAGE_PREFIX,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  decodeHtmlEntities,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { SESSION_COOKIE } from '../testing/session-cookie-value';

/**
 * THE UPSTREAM SIGN-IN FLOW AND NEW ACCOUNTS (#639, ADR-020 §3), end to end
 * against real Postgres and Redis.
 *
 * A realm's upstream OpenID Connect providers are rows of
 * `realm_upstream_providers`, their configs sealed with the server's signer.
 * The provider is the fake OpenID Provider of the upstream OIDC library,
 * served from a local HTTPS fixture that only the test-only egress client
 * reaches; discovery, the key set and the code exchange cross TLS to it. The
 * browser is a cookie jar; the person signing in at the provider is
 * `provider.authorize()`.
 *
 * Covers the acceptance criteria of #639:
 *
 * - a first sign-in creates one user, one credential (`oidc_<alias>`, the
 *   external `sub`, `{ kind: 'upstream', iss, verified }`) and the provider's
 *   claims as attributes of its source, in one go; a second one signs the
 *   same user in;
 * - a stored credential stands only under the issuer it was created with;
 * - an account that holds a passkey never completes through the provider
 *   alone, whatever the MFA policy; one without signs in through it alone;
 * - an account holding the same email gets no match: a new account is
 *   created, the other is untouched;
 * - with sign-up off an unknown identity creates nothing;
 * - the provider's verified switch off leaves the account and its address
 *   unverified, whatever the provider said;
 * - a hidden provider is listed nowhere and reachable by `qauth_upstream`;
 * - a callback replayed in another browser is refused before any code is
 *   redeemed, and the original browser still completes;
 * - a cancel at the provider shows the provider-error page and sends
 *   nothing to the client;
 * - the whole flow works without JavaScript on the server-rendered pages.
 *
 * Each deployment the criteria differ in (the pages or the Interaction API's
 * ceremony page, sign-up on or off) is booted once, in a block of its own.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ORIGIN = 'https://auth.example.com';
/** An operator-flagged first-party client (`web_redirect`): its codes need no consent screen. */
const CLIENT_ID = 'portal';
const REDIRECT_URI = 'https://portal.example.com/auth/callback';
/** A public key the client authenticates with; no test here reaches the token endpoint. */
const CLIENT_JWKS = {
  keys: [{ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }],
};
const STATE = 'upstream-state';

/** The listed provider, and a hidden one only `qauth_upstream` reaches. */
const TYPE = 'oidc_corp';
const HIDDEN_TYPE = 'oidc_partner';
/** QAuth's registration at the fake provider. */
const UPSTREAM_CLIENT_ID = 'qauth-corp';
const UPSTREAM_CLIENT_SECRET = 'an-upstream-client-secret-of-some-length-0042';

const EMAIL = 'ada@example.com';
/** The person signing in at the provider: an address the provider vouches for. */
const PERSON: FakeSignIn = {
  sub: 'corp-user-1',
  claims: { email: EMAIL, email_verified: true, name: 'Ada Lovelace' },
};

/** The page titles of `helpers/upstream-pages.ts`, written out: app modules read the environment at import. */
const WAITING_TITLE = 'Continuing to your sign-in provider';
const PROVIDER_ERROR_TITLE = 'Sign-in was not completed';
const ERROR_TITLE = 'We could not sign you in';

const IDENTIFIER = stepUrn('identifier');
const UPSTREAM = stepUrn('upstream');
const EMAIL_CODE = stepUrn('email_code');
const SIGN_IN_FAILED = 'urn:qauth:event:user.sign_in_failed:v1-rc.0';
const REGISTERED = 'urn:qauth:event:user.registered:v1-rc.0';
const SIGNED_IN = 'urn:qauth:event:user.signed_in:v1-rc.0';
/** An interaction id: 43 base64url characters. */
const INTERACTION_ID = /^[A-Za-z0-9_-]{43}$/;

/** The environment variables a block sets beyond the base environment, cleared after it. */
const BLOCK_VARIABLES = [
  'INTERACTION_UI_ENABLED',
  'ALLOW_SIGN_UP',
  'AUTHORIZE_RATE_LIMIT',
  'AUTHORIZE_RATE_LIMIT_LENIENT',
];

/** The callback URL the provider of `type` sends the browser back to. */
function callbackUrlOf(type: string): string {
  return `${ORIGIN}/upstream/${type}/callback`;
}

/** The path and query of a location, relative or on the realm origin. */
function pathOf(location: unknown): string {
  const url = new URL(String(location), ORIGIN);
  expect(url.origin).toBe(ORIGIN);
  return `${url.pathname}${url.search}`;
}

/** The interaction id of a ceremony page location, relative or on the realm origin. */
function ceremonyIdOf(location: unknown): string {
  const path = pathOf(location);
  expect(path.startsWith(CEREMONY_PAGE_PREFIX), path).toBe(true);
  const id = path.slice(CEREMONY_PAGE_PREFIX.length);
  expect(id).toMatch(INTERACTION_ID);
  return id;
}

/** The code a redirect to the client carries, with the request's `state` and `iss`. */
function codeAt(location: unknown): string {
  const url = new URL(String(location));
  expect(`${url.origin}${url.pathname}`).toBe(REDIRECT_URI);
  expect(url.searchParams.get('state')).toBe(STATE);
  expect(url.searchParams.get('iss')).toBe(ORIGIN);
  const code = url.searchParams.get('code');
  expect(code).toMatch(/.+/);
  return code as string;
}

/** The one error page: 400, its text and a trace id, and no redirect anywhere. */
function expectErrorPage(response: LightMyRequestResponse): void {
  expect(response.statusCode, response.body).toBe(400);
  expect(response.body).toContain(ERROR_TITLE);
  expect(response.body).toMatch(/<code>[^<]+<\/code>/);
  expect(response.headers['location']).toBeUndefined();
}

/** The provider links of a sign-in page, entity-decoded. */
function providerLinksOf(html: string): string[] {
  return [...html.matchAll(/href="(\/ui\/upstream\/[^"]+)"/g)].map(([, href]) =>
    decodeHtmlEntities(href)
  );
}

describe('the upstream sign-in flow and new accounts (#639, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let fixture: LocalHttpsFixture | undefined;
  let provider: FakeProvider;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    // The provider lives at the fixture's origin: it is started first.
    fixture = await startLocalHttpsFixture();
    const served = await createFakeProvider({ issuer: fixture.origin });
    served.register({
      clientId: UPSTREAM_CLIENT_ID,
      method: 'client_secret_basic',
      clientSecret: UPSTREAM_CLIENT_SECRET,
      redirectUris: [callbackUrlOf(TYPE), callbackUrlOf(HIDDEN_TYPE)],
    });
    const origin = fixture.origin;
    fixture.handler = (req, body, res) => {
      const headers = Object.fromEntries(
        Object.entries(req.headers).flatMap(([name, value]) =>
          typeof value === 'string' ? [[name, value]] : []
        )
      );
      served
        .answer({
          method: req.method ?? 'GET',
          url: `${origin}${req.url ?? '/'}`,
          headers,
          body: body.toString('utf8'),
        })
        .then(
          (answer) => {
            res.writeHead(answer.status, answer.headers);
            res.end(Buffer.from(answer.body));
          },
          () => {
            res.writeHead(500);
            res.end();
          }
        );
    };
    provider = served;
  }, 240_000);

  afterAll(async () => {
    await fixture?.close();
    await infra?.teardown();
  });

  /** A deployment of one block: booted once, its state reset and seeded before each test. */
  interface BlockServer {
    readonly app: () => FastifyInstance;
    readonly realmId: () => string;
  }

  /**
   * The server's warnings and errors in the current test: a refusal answers
   * the same page whatever its cause, and a fault only its trace id, so an
   * assertion on an answer carries them to say why.
   */
  const serverLog: string[] = [];

  /** `body`, with the server's warnings and errors of this test after it. */
  function withServerLog(body: string): string {
    return serverLog.length === 0 ? body : `${body}\nserver log:\n${serverLog.join('')}`;
  }

  /**
   * Boot a deployment for the enclosing block with `environment` over the
   * base one, its egress through the test-only client, and before each test
   * reset it and seed the client and the two providers.
   */
  function bootForBlock(environment: Record<string, string>): BlockServer {
    let booted: BootedAuthServer | undefined;
    let realmId = '';

    beforeAll(async () => {
      if (!dockerUp || infra === undefined || jwt === undefined) return;
      booted = await bootAuthServer(
        {
          ...baseEnvironment(infra, jwt),
          // Each test runs several authorization requests from one address.
          AUTHORIZE_RATE_LIMIT: '10000',
          AUTHORIZE_RATE_LIMIT_LENIENT: '10000',
          ...environment,
        },
        {
          egressClientFactory: createTestEgressClient,
          logStream: { write: (line: string) => void serverLog.push(line) },
        }
      );
    }, 240_000);

    afterAll(async () => {
      await booted?.close();
      booted = undefined;
      for (const name of BLOCK_VARIABLES) delete process.env[name];
    });

    beforeEach(async (ctx) => {
      if (!dockerUp || booted === undefined) {
        ctx.skip();
        return;
      }
      realmId = await seed(booted.app);
      serverLog.length = 0;
    }, 120_000);

    return {
      app: () => {
        if (booted === undefined) throw new Error('server not booted');
        return booted.app;
      },
      realmId: () => realmId,
    };
  }

  /** Reset the deployment; seed the first-party client and the realm's two providers. */
  async function seed(app: FastifyInstance): Promise<string> {
    await resetE2eState(app);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CLIENT_ID,
      clientSecretHash: 'unused',
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwks: CLIENT_JWKS,
      name: 'Developer Portal',
      redirectUris: [REDIRECT_URI],
      scopes: ['openid', 'email'],
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
      // A seeded client: its redirect URI receives authorization errors.
      provisionedByOperator: true,
    });
    // The operator flags it first-party (ADR-017 Decision 2), as the seed
    // manifest does: an account the flow creates gets its code with no
    // consent screen.
    await app.dbPool.query(
      `UPDATE oauth_clients
          SET first_party_profile = 'web_redirect', first_party_reason = 'The developer portal.'
        WHERE client_id = $1`,
      [CLIENT_ID]
    );
    await addProvider(app, realm.id, TYPE, { displayName: 'Corp', displayOrder: 0 });
    await addProvider(app, realm.id, HIDDEN_TYPE, {
      displayName: 'Partner',
      displayOrder: 1,
      hidden: true,
    });
    return realm.id;
  }

  /** A provider row of the realm, its config sealed with the server's signer as `api`. */
  async function addProvider(
    app: FastifyInstance,
    realmId: string,
    type: string,
    row: { displayName: string; displayOrder: number; hidden?: boolean }
  ): Promise<void> {
    const config: UpstreamOidcConfigInput = {
      issuer: provider.issuer,
      clientId: UPSTREAM_CLIENT_ID,
      clientAuthentication: {
        method: 'client_secret_basic',
        clientSecret: UPSTREAM_CLIENT_SECRET,
      },
    };
    await app.repositories.realmUpstreamProviders.create({
      realmId,
      type,
      displayName: row.displayName,
      displayOrder: row.displayOrder,
      hidden: row.hidden ?? false,
      enabled: true,
      marksVerified: true,
      config: await sealUpstreamOidcConfig(
        app.signer,
        { realmId, providerId: type, caller: 'api' },
        config
      ),
    });
  }

  /** A GET from the browser holding `jar`, which keeps what the answer sets. */
  async function get(
    app: FastifyInstance,
    jar: CookieJar,
    url: string
  ): Promise<LightMyRequestResponse> {
    const cookie = jar.header();
    const response = await app.inject({
      method: 'GET',
      url,
      headers: cookie === undefined ? {} : { cookie },
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** The client's authorization request, with `extra` parameters. */
  function authorizeUrl(extra: Record<string, string> = {}): string {
    return `/oauth/authorize?${new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'openid email',
      code_challenge: pkcePair().challenge,
      code_challenge_method: 'S256',
      state: STATE,
      ...extra,
    }).toString()}`;
  }

  /** A provider started for a request: its interaction, the waiting page and the provider's URL on it. */
  interface Started {
    readonly interactionId: string;
    readonly page: string;
    readonly providerRequest: URL;
  }

  /**
   * Follow the authorization endpoint's redirect to the start of `type` and
   * read the waiting page: its link is the provider's authorization request.
   */
  async function waitingPage(
    app: FastifyInstance,
    jar: CookieJar,
    routed: LightMyRequestResponse,
    type: string
  ): Promise<Started> {
    expect(routed.statusCode, withServerLog(routed.body)).toBe(302);
    const start = new URL(String(routed.headers['location']), ORIGIN);
    expect(start.pathname).toBe(`/ui/upstream/${type}/start`);
    const interactionId = start.searchParams.get('interaction') ?? '';
    expect(interactionId).toMatch(INTERACTION_ID);
    const page = await get(app, jar, `${start.pathname}${start.search}`);
    expect(page.statusCode, withServerLog(page.body)).toBe(200);
    expect(page.body).toContain(WAITING_TITLE);
    const link = /<a class="alt-action" href="([^"]+)"/.exec(page.body)?.[1];
    if (link === undefined) throw new Error('no provider link on the waiting page');
    const providerRequest = new URL(decodeHtmlEntities(link));
    expect(`${providerRequest.origin}${providerRequest.pathname}`).toBe(
      provider.authorizationEndpoint
    );
    expect(providerRequest.searchParams.get('redirect_uri')).toBe(callbackUrlOf(type));
    return { interactionId, page: page.body, providerRequest };
  }

  /** Route the client's request to `type` with `qauth_upstream`, up to the waiting page. */
  async function startProvider(
    app: FastifyInstance,
    jar: CookieJar,
    type = TYPE
  ): Promise<Started> {
    const routed = await get(app, jar, authorizeUrl({ qauth_upstream: type }));
    return waitingPage(app, jar, routed, type);
  }

  /** The provider's callback with the response `params`, from the browser holding `jar`. */
  function callbackAt(
    app: FastifyInstance,
    jar: CookieJar,
    type: string,
    params: Record<string, string>
  ): Promise<LightMyRequestResponse> {
    return get(app, jar, `/upstream/${type}/callback?${new URLSearchParams(params).toString()}`);
  }

  /** Start `type`, sign `person` in at the provider, and come back to the callback. */
  async function signInAtProvider(
    app: FastifyInstance,
    jar: CookieJar,
    person: FakeSignIn = PERSON,
    type = TYPE
  ): Promise<LightMyRequestResponse> {
    const started = await startProvider(app, jar, type);
    const answer = provider.authorize(started.providerRequest, person);
    expect(answer['error']).toBeUndefined();
    return callbackAt(app, jar, type, answer);
  }

  /**
   * The pages' end of a sign-in: the callback sends the browser back to the
   * authorization request, which issues the code under the new session.
   */
  async function codeAfterPages(
    app: FastifyInstance,
    jar: CookieJar,
    callback: LightMyRequestResponse
  ): Promise<string> {
    expect(callback.statusCode, withServerLog(callback.body)).toBe(303);
    expect(jar.get(SESSION_COOKIE)).toBeDefined();
    const back = pathOf(callback.headers['location']);
    expect(back.startsWith('/oauth/authorize?'), back).toBe(true);
    expect(back).not.toContain('qauth_upstream');
    const again = await get(app, jar, back);
    expect(again.statusCode, again.body).toBe(302);
    return codeAt(again.headers['location']);
  }

  async function count(app: FastifyInstance, sql: string, params: unknown[] = []) {
    const { rows } = await app.dbPool.query<{ count: string }>(sql, params);
    return Number(rows[0]?.count ?? 0);
  }

  const users = (app: FastifyInstance) => count(app, 'SELECT count(*) AS count FROM users');
  const credentialsOf = (app: FastifyInstance, type: string) =>
    count(app, 'SELECT count(*) AS count FROM user_credentials WHERE provider_type = $1', [type]);
  const sessions = (app: FastifyInstance) => count(app, 'SELECT count(*) AS count FROM sessions');
  const codes = (app: FastifyInstance) =>
    count(app, 'SELECT count(*) AS count FROM authorization_codes');

  /** The upstream sign-in's events of `type` (`method: upstream`), oldest first. */
  async function events(app: FastifyInstance, type: string) {
    const { rows } = await app.dbPool.query<{
      data: Record<string, unknown>;
      subject_id: string | null;
    }>('SELECT data, subject_id FROM events WHERE type = $1 ORDER BY seq', [type]);
    return rows.filter((row) => row.data['method'] === 'upstream');
  }

  /** The subjects of the upstream sign-in's events of `type`, oldest first. */
  async function subjectsOf(app: FastifyInstance, type: string) {
    return (await events(app, type)).map((event) => event.subject_id);
  }

  /** The reasons of the refused upstream sign-ins, oldest first. */
  async function refusals(app: FastifyInstance): Promise<unknown[]> {
    return (await events(app, SIGN_IN_FAILED)).map((event) => event.data['reason']);
  }

  /** The account's credential of `type` for the person's `sub`. */
  async function credentialOf(
    app: FastifyInstance,
    realmId: string,
    type = TYPE,
    sub = PERSON.sub
  ) {
    const credential = await app.repositories.userCredentials.findByRealmProviderSub(
      realmId,
      type,
      sub
    );
    if (credential === undefined) throw new Error(`no ${type} credential for ${sub}`);
    return credential;
  }

  /** The attributes of the account from `source`, by key. */
  async function attributesOf(app: FastifyInstance, userId: string, source = TYPE) {
    const rows = await app.repositories.userAttributes.findByUserIdAndSource(userId, source);
    return rows
      .map((row) => ({ key: row.attrKey, value: row.attrValue, verified: row.verified }))
      .sort((a, b) => a.key.localeCompare(b.key));
  }

  /** Give the account a passkey: a `webauthn` credential, as an enrolment stores it. */
  async function addPasskey(app: FastifyInstance, realmId: string, userId: string): Promise<void> {
    await app.repositories.userCredentials.create({
      userId,
      realmId,
      providerType: 'webauthn',
      externalSub: 'Y3JlZGVudGlhbC0x',
      credentialData: {
        public_key: 'pQECAyYgASFYIK_voW-Xypst',
        algorithm: -7,
        sign_count: 0,
        transports: ['internal'],
        backup_eligible: true,
        backed_up: true,
        aaguid: '00000000-0000-0000-0000-000000000000',
        rp_id: 'auth.example.com',
        user_handle: 'dXNlci1oYW5kbGU',
        nickname: null,
        created_at: Date.now(),
        last_used_at: null,
        sign_counter_regressed_at: null,
      },
    });
  }

  describe('with the server-rendered pages (INTERACTION_UI_ENABLED off), sign-up on', () => {
    const server = bootForBlock({ ALLOW_SIGN_UP: 'true' });

    describe('a first sign-in through the provider', () => {
      it('creates one user, one credential and the provider attributes of its source, and issues the code', async () => {
        const app = server.app();
        const usersBefore = await users(app);
        const jar = new CookieJar();

        await codeAfterPages(app, jar, await signInAtProvider(app, jar));

        expect(await users(app)).toBe(usersBefore + 1);
        expect(await credentialsOf(app, TYPE)).toBe(1);
        const credential = await credentialOf(app, server.realmId());
        expect(credential).toMatchObject({ providerType: TYPE, externalSub: PERSON.sub });
        expect(credential.credentialData).toEqual({
          kind: 'upstream',
          iss: provider.issuer,
          verified: true,
        });
        // The provider's claims, under its source only; `email` verified as the provider said.
        expect(await attributesOf(app, credential.userId)).toEqual([
          { key: 'email', value: EMAIL, verified: true },
          { key: 'name', value: 'Ada Lovelace', verified: false },
        ]);
        const { rows } = await app.dbPool.query<{ source: string }>(
          'SELECT DISTINCT source FROM user_attributes WHERE user_id = $1',
          [credential.userId]
        );
        expect(rows.map((row) => row.source)).toEqual([TYPE]);
        expect(await subjectsOf(app, REGISTERED)).toEqual([credential.userId]);
        expect(await subjectsOf(app, SIGNED_IN)).toEqual([credential.userId]);
      });
    });

    describe('a returning sign-in', () => {
      it('signs the same user in again for the same subject, creating nothing', async () => {
        const app = server.app();
        const first = new CookieJar();
        await codeAfterPages(app, first, await signInAtProvider(app, first));
        const { userId } = await credentialOf(app, server.realmId());
        const usersAfterFirst = await users(app);

        const second = new CookieJar();
        await codeAfterPages(app, second, await signInAtProvider(app, second));

        expect(await users(app)).toBe(usersAfterFirst);
        expect(await credentialsOf(app, TYPE)).toBe(1);
        expect(await events(app, REGISTERED)).toHaveLength(1);
        expect(await subjectsOf(app, SIGNED_IN)).toEqual([userId, userId]);
      });
    });

    describe('the issuer tie', () => {
      it('refuses a credential stored under another issuer with the error page, and signs nobody in', async () => {
        const app = server.app();
        const first = new CookieJar();
        await codeAfterPages(app, first, await signInAtProvider(app, first));
        const { userId } = await credentialOf(app, server.realmId());
        // The credential was created under another issuer that used the same `sub`.
        await app.dbPool.query(
          `UPDATE user_credentials
              SET credential_data = credential_data || '{"iss":"https://idp.retired.example"}'::jsonb
            WHERE provider_type = $1 AND external_sub = $2`,
          [TYPE, PERSON.sub]
        );
        const sessionsBefore = await sessions(app);
        const codesBefore = await codes(app);

        const jar = new CookieJar();
        const refused = await signInAtProvider(app, jar);

        expectErrorPage(refused);
        expect(jar.get(SESSION_COOKIE)).toBeUndefined();
        expect(await sessions(app)).toBe(sessionsBefore);
        expect(await codes(app)).toBe(codesBefore);
        expect(await refusals(app)).toEqual(['issuer_mismatch']);
        expect(await subjectsOf(app, SIGN_IN_FAILED)).toEqual([userId]);
        expect(await credentialsOf(app, TYPE)).toBe(1);
      });
    });

    describe('an account that holds a passkey', () => {
      it('fails closed with the error page: the pages cannot ask for the passkey, MFA off', async () => {
        const app = server.app();
        const first = new CookieJar();
        await codeAfterPages(app, first, await signInAtProvider(app, first));
        const { userId } = await credentialOf(app, server.realmId());
        await addPasskey(app, server.realmId(), userId);
        const sessionsBefore = await sessions(app);
        const codesBefore = await codes(app);

        const jar = new CookieJar();
        const refused = await signInAtProvider(app, jar);

        expectErrorPage(refused);
        expect(jar.get(SESSION_COOKIE)).toBeUndefined();
        expect(await sessions(app)).toBe(sessionsBefore);
        expect(await codes(app)).toBe(codesBefore);
        expect(await refusals(app)).toContain('step_not_available');
        expect(await subjectsOf(app, SIGNED_IN)).toEqual([userId]);
      });
    });

    describe('an account with the same email', () => {
      it('gets no match: the provider creates a separate account and leaves the password account as it was', async () => {
        const app = server.app();
        const passwordUserId = await registerPasswordAccount(app, EMAIL);
        const passwordCredential = await credentialOf(app, server.realmId(), 'password', EMAIL);
        const usersBefore = await users(app);

        const jar = new CookieJar();
        await codeAfterPages(app, jar, await signInAtProvider(app, jar));

        expect(await users(app)).toBe(usersBefore + 1);
        const upstream = await credentialOf(app, server.realmId());
        expect(upstream.userId).not.toBe(passwordUserId);
        // The password account: its one credential, unchanged, and no attribute of the provider.
        expect(await credentialOf(app, server.realmId(), 'password', EMAIL)).toEqual(
          passwordCredential
        );
        expect(await app.repositories.userCredentials.findAllByUserId(passwordUserId)).toHaveLength(
          1
        );
        expect(await attributesOf(app, passwordUserId)).toEqual([]);
        expect(await subjectsOf(app, SIGNED_IN)).toEqual([upstream.userId]);
      });
    });

    describe('a hidden provider', () => {
      it('is absent from the sign-in page and still reachable through qauth_upstream', async () => {
        const app = server.app();
        const jar = new CookieJar();
        const toLogin = await get(app, jar, authorizeUrl());
        expect(toLogin.statusCode, toLogin.body).toBe(302);
        const login = await get(app, jar, pathOf(toLogin.headers['location']));
        expect(login.statusCode).toBe(200);

        const links = providerLinksOf(login.body);
        expect(links).toHaveLength(1);
        expect(links[0]?.startsWith(`/ui/upstream/${TYPE}?return_to=`)).toBe(true);
        expect(login.body).not.toContain(HIDDEN_TYPE);
        expect(login.body).not.toContain('Partner');

        const routed = new CookieJar();
        await codeAfterPages(app, routed, await signInAtProvider(app, routed, PERSON, HIDDEN_TYPE));
        expect(await credentialsOf(app, HIDDEN_TYPE)).toBe(1);
        expect(await credentialsOf(app, TYPE)).toBe(0);
      });
    });

    describe('a callback replayed in another browser', () => {
      it('is refused before any code is redeemed and creates nothing, and the original browser still completes', async () => {
        const app = server.app();
        const usersBefore = await users(app);
        const jar = new CookieJar();
        const started = await startProvider(app, jar);
        const answer = provider.authorize(started.providerRequest, PERSON);
        const redeemedBefore = provider.tokenRequests.length;

        // Another browser: no flow cookie of the start.
        const elsewhere = new CookieJar();
        const replayed = await callbackAt(app, elsewhere, TYPE, answer);

        expectErrorPage(replayed);
        expect(provider.tokenRequests).toHaveLength(redeemedBefore);
        expect(elsewhere.get(SESSION_COOKIE)).toBeUndefined();
        expect(await users(app)).toBe(usersBefore);
        expect(await credentialsOf(app, TYPE)).toBe(0);
        expect(await refusals(app)).toEqual(['transaction_mismatch']);

        // The pending sign-in is still the original browser's.
        await codeAfterPages(app, jar, await callbackAt(app, jar, TYPE, answer));
        expect(provider.tokenRequests).toHaveLength(redeemedBefore + 1);
        expect(await users(app)).toBe(usersBefore + 1);
      });
    });

    describe('a cancel at the provider', () => {
      it('shows the provider-error page and sends nothing to the client', async () => {
        const app = server.app();
        const usersBefore = await users(app);
        const jar = new CookieJar();
        const started = await startProvider(app, jar);
        const redeemedBefore = provider.tokenRequests.length;

        const cancelled = await callbackAt(app, jar, TYPE, {
          error: 'access_denied',
          state: started.providerRequest.searchParams.get('state') ?? '',
          iss: provider.issuer,
        });

        expect(cancelled.statusCode, cancelled.body).toBe(200);
        expect(cancelled.body).toContain(PROVIDER_ERROR_TITLE);
        expect(cancelled.body).toContain('Corp');
        // Nothing for the client: no redirect, no code, no error at its redirect URI.
        expect(cancelled.headers['location']).toBeUndefined();
        expect(await codes(app)).toBe(0);
        expect(provider.tokenRequests).toHaveLength(redeemedBefore);
        expect(jar.get(SESSION_COOKIE)).toBeUndefined();
        expect(await users(app)).toBe(usersBefore);
        expect(await refusals(app)).toEqual(['declined']);
      });
    });

    describe("the provider's verified switch off", () => {
      it('creates no account the pages could never sign in, and shows the error page', async () => {
        const app = server.app();
        await app.repositories.realmUpstreamProviders.update(server.realmId(), TYPE, {
          marksVerified: false,
        });
        const usersBefore = await users(app);
        const jar = new CookieJar();

        // The pages show no code step, so the address QAuth would verify could never be.
        const refused = await signInAtProvider(app, jar);

        expectErrorPage(refused);
        expect(jar.get(SESSION_COOKIE)).toBeUndefined();
        expect(await users(app)).toBe(usersBefore);
        expect(await credentialsOf(app, TYPE)).toBe(0);
        expect(await events(app, REGISTERED)).toEqual([]);
        expect(await codes(app)).toBe(0);
        expect(await refusals(app)).toEqual(['verification_unavailable']);
      });
    });

    describe('without JavaScript', () => {
      it('goes from the sign-in page through the provider link and the waiting page to the code', async () => {
        const app = server.app();
        const jar = new CookieJar();

        // No session: the sign-in page, for the parked request.
        const toLogin = await get(app, jar, authorizeUrl());
        expect(toLogin.statusCode, toLogin.body).toBe(302);
        const loginPath = pathOf(toLogin.headers['location']);
        expect(loginPath.startsWith('/ui/login?return_to='), loginPath).toBe(true);
        const login = await get(app, jar, loginPath);
        expect(login.statusCode).toBe(200);
        expect(login.body).toContain('Sign in with Corp');

        // The provider's button: a plain link, back to the request with qauth_upstream.
        const [button] = providerLinksOf(login.body);
        if (button === undefined) throw new Error('no provider link on the sign-in page');
        const routedBack = await get(app, jar, button);
        expect(routedBack.statusCode, routedBack.body).toBe(302);
        const routed = pathOf(routedBack.headers['location']);
        expect(routed.startsWith('/oauth/authorize?'), routed).toBe(true);
        expect(new URL(routed, ORIGIN).searchParams.get('qauth_upstream')).toBe(TYPE);

        // The waiting page: a meta refresh and a link to the provider.
        const started = await waitingPage(app, jar, await get(app, jar, routed), TYPE);
        expect(started.page).toContain('http-equiv="refresh"');

        const answer = provider.authorize(started.providerRequest, PERSON);
        const callback = await callbackAt(app, jar, TYPE, answer);

        await codeAfterPages(app, jar, callback);
        expect(await credentialsOf(app, TYPE)).toBe(1);
      });
    });
  });

  describe('with the Interaction API ceremony page (INTERACTION_UI_ENABLED on), sign-up on', () => {
    const server = bootForBlock({ INTERACTION_UI_ENABLED: 'true', ALLOW_SIGN_UP: 'true' });

    /** The step read of the interaction `id`, as the ceremony app's server makes it. */
    async function stepOf(app: FastifyInstance, id: string) {
      const response = await app.inject({ method: 'GET', url: `${INTERACTION_API_PREFIX}/${id}` });
      expect(response.statusCode, response.body).toBe(200);
      return response.json() as {
        step: string;
        alternatives: string[];
        params: Record<string, unknown>;
      };
    }

    describe('an account with no passkey', () => {
      it('signs in through the provider alone: the callback sends the code to the client', async () => {
        const app = server.app();
        const jar = new CookieJar();

        const callback = await signInAtProvider(app, jar);

        expect(callback.statusCode, withServerLog(callback.body)).toBe(303);
        codeAt(callback.headers['location']);
        expect(jar.get(SESSION_COOKIE)).toBeDefined();
        const { userId } = await credentialOf(app, server.realmId());
        expect(await subjectsOf(app, SIGNED_IN)).toEqual([userId]);
        expect(await codes(app)).toBe(1);
      });
    });

    describe('an account that holds a passkey', () => {
      // Upstream ranks below a passkey (ADR-017 Decision 4): the sign-in
      // cannot complete through the provider alone. No passkey step handler
      // is registered with the engine yet (#651), so it fails closed here
      // too; once one is, this callback goes to the ceremony page instead.
      it('never completes through the provider alone, MFA off: no session and no code', async () => {
        const app = server.app();
        const first = new CookieJar();
        const created = await signInAtProvider(app, first);
        expect(created.statusCode, created.body).toBe(303);
        codeAt(created.headers['location']);
        const { userId } = await credentialOf(app, server.realmId());
        await addPasskey(app, server.realmId(), userId);
        const sessionsBefore = await sessions(app);

        const jar = new CookieJar();
        const refused = await signInAtProvider(app, jar);

        expectErrorPage(refused);
        expect(jar.get(SESSION_COOKIE)).toBeUndefined();
        expect(await sessions(app)).toBe(sessionsBefore);
        expect(await codes(app)).toBe(1);
        expect(await refusals(app)).toContain('step_not_available');
      });
    });

    describe("the provider's verified switch off", () => {
      it('leaves the account and its email unverified though the provider vouched for it, and asks for a code', async () => {
        const app = server.app();
        await app.repositories.realmUpstreamProviders.update(server.realmId(), TYPE, {
          marksVerified: false,
        });
        const jar = new CookieJar();

        const callback = await signInAtProvider(app, jar);

        const credential = await credentialOf(app, server.realmId());
        expect(credential.credentialData).toEqual({
          kind: 'upstream',
          iss: provider.issuer,
          verified: false,
        });
        expect(await attributesOf(app, credential.userId)).toEqual([
          { key: 'email', value: EMAIL, verified: false },
          { key: 'name', value: 'Ada Lovelace', verified: false },
        ]);
        // The address QAuth has not verified: the ceremony page asks for an emailed code.
        expect(callback.statusCode, withServerLog(callback.body)).toBe(303);
        const id = ceremonyIdOf(callback.headers['location']);
        expect((await stepOf(app, id)).step).toBe(EMAIL_CODE);
        expect(await codes(app)).toBe(0);
      });
    });

    describe('a hidden provider', () => {
      it("is absent from the first step's provider list and still reachable through qauth_upstream", async () => {
        const app = server.app();
        const jar = new CookieJar();
        const ceremony = await get(app, jar, authorizeUrl());
        expect(ceremony.statusCode, ceremony.body).toBe(302);

        const step = await stepOf(app, ceremonyIdOf(ceremony.headers['location']));

        expect(step.step).toBe(IDENTIFIER);
        expect(step.alternatives).toEqual([UPSTREAM]);
        expect(step.params[UPSTREAM]).toEqual({ providers: [{ provider: TYPE, name: 'Corp' }] });
        expect(JSON.stringify(step)).not.toContain(HIDDEN_TYPE);

        const routed = new CookieJar();
        const callback = await signInAtProvider(app, routed, PERSON, HIDDEN_TYPE);
        expect(callback.statusCode, withServerLog(callback.body)).toBe(303);
        codeAt(callback.headers['location']);
        expect(await credentialsOf(app, HIDDEN_TYPE)).toBe(1);
      });
    });
  });

  describe('with sign-up off (ALLOW_SIGN_UP unset)', () => {
    const server = bootForBlock({});

    describe('an unknown subject', () => {
      it('gets the error page and creates no account', async () => {
        const app = server.app();
        const usersBefore = await users(app);
        const jar = new CookieJar();

        const refused = await signInAtProvider(app, jar);

        expectErrorPage(refused);
        expect(jar.get(SESSION_COOKIE)).toBeUndefined();
        expect(await users(app)).toBe(usersBefore);
        expect(await credentialsOf(app, TYPE)).toBe(0);
        expect(await events(app, REGISTERED)).toEqual([]);
        expect(await codes(app)).toBe(0);
        expect(await refusals(app)).toEqual(['sign_up_disabled']);
      });
    });

    describe('a known subject', () => {
      it('still signs in: sign-up off creates nothing, it refuses no account', async () => {
        const app = server.app();
        const realmId = server.realmId();
        const user = await app.repositories.users.create({ realmId });
        await app.repositories.userCredentials.create({
          userId: user.id,
          realmId,
          providerType: TYPE,
          externalSub: PERSON.sub,
          credentialData: { kind: 'upstream', iss: provider.issuer, verified: true },
        });
        const jar = new CookieJar();

        await codeAfterPages(app, jar, await signInAtProvider(app, jar));

        expect(await subjectsOf(app, SIGNED_IN)).toEqual([user.id]);
      });
    });
  });
});
