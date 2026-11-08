import type { EgressClient } from '@qauth-labs/fastify-plugin-egress';
import {
  createFakeProvider,
  type FakeProvider,
  type FakeSignIn,
} from '@qauth-labs/fastify-plugin-federation/src/testing/upstream-oidc-fixtures';
import {
  createTestSigner,
  type TestSigner,
} from '@qauth-labs/fastify-plugin-signer/src/testing/memory-signer';
import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  ADMIN_LISTENER_ENVIRONMENT,
  adminCallHeaders,
  signBoundAccessToken,
} from '../testing/admin-dpop';
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
  provisionRealmKeys,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { SESSION_COOKIE } from '../testing/session-cookie-value';
import { API_FAMILY_AUDIENCES } from './api-conventions/families';

/**
 * THE PROVIDER PLUGINS OF `libs/plugins/` (#671), end to end against real
 * Postgres and Redis: the Google, Microsoft and Apple plugins, presets on the
 * generic upstream OpenID Connect client, loaded by package name from the
 * server's first-party list with the plugin API off.
 *
 * Each provider is the upstream OIDC library's fake OpenID Provider at the
 * provider's real issuer. The suite's egress client answers from those fakes
 * by issuer and reaches nothing else: no network. The realm's state of each
 * plugin is written as the admin API's plugin operations write it, its
 * client secret sealed under the plugin's context.
 *
 * - a full sign-in through each plugin creates one account, its credential
 *   and the provider's attributes as the plugin maps them;
 * - Microsoft: with a fixed tenant, a token another tenant issued is
 *   refused; through the multi-tenant endpoints, a token whose issuer is the
 *   template with its `tid` is accepted; the email is unverified;
 * - Apple: the response arrives as a cross-site `form_post`, which the
 *   callback bounces to its GET route; the name of the `user` member is
 *   stored once and a later sign-in does not change it; a private relay
 *   address is not kept as the account's email;
 * - the admin API's plugin list shows the three, first-party and off.
 *
 * Apple's client secret is a JWT the signer role signs with the realm's
 * `upstream_client_assertion` key for the plugin, as the Team ID. The
 * deployment's signer store reads no provider configuration yet
 * (`findUpstreamClient` answers none), so the Apple tests hand that one
 * operation to a test signer: the in-process signer over an in-memory key
 * store, holding the realm's Apple key and Team ID.
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
const STATE = 'provider-plugin-state';

/** The packages, as `AUTH_METHOD_PLUGINS` lists them. The server loads them by name. */
const PACKAGES = [
  '@qauth-labs/plugin-google',
  '@qauth-labs/plugin-microsoft',
  '@qauth-labs/plugin-apple',
];

const GOOGLE_ISSUER = 'https://accounts.google.com';
const GOOGLE_CLIENT_ID = '1234-qauth.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = '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th';

const MICROSOFT_HOST = 'https://login.microsoftonline.com';
const microsoftIssuer = (tenant: string) => `${MICROSOFT_HOST}/${tenant}/v2.0`;
const MICROSOFT_ISSUER_TEMPLATE = microsoftIssuer('{tenantid}');
const MICROSOFT_CLIENT_ID = '6731de76-14a6-49ae-97bc-6eba6914391e';
const MICROSOFT_CLIENT_SECRET = 'a-microsoft-client-secret-of-some-length';
const TENANT = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a';
const OTHER_TENANT = '9122040d-6c67-4c5b-b112-36a304b66dad';

const APPLE_ISSUER = 'https://appleid.apple.com';
/** The Services ID: the client id at Apple. */
const SERVICES_ID = 'com.example.signin';
/** The developer team's Team ID: the client secret's `iss`. */
const TEAM_ID = 'A1B2C3D4E5';

/** The page titles of `helpers/upstream-pages.ts`, written out: app modules read the environment at import. */
const WAITING_TITLE = 'Continuing to your sign-in provider';
const ERROR_TITLE = 'We could not sign you in';

const SIGN_IN_FAILED = 'urn:qauth:event:user.sign_in_failed:v1-rc.0';

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

/**
 * An egress client that answers every call from the fake provider whose
 * issuer the URL is under, and refuses any other: the providers' real hosts
 * are never resolved.
 */
function fakeProviderEgress(providers: readonly FakeProvider[]): () => EgressClient {
  const owner = (url: URL) =>
    providers.find((provider) => url.href.startsWith(`${provider.issuer}/`));
  return () => ({
    async request(call) {
      const url = new URL(String(call.url));
      const provider = owner(url);
      if (provider === undefined) {
        throw new Error(`no fake provider answers ${url.origin}${url.pathname}`);
      }
      const answer = await provider.answer({
        method: call.method,
        url: url.href,
        ...(call.headers === undefined ? {} : { headers: call.headers }),
        ...(call.body === undefined ? {} : { body: call.body }),
      });
      return {
        status: answer.status,
        headers: answer.headers,
        body: Buffer.from(answer.body),
        url: answer.url,
        redirects: 0,
      };
    },
    async validateDestination(url) {
      const parsed = new URL(String(url));
      if (owner(parsed) === undefined) {
        throw new Error(`no fake provider answers ${parsed.origin}${parsed.pathname}`);
      }
      return { url: parsed.href, host: parsed.hostname, port: 443, addresses: ['192.0.2.10'] };
    },
    counts: () => ({}),
  });
}

describe('the provider plugins (#671, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let realmId = '';

  let google: FakeProvider;
  /** Microsoft's endpoints of one tenant, and its multi-tenant `organizations` endpoints. */
  let microsoftTenant: FakeProvider;
  let microsoftOrganizations: FakeProvider;
  let apple: FakeProvider;
  /** The test signer the current Apple test signs its client secrets with. */
  let appleSigner: TestSigner | undefined;
  /** Puts the server's own signer back after an Apple test. */
  let restoreSigner: (() => void) | undefined;

  /** The server's warnings and errors in the current test, for an assertion to say why. */
  const serverLog: string[] = [];

  /** `body`, with the server's warnings and errors of this test after it. */
  function withServerLog(body: string): string {
    return serverLog.length === 0 ? body : `${body}\nserver log:\n${serverLog.join('')}`;
  }

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();

    google = await createFakeProvider({
      issuer: GOOGLE_ISSUER,
      algorithm: 'RS256',
      issParameter: false,
    });
    google.register({
      clientId: GOOGLE_CLIENT_ID,
      method: 'client_secret_post',
      clientSecret: GOOGLE_CLIENT_SECRET,
      redirectUris: [callbackUrlOf('google')],
    });

    microsoftTenant = await createFakeProvider({
      issuer: microsoftIssuer(TENANT),
      algorithm: 'RS256',
      issParameter: false,
    });
    microsoftOrganizations = await createFakeProvider({
      issuer: microsoftIssuer('organizations'),
      algorithm: 'RS256',
      issParameter: false,
      documentIssuer: MICROSOFT_ISSUER_TEMPLATE,
    });
    for (const provider of [microsoftTenant, microsoftOrganizations]) {
      provider.register({
        clientId: MICROSOFT_CLIENT_ID,
        method: 'client_secret_post',
        clientSecret: MICROSOFT_CLIENT_SECRET,
        redirectUris: [callbackUrlOf('microsoft')],
      });
    }

    apple = await createFakeProvider({
      issuer: APPLE_ISSUER,
      algorithm: 'RS256',
      issParameter: false,
      tokenEndpointAuthMethods: ['client_secret_post'],
    });
    apple.register({
      clientId: SERVICES_ID,
      method: 'signed_client_secret',
      secretIssuer: TEAM_ID,
      redirectUris: [callbackUrlOf('apple')],
      // The key Apple holds for the developer team: the realm's Apple key.
      assertionKeys: async () => {
        if (appleSigner === undefined) return { keys: [] };
        return appleSigner.signer.getUpstreamJwks('api', realmId, 'apple');
      },
    });

    booted = await bootAuthServer(
      {
        ...baseEnvironment(infra, jwt),
        ...ADMIN_LISTENER_ENVIRONMENT,
        AUTHORIZE_RATE_LIMIT: '10000',
        AUTHORIZE_RATE_LIMIT_LENIENT: '10000',
        ALLOW_SIGN_UP: 'true',
        AUTH_METHOD_PLUGINS: PACKAGES.join(','),
      },
      {
        egressClientFactory: fakeProviderEgress([
          google,
          microsoftTenant,
          microsoftOrganizations,
          apple,
        ]),
        adminListener: async () => ({}),
        // The packages themselves, imported from this app as the server
        // imports them; the first-party list is the server's own.
        authMethodPlugins: { importPackage: (name: string) => import(name) },
        logStream: { write: (line: string) => void serverLog.push(line) },
      }
    );
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    for (const name of ['AUTHORIZE_RATE_LIMIT', 'AUTHORIZE_RATE_LIMIT_LENIENT', 'ALLOW_SIGN_UP']) {
      delete process.env[name];
    }
    await infra?.teardown();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined) {
      ctx.skip();
      return;
    }
    realmId = await seed(booted.app);
    serverLog.length = 0;
  }, 120_000);

  afterEach(() => {
    restoreSigner?.();
    restoreSigner = undefined;
    appleSigner = undefined;
  });

  function app(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  function admin(): FastifyInstance {
    if (booted?.admin === undefined) throw new Error('admin listener not booted');
    return booted.admin;
  }

  /** Reset the state, seed the client, and answer the default realm's id. */
  async function seed(server: FastifyInstance): Promise<string> {
    await resetE2eState(server);
    const realm = await server.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    await server.repositories.oauthClients.create({
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
      provisionedByOperator: true,
    });
    // The operator flags it first-party (ADR-017 Decision 2): an account the
    // flow creates gets its code with no consent screen.
    await server.dbPool.query(
      `UPDATE oauth_clients
          SET first_party_profile = 'web_redirect', first_party_reason = 'The developer portal.'
        WHERE client_id = $1`,
      [CLIENT_ID]
    );
    return realm.id;
  }

  /**
   * Turn the plugin `id` on in the realm with `config`, and `secrets` sealed
   * under the plugin's context, as `plugins.update` and `plugins.enable`
   * store them.
   */
  async function enablePlugin(
    id: string,
    config: Record<string, unknown>,
    secrets: Record<string, string> = {}
  ): Promise<void> {
    const plugin = app().authMethodPlugins.find(id);
    if (plugin === undefined) throw new Error(`the plugin ${id} is not loaded`);
    // Imported once the boot reset the modules, as the app loaded it.
    const { authMethodPluginSecretCipher } = await import('./helpers/auth-method-plugins');
    const cipher = authMethodPluginSecretCipher(app());
    const sealed: Record<string, string> = {};
    for (const [path, value] of Object.entries(secrets)) {
      sealed[path] = await cipher.seal(realmId, plugin, path, value);
    }
    const repository = app().repositories.realmAuthMethodPlugins;
    const before = await repository.find(realmId, id);
    const written = await repository.save(
      realmId,
      id,
      {
        enabled: true,
        config,
        secrets: sealed,
        binding: { package: plugin.package, type: plugin.type },
      },
      before?.version ?? null
    );
    if (written === undefined) throw new Error(`the state of ${id} was not written`);
  }

  async function get(jar: CookieJar, url: string): Promise<LightMyRequestResponse> {
    const cookie = jar.header();
    const response = await app().inject({
      method: 'GET',
      url,
      headers: cookie === undefined ? {} : { cookie },
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  function authorizeUrl(type: string): string {
    return `/oauth/authorize?${new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'openid email',
      code_challenge: pkcePair().challenge,
      code_challenge_method: 'S256',
      state: STATE,
      qauth_upstream: type,
    }).toString()}`;
  }

  /**
   * Route the client's request to the plugin of `type`, up to the waiting
   * page, and answer the authorization request it sends the browser to.
   */
  async function startAt(jar: CookieJar, type: string, provider: FakeProvider): Promise<URL> {
    const routed = await get(jar, authorizeUrl(type));
    expect(routed.statusCode, withServerLog(routed.body)).toBe(302);
    const start = new URL(String(routed.headers['location']), ORIGIN);
    expect(start.pathname).toBe(`/ui/upstream/${type}/start`);
    const page = await get(jar, `${start.pathname}${start.search}`);
    expect(page.statusCode, withServerLog(page.body)).toBe(200);
    expect(page.body).toContain(WAITING_TITLE);
    const link = /<a class="alt-action" href="([^"]+)"/.exec(page.body)?.[1];
    if (link === undefined) throw new Error('no provider link on the waiting page');
    const providerRequest = new URL(decodeHtmlEntities(link));
    expect(`${providerRequest.origin}${providerRequest.pathname}`).toBe(
      provider.authorizationEndpoint
    );
    expect(providerRequest.searchParams.get('redirect_uri')).toBe(callbackUrlOf(type));
    return providerRequest;
  }

  /** Start the plugin of `type`, sign `person` in at `provider`, and come back to the GET callback. */
  async function signInAt(
    jar: CookieJar,
    type: string,
    provider: FakeProvider,
    person: FakeSignIn
  ): Promise<LightMyRequestResponse> {
    const answer = provider.authorize(await startAt(jar, type, provider), person);
    expect(answer['error']).toBeUndefined();
    return get(jar, `/upstream/${type}/callback?${new URLSearchParams(answer).toString()}`);
  }

  /**
   * The pages' end of a sign-in: the callback sends the browser back to the
   * authorization request, which issues the code under the new session.
   */
  async function codeAfterPages(jar: CookieJar, callback: LightMyRequestResponse): Promise<void> {
    expect(callback.statusCode, withServerLog(callback.body)).toBe(303);
    expect(jar.get(SESSION_COOKIE)).toBeDefined();
    const back = pathOf(callback.headers['location']);
    expect(back.startsWith('/oauth/authorize?'), back).toBe(true);
    const again = await get(jar, back);
    expect(again.statusCode, again.body).toBe(302);
    codeAt(again.headers['location']);
  }

  /** The one error page: 400, its text, and no redirect anywhere. */
  function expectErrorPage(response: LightMyRequestResponse): void {
    expect(response.statusCode, response.body).toBe(400);
    expect(response.body).toContain(ERROR_TITLE);
    expect(response.headers['location']).toBeUndefined();
  }

  async function users(): Promise<number> {
    const { rows } = await app().dbPool.query<{ count: string }>(
      'SELECT count(*) AS count FROM users'
    );
    return Number(rows[0]?.count ?? 0);
  }

  /** The reasons of the refused upstream sign-ins, oldest first. */
  async function refusals(): Promise<unknown[]> {
    const { rows } = await app().dbPool.query<{ data: Record<string, unknown> }>(
      'SELECT data FROM events WHERE type = $1 ORDER BY seq',
      [SIGN_IN_FAILED]
    );
    return rows.filter((row) => row.data['method'] === 'upstream').map((row) => row.data['reason']);
  }

  /** The account's credential of `type` for `sub`. */
  async function credentialOf(type: string, sub: string) {
    const credential = await app().repositories.userCredentials.findByRealmProviderSub(
      realmId,
      type,
      sub
    );
    if (credential === undefined) throw new Error(`no ${type} credential for ${sub}`);
    return credential;
  }

  /** The attributes of the account from `source`, by key. */
  async function attributesOf(userId: string, source: string) {
    const rows = await app().repositories.userAttributes.findByUserIdAndSource(userId, source);
    return rows
      .map((row) => ({ key: row.attrKey, value: row.attrValue, verified: row.verified }))
      .sort((a, b) => a.key.localeCompare(b.key));
  }

  // Acceptance criterion: a full sign-in (mock provider per plugin) creates
  // an account with the right attributes.
  describe('Google', () => {
    const PERSON: FakeSignIn = {
      sub: '110169484474386276334',
      claims: {
        email: 'ada@example.com',
        email_verified: true,
        name: 'Ada Lovelace',
        given_name: 'Ada',
        family_name: 'Lovelace',
        hd: 'example.com',
      },
    };

    it('creates the account with the verified email and an unverified hd', async () => {
      await enablePlugin(
        'google',
        { clientId: GOOGLE_CLIENT_ID },
        { clientSecret: GOOGLE_CLIENT_SECRET }
      );
      const usersBefore = await users();
      const jar = new CookieJar();

      await codeAfterPages(jar, await signInAt(jar, 'google', google, PERSON));

      expect(await users()).toBe(usersBefore + 1);
      const credential = await credentialOf('google', PERSON.sub);
      expect(credential).toMatchObject({ providerType: 'google', isPrimary: true });
      expect(credential.credentialData).toEqual({
        kind: 'upstream',
        iss: GOOGLE_ISSUER,
        verified: true,
      });
      expect(await attributesOf(credential.userId, 'google')).toEqual([
        { key: 'email', value: 'ada@example.com', verified: true },
        { key: 'family_name', value: 'Lovelace', verified: false },
        { key: 'given_name', value: 'Ada', verified: false },
        { key: 'hd', value: 'example.com', verified: false },
        { key: 'name', value: 'Ada Lovelace', verified: false },
      ]);
      // The client secret went in the token request's body.
      expect(google.tokenRequests.at(-1)?.get('client_secret')).toBe(GOOGLE_CLIENT_SECRET);
    });
  });

  describe('Microsoft', () => {
    const SUB = 'AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ';
    const person = (tenant: string, claims: Record<string, unknown> = {}): FakeSignIn => ({
      sub: SUB,
      claims: {
        iss: microsoftIssuer(tenant),
        tid: tenant,
        email: 'ada@contoso.example',
        // A verified email elsewhere: never the domain's verification.
        email_verified: true,
        name: 'Ada Lovelace',
        preferred_username: 'ada@contoso.example',
        ...claims,
      },
    });

    const configFor = (tenant: string) => ({ tenant, clientId: MICROSOFT_CLIENT_ID });
    const SECRETS = { clientSecret: MICROSOFT_CLIENT_SECRET };

    // Acceptance criteria: the email attribute is unverified by default; and
    // the full sign-in creates the account with the right attributes.
    it("creates the account of the configured tenant's person, the email unverified", async () => {
      await enablePlugin('microsoft', configFor(TENANT), SECRETS);
      const usersBefore = await users();
      const jar = new CookieJar();

      await codeAfterPages(jar, await signInAt(jar, 'microsoft', microsoftTenant, person(TENANT)));

      expect(await users()).toBe(usersBefore + 1);
      const credential = await credentialOf('microsoft', SUB);
      expect(credential.credentialData).toMatchObject({ iss: microsoftIssuer(TENANT) });
      expect(await attributesOf(credential.userId, 'microsoft')).toEqual([
        { key: 'email', value: 'ada@contoso.example', verified: false },
        { key: 'name', value: 'Ada Lovelace', verified: false },
        { key: 'preferred_username', value: 'ada@contoso.example', verified: false },
        { key: 'tid', value: TENANT, verified: false },
      ]);
    });

    // Acceptance criterion: a token from another tenant than the configured
    // one is refused.
    it('refuses, with a fixed tenant, a token another tenant issued, and creates nothing', async () => {
      await enablePlugin('microsoft', configFor(TENANT), SECRETS);
      const usersBefore = await users();
      const jar = new CookieJar();

      const refused = await signInAt(jar, 'microsoft', microsoftTenant, person(OTHER_TENANT));

      expectErrorPage(refused);
      expect(jar.get(SESSION_COOKIE)).toBeUndefined();
      expect(await users()).toBe(usersBefore);
      expect(await refusals()).toEqual(['invalid_response']);
    });

    // Acceptance criterion: a multi-tenant token with a matching issuer
    // template is accepted.
    it("accepts, through the multi-tenant endpoints, a token whose issuer is the template with the token's tid", async () => {
      await enablePlugin('microsoft', configFor('organizations'), SECRETS);
      const jar = new CookieJar();

      await codeAfterPages(
        jar,
        await signInAt(jar, 'microsoft', microsoftOrganizations, person(OTHER_TENANT))
      );

      const credential = await credentialOf('microsoft', SUB);
      expect(credential.credentialData).toMatchObject({ iss: microsoftIssuer(OTHER_TENANT) });
      expect(await attributesOf(credential.userId, 'microsoft')).toContainEqual({
        key: 'tid',
        value: OTHER_TENANT,
        verified: false,
      });
    });

    it('refuses, through the multi-tenant endpoints, a token whose issuer names another tenant than its tid', async () => {
      await enablePlugin('microsoft', configFor('organizations'), SECRETS);
      const usersBefore = await users();
      const jar = new CookieJar();

      const refused = await signInAt(
        jar,
        'microsoft',
        microsoftOrganizations,
        person(OTHER_TENANT, { iss: microsoftIssuer(TENANT) })
      );

      expectErrorPage(refused);
      expect(await users()).toBe(usersBefore);
      expect(await refusals()).toEqual(['invalid_response']);
    });
  });

  describe('Apple', () => {
    const SUB = '001234.0a1b2c3d4e5f60718293a4b5c6d7e8f9.1234';
    const person = (claims: Record<string, unknown> = {}): FakeSignIn => ({
      sub: SUB,
      claims: {
        email: 'ada@example.com',
        email_verified: 'true',
        is_private_email: 'false',
        ...claims,
      },
    });
    const userMember = (firstName: string, lastName: string) =>
      JSON.stringify({ name: { firstName, lastName }, email: 'ada@example.com' });

    /**
     * The realm's Apple key and Team ID, in a test signer that signs the
     * client secrets in place of the server's, whose store reads no provider
     * configuration yet. Every other operation stays the server's.
     */
    async function appleKeyInSigner(): Promise<void> {
      const signer = createTestSigner({ refreshIntervalMs: 0 });
      await signer.addRealm({ issuer: ORIGIN, id: realmId });
      await signer.addUpstreamClient(realmId, 'apple', {
        clientId: SERVICES_ID,
        assertionIssuer: TEAM_ID,
        algorithm: 'ES256',
      });
      appleSigner = signer;
      // The decorator's own object: every scope of the app reads it there.
      let owner: object | null = app();
      while (owner !== null && !Object.hasOwn(owner, 'signer')) {
        owner = Object.getPrototypeOf(owner) as object | null;
      }
      if (owner === null) throw new Error('the app has no signer');
      const holder = owner as { signer: FastifyInstance['signer'] };
      const server = holder.signer;
      holder.signer = Object.freeze({
        ...server,
        signClientAssertion: (...call: Parameters<typeof server.signClientAssertion>) =>
          signer.signer.signClientAssertion(...call),
      });
      restoreSigner = () => {
        holder.signer = server;
      };
    }

    /**
     * Start the plugin and sign `signedIn` in at Apple, which posts the
     * response cross-site, with `user` when it sends one; the bounce sends
     * the browser to the GET callback. Answers that callback's response.
     */
    async function formPostSignIn(
      jar: CookieJar,
      signedIn: FakeSignIn,
      user: string | null
    ): Promise<LightMyRequestResponse> {
      const providerRequest = await startAt(jar, 'apple', apple);
      expect(providerRequest.searchParams.get('response_mode')).toBe('form_post');
      const answer = apple.authorize(providerRequest, signedIn);
      expect(answer['error']).toBeUndefined();

      // A cross-site POST: the browser sends no cookie of the realm with it.
      const posted = await app().inject({
        method: 'POST',
        url: '/upstream/apple/callback',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          origin: APPLE_ISSUER,
        },
        payload: new URLSearchParams(user === null ? answer : { ...answer, user }).toString(),
      });
      expect(posted.statusCode, withServerLog(posted.body)).toBe(303);
      const bounced = pathOf(posted.headers['location']);
      expect(bounced.startsWith('/upstream/apple/callback?'), bounced).toBe(true);
      // Only the name rides on in the URL, never the address in the user member.
      expect(new URL(bounced, ORIGIN).searchParams.get('user') ?? '').not.toContain('@');
      return get(jar, bounced);
    }

    // Acceptance criterion: a form_post callback with a user body stores the
    // name once and does not overwrite it later.
    it('stores the name of the first form_post once, and a later sign-in does not change it', async () => {
      await appleKeyInSigner();
      await enablePlugin('apple', { clientId: SERVICES_ID });
      const usersBefore = await users();

      const first = new CookieJar();
      await codeAfterPages(
        first,
        await formPostSignIn(first, person(), userMember('Ada', 'Lovelace'))
      );

      expect(await users()).toBe(usersBefore + 1);
      const credential = await credentialOf('apple', SUB);
      expect(credential.credentialData).toEqual({
        kind: 'upstream',
        iss: APPLE_ISSUER,
        verified: true,
      });
      const stored = [
        { key: 'email', value: 'ada@example.com', verified: true },
        { key: 'family_name', value: 'Lovelace', verified: false },
        { key: 'given_name', value: 'Ada', verified: false },
      ];
      expect(await attributesOf(credential.userId, 'apple')).toEqual(stored);
      // The client secret was the test signer's JWT, sent in the body.
      const secret = apple.tokenRequests.at(-1)?.get('client_secret') ?? '';
      expect(secret.split('.')).toHaveLength(3);
      expect(apple.assertions.at(-1)).toMatchObject({
        iss: TEAM_ID,
        sub: SERVICES_ID,
        aud: APPLE_ISSUER,
      });

      // A later sign-in, in another browser, carrying another name.
      const later = new CookieJar();
      await codeAfterPages(
        later,
        await formPostSignIn(later, person(), userMember('Grace', 'Hopper'))
      );
      expect(await users()).toBe(usersBefore + 1);
      expect((await credentialOf('apple', SUB)).userId).toBe(credential.userId);
      expect(await attributesOf(credential.userId, 'apple')).toEqual(stored);

      // And one with no user member, as Apple sends after the first.
      const again = new CookieJar();
      await codeAfterPages(again, await formPostSignIn(again, person(), null));
      expect(await attributesOf(credential.userId, 'apple')).toEqual(stored);
    });

    it('keeps a private relay address apart from email, so it is never the address mailed', async () => {
      await appleKeyInSigner();
      await enablePlugin('apple', { clientId: SERVICES_ID });
      const relay = 'x7d2kq9p@privaterelay.appleid.com';
      const jar = new CookieJar();

      await codeAfterPages(
        jar,
        await formPostSignIn(
          jar,
          person({ email: relay, is_private_email: 'true' }),
          userMember('Ada', 'Lovelace')
        )
      );

      const credential = await credentialOf('apple', SUB);
      expect(await attributesOf(credential.userId, 'apple')).toEqual([
        { key: 'family_name', value: 'Lovelace', verified: false },
        { key: 'given_name', value: 'Ada', verified: false },
        { key: 'private_relay_email', value: relay, verified: false },
      ]);
    });
  });

  // Acceptance criterion: each plugin appears in the admin console's plugin list.
  describe('the admin API', () => {
    it('lists the three plugins, first-party, each off until a realm turns it on', async () => {
      const host = 'alpha.example.com';
      const { realm } = await app().repositories.realms.createWithPrimaryHost(
        { name: 'alpha', issuer: `https://${host}`, enabled: true },
        host
      );
      await provisionRealmKeys(app(), 'alpha');
      const operator = await app().repositories.realms.findByName(E2E_REALM_NAME);
      if (operator === undefined) throw new Error('default realm missing');
      const userId = (
        await app().repositories.users.create({ realmId: operator.id }, testPrimaryCredential())
      ).id;
      await app().repositories.adminGrants.create({
        userId,
        role: { kind: 'built-in', name: 'viewer' },
        targetRealmId: realm.id,
        createdBy: null,
      });
      const token = await signBoundAccessToken(
        app(),
        { id: operator.id },
        {
          sub: userId,
          clientId: 'admin-console',
          aud: API_FAMILY_AUDIENCES.admin,
          scope: 'qauth:admin:read',
        }
      );
      const url = `/admin/v1-rc.0/realms/${realm.id}/plugins`;

      const list = await admin().inject({
        method: 'GET',
        url,
        headers: await adminCallHeaders(token, 'GET', url),
      });

      expect(list.statusCode, list.body).toBe(200);
      const items = list.json<{ items: Record<string, unknown>[] }>().items;
      expect(
        items.map(({ name, type, package: pkg, firstParty, displayName, enabled, secrets }) => ({
          name,
          type,
          package: pkg,
          firstParty,
          displayName,
          enabled,
          secrets,
        }))
      ).toEqual([
        {
          name: 'google',
          type: 'google',
          package: '@qauth-labs/plugin-google',
          firstParty: true,
          displayName: 'Google',
          enabled: false,
          secrets: [{ path: 'clientSecret', set: false }],
        },
        {
          name: 'microsoft',
          type: 'microsoft',
          package: '@qauth-labs/plugin-microsoft',
          firstParty: true,
          displayName: 'Microsoft',
          enabled: false,
          secrets: [{ path: 'clientSecret', set: false }],
        },
        {
          name: 'apple',
          type: 'apple',
          package: '@qauth-labs/plugin-apple',
          firstParty: true,
          displayName: 'Apple',
          enabled: false,
          secrets: [],
        },
      ]);
    });
  });
});
