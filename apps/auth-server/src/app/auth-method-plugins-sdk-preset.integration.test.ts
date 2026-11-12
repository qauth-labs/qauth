import type { EgressClient } from '@qauth-labs/fastify-plugin-egress';
import {
  createFakeProvider,
  type FakeProvider,
  type FakeSignIn,
} from '@qauth-labs/fastify-plugin-federation/src/testing/upstream-oidc-fixtures';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

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
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import {
  SDK_PRESET_ID,
  SDK_PRESET_ISSUER_TEMPLATE,
  SDK_PRESET_MEMBER,
  SDK_PRESET_MULTI_TENANT,
  SDK_PRESET_PACKAGE,
  SDK_PRESET_TYPE,
  sdkPresetIssuer,
  writeSdkPresetPackage,
  type WrittenSdkPresetPackage,
} from '../testing/sdk-preset-package';
import { SESSION_COOKIE } from '../testing/session-cookie-value';

/**
 * A PROVIDER PLUGIN IN ITS OWN REPOSITORY (#671, ADR-018 §3), end to end
 * against real Postgres and Redis: a preset package that imports only the
 * plugin SDK, `@qauth-labs/plugin-sdk`, and its peer Zod
 * (`testing/sdk-preset-package.ts`), loaded by its name from
 * `AUTH_METHOD_PLUGINS` and built on the server's own OpenID Connect client.
 *
 * - with the plugin API off, the package is never imported, and the boot
 *   says why;
 * - with it on, a full sign-in against a fake provider creates the account,
 *   its credential and the attributes the preset's rules map, and those
 *   attributes rank with an `oidc_*` provider's;
 * - with a fixed tenant, a token another tenant issued is refused; through
 *   the multi-tenant endpoint, a token whose issuer is the template with its
 *   `tid` is accepted;
 * - a `form_post` response member reaches the preset's identity claims, is
 *   dropped by the bounce past 1024 characters, and never sets a claim the
 *   provider vouches for.
 *
 * The provider is the upstream OIDC library's fake OpenID Provider, one per
 * issuer. The suite's egress client answers from those fakes by issuer and
 * reaches nothing else: no network. The realm's state of the plugin is
 * written as the admin API's plugin operations write it, its client secret
 * sealed under the plugin's context.
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
const STATE = 'sdk-preset-state';

const UPSTREAM_CLIENT_ID = 'sdk-idp-client';
const UPSTREAM_CLIENT_SECRET = 'an-sdk-idp-client-secret-of-some-length';
const TENANT = 'tenant-a';
const OTHER_TENANT = 'tenant-b';

/** The page titles of `helpers/upstream-pages.ts`, written out: app modules read the environment at import. */
const WAITING_TITLE = 'Continuing to your sign-in provider';
const ERROR_TITLE = 'We could not sign you in';

const SIGN_IN_FAILED = 'urn:qauth:event:user.sign_in_failed:v1-rc.0';

/** pino's numeric level for `warn`. */
const PINO_WARN_LEVEL = 40;

/** One parsed line of the server's own log. */
interface LogLine {
  readonly level: number;
  readonly msg?: string;
  readonly [key: string]: unknown;
}

/** The callback URL the provider sends the browser back to. */
const CALLBACK_URL = `${ORIGIN}/upstream/${SDK_PRESET_TYPE}/callback`;

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
 * issuer the URL is under, and refuses any other.
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

describe('a preset package that imports only the plugin SDK (#671, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let written: WrittenSdkPresetPackage | undefined;
  let dockerUp = false;

  /** The provider's endpoints of one tenant, and its multi-tenant endpoint. */
  let tenant: FakeProvider;
  let multiTenant: FakeProvider;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    written = await writeSdkPresetPackage();

    tenant = await createFakeProvider({
      issuer: sdkPresetIssuer(TENANT),
      algorithm: 'RS256',
      issParameter: false,
    });
    multiTenant = await createFakeProvider({
      issuer: sdkPresetIssuer(SDK_PRESET_MULTI_TENANT),
      algorithm: 'RS256',
      issParameter: false,
      documentIssuer: SDK_PRESET_ISSUER_TEMPLATE,
    });
    for (const provider of [tenant, multiTenant]) {
      provider.register({
        clientId: UPSTREAM_CLIENT_ID,
        method: 'client_secret_post',
        clientSecret: UPSTREAM_CLIENT_SECRET,
        redirectUris: [CALLBACK_URL],
      });
    }
  }, 240_000);

  afterAll(async () => {
    await written?.remove();
    await infra?.teardown();
  });

  function preset(): WrittenSdkPresetPackage {
    if (written === undefined) throw new Error('the preset package is not written');
    return written;
  }

  // Acceptance criterion: with the API off, it is skipped and the boot says why.
  describe('with the plugin API off', () => {
    beforeEach((ctx) => {
      if (!dockerUp) ctx.skip();
    });

    it('never imports the package, and the boot says why', async () => {
      if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
      const log: LogLine[] = [];
      const importPackage = vi.fn(preset().importPackage);
      let booted: BootedAuthServer | undefined;
      try {
        booted = await bootAuthServer(
          { ...baseEnvironment(infra, jwt), AUTH_METHOD_PLUGINS: SDK_PRESET_PACKAGE },
          {
            logStream: { write: (line) => log.push(JSON.parse(line) as LogLine) },
            authMethodPlugins: { importPackage },
          }
        );
        const app = booted.app;
        expect(app.authMethodPlugins.installed).toEqual([]);
        expect(app.providerRegistry.authMethods().map((method) => method.type)).toEqual([]);
        const callback = await app.inject({
          method: 'GET',
          url: `/upstream/${SDK_PRESET_TYPE}/callback`,
        });
        expect(callback.statusCode).toBe(404);
      } finally {
        await booted?.close();
      }

      expect(importPackage).not.toHaveBeenCalled();
      expect(log.filter((line) => line['authMethodPlugin'] !== undefined)).toEqual([
        expect.objectContaining({
          level: PINO_WARN_LEVEL,
          authMethodPlugin: SDK_PRESET_PACKAGE,
          reason: 'plugin-api-off',
          msg: `The AuthMethod plugin ${SDK_PRESET_PACKAGE} is not loaded: it is not a first-party plugin, and the experimental plugin API is off. Set PLUGIN_API_ENABLED=true to load it, or remove it from AUTH_METHOD_PLUGINS`,
        }),
      ]);
    });
  });

  describe('with the plugin API on', () => {
    let booted: BootedAuthServer | undefined;
    let realmId = '';

    /** The server's warnings and errors in the current test, for an assertion to say why. */
    const serverLog: string[] = [];

    /** `body`, with the server's warnings and errors of this test after it. */
    function withServerLog(body: string): string {
      return serverLog.length === 0 ? body : `${body}\nserver log:\n${serverLog.join('')}`;
    }

    beforeAll(async () => {
      if (!dockerUp || infra === undefined || jwt === undefined) return;
      booted = await bootAuthServer(
        {
          ...baseEnvironment(infra, jwt),
          AUTHORIZE_RATE_LIMIT: '10000',
          AUTHORIZE_RATE_LIMIT_LENIENT: '10000',
          ALLOW_SIGN_UP: 'true',
          PLUGIN_API_ENABLED: 'true',
          AUTH_METHOD_PLUGINS: SDK_PRESET_PACKAGE,
        },
        {
          egressClientFactory: fakeProviderEgress([tenant, multiTenant]),
          // The package, imported by its name as the server imports it; the
          // first-party list is the server's own, which names no provider.
          authMethodPlugins: { importPackage: preset().importPackage },
          logStream: { write: (line: string) => void serverLog.push(line) },
        }
      );
    }, 240_000);

    afterAll(async () => {
      await booted?.close();
      for (const name of [
        'AUTHORIZE_RATE_LIMIT',
        'AUTHORIZE_RATE_LIMIT_LENIENT',
        'ALLOW_SIGN_UP',
        'PLUGIN_API_ENABLED',
      ]) {
        delete process.env[name];
      }
    });

    beforeEach(async (ctx) => {
      if (!dockerUp || booted === undefined) {
        ctx.skip();
        return;
      }
      realmId = await seed(booted.app);
      serverLog.length = 0;
    }, 120_000);

    function app(): FastifyInstance {
      if (booted === undefined) throw new Error('server not booted');
      return booted.app;
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
     * Turn the plugin on in the realm with `config` and its client secret
     * sealed under the plugin's context, as `plugins.update` and
     * `plugins.enable` store them.
     */
    async function enablePreset(config: Record<string, unknown>): Promise<void> {
      const plugin = app().authMethodPlugins.find(SDK_PRESET_ID);
      if (plugin === undefined) throw new Error(`the plugin ${SDK_PRESET_ID} is not loaded`);
      // Imported once the boot reset the modules, as the app loaded it.
      const { authMethodPluginSecretCipher } = await import('./helpers/auth-method-plugins');
      const cipher = authMethodPluginSecretCipher(app());
      const sealed = {
        clientSecret: await cipher.seal(realmId, plugin, 'clientSecret', UPSTREAM_CLIENT_SECRET),
      };
      const repository = app().repositories.realmAuthMethodPlugins;
      const before = await repository.find(realmId, SDK_PRESET_ID);
      const saved = await repository.save(
        realmId,
        SDK_PRESET_ID,
        {
          enabled: true,
          config: { clientId: UPSTREAM_CLIENT_ID, ...config },
          secrets: sealed,
          binding: { package: plugin.package, type: plugin.type },
        },
        before?.version ?? null
      );
      if (saved === undefined) throw new Error(`the state of ${SDK_PRESET_ID} was not written`);
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

    function authorizeUrl(): string {
      return `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: 'openid email',
        code_challenge: pkcePair().challenge,
        code_challenge_method: 'S256',
        state: STATE,
        qauth_upstream: SDK_PRESET_TYPE,
      }).toString()}`;
    }

    /**
     * Route the client's request to the plugin, up to the waiting page, and
     * answer the authorization request it sends the browser to.
     */
    async function startAt(jar: CookieJar, provider: FakeProvider): Promise<URL> {
      const routed = await get(jar, authorizeUrl());
      expect(routed.statusCode, withServerLog(routed.body)).toBe(302);
      const start = new URL(String(routed.headers['location']), ORIGIN);
      expect(start.pathname).toBe(`/ui/upstream/${SDK_PRESET_TYPE}/start`);
      const page = await get(jar, `${start.pathname}${start.search}`);
      expect(page.statusCode, withServerLog(page.body)).toBe(200);
      expect(page.body).toContain(WAITING_TITLE);
      const link = /<a class="alt-action" href="([^"]+)"/.exec(page.body)?.[1];
      if (link === undefined) throw new Error('no provider link on the waiting page');
      const providerRequest = new URL(decodeHtmlEntities(link));
      expect(`${providerRequest.origin}${providerRequest.pathname}`).toBe(
        provider.authorizationEndpoint
      );
      expect(providerRequest.searchParams.get('redirect_uri')).toBe(CALLBACK_URL);
      return providerRequest;
    }

    /** Start the plugin, sign `person` in at `provider`, and come back to the GET callback. */
    async function signInAt(
      jar: CookieJar,
      provider: FakeProvider,
      person: FakeSignIn
    ): Promise<LightMyRequestResponse> {
      const answer = provider.authorize(await startAt(jar, provider), person);
      expect(answer['error']).toBeUndefined();
      return get(
        jar,
        `/upstream/${SDK_PRESET_TYPE}/callback?${new URLSearchParams(answer).toString()}`
      );
    }

    /**
     * Start the plugin and sign `person` in at `provider`, which posts the
     * response cross-site, with the `profile` member when one is given; the
     * bounce sends the browser to the GET callback. Answers that callback's
     * response, and the query the bounce carried.
     */
    async function formPostSignIn(
      jar: CookieJar,
      provider: FakeProvider,
      person: FakeSignIn,
      profile: string | null
    ): Promise<{ callback: LightMyRequestResponse; carried: URLSearchParams }> {
      const providerRequest = await startAt(jar, provider);
      expect(providerRequest.searchParams.get('response_mode')).toBe('form_post');
      const answer = provider.authorize(providerRequest, person);
      expect(answer['error']).toBeUndefined();

      // A cross-site POST: the browser sends no cookie of the realm with it.
      const posted = await app().inject({
        method: 'POST',
        url: `/upstream/${SDK_PRESET_TYPE}/callback`,
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          origin: new URL(provider.issuer).origin,
        },
        payload: new URLSearchParams(
          profile === null ? answer : { ...answer, [SDK_PRESET_MEMBER]: profile }
        ).toString(),
      });
      expect(posted.statusCode, withServerLog(posted.body)).toBe(303);
      const bounced = pathOf(posted.headers['location']);
      expect(bounced.startsWith(`/upstream/${SDK_PRESET_TYPE}/callback?`), bounced).toBe(true);
      return {
        callback: await get(jar, bounced),
        carried: new URL(bounced, ORIGIN).searchParams,
      };
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
      return rows
        .filter((row) => row.data['method'] === 'upstream')
        .map((row) => row.data['reason']);
    }

    /** The account's credential of the preset for `sub`. */
    async function credentialOf(sub: string) {
      const credential = await app().repositories.userCredentials.findByRealmProviderSub(
        realmId,
        SDK_PRESET_TYPE,
        sub
      );
      if (credential === undefined) throw new Error(`no ${SDK_PRESET_TYPE} credential for ${sub}`);
      return credential;
    }

    /** The attributes of the account from the preset, by key. */
    async function attributesOf(userId: string) {
      const rows = await app().repositories.userAttributes.findByUserIdAndSource(
        userId,
        SDK_PRESET_TYPE
      );
      return rows
        .map((row) => ({ key: row.attrKey, value: row.attrValue, verified: row.verified }))
        .sort((a, b) => a.key.localeCompare(b.key));
    }

    const SUB = 'sdk-idp-subject-0001';
    const person = (tenantId: string, claims: Record<string, unknown> = {}): FakeSignIn => ({
      sub: SUB,
      claims: {
        iss: sdkPresetIssuer(tenantId),
        tid: tenantId,
        email: 'ada@example.com',
        email_verified: true,
        name: 'Ada Lovelace',
        ...claims,
      },
    });
    const profileMember = (name: string) =>
      JSON.stringify({ name, email: 'someone-else@example.com' });

    // Acceptance criterion: it loads via AUTH_METHOD_PLUGINS with the plugin
    // API on, and signs in against a fake provider.
    it("signs in through the server's client, creating the account the preset's rules describe", async () => {
      expect(app().authMethodPlugins.ofType(SDK_PRESET_TYPE)).toMatchObject({
        package: SDK_PRESET_PACKAGE,
        kind: 'upstream-oidc-preset',
        firstParty: false,
      });
      await enablePreset({ tenant: TENANT });
      const usersBefore = await users();
      const jar = new CookieJar();

      await codeAfterPages(jar, await signInAt(jar, tenant, person(TENANT)));

      expect(await users()).toBe(usersBefore + 1);
      const credential = await credentialOf(SUB);
      expect(credential).toMatchObject({ providerType: SDK_PRESET_TYPE, isPrimary: true });
      expect(credential.credentialData).toEqual({
        kind: 'upstream',
        iss: sdkPresetIssuer(TENANT),
        verified: true,
      });
      expect(await attributesOf(credential.userId)).toEqual([
        { key: 'email', value: 'ada@example.com', verified: true },
        { key: 'name', value: 'Ada Lovelace', verified: false },
        { key: 'tid', value: TENANT, verified: false },
      ]);
      // The client secret went in the token request's body.
      expect(tenant.tokenRequests.at(-1)?.get('client_secret')).toBe(UPSTREAM_CLIENT_SECRET);
    });

    // Acceptance criterion: a preset-built method's attributes rank with oidc_*.
    it("ranks the preset's verified email with an oidc_* provider's, above a self-reported one", async () => {
      await enablePreset({ tenant: TENANT });
      const jar = new CookieJar();
      await codeAfterPages(jar, await signInAt(jar, tenant, person(TENANT)));
      const credential = await credentialOf(SUB);
      await app().repositories.userAttributes.upsertMany(credential.userId, [
        {
          source: 'self_reported',
          attrKey: 'email',
          attrValue: 'self@example.com',
          verified: true,
        },
      ]);

      // Imported once the boot reset the modules, as the app loaded it.
      const { resolveEmailClaims } = await import('./helpers/email-claims');
      expect(await resolveEmailClaims(app(), { id: credential.userId, realmId })).toEqual({
        email: 'ada@example.com',
        email_verified: true,
      });

      // The sign-in recorded how the method was built on each row it wrote,
      // so a process that loads no plugin, as one of the `api` role, which
      // serves the token endpoint, ranks it the same.
      const rows = await app().repositories.userAttributes.findByUserIdAndSource(
        credential.userId,
        SDK_PRESET_TYPE
      );
      expect(rows.map((row) => row.provenance)).toEqual(
        rows.map(() => ({ builtFrom: 'upstream-oidc-preset' }))
      );
      const withoutPlugins = { repositories: app().repositories } as unknown as FastifyInstance;
      expect(await resolveEmailClaims(withoutPlugins, { id: credential.userId, realmId })).toEqual({
        email: 'ada@example.com',
        email_verified: true,
      });
    });

    // Acceptance criterion: another tenant's token is refused.
    it('refuses, with a fixed tenant, a token another tenant issued, and creates nothing', async () => {
      await enablePreset({ tenant: TENANT });
      const usersBefore = await users();
      const jar = new CookieJar();

      const refused = await signInAt(jar, tenant, person(OTHER_TENANT));

      expectErrorPage(refused);
      expect(jar.get(SESSION_COOKIE)).toBeUndefined();
      expect(await users()).toBe(usersBefore);
      expect(await refusals()).toEqual(['invalid_response']);
    });

    // Acceptance criterion: a multi-tenant token matching the template is accepted.
    it("accepts, through the multi-tenant endpoint, a token whose issuer is the template with the token's tid", async () => {
      await enablePreset({ tenant: SDK_PRESET_MULTI_TENANT });
      const jar = new CookieJar();

      await codeAfterPages(jar, await signInAt(jar, multiTenant, person(OTHER_TENANT)));

      const credential = await credentialOf(SUB);
      expect(credential.credentialData).toMatchObject({ iss: sdkPresetIssuer(OTHER_TENANT) });
      expect(await attributesOf(credential.userId)).toContainEqual({
        key: 'tid',
        value: OTHER_TENANT,
        verified: false,
      });
    });

    it('refuses, through the multi-tenant endpoint, a token whose issuer names another tenant than its tid', async () => {
      await enablePreset({ tenant: SDK_PRESET_MULTI_TENANT });
      const usersBefore = await users();
      const jar = new CookieJar();

      const refused = await signInAt(
        jar,
        multiTenant,
        person(OTHER_TENANT, { iss: sdkPresetIssuer(TENANT) })
      );

      expectErrorPage(refused);
      expect(await users()).toBe(usersBefore);
      expect(await refusals()).toEqual(['invalid_response']);
    });

    // Acceptance criterion: a form_post member reaches identityClaims and is
    // never a verified attribute.
    it("carries a form_post member to the preset's identity claims, never as a claim the provider vouches for", async () => {
      await enablePreset({ tenant: TENANT, formPost: true });
      const jar = new CookieJar();

      const { callback, carried } = await formPostSignIn(
        jar,
        tenant,
        person(TENANT),
        profileMember('Countess')
      );
      // Only what the preset's map keeps rides on in the URL: the name, not
      // the address the member held.
      expect(JSON.parse(carried.get(SDK_PRESET_MEMBER) ?? 'null')).toEqual({ name: 'Countess' });
      await codeAfterPages(jar, callback);

      const credential = await credentialOf(SUB);
      // The member's name is a nickname, unverified though the preset set a
      // flag its rule reads; the address and the flag the preset set from it
      // are not taken: the email is the ID token's.
      expect(await attributesOf(credential.userId)).toEqual([
        { key: 'email', value: 'ada@example.com', verified: true },
        { key: 'name', value: 'Ada Lovelace', verified: false },
        { key: 'nickname', value: 'Countess', verified: false },
        { key: 'tid', value: TENANT, verified: false },
      ]);
    });

    // Acceptance criterion: the member is capped at 1024 characters.
    it('drops a form_post member longer than 1024 characters, and the sign-in goes on without it', async () => {
      await enablePreset({ tenant: TENANT, formPost: true });
      const jar = new CookieJar();

      const { callback, carried } = await formPostSignIn(
        jar,
        tenant,
        person(TENANT),
        profileMember('A'.repeat(1100))
      );
      expect(carried.has(SDK_PRESET_MEMBER)).toBe(false);
      await codeAfterPages(jar, callback);

      const credential = await credentialOf(SUB);
      expect((await attributesOf(credential.userId)).map((attribute) => attribute.key)).toEqual([
        'email',
        'name',
        'tid',
      ]);
    });
  });
});
