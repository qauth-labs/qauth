import {
  createFixtureNetwork,
  type EgressTransport,
  type FixtureNetwork,
  type FixtureServer,
} from '@qauth-labs/fastify-plugin-egress/src/testing/egress-fixtures';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  decodeHtmlEntities,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  extractCsrfToken,
  generateJwtPem,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE SCOPES OF A REGISTERED PROTECTED RESOURCE (#1087), end to end against
 * real Postgres and Redis.
 *
 * A realm registers a protected resource: its RFC 8707 resource indicator,
 * the scopes it defines with their consent texts by locale, and who may ask
 * for them. A scope it defines is granted only when the authorization request
 * names the resource, and then to any client it is open to, a CIMD or a
 * dynamically registered client included, whatever the client's own `scopes`
 * hold; the user's consent is still required. Asked for without its resource,
 * or with another, it is dropped, so a token's `aud` and its resource scopes
 * agree. The consent page shows the resource's text in the request's
 * `ui_locales`, English otherwise. The Interaction API's consent step is
 * covered in `consent-interaction.integration.test.ts`, the step-up loop of
 * an MCP client in `mcp-quickstart.integration.test.ts`.
 *
 * The CIMD client's metadata document is served by a fixture server on a
 * public address of the fixture network, which replaces only the production
 * egress client's two network edges (DNS and dialler), as the egress suites
 * do.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const network = vi.hoisted(() => ({ current: undefined as EgressTransport | undefined }));

// The production client's network edges: the fixture network while a test
// sets one, the real ones otherwise.
vi.mock('../../../../libs/server/egress/src/lib/transport', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const real = actual['NODE_TRANSPORT'] as EgressTransport;
  const current = (): EgressTransport => network.current ?? real;
  return {
    ...actual,
    NODE_TRANSPORT: {
      resolveHost: (...args: Parameters<EgressTransport['resolveHost']>) =>
        current().resolveHost(...args),
      exchange: (...args: Parameters<EgressTransport['exchange']>) => current().exchange(...args),
    },
  };
});

/** Keys this suite sets that the harness does not clear between boots. */
const SUITE_KEYS = [
  'DEFAULT_DYNAMIC_REGISTRATION_SCOPES',
  'CIMD_ENABLED',
  'REGISTER_CLIENT_RATE_LIMIT',
  'AUTHORIZE_RATE_LIMIT',
  'AUTHORIZE_RATE_LIMIT_LENIENT',
] as const;

const EMAIL = 'protected-resource-scopes@example.test';
const REDIRECT_URI = 'https://app.example.com/callback';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

/** The registered resource, and its scopes' texts. */
const RESOURCE = 'https://files.example.com/mcp';
const OTHER_RESOURCE = 'https://mail.example.com/mcp';
const READ_TEXT = { en: 'Read your files', tr: 'Dosyalarınızı okusun' };
const WRITE_TEXT = { en: 'Change your files' };

/** A CIMD client of the fixture network, which no operator ever listed. */
const CIMD_HOST = 'agent.egress.test';
const CIMD_ID = `https://${CIMD_HOST}/client.json`;
/** A public address, as the CIMD fetch (`source: client`) requires. */
const CIMD_ADDRESS = '93.184.215.34';

interface TokenResponse {
  readonly access_token: string;
  readonly refresh_token?: string;
  readonly scope?: string;
}

/** The claims of a compact JWT, unverified: the token endpoint signed it in this process. */
function claimsOf(token: string): { aud: string | string[]; scope?: string } {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
}

/** A token's `aud`, as a list. */
function audienceOf(token: string): string[] {
  return [claimsOf(token).aud].flat();
}

/** A token's scopes, as a list. */
function scopesOf(token: string): string[] {
  return (claimsOf(token).scope ?? '').split(' ').filter((scope) => scope.length > 0);
}

describe('the scopes of a registered protected resource (#1087, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let net: FixtureNetwork | undefined;
  let documentHost: FixtureServer;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let realmId = '';
  let cookie = '';

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    net = await createFixtureNetwork();
    documentHost = await net.serve(CIMD_ADDRESS, () => undefined);
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      // A dynamically registered client may register with `files:read`, the
      // narrower of the resource's two scopes.
      DEFAULT_DYNAMIC_REGISTRATION_SCOPES: 'openid profile email offline_access files:read',
      CIMD_ENABLED: 'true',
      // Sized for humans; a test sends a burst from one address.
      REGISTER_CLIENT_RATE_LIMIT: '1000',
      AUTHORIZE_RATE_LIMIT: '10000',
      AUTHORIZE_RATE_LIMIT_LENIENT: '10000',
    });
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await net?.close();
    await infra?.teardown();
    for (const key of SUITE_KEYS) delete process.env[key];
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined || net === undefined) {
      ctx.skip();
      return;
    }
    net.dns.clear();
    net.dns.set(CIMD_HOST, [CIMD_ADDRESS]);
    documentHost.handler = (_req, _body, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'max-age=600' });
      res.end(
        JSON.stringify({
          client_id: CIMD_ID,
          client_name: 'Files agent',
          redirect_uris: [REDIRECT_URI],
          grant_types: ['authorization_code', 'refresh_token'],
        })
      );
    };
    network.current = net.transport;
    const app = booted.app;
    await resetE2eState(app);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
    await registerPasswordAccount(app, EMAIL);
    cookie = (await signInWithPassword(app, EMAIL)).header() as string;
  }, 120_000);

  afterEach(() => {
    network.current = undefined;
  });

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  /** Register the files resource in the default realm, open to `clients`. */
  async function registerResource(clients: 'any_client' | string[]): Promise<string> {
    const row = await server().repositories.protectedResources.create(realmId, RESOURCE, {
      scopes: [
        { scope: 'files:read', text: READ_TEXT, sensitive: false },
        { scope: 'files:write', text: WRITE_TEXT, sensitive: true },
      ],
      anyClient: clients === 'any_client',
      clientIds: clients === 'any_client' ? [] : clients,
    });
    if (row === undefined) throw new Error('resource not registered');
    return row.id;
  }

  /** An operator-provisioned public client with its own scope list. */
  async function createClient(clientId: string, scopes: string[]): Promise<void> {
    await server().repositories.oauthClients.create({
      realmId,
      clientId,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: `Client ${clientId}`,
      redirectUris: [REDIRECT_URI],
      scopes,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
      provisionedByOperator: true,
    });
  }

  /** The scope rows of a consent page: each scope with the words it is shown with. */
  function shownScopes(body: string): Record<string, string> {
    return Object.fromEntries(
      [...body.matchAll(/<li><code>([^<]+)<\/code> — ([^<]*)<\/li>/g)].map(([, scope, text]) => [
        decodeHtmlEntities(scope),
        decodeHtmlEntities(text),
      ])
    );
  }

  /**
   * Run an authorization request of `clientId` from the signed-in browser:
   * the consent page is shown, read, and allowed with "Remember this
   * decision" ticked. Returns the page's scope rows and the code.
   */
  async function authorize(
    clientId: string,
    params: { scope: string; resource?: string; ui_locales?: string }
  ): Promise<{ shown: Record<string, string>; code: string; verifier: string }> {
    const app = server();
    const pkce = pkcePair();
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: REDIRECT_URI,
      scope: params.scope,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
      state: 'protected-resource-state',
    });
    if (params.resource !== undefined) query.set('resource', params.resource);
    if (params.ui_locales !== undefined) query.set('ui_locales', params.ui_locales);
    const response = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${query.toString()}`,
      headers: { cookie },
    });
    expect(response.statusCode, response.body).toBe(302);
    const location = String(response.headers['location']);
    expect(location.startsWith('/ui/consent?'), location).toBe(true);

    const screen = await app.inject({ method: 'GET', url: location, headers: { cookie } });
    expect(screen.statusCode, screen.body).toBe(200);
    const form = new URLSearchParams();
    for (const [, name, value] of screen.body.matchAll(
      /<input type="hidden" name="([^"]+)" value="([^"]*)"/g
    )) {
      form.append(name, decodeHtmlEntities(value));
    }
    form.set('csrf_token', extractCsrfToken(screen.body));
    form.set('decision', 'allow');
    form.set('allow_forever', '1');
    const decision = await app.inject({
      method: 'POST',
      url: '/ui/consent',
      headers: { ...FORM, cookie },
      payload: form.toString(),
    });
    expect(decision.statusCode, decision.body).toBe(302);
    const callback = new URL(String(decision.headers['location']));
    const code = callback.searchParams.get('code');
    if (code === null) throw new Error(`no code in ${callback.toString()}`);
    return { shown: shownScopes(screen.body), code, verifier: pkce.verifier };
  }

  /** `POST /oauth/token` with a form. */
  function tokenRequest(form: Record<string, string>): Promise<LightMyRequestResponse> {
    return server().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams(form).toString(),
    });
  }

  /** Redeem a code as the public client `clientId`. */
  async function exchange(
    clientId: string,
    code: string,
    verifier: string
  ): Promise<TokenResponse> {
    const response = await tokenRequest({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json<TokenResponse>();
  }

  /** Register a public client by DCR, asking for `scope`; its client_id and granted scopes. */
  async function registerDynamicClient(
    scope: string
  ): Promise<{ clientId: string; scopes: string[] }> {
    const response = await server().inject({
      method: 'POST',
      url: '/oauth/register',
      headers: { 'content-type': 'application/json' },
      payload: {
        client_name: 'Dynamic files agent',
        redirect_uris: [REDIRECT_URI],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        scope,
      },
    });
    expect(response.statusCode, response.body).toBe(201);
    const body = response.json<{ client_id: string; scope?: string }>();
    return { clientId: body.client_id, scopes: (body.scope ?? '').split(' ').filter(Boolean) };
  }

  it('grants a CIMD client no operator listed the scope for its resource, after consent, with the resource as aud', async () => {
    await registerResource('any_client');

    const { shown, code, verifier } = await authorize(CIMD_ID, {
      scope: 'files:read',
      resource: RESOURCE,
    });
    expect(shown).toEqual({ 'files:read': READ_TEXT.en });
    const tokens = await exchange(CIMD_ID, code, verifier);
    expect(scopesOf(tokens.access_token)).toEqual(['files:read']);
    expect(audienceOf(tokens.access_token)).toEqual([RESOURCE]);

    // The operator granted the client nothing: its own list is still empty,
    // and the consent is recorded for the resource.
    const client = await server().repositories.oauthClients.findByClientId(realmId, CIMD_ID);
    expect(client?.scopes).toEqual([]);
    const { rows } = await server().dbPool.query<{ resource_scopes: Record<string, string[]> }>(
      `SELECT c.resource_scopes FROM oauth_consents c
         JOIN oauth_clients o ON o.id = c.oauth_client_id
        WHERE o.client_id = $1 AND c.revoked_at IS NULL`,
      [CIMD_ID]
    );
    expect(rows[0]?.resource_scopes[RESOURCE]).toEqual(['files:read']);
  });

  it('drops the scope when the request names another resource, or none', async () => {
    await registerResource('any_client');

    const other = await authorize(CIMD_ID, { scope: 'files:read', resource: OTHER_RESOURCE });
    expect(other.shown).toEqual({});
    const otherTokens = await exchange(CIMD_ID, other.code, other.verifier);
    expect(scopesOf(otherTokens.access_token)).toEqual([]);
    expect(audienceOf(otherTokens.access_token)).toEqual([OTHER_RESOURCE]);

    const none = await authorize(CIMD_ID, { scope: 'files:read' });
    expect(none.shown).toEqual({});
    const noneTokens = await exchange(CIMD_ID, none.code, none.verifier);
    expect(scopesOf(noneTokens.access_token)).toEqual([]);
  });

  it('drops the scope without its resource even for a client that lists it itself', async () => {
    await registerResource('any_client');
    await createClient('listing-app', ['openid', 'files:read']);

    const { shown, code, verifier } = await authorize('listing-app', {
      scope: 'openid files:read',
    });
    expect(Object.keys(shown)).toEqual(['openid']);
    const tokens = await exchange('listing-app', code, verifier);
    expect(scopesOf(tokens.access_token)).toEqual(['openid']);
  });

  it('grants a DCR client registered with fewer of the scopes another one later, with the resource, after consent', async () => {
    await registerResource('any_client');
    const registered = await registerDynamicClient('openid files:read');
    expect(registered.scopes).toEqual(['openid', 'files:read']);

    const { shown, code, verifier } = await authorize(registered.clientId, {
      scope: 'openid files:read files:write',
      resource: RESOURCE,
    });
    expect(Object.keys(shown)).toEqual(['openid', 'files:read', 'files:write']);
    expect(shown['files:write']).toBe(WRITE_TEXT.en);
    const tokens = await exchange(registered.clientId, code, verifier);
    expect(scopesOf(tokens.access_token)).toEqual(['openid', 'files:read', 'files:write']);
    expect(audienceOf(tokens.access_token)).toEqual([RESOURCE]);
  });

  it('grants nothing of a resource open to a client list to a client outside it, whatever its own list holds', async () => {
    await registerResource(['listed-app']);
    await createClient('listed-app', ['openid']);
    await createClient('outside-app', ['openid', 'files:read']);

    const outside = await authorize('outside-app', {
      scope: 'openid files:read',
      resource: RESOURCE,
    });
    expect(Object.keys(outside.shown)).toEqual(['openid']);
    const outsideTokens = await exchange('outside-app', outside.code, outside.verifier);
    expect(scopesOf(outsideTokens.access_token)).toEqual(['openid']);

    // The CIMD client is outside the list too.
    const cimd = await authorize(CIMD_ID, { scope: 'files:read', resource: RESOURCE });
    expect(cimd.shown).toEqual({});

    const listed = await authorize('listed-app', {
      scope: 'openid files:read',
      resource: RESOURCE,
    });
    expect(Object.keys(listed.shown)).toEqual(['openid', 'files:read']);
    const listedTokens = await exchange('listed-app', listed.code, listed.verifier);
    expect(scopesOf(listedTokens.access_token)).toEqual(['openid', 'files:read']);
  });

  it("shows the resource's text in the request's ui_locales, and English when it has none in it", async () => {
    await registerResource('any_client');

    const turkish = await authorize(CIMD_ID, {
      scope: 'files:read files:write',
      resource: RESOURCE,
      ui_locales: 'tr-TR en',
    });
    expect(turkish.shown).toEqual({ 'files:read': READ_TEXT.tr, 'files:write': WRITE_TEXT.en });

    const german = await authorize(CIMD_ID, {
      scope: 'files:read',
      resource: RESOURCE,
      ui_locales: 'de',
    });
    expect(german.shown).toEqual({ 'files:read': READ_TEXT.en });
  });

  it('drops a resource scope on refresh once the resource is closed to the client', async () => {
    const resourceId = await registerResource('any_client');
    await createClient('refreshing-app', ['openid']);
    const { code, verifier } = await authorize('refreshing-app', {
      scope: 'openid files:read',
      resource: RESOURCE,
    });
    const tokens = await exchange('refreshing-app', code, verifier);
    expect(scopesOf(tokens.access_token)).toEqual(['openid', 'files:read']);
    expect(tokens.refresh_token).toEqual(expect.any(String));

    const refreshed = await tokenRequest({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token as string,
      client_id: 'refreshing-app',
    });
    expect(refreshed.statusCode, refreshed.body).toBe(200);
    const kept = refreshed.json<TokenResponse>();
    expect(scopesOf(kept.access_token)).toEqual(['openid', 'files:read']);

    // The operator closes the resource to every client but another one.
    const updated = await server().repositories.protectedResources.update(
      realmId,
      resourceId,
      {
        scopes: [{ scope: 'files:read', text: READ_TEXT, sensitive: false }],
        anyClient: false,
        clientIds: ['someone-else'],
      },
      1
    );
    expect(updated?.version).toBe(2);

    const closed = await tokenRequest({
      grant_type: 'refresh_token',
      refresh_token: kept.refresh_token as string,
      client_id: 'refreshing-app',
    });
    expect(closed.statusCode, closed.body).toBe(200);
    const narrowed = closed.json<TokenResponse>();
    expect(scopesOf(narrowed.access_token)).toEqual(['openid']);
    expect(audienceOf(narrowed.access_token)).toEqual([RESOURCE]);
  });

  it("keeps QAuth's own scopes in discovery: a resource advertises its scopes in its own metadata", async () => {
    await registerResource('any_client');
    const response = await server().inject({
      method: 'GET',
      url: '/.well-known/oauth-authorization-server',
    });
    expect(response.statusCode, response.body).toBe(200);
    const supported = response.json<{ scopes_supported?: string[] }>().scopes_supported ?? [];
    expect(supported).not.toContain('files:read');
    expect(supported).not.toContain('files:write');
  });
});
