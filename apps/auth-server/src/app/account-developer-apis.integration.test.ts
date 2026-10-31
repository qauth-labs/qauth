import { readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  decodeJwtClaims,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE ACCOUNT AND DEVELOPER APIS UNDER VERSIONED PREFIXES (#524), against a
 * real Postgres and Redis, one case per acceptance criterion:
 *
 * - every deprecated route's data on its new path, in the new format;
 * - the deprecated routes' old response shapes, their `Deprecation` header,
 *   and `deprecated: true` in the OpenAPI document;
 * - a token of one family refused by the other;
 * - lists as `{ items, nextCursor }` that honour `limit`;
 * - an update without `If-Match` (428) and with a stale one (412);
 * - another developer's client as 404, old paths and new;
 * - the system client of a fresh database, and of an older one at boot,
 *   with the developer audience; the token `/auth/login` mints carrying it;
 * - the developer portal's own server code (`auth-server-client.ts`) end to
 *   end against the listening server, on the new paths only.
 *
 * The server listens on a real port, its issuer naming it, so the portal's
 * `fetch` reaches the default realm's host.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const DEVELOPER = '/developer/v1-rc.0';
const ACCOUNT = '/account/v1-rc.0';
const DEVELOPER_AUDIENCE = 'urn:qauth:aud:developer:v1-rc.0';
const ACCOUNT_AUDIENCE = 'urn:qauth:aud:account:v1-rc.0';
/** RFC 9745: the date the old paths were deprecated, 2026-10-31T00:00:00Z. */
const DEPRECATION = '@1793404800';
const REPO_ROOT = join(__dirname, '..', '..', '..', '..');
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

/** A free TCP port on this host, for the issuer the server listens under. */
async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  if (address === null || typeof address === 'string') throw new Error('no port');
  return address.port;
}

/** The members of the deprecated `/api/clients` representation, in its order. */
const OLD_CLIENT_MEMBERS = [
  'id',
  'clientId',
  'name',
  'description',
  'redirectUris',
  'scopes',
  'grantTypes',
  'responseTypes',
  'tokenEndpointAuthMethod',
  'enabled',
  'suspended',
  'requirePkce',
  'environment',
  'staticApiKeysAllowed',
  'createdAt',
  'updatedAt',
  'lastUsedAt',
];

describe('the account and developer APIs under versioned prefixes (#524, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let booted: BootedAuthServer | undefined;
  let environment: Record<string, string> = {};
  let origin = '';
  let dockerUp = false;
  let accounts = 0;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    const port = await freePort();
    origin = `http://localhost:${port}`;
    environment = {
      ...baseEnvironment(infra, jwt),
      JWT_ISSUER: origin,
      // Every case registers and signs in its own developers, and creates
      // clients, from one address.
      REGISTRATION_RATE_LIMIT: '10000',
      REGISTER_CLIENT_RATE_LIMIT: '10000',
    };
    booted = await bootAuthServer(environment);
    await booted.app.listen({ host: 'localhost', port });
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || !booted) {
      ctx.skip();
      return;
    }
    await resetE2eState(booted.app);
  });

  function app(): FastifyInstance {
    if (!booted) throw new Error('server not booted');
    return booted.app;
  }

  async function realmId(): Promise<string> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    return realm.id;
  }

  interface Developer {
    readonly email: string;
    readonly userId: string;
    /** The token `/auth/login` gives the developer portal. */
    readonly token: string;
  }

  /** A verified account, signed in through `/auth/login` as the portal signs in. */
  async function developer(): Promise<Developer> {
    const email = `dev-${++accounts}-${Date.now()}@example.com`;
    const userId = await registerPasswordAccount(app(), email);
    const login = await app().inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: E2E_PASSWORD },
    });
    expect(login.statusCode, login.body).toBe(200);
    return { email, userId, token: login.json<{ access_token: string }>().access_token };
  }

  /** A token for the account API, as the account console's backend holds it. */
  async function accountToken(userId: string): Promise<string> {
    return app().jwtUtils.signAccessToken(
      { id: await realmId() },
      { sub: userId, clientId: 'account-console', aud: ACCOUNT_AUDIENCE }
    );
  }

  function call(
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url: string,
    token: string,
    options: { payload?: unknown; headers?: Record<string, string> } = {}
  ): Promise<LightMyRequestResponse> {
    return app().inject({
      method,
      url,
      headers: { authorization: `Bearer ${token}`, ...options.headers },
      ...(options.payload === undefined ? {} : { payload: options.payload as object }),
    });
  }

  /** A client through the deprecated route: the data the new paths must serve. */
  async function oldClient(
    token: string,
    body: Record<string, unknown> = {}
  ): Promise<Record<string, unknown>> {
    const response = await call('POST', '/api/clients', token, {
      payload: {
        name: 'Old App',
        redirectUris: ['https://app.example.com/cb'],
        scopes: ['openid'],
        tokenEndpointAuthMethod: 'client_secret_post',
        ...body,
      },
    });
    expect(response.statusCode, response.body).toBe(201);
    return response.json();
  }

  /** The deprecated representation of a client, as the new path must show it. */
  function asNew(old: Record<string, unknown>): Record<string, unknown> {
    const time = (value: unknown) =>
      value === null ? null : new Date(value as number).toISOString();
    return {
      id: old['id'],
      client_id: old['clientId'],
      client_name: old['name'],
      description: old['description'],
      redirect_uris: old['redirectUris'],
      scopes: old['scopes'],
      grant_types: old['grantTypes'],
      response_types: old['responseTypes'],
      token_endpoint_auth_method: old['tokenEndpointAuthMethod'],
      enabled: old['enabled'],
      suspended: old['suspended'],
      requirePkce: old['requirePkce'],
      environment: old['environment'],
      staticApiKeysAllowed: old['staticApiKeysAllowed'],
      createdAt: time(old['createdAt']),
      updatedAt: time(old['updatedAt']),
      lastUsedAt: time(old['lastUsedAt']),
    };
  }

  /** Let static API keys be minted for one client: development, in a development realm. */
  async function allowApiKeys(clientRowId: string): Promise<void> {
    await app().dbPool.query(`UPDATE oauth_clients SET environment = 'development' WHERE id = $1`, [
      clientRowId,
    ]);
    await app().dbPool.query(
      `UPDATE realms SET max_environment_laxity = 'development' WHERE name = $1`,
      [E2E_REALM_NAME]
    );
    app().realmHostCache.clear();
  }

  /** An active consent of `userId` to a client, as the consent screen stores it. */
  async function consentTo(userId: string, clientRowId: string): Promise<string> {
    const consent = await app().repositories.oauthConsents.upsertGrant(
      await realmId(),
      userId,
      clientRowId,
      ['openid']
    );
    return consent.id;
  }

  describe('the system client and the portal token', () => {
    it('creates the system client of a fresh database with the developer audience, and mints it', async () => {
      const dev = await developer();

      const { rows } = await app().dbPool.query<{ audience: string[] | null }>(
        `SELECT audience FROM oauth_clients WHERE client_id = 'system'`
      );
      expect(rows).toEqual([{ audience: [DEVELOPER_AUDIENCE] }]);
      expect(decodeJwtClaims(dev.token)).toMatchObject({
        aud: DEVELOPER_AUDIENCE,
        client_id: 'system',
        sub: dev.userId,
      });
      // The developer family's guard admits it, and so does the deprecated
      // path's.
      expect((await call('GET', `${DEVELOPER}/clients`, dev.token)).statusCode).toBe(200);
      expect((await call('GET', '/api/clients', dev.token)).statusCode).toBe(200);
    });

    it("gives every realm's system client without it the developer audience when a node boots", async () => {
      await developer();
      // A second realm's system client, as a release before #524 created it.
      const { realm: beta } = await app().repositories.realms.createWithPrimaryHost(
        { name: 'beta', issuer: 'https://beta.example.com', enabled: true },
        'beta.example.com'
      );
      await app().repositories.oauthClients.create({
        realmId: beta.id,
        clientId: 'system',
        clientSecretHash: 'unused',
        name: 'System Client',
        redirectUris: [],
        grantTypes: ['refresh_token'],
        requirePkce: false,
        developerId: null,
        provisionedByOperator: true,
      });
      await app().dbPool.query(
        `UPDATE oauth_clients SET audience = NULL WHERE client_id = 'system'`
      );

      const second = await bootAuthServer(environment);
      try {
        const { rows } = await second.app.dbPool.query<{ audience: string[] | null }>(
          `SELECT audience FROM oauth_clients WHERE client_id = 'system'`
        );
        expect(rows).toEqual([
          { audience: [DEVELOPER_AUDIENCE] },
          { audience: [DEVELOPER_AUDIENCE] },
        ]);
      } finally {
        await second.close();
      }
    });

    it("refuses a portal token minted before #524, whose audience was the system client's id", async () => {
      const dev = await developer();
      const legacy = await app().jwtUtils.signAccessToken(
        { id: await realmId() },
        { sub: dev.userId, clientId: 'system', aud: 'system' }
      );

      for (const url of ['/api/clients', '/api/consents', `${DEVELOPER}/clients`]) {
        expect((await call('GET', url, legacy)).statusCode, url).toBe(401);
      }
      const logout = await call('POST', '/auth/logout', legacy);
      expect(logout.statusCode).toBe(401);
    });

    it('no longer takes the portal token as a sign-in at /oauth/authorize', async () => {
      const dev = await developer();
      const client = await oldClient(dev.token, {
        tokenEndpointAuthMethod: 'none',
        grantTypes: ['authorization_code'],
      });
      await consentTo(dev.userId, client['id'] as string);

      const response = await call(
        'GET',
        `/oauth/authorize?${new URLSearchParams({
          response_type: 'code',
          client_id: client['clientId'] as string,
          redirect_uri: 'https://app.example.com/cb',
          scope: 'openid',
          state: 'st',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
        }).toString()}`,
        dev.token
      );

      expect(response.statusCode).toBe(302);
      expect(response.headers.location).toMatch(/^\/ui\/login\?return_to=/);
      const { rows } = await app().dbPool.query('SELECT 1 FROM authorization_codes');
      expect(rows).toEqual([]);
    });
  });

  describe("every deprecated route's data on its new path", () => {
    it('GET /developer/v1-rc.0/clients lists what /api/clients lists, in the new format', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);
      const old = (await call('GET', '/api/clients', dev.token)).json<{
        clients: Record<string, unknown>[];
      }>().clients;

      const response = await call('GET', `${DEVELOPER}/clients`, dev.token);

      expect(response.statusCode).toBe(200);
      expect(response.headers['deprecation']).toBeUndefined();
      expect(response.json()).toEqual({ items: old.map(asNew), nextCursor: null });
      expect(response.json().items[0]).toMatchObject({ client_id: created['clientId'] });
      expect(response.json().items[0].createdAt).toMatch(ISO_TIME);
    });

    it('POST /developer/v1-rc.0/clients creates what /api/clients then serves', async () => {
      const dev = await developer();

      const response = await call('POST', `${DEVELOPER}/clients`, dev.token, {
        payload: {
          client_name: 'New App',
          redirect_uris: ['https://app.example.com/cb'],
          scopes: ['openid'],
          token_endpoint_auth_method: 'client_secret_basic',
        },
      });

      expect(response.statusCode, response.body).toBe(201);
      const body = response.json<Record<string, unknown>>();
      expect(body['client_secret']).toMatch(/^[0-9a-f]{64}$/);
      expect(response.headers['etag']).toMatch(/^"[A-Za-z0-9_-]+"$/);
      expect(response.headers['location']).toBe(`${DEVELOPER}/clients/${String(body['id'])}`);
      const old = await call('GET', `/api/clients/${String(body['id'])}`, dev.token);
      expect({ ...asNew(old.json()), client_secret: body['client_secret'] }).toEqual(body);
    });

    it('GET /developer/v1-rc.0/clients/{clientId} serves one client with its ETag', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);
      const old = (await call('GET', `/api/clients/${String(created['id'])}`, dev.token)).json();

      const response = await call(
        'GET',
        `${DEVELOPER}/clients/${String(created['id'])}`,
        dev.token
      );

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual(asNew(old));
      expect(response.headers['etag']).toMatch(/^"[A-Za-z0-9_-]+"$/);
      expect(response.headers['cache-control']).toBe('no-store');
    });

    it('PATCH /developer/v1-rc.0/clients/{clientId} changes what /api/clients/:id serves', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);
      const url = `${DEVELOPER}/clients/${String(created['id'])}`;
      const read = await call('GET', url, dev.token);

      const response = await call('PATCH', url, dev.token, {
        headers: {
          'content-type': 'application/merge-patch+json',
          'if-match': read.headers['etag'] as string,
        },
        payload: { client_name: 'Renamed', description: 'Now described', enabled: false },
      });

      expect(response.statusCode, response.body).toBe(200);
      expect(response.json()).toMatchObject({
        client_name: 'Renamed',
        description: 'Now described',
        enabled: false,
      });
      expect(response.headers['etag']).not.toBe(read.headers['etag']);
      const old = await call('GET', `/api/clients/${String(created['id'])}`, dev.token);
      expect(old.json()).toMatchObject({
        name: 'Renamed',
        description: 'Now described',
        enabled: false,
      });
      // The new version is the one to name next.
      const again = await call('PATCH', url, dev.token, {
        headers: {
          'content-type': 'application/merge-patch+json',
          'if-match': response.headers['etag'] as string,
        },
        payload: { description: null },
      });
      expect(again.statusCode).toBe(200);
      expect(again.json()).toMatchObject({ description: null });
    });

    it('DELETE /developer/v1-rc.0/clients/{clientId} deletes what /api/clients/:id served', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);

      const response = await call(
        'DELETE',
        `${DEVELOPER}/clients/${String(created['id'])}`,
        dev.token
      );

      expect(response.statusCode).toBe(204);
      expect(
        (await call('GET', `/api/clients/${String(created['id'])}`, dev.token)).statusCode
      ).toBe(404);
    });

    it('POST /developer/v1-rc.0/clients/{clientId}/regenerate-secret issues a new secret', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);

      const response = await call(
        'POST',
        `${DEVELOPER}/clients/${String(created['id'])}/regenerate-secret`,
        dev.token
      );

      expect(response.statusCode, response.body).toBe(200);
      expect(response.json().client_secret).toMatch(/^[0-9a-f]{64}$/);
      expect(response.json().client_secret).not.toBe(created['clientSecret']);
      expect(response.headers['cache-control']).toBe('no-store');
    });

    it('lists, mints and revokes API keys where /api/clients/:clientId/api-keys did', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);
      await allowApiKeys(created['id'] as string);
      const base = `${DEVELOPER}/clients/${String(created['id'])}/api-keys`;
      const old = await call('POST', `/api/clients/${String(created['id'])}/api-keys`, dev.token, {
        payload: { name: 'old key' },
      });
      expect(old.statusCode, old.body).toBe(201);

      const minted = await call('POST', base, dev.token, { payload: { name: 'new key' } });
      expect(minted.statusCode, minted.body).toBe(201);
      expect(minted.json()).toMatchObject({ name: 'new key', clientId: created['id'] });
      expect(minted.json().key).toMatch(/^qauth_/);
      expect(minted.json().createdAt).toMatch(ISO_TIME);

      const listed = await call('GET', base, dev.token);
      expect(listed.statusCode).toBe(200);
      expect(listed.json().items.map((key: { name: string }) => key.name)).toEqual([
        'new key',
        'old key',
      ]);
      expect(listed.json().nextCursor).toBeNull();

      const revoked = await call('DELETE', `${base}/${String(old.json().id)}`, dev.token);
      expect(revoked.statusCode).toBe(200);
      expect(revoked.json().revokedAt).toMatch(ISO_TIME);
      const oldList = await call(
        'GET',
        `/api/clients/${String(created['id'])}/api-keys`,
        dev.token
      );
      expect(
        oldList.json().apiKeys.find((key: { id: string }) => key.id === old.json().id).revokedAt
      ).toEqual(expect.any(Number));
    });

    it.each([
      ['developer', DEVELOPER],
      ['account', ACCOUNT],
    ] as const)(
      'lists and revokes on /%s/v1-rc.0/consents the consents /api/consents lists',
      async (family, prefix) => {
        const dev = await developer();
        const created = await oldClient(dev.token);
        const consentId = await consentTo(dev.userId, created['id'] as string);
        const token = family === 'developer' ? dev.token : await accountToken(dev.userId);
        const old = (await call('GET', '/api/consents', dev.token)).json<{
          consents: Array<Record<string, unknown>>;
        }>().consents;

        const listed = await call('GET', `${prefix}/consents`, token);

        expect(listed.statusCode, listed.body).toBe(200);
        expect(listed.json()).toEqual({
          items: old.map((consent) => ({
            id: consent['id'],
            client_id: consent['clientId'],
            client_name: consent['clientName'],
            scopes: consent['scopes'],
            grantedAt: new Date(consent['grantedAt'] as number).toISOString(),
          })),
          nextCursor: null,
        });
        expect(listed.json().items[0]).toMatchObject({ id: consentId });

        const revoked = await call('DELETE', `${prefix}/consents/${consentId}`, token);
        expect(revoked.statusCode).toBe(204);
        expect((await call('GET', '/api/consents', dev.token)).json().consents).toEqual([]);
      }
    );
  });

  describe('the deprecated routes', () => {
    it('keep their old response shapes', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);
      await allowApiKeys(created['id'] as string);
      await call('POST', `/api/clients/${String(created['id'])}/api-keys`, dev.token, {
        payload: { name: 'k' },
      });
      await consentTo(dev.userId, created['id'] as string);

      expect(Object.keys(created).sort()).toEqual([...OLD_CLIENT_MEMBERS, 'clientSecret'].sort());
      const list = (await call('GET', '/api/clients', dev.token)).json();
      expect(Object.keys(list)).toEqual(['clients']);
      expect(Object.keys(list.clients[0])).toEqual(OLD_CLIENT_MEMBERS);
      expect(list.clients[0].createdAt).toEqual(expect.any(Number));

      const keys = (
        await call('GET', `/api/clients/${String(created['id'])}/api-keys`, dev.token)
      ).json();
      expect(Object.keys(keys)).toEqual(['apiKeys']);
      expect(Object.keys(keys.apiKeys[0])).toEqual([
        'id',
        'clientId',
        'name',
        'prefix',
        'last4',
        'createdAt',
        'lastUsedAt',
        'revokedAt',
      ]);
      expect(keys.apiKeys[0].createdAt).toEqual(expect.any(Number));

      const consents = (await call('GET', '/api/consents', dev.token)).json();
      expect(Object.keys(consents)).toEqual(['consents']);
      expect(Object.keys(consents.consents[0])).toEqual([
        'id',
        'clientId',
        'clientName',
        'scopes',
        'grantedAt',
      ]);
      expect(consents.consents[0].grantedAt).toEqual(expect.any(Number));

      // The cookie-and-CSRF alias, signed in through the hosted UI.
      const jar = await signInWithPassword(app(), dev.email);
      const cookie = await app().inject({
        method: 'GET',
        url: '/consents',
        headers: { cookie: jar.header() as string },
      });
      expect(cookie.statusCode).toBe(200);
      expect(Object.keys(cookie.json()).sort()).toEqual(['consents', 'csrfToken']);
      expect(cookie.json().consents[0].grantedAt).toEqual(expect.any(Number));
    });

    it('carry the Deprecation header on every answer, errors included', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);
      const answers = [
        await call('GET', '/api/clients', dev.token),
        await call('GET', `/api/clients/${String(created['id'])}`, dev.token),
        await call('GET', `/api/clients/${String(created['id'])}/api-keys`, dev.token),
        await call('GET', '/api/consents', dev.token),
        await call('GET', '/api/clients', 'not-a-token'),
        await app().inject({ method: 'GET', url: '/consents' }),
      ];

      for (const answer of answers) {
        expect(answer.headers['deprecation'], answer.body).toBe(DEPRECATION);
        expect(answer.headers['link']).toBe(
          '<https://docs.qauth.dev/reference/api-conventions/#deprecations>; rel="deprecation"; type="text/html"'
        );
      }
      expect(answers[4].statusCode).toBe(401);
      expect(answers[5].statusCode).toBe(401);
      const fresh = await call('GET', `${DEVELOPER}/clients`, dev.token);
      expect(fresh.headers['deprecation']).toBeUndefined();
    });

    it('are deprecated: true in the OpenAPI document, and their replacements are not', () => {
      const document = JSON.parse(
        readFileSync(join(REPO_ROOT, 'stable-surface', 'openapi.json'), 'utf8')
      ) as { paths: Record<string, Record<string, { deprecated?: boolean }>> };
      const operations = Object.entries(document.paths).flatMap(([path, item]) =>
        Object.entries(item).map(([method, operation]) => ({ path, method, operation }))
      );
      const old = operations.filter(({ path }) =>
        /^\/(api\/clients|api\/consents|consents)(\/|$)/.test(path)
      );
      const replacements = operations.filter(({ path }) =>
        /^\/(developer|account)\/v1-rc\.0\//.test(path)
      );

      expect(old).toHaveLength(13);
      for (const { path, method, operation } of old) {
        expect(operation.deprecated, `${method} ${path}`).toBe(true);
      }
      expect(replacements).toHaveLength(13);
      for (const { path, method, operation } of replacements) {
        expect(operation.deprecated, `${method} ${path}`).toBeUndefined();
      }
    });
  });

  describe('a delegated account token (RFC 8693)', () => {
    it('revokes a consent for its user, and the event names the acting agent', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);
      const consentId = await consentTo(dev.userId, created['id'] as string);
      const delegated = await app().jwtUtils.signAccessToken(
        { id: await realmId() },
        {
          sub: dev.userId,
          clientId: 'agent-client',
          aud: ACCOUNT_AUDIENCE,
          act: { sub: 'agent-client' },
        }
      );

      const revoked = await call('DELETE', `${ACCOUNT}/consents/${consentId}`, delegated);

      expect(revoked.statusCode, revoked.body).toBe(204);
      const { rows } = await app().dbPool.query(
        `SELECT actor_type, actor_id, actor_delegation_chain FROM events
          WHERE type = 'urn:qauth:event:consent.revoked:v1-rc.0'`
      );
      expect(rows).toEqual([
        {
          actor_type: 'client',
          actor_id: 'agent-client',
          actor_delegation_chain: ['agent-client'],
        },
      ]);
      // The developer family refuses a delegated token outright.
      const developerToken = await app().jwtUtils.signAccessToken(
        { id: await realmId() },
        {
          sub: dev.userId,
          clientId: 'system',
          aud: DEVELOPER_AUDIENCE,
          act: { sub: 'agent-client' },
        }
      );
      expect((await call('GET', `${DEVELOPER}/consents`, developerToken)).statusCode).toBe(401);
    });
  });

  describe('the family guards', () => {
    it('refuse an account token on the developer API and a developer token on the account API', async () => {
      const dev = await developer();
      const account = await accountToken(dev.userId);

      const crossed = [
        await call('GET', `${DEVELOPER}/clients`, account),
        await call('GET', `${DEVELOPER}/consents`, account),
        await call('GET', `${ACCOUNT}/consents`, dev.token),
      ];
      for (const response of crossed) {
        expect(response.statusCode).toBe(401);
        expect(response.json()).toMatchObject({ code: 'invalid_access_token' });
        expect(response.headers['www-authenticate']).toContain('error="invalid_token"');
      }
      expect((await call('GET', `${ACCOUNT}/consents`, account)).statusCode).toBe(200);
    });

    it('refuse a request with no token before reading its body or query', async () => {
      const response = await app().inject({
        method: 'GET',
        url: `${DEVELOPER}/clients?limit=9999`,
      });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({ code: 'unauthorized' });
    });
  });

  describe('lists', () => {
    it('answer { items, nextCursor } and honour limit, page after page', async () => {
      const dev = await developer();
      const ids: string[] = [];
      for (let i = 0; i < 3; i++) ids.push((await oldClient(dev.token))['id'] as string);

      const first = await call('GET', `${DEVELOPER}/clients?limit=2`, dev.token);
      expect(first.statusCode).toBe(200);
      expect(Object.keys(first.json())).toEqual(['items', 'nextCursor']);
      expect(first.json().items).toHaveLength(2);
      expect(first.json().nextCursor).toEqual(expect.any(String));

      const second = await call(
        'GET',
        `${DEVELOPER}/clients?limit=2&cursor=${encodeURIComponent(first.json().nextCursor)}`,
        dev.token
      );
      expect(second.json().items).toHaveLength(1);
      expect(second.json().nextCursor).toBeNull();
      const seen = [...first.json().items, ...second.json().items].map(
        (client: { id: string }) => client.id
      );
      // Newest first, every client once.
      expect(seen).toEqual([...ids].reverse());
    });

    it('refuse a limit above 200, and a cursor another list issued or nobody did', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);
      await consentTo(dev.userId, created['id'] as string);
      await consentTo(dev.userId, (await oldClient(dev.token, { name: 'Second' }))['id'] as string);
      const consents = await call('GET', `${DEVELOPER}/consents?limit=1`, dev.token);
      const foreignCursor = consents.json().nextCursor as string;
      expect(foreignCursor).toEqual(expect.any(String));

      const tooMany = await call('GET', `${DEVELOPER}/clients?limit=201`, dev.token);
      expect(tooMany.statusCode).toBe(400);
      expect(tooMany.json()).toMatchObject({ code: 'validation_error' });
      for (const cursor of [foreignCursor, 'not-a-cursor']) {
        const response = await call(
          'GET',
          `${DEVELOPER}/clients?cursor=${encodeURIComponent(cursor)}`,
          dev.token
        );
        expect(response.statusCode).toBe(400);
        expect(response.json()).toMatchObject({ code: 'invalid_cursor' });
      }
    });
  });

  describe('an update', () => {
    it('without If-Match is 428, with a stale one 412, and nothing changes', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);
      const url = `${DEVELOPER}/clients/${String(created['id'])}`;
      const read = await call('GET', url, dev.token);
      const headers = { 'content-type': 'application/merge-patch+json' };

      const missing = await call('PATCH', url, dev.token, {
        headers,
        payload: { client_name: 'Lost' },
      });
      expect(missing.statusCode).toBe(428);
      expect(missing.json()).toMatchObject({ code: 'precondition_required' });

      // Another tab changes the client after this one read it.
      const other = await call('PATCH', url, dev.token, {
        headers: { ...headers, 'if-match': read.headers['etag'] as string },
        payload: { description: 'Changed elsewhere' },
      });
      expect(other.statusCode).toBe(200);

      const stale = await call('PATCH', url, dev.token, {
        headers: { ...headers, 'if-match': read.headers['etag'] as string },
        payload: { client_name: 'Lost' },
      });
      expect(stale.statusCode).toBe(412);
      expect(stale.json()).toMatchObject({ code: 'precondition_failed' });
      expect((await call('GET', url, dev.token)).json()).toMatchObject({
        client_name: 'Old App',
        description: 'Changed elsewhere',
      });
    });

    it('lets one of two updates naming the same version through, and refuses the other with 412', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);
      const url = `${DEVELOPER}/clients/${String(created['id'])}`;
      const etag = (await call('GET', url, dev.token)).headers['etag'] as string;
      const patch = (description: string) =>
        call('PATCH', url, dev.token, {
          headers: { 'content-type': 'application/merge-patch+json', 'if-match': etag },
          payload: { description },
        });

      const answers = await Promise.all([patch('first'), patch('second')]);

      expect(answers.map((answer) => answer.statusCode).sort()).toEqual([200, 412]);
      const winner = answers.find((answer) => answer.statusCode === 200);
      expect((await call('GET', url, dev.token)).json().description).toBe(
        winner?.json().description
      );
    });

    it('is a merge patch: another media type is 415, and a client_name set to null 422', async () => {
      const dev = await developer();
      const created = await oldClient(dev.token);
      const url = `${DEVELOPER}/clients/${String(created['id'])}`;
      const etag = (await call('GET', url, dev.token)).headers['etag'] as string;

      const json = await call('PATCH', url, dev.token, {
        headers: { 'content-type': 'application/json', 'if-match': etag },
        payload: { client_name: 'x' },
      });
      expect(json.statusCode).toBe(415);

      const unnamed = await call('PATCH', url, dev.token, {
        headers: { 'content-type': 'application/merge-patch+json', 'if-match': etag },
        payload: { client_name: null },
      });
      expect(unnamed.statusCode).toBe(422);
      expect(unnamed.json()).toMatchObject({
        code: 'unprocessable_content',
        errors: [expect.objectContaining({ pointer: '/client_name' })],
      });

      const unknown = await call('PATCH', url, dev.token, {
        headers: { 'content-type': 'application/merge-patch+json', 'if-match': etag },
        payload: { client_id: 'mine-now' },
      });
      expect(unknown.statusCode).toBe(400);
      expect(unknown.json()).toMatchObject({ code: 'validation_error' });
    });
  });

  describe("another developer's client (ADR-012)", () => {
    it('is 404 on every path, old and new, as one that does not exist', async () => {
      const alice = await developer();
      const bob = await developer();
      const client = await oldClient(alice.token);
      const id = client['id'] as string;
      const patch = {
        headers: {
          'content-type': 'application/merge-patch+json',
          'if-match': (await call('GET', `${DEVELOPER}/clients/${id}`, alice.token)).headers[
            'etag'
          ] as string,
        },
        payload: { client_name: 'Taken' },
      };

      const answers = [
        await call('GET', `${DEVELOPER}/clients/${id}`, bob.token),
        await call('PATCH', `${DEVELOPER}/clients/${id}`, bob.token, patch),
        await call('DELETE', `${DEVELOPER}/clients/${id}`, bob.token),
        await call('POST', `${DEVELOPER}/clients/${id}/regenerate-secret`, bob.token),
        await call('GET', `${DEVELOPER}/clients/${id}/api-keys`, bob.token),
        await call('GET', `/api/clients/${id}`, bob.token),
        await call('DELETE', `/api/clients/${id}`, bob.token),
      ];
      for (const answer of answers) {
        expect(answer.statusCode, answer.body).toBe(404);
        expect(answer.json()).toMatchObject({ code: 'not_found' });
      }
      expect((await call('GET', `${DEVELOPER}/clients`, bob.token)).json().items).toEqual([]);

      // Alice's key named under Bob's own client is no key of his.
      await allowApiKeys(id);
      const key = await call('POST', `${DEVELOPER}/clients/${id}/api-keys`, alice.token, {
        payload: { name: 'alice' },
      });
      expect(key.statusCode).toBe(201);
      const bobClient = (await oldClient(bob.token))['id'] as string;
      const stolenKey = await call(
        'DELETE',
        `${DEVELOPER}/clients/${bobClient}/api-keys/${String(key.json().id)}`,
        bob.token
      );
      expect(stolenKey.statusCode).toBe(404);

      // Alice's consent is no consent of Bob's, on either family.
      const consentId = await consentTo(alice.userId, id);
      for (const [url, token] of [
        [`${DEVELOPER}/consents/${consentId}`, bob.token],
        [`${ACCOUNT}/consents/${consentId}`, await accountToken(bob.userId)],
      ] as const) {
        const answer = await call('DELETE', url, token);
        expect(answer.statusCode, url).toBe(404);
        expect(answer.json()).toMatchObject({ code: 'not_found' });
      }
      expect((await call('GET', '/api/consents', alice.token)).json().consents).toHaveLength(1);
      expect((await call('GET', `${DEVELOPER}/clients/${id}`, alice.token)).json()).toMatchObject({
        client_name: 'Old App',
      });
    });
  });

  describe('the developer portal, end to end on the new paths', () => {
    /** The portal's own server-side client, as `apps/developer-portal` runs it. */
    interface PortalResult<T> {
      ok: boolean;
      data?: T;
      error?: { code: string; status: number };
    }
    type PortalClient = Record<string, (...args: unknown[]) => Promise<PortalResult<never>>>;

    /** The portal's variables as they were, put back after the case. */
    let saved: Record<string, string | undefined> = {};

    afterEach(() => {
      for (const [key, value] of Object.entries(saved)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      saved = {};
    });

    /**
     * Load `apps/developer-portal/src/server/auth-server-client.ts` pointed at
     * this server. The path is computed, so no project imports another: the
     * portal is an application, and only this suite runs its code here.
     */
    async function portalClient(): Promise<PortalClient> {
      saved = {
        AUTH_SERVER_URL: process.env['AUTH_SERVER_URL'],
        PORTAL_SESSION_SECRET: process.env['PORTAL_SESSION_SECRET'],
      };
      process.env['AUTH_SERVER_URL'] = origin;
      process.env['PORTAL_SESSION_SECRET'] = 'portal-e2e-session-secret-of-32-characters';
      const path = join(
        REPO_ROOT,
        'apps',
        'developer-portal',
        'src',
        'server',
        'auth-server-client.ts'
      );
      const module = (await import(/* @vite-ignore */ pathToFileURL(path).href)) as {
        authServerClient: PortalClient;
      };
      return module.authServerClient;
    }

    it('signs in, manages a client, its keys and a consent, and signs out, never calling /api', async () => {
      const portal = await portalClient();
      const email = `portal-${Date.now()}@example.com`;
      const userId = await registerPasswordAccount(app(), email);
      const requested: string[] = [];
      const realFetch = globalThis.fetch;
      globalThis.fetch = (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        requested.push(`${init?.method ?? 'GET'} ${String(input)}`);
        return realFetch(input, init);
      };
      try {
        const login = (await portal['login'](email, E2E_PASSWORD)) as PortalResult<{
          access_token: string;
        }>;
        expect(login.ok).toBe(true);
        const token = login.data?.access_token as string;
        expect((await portal['userinfo'](token)).ok).toBe(true);

        const created = (await portal['createClient'](token, {
          name: 'Portal App',
          redirectUris: ['https://portal-app.example.com/cb'],
          scopes: ['openid'],
          grantTypes: ['authorization_code', 'refresh_token'],
          tokenEndpointAuthMethod: 'client_secret_post',
        })) as PortalResult<{ id: string; clientId: string; clientSecret?: string }>;
        expect(created.ok, JSON.stringify(created.error)).toBe(true);
        const id = created.data?.id as string;
        expect(created.data?.clientSecret).toMatch(/^[0-9a-f]{64}$/);

        const listed = (await portal['listClients'](token)) as PortalResult<{
          clients: Array<{ id: string; name: string; createdAt: number }>;
        }>;
        expect(listed.data?.clients).toEqual([
          expect.objectContaining({ id, name: 'Portal App', createdAt: expect.any(Number) }),
        ]);

        const read = (await portal['getClient'](token, id)) as PortalResult<{ etag: string }>;
        expect(read.data?.etag).toMatch(/^"/);
        const updated = (await portal['updateClient'](
          token,
          id,
          { name: 'Portal App 2' },
          read.data?.etag
        )) as PortalResult<{ name: string }>;
        expect(updated.data?.name).toBe('Portal App 2');
        const stale = await portal['updateClient'](token, id, { name: 'Lost' }, read.data?.etag);
        expect(stale.error).toMatchObject({ code: 'CONFLICT', status: 412 });

        const regenerated = (await portal['regenerateClientSecret'](token, id)) as PortalResult<{
          clientSecret: string;
        }>;
        expect(regenerated.data?.clientSecret).toMatch(/^[0-9a-f]{64}$/);

        await allowApiKeys(id);
        const key = (await portal['createApiKey'](token, id, { name: 'ci' })) as PortalResult<{
          id: string;
          key: string;
        }>;
        expect(key.data?.key).toMatch(/^qauth_/);
        const keys = (await portal['listApiKeys'](token, id)) as PortalResult<{
          apiKeys: unknown[];
        }>;
        expect(keys.data?.apiKeys).toHaveLength(1);
        const revokedKey = (await portal['revokeApiKey'](token, id, key.data?.id)) as PortalResult<{
          revokedAt: number | null;
        }>;
        expect(revokedKey.data?.revokedAt).toEqual(expect.any(Number));

        await consentTo(userId, id);
        const consents = (await portal['listConsents'](token)) as PortalResult<{
          consents: Array<{ id: string; clientName: string }>;
        }>;
        expect(consents.data?.consents).toEqual([
          expect.objectContaining({ clientName: 'Portal App 2' }),
        ]);
        expect((await portal['revokeConsent'](token, consents.data?.consents[0]?.id)).ok).toBe(
          true
        );

        expect((await portal['deleteClient'](token, id)).ok).toBe(true);
        expect((await portal['getClient'](token, id)).error).toMatchObject({ code: 'NOT_FOUND' });

        expect((await portal['logout'](token)).ok).toBe(true);
        expect((await portal['listClients'](token)).error).toMatchObject({
          code: 'UNAUTHENTICATED',
        });
      } finally {
        globalThis.fetch = realFetch;
      }

      expect(requested.length).toBeGreaterThan(10);
      expect(requested.filter((line) => line.includes('/api/'))).toEqual([]);
      expect(requested.some((line) => line.includes(`${origin}${DEVELOPER}/clients`))).toBe(true);
    });
  });
});
