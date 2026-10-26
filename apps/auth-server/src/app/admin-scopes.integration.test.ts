import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { isReservedAdminScope } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_PASSWORD,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { ADMIN_SCOPE_LIST } from './helpers/admin-scopes';

/**
 * THE `admin:` SCOPES ARE RESERVED (#507, ADR-019 Decision 7), against a real
 * Postgres and Redis.
 *
 * - `POST /oauth/register` refuses a registration that asks for an admin
 *   scope with RFC 7591's bare `invalid_client_metadata`, and stores no
 *   client.
 * - `POST /api/clients` and `PATCH /api/clients/{id}` refuse one with the
 *   `invalid_client_metadata` problem document (#513), and store nothing.
 * - A Client ID Metadata Document (the fixture below) whose `scope` holds an
 *   admin scope is refused at `/oauth/authorize` (its `client_id` resolves to
 *   no client, `invalid_request`), and no client row is materialised from it.
 * - Neither discovery document lists an admin scope.
 * - The realm's dynamic registration allowlist cannot hold one, through the
 *   repository or by hand, and the boot refuses a seed list that names one.
 *
 * Only the network fetch of the metadata document is replaced (`ssrfSafeGet`);
 * the resolver, the materialisation and the routes are the real ones.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const { ssrfSafeGet } = vi.hoisted(() => ({ ssrfSafeGet: vi.fn() }));
vi.mock('./helpers/ssrf-safe-fetch', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, ssrfSafeGet };
});

const CIMD_CLIENT_ID = 'https://agent.example.com/oauth/client.json';
const CIMD_REDIRECT_URI = 'https://agent.example.com/callback';

/** The CIMD fixture: a public client's metadata document, with the `scope` given. */
function cimdDocument(scope: string): Record<string, unknown> {
  return {
    client_id: CIMD_CLIENT_ID,
    client_name: 'Fixture agent',
    redirect_uris: [CIMD_REDIRECT_URI],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    scope,
  };
}

describe('the reserved admin: scopes (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    booted = await bootAuthServer(baseEnvironment(infra, jwt));
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
    ssrfSafeGet.mockReset();
    await resetE2eState(booted.app);
  });

  function app(): FastifyInstance {
    if (!booted) throw new Error('server not booted');
    return booted.app;
  }

  /** The server's own pool, for reading and writing rows by hand. */
  function db(): FastifyInstance['dbPool'] {
    return app().dbPool;
  }

  async function clientCount(clientId?: string): Promise<number> {
    const { rows } = await db().query<{ count: string }>(
      clientId === undefined
        ? 'SELECT count(*) FROM oauth_clients'
        : 'SELECT count(*) FROM oauth_clients WHERE client_id = $1',
      clientId === undefined ? [] : [clientId]
    );
    return Number(rows[0].count);
  }

  function register(scope: string) {
    return app().inject({
      method: 'POST',
      url: '/oauth/register',
      payload: {
        client_name: 'Dynamic client',
        redirect_uris: ['https://app.example.com/callback'],
        scope,
      },
    });
  }

  describe('POST /oauth/register', () => {
    it('registers a client that asks for ordinary scopes', async () => {
      const response = await register('openid profile');
      expect(response.statusCode).toBe(201);
      expect(response.json()).toMatchObject({ scope: 'openid profile' });
    });

    it.each([...ADMIN_SCOPE_LIST, 'admin:other', 'Admin:Security'])(
      'refuses a registration that asks for %s, and stores nothing',
      async (adminScope) => {
        const before = await clientCount();
        const response = await register(`openid ${adminScope}`);
        expect(response.statusCode).toBe(400);
        expect(response.headers['content-type']).toMatch(/^application\/json(?:;|$)/);
        // RFC 7591 §3.2.2: the bare code in `error`, the text beside it.
        expect(response.json()).toEqual({
          error: 'invalid_client_metadata',
          error_description:
            'scopes starting with admin: are reserved for the admin API and cannot be registered',
        });
        expect(await clientCount()).toBe(before);
      }
    );
  });

  describe('the developer API (/api/clients)', () => {
    /** A developer's access token from the first-party password sign-in. */
    async function developerToken(): Promise<string> {
      await registerPasswordAccount(app(), 'admin-scopes-dev@example.com');
      const signedIn = await app().inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'admin-scopes-dev@example.com', password: E2E_PASSWORD },
      });
      expect(signedIn.statusCode).toBe(200);
      return signedIn.json<{ access_token: string }>().access_token;
    }

    /** The `invalid_client_metadata` problem document (RFC 9457, #513). */
    function expectInvalidClientMetadata(response: Awaited<ReturnType<FastifyInstance['inject']>>) {
      expect(response.statusCode).toBe(400);
      expect(response.headers['content-type']).toMatch(/^application\/problem\+json(?:;|$)/);
      expect(response.json()).toMatchObject({
        status: 400,
        code: 'invalid_client_metadata',
        detail: expect.stringContaining('the admin: prefix is reserved for the admin API'),
      });
    }

    it.each([...ADMIN_SCOPE_LIST, 'Admin:Other'])(
      'POST refuses a client that asks for %s, and stores nothing',
      async (adminScope) => {
        const token = await developerToken();
        const before = await clientCount();
        const response = await app().inject({
          method: 'POST',
          url: '/api/clients',
          headers: { authorization: `Bearer ${token}` },
          payload: {
            name: 'Admin-scoped',
            redirectUris: ['https://app.example.com/callback'],
            scopes: ['openid', adminScope],
          },
        });
        expectInvalidClientMetadata(response);
        expect(await clientCount()).toBe(before);
      }
    );

    it('PATCH refuses to add an admin scope to a client, and leaves its scopes', async () => {
      const token = await developerToken();
      const created = await app().inject({
        method: 'POST',
        url: '/api/clients',
        headers: { authorization: `Bearer ${token}` },
        payload: {
          name: 'Ordinary',
          redirectUris: ['https://app.example.com/callback'],
          scopes: ['openid'],
        },
      });
      expect(created.statusCode).toBe(201);
      const { id } = created.json<{ id: string }>();

      const response = await app().inject({
        method: 'PATCH',
        url: `/api/clients/${id}`,
        headers: { authorization: `Bearer ${token}` },
        payload: { scopes: ['openid', 'admin:write'] },
      });
      expectInvalidClientMetadata(response);
      const { rows } = await db().query<{ scopes: string[] }>(
        'SELECT scopes FROM oauth_clients WHERE id = $1',
        [id]
      );
      expect(rows[0].scopes).toEqual(['openid']);
    });
  });

  describe('a Client ID Metadata Document', () => {
    function authorize() {
      const { challenge } = pkcePair();
      const query = new URLSearchParams({
        response_type: 'code',
        client_id: CIMD_CLIENT_ID,
        redirect_uri: CIMD_REDIRECT_URI,
        scope: 'openid',
        state: 'state-507',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      });
      return app().inject({ method: 'GET', url: `/oauth/authorize?${query}` });
    }

    /**
     * A `client_id` that resolves to no client is answered in place with
     * `invalid_request` (RFC 6749 §4.1.2.1, #513); why goes to the event only.
     */
    function expectUnresolvedClient(response: Awaited<ReturnType<typeof authorize>>): void {
      expect(response.statusCode).toBe(400);
      expect(response.json()).toMatchObject({ error: 'invalid_request' });
    }

    function serveDocument(scope: string) {
      ssrfSafeGet.mockImplementation(async (url: string) => {
        expect(url).toBe(CIMD_CLIENT_ID);
        return {
          status: 200,
          body: JSON.stringify(cimdDocument(scope)),
          headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
        };
      });
    }

    it('is accepted when its scope holds no admin scope', async () => {
      serveDocument('openid profile');
      const response = await authorize();
      expect(response.statusCode).not.toBe(400);
      expect(ssrfSafeGet).toHaveBeenCalledTimes(1);
      expect(await clientCount(CIMD_CLIENT_ID)).toBe(1);
    });

    it.each(['openid admin:read', 'admin:write', 'profile admin:security', 'ADMIN:read'])(
      'is refused when its scope is %j, and no client is materialised',
      async (scope) => {
        serveDocument(scope);
        const response = await authorize();
        expectUnresolvedClient(response);
        expect(ssrfSafeGet).toHaveBeenCalledTimes(1);
        expect(await clientCount(CIMD_CLIENT_ID)).toBe(0);
      }
    );

    it('refuses a client already materialised once its document asks for an admin scope', async () => {
      serveDocument('openid');
      expect((await authorize()).statusCode).not.toBe(400);
      expect(await clientCount(CIMD_CLIENT_ID)).toBe(1);

      serveDocument('openid admin:security');
      expectUnresolvedClient(await authorize());
    });
  });

  describe('discovery', () => {
    it.each(['/.well-known/openid-configuration', '/.well-known/oauth-authorization-server'])(
      '%s lists no admin scope',
      async (url) => {
        const response = await app().inject({ method: 'GET', url });
        expect(response.statusCode).toBe(200);
        const scopes = response.json<{ scopes_supported: string[] }>().scopes_supported;
        expect(scopes.length).toBeGreaterThan(0);
        expect(scopes.filter(isReservedAdminScope)).toEqual([]);
        for (const scope of ADMIN_SCOPE_LIST) expect(scopes).not.toContain(scope);
      }
    );
  });

  describe("the realm's dynamic registration allowlist", () => {
    async function defaultRealmId(): Promise<string> {
      const { rows } = await db().query<{ id: string }>(
        `SELECT id FROM realms WHERE name = 'master'`
      );
      expect(rows).toHaveLength(1);
      return rows[0].id;
    }

    it('cannot hold an admin scope through the repository', async () => {
      const realmId = await defaultRealmId();
      await expect(
        app().repositories.realms.update(realmId, {
          dynamicRegistrationAllowedScopes: ['openid', 'admin:read'],
        })
      ).rejects.toMatchObject({ name: 'BadRequestError' });
    });

    it('cannot hold an admin scope written by hand', async () => {
      const realmId = await defaultRealmId();
      await expect(
        db().query(
          `UPDATE realms SET dynamic_registration_allowed_scopes = '["openid","admin:write"]'::jsonb
           WHERE id = $1`,
          [realmId]
        )
      ).rejects.toMatchObject({
        code: '23514',
        constraint: 'realms_dynamic_registration_scopes_not_admin',
      });
    });
  });

  // Last: a failed boot leaves its variable in `process.env`, and the harness
  // clears only its own prefixes, so it is removed here by hand.
  it('the boot refuses DEFAULT_DYNAMIC_REGISTRATION_SCOPES when it names an admin scope', async () => {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    try {
      await expect(
        bootAuthServer({
          ...baseEnvironment(infra, jwt),
          DEFAULT_DYNAMIC_REGISTRATION_SCOPES: 'openid admin:read',
        })
      ).rejects.toMatchObject({
        issues: [
          expect.objectContaining({
            path: ['DEFAULT_DYNAMIC_REGISTRATION_SCOPES'],
            message: expect.stringContaining('lists "admin:read"'),
          }),
        ],
      });
    } finally {
      delete process.env['DEFAULT_DYNAMIC_REGISTRATION_SCOPES'];
    }
  });
});
