import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  decodeJwtClaims,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { API_FAMILIES, API_FAMILY_AUDIENCES, type ApiFamily } from './api-conventions/families';

/**
 * ONE AUDIENCE PER API FAMILY, AND A TOKEN GUARD FOR EACH (#509, ADR-019
 * Decision 7), against a real Postgres and Redis.
 *
 * No family route ships yet, so the suite adds one probe route per family
 * under its prefix, guarded by `requireFamilyToken`, beside the real app. The
 * tokens come from the real token endpoint.
 *
 * - The 3 by 3 matrix: each family's token works on its own family only.
 * - The token endpoint issues a family audience only to a client that lists
 *   it, mapping the RFC 8707 `resource` value to the audience, on the
 *   client_credentials and the authorization code grants.
 * - `POST /oauth/register` and a Client ID Metadata Document refuse a
 *   `urn:qauth:aud:` audience or resource.
 * - The developer portal's token: `/auth/login` mints it with the developer
 *   audience, and a token minted before #509 (the system client id as
 *   audience) still works at the legacy `/api/clients` path and at userinfo.
 * - A bad token gets the RFC 6750 challenge; a missing scope 403
 *   `insufficient_scope`.
 *
 * Only the network fetch of the metadata document is replaced (`ssrfSafeGet`).
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const { ssrfSafeGet } = vi.hoisted(() => ({ ssrfSafeGet: vi.fn() }));
vi.mock('./helpers/ssrf-safe-fetch', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, ssrfSafeGet };
});

const CLIENT_SECRET = 'family-client-secret-of-sufficient-length-42';
const PROBE_SCOPE = 'probe:read';
const REDIRECT_URI = 'https://client.example.com/callback';
const CIMD_CLIENT_ID = 'https://agent.example.com/oauth/client.json';
const CIMD_REDIRECT_URI = 'https://agent.example.com/callback';

/** The probe route of a family, and the one that also needs a scope. */
function probePath(family: ApiFamily, suffix = 'probe'): string {
  return `/${family}/v1-rc.0/${suffix}`;
}

/** The machine client whose `audience` lists one family's audience. */
function familyClientId(family: ApiFamily): string {
  return `${family}-family-client`;
}

describe('one audience per API family and a guard for each (#509, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    booted = await bootAuthServer(baseEnvironment(infra, jwt), {
      // The guard is imported from the module registry the booted app loaded
      // (the harness resets it per boot), so its errors are the classes the
      // app's error handler knows.
      routes: async (scope) => {
        const { requireFamilyToken } = await import('./helpers/family-token');
        for (const family of API_FAMILIES) {
          scope.get(
            probePath(family),
            { preHandler: requireFamilyToken(family), config: { surface: 'api' } },
            async (request) => ({ sub: request.jwtPayload?.sub })
          );
          scope.get(
            probePath(family, 'scoped'),
            {
              preHandler: requireFamilyToken(family, { requiredScopes: ['probe:write'] }),
              config: { surface: 'api' },
            },
            async () => ({ ok: true })
          );
        }
      },
    });
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

  async function realmId(): Promise<string> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    return realm.id;
  }

  /** A confidential machine client with the `audience` given. */
  async function seedMachineClient(clientId: string, audience: string[] | null): Promise<void> {
    await app().repositories.oauthClients.create({
      realmId: await realmId(),
      clientId,
      clientSecretHash: await app().passwordHasher.hashPassword(CLIENT_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: clientId,
      redirectUris: [],
      grantTypes: ['client_credentials'],
      scopes: [PROBE_SCOPE],
      audience,
      enabled: true,
    });
  }

  function tokenRequest(form: Record<string, string>): Promise<LightMyRequestResponse> {
    return app().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams(form).toString(),
    });
  }

  /** A client_credentials token for `clientId`, asking for `resource`. */
  function machineToken(clientId: string, resource?: string): Promise<LightMyRequestResponse> {
    return tokenRequest({
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: CLIENT_SECRET,
      scope: PROBE_SCOPE,
      ...(resource === undefined ? {} : { resource }),
    });
  }

  function call(path: string, token: string): Promise<LightMyRequestResponse> {
    return app().inject({
      method: 'GET',
      url: path,
      headers: { authorization: `Bearer ${token}` },
    });
  }

  async function clientCount(clientId?: string): Promise<number> {
    const { rows } = await app().dbPool.query<{ count: string }>(
      clientId === undefined
        ? 'SELECT count(*) FROM oauth_clients'
        : 'SELECT count(*) FROM oauth_clients WHERE client_id = $1',
      clientId === undefined ? [] : [clientId]
    );
    return Number(rows[0].count);
  }

  describe('the 3 by 3 matrix', () => {
    it("admits each family's token on its own family and refuses it on the other two", async () => {
      const tokens = {} as Record<ApiFamily, string>;
      for (const family of API_FAMILIES) {
        await seedMachineClient(familyClientId(family), [API_FAMILY_AUDIENCES[family]]);
        const response = await machineToken(familyClientId(family), API_FAMILY_AUDIENCES[family]);
        expect(response.statusCode).toBe(200);
        const token = response.json<{ access_token: string }>().access_token;
        // The token endpoint maps the RFC 8707 resource value to the audience.
        expect(decodeJwtClaims(token)['aud']).toBe(API_FAMILY_AUDIENCES[family]);
        tokens[family] = token;
      }

      const matrix = API_FAMILIES.map((tokenFamily) =>
        API_FAMILIES.map((routeFamily) => ({ tokenFamily, routeFamily }))
      ).flat();
      for (const { tokenFamily, routeFamily } of matrix) {
        const response = await call(probePath(routeFamily), tokens[tokenFamily]);
        expect(
          { tokenFamily, routeFamily, status: response.statusCode },
          `${tokenFamily} token on the ${routeFamily} family`
        ).toEqual({ tokenFamily, routeFamily, status: tokenFamily === routeFamily ? 200 : 401 });
        if (tokenFamily === routeFamily) {
          expect(response.json()).toEqual({ sub: familyClientId(tokenFamily) });
        }
      }
    });
  });

  describe('issuing a family audience', () => {
    it('refuses invalid_target to a client that does not list it', async () => {
      await seedMachineClient('plain-machine', ['https://api.example.com']);
      for (const family of API_FAMILIES) {
        const response = await machineToken('plain-machine', API_FAMILY_AUDIENCES[family]);
        expect(response.statusCode).toBe(400);
        expect(response.json()).toMatchObject({ error: 'invalid_target' });
      }
    });

    it('binds it through the authorization code flow only for a client that lists it', async () => {
      const email = 'family-code@example.com';
      const userId = await registerPasswordAccount(app(), email);
      const jar = await signInWithPassword(app(), email);
      const realm = await realmId();
      const account = API_FAMILY_AUDIENCES.account;

      for (const [clientId, audience] of [
        ['account-console', [account]],
        ['unlisted-app', null],
      ] as const) {
        const client = await app().repositories.oauthClients.create({
          realmId: realm,
          clientId,
          clientSecretHash: 'unused-public-client',
          tokenEndpointAuthMethod: 'none',
          name: clientId,
          redirectUris: [REDIRECT_URI],
          scopes: ['openid'],
          grantTypes: ['authorization_code'],
          audience: audience === null ? null : [...audience],
          enabled: true,
          requirePkce: true,
          // Operator-provisioned, so an authorization error redirects to it.
          provisionedByOperator: true,
        });
        await app().repositories.oauthConsents.upsertGrant(
          userId,
          client.id,
          realm,
          ['openid'],
          [account]
        );
      }

      const authorize = (clientId: string, challenge: string) =>
        app().inject({
          method: 'GET',
          url: `/oauth/authorize?${new URLSearchParams({
            response_type: 'code',
            client_id: clientId,
            redirect_uri: REDIRECT_URI,
            scope: 'openid',
            resource: account,
            code_challenge: challenge,
            code_challenge_method: 'S256',
            state: 'family-state',
          })}`,
          headers: { cookie: jar.header() as string },
        });

      const refused = await authorize('unlisted-app', pkcePair().challenge);
      expect(refused.statusCode).toBe(302);
      expect(new URL(refused.headers['location'] as string).searchParams.get('error')).toBe(
        'invalid_target'
      );

      const { verifier, challenge } = pkcePair();
      const granted = await authorize('account-console', challenge);
      expect(granted.statusCode).toBe(302);
      const code = new URL(granted.headers['location'] as string).searchParams.get('code');
      expect(code).not.toBeNull();
      const token = await tokenRequest({
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: REDIRECT_URI,
        client_id: 'account-console',
        code_verifier: verifier,
      });
      expect(token.statusCode).toBe(200);
      const accessToken = token.json<{ access_token: string }>().access_token;
      expect(decodeJwtClaims(accessToken)).toMatchObject({ aud: account, sub: userId });
      expect((await call(probePath('account'), accessToken)).statusCode).toBe(200);
      expect((await call(probePath('developer'), accessToken)).statusCode).toBe(401);
    });
  });

  describe('the reserved urn:qauth:aud: namespace', () => {
    function register(metadata: Record<string, unknown>) {
      return app().inject({
        method: 'POST',
        url: '/oauth/register',
        payload: {
          client_name: 'Dynamic client',
          redirect_uris: ['https://app.example.com/callback'],
          ...metadata,
        },
      });
    }

    it.each([
      { audience: API_FAMILY_AUDIENCES.developer },
      { audience: ['https://api.example.com', API_FAMILY_AUDIENCES.admin] },
      { resource: API_FAMILY_AUDIENCES.account },
      { resource: ['URN:QAUTH:AUD:developer:v1-rc.0'] },
    ])('POST /oauth/register refuses %j and stores nothing', async (metadata) => {
      const before = await clientCount();
      const response = await register(metadata);
      expect(response.statusCode).toBe(400);
      expect(response.body).toContain('invalid_client_metadata');
      expect(await clientCount()).toBe(before);
    });

    it('POST /oauth/register still ignores an ordinary audience', async () => {
      const response = await register({ audience: 'https://api.example.com' });
      expect(response.statusCode).toBe(201);
      expect(response.json()).not.toHaveProperty('audience');
    });

    function serveDocument(extra: Record<string, unknown>) {
      ssrfSafeGet.mockImplementation(async (url: string) => {
        expect(url).toBe(CIMD_CLIENT_ID);
        return {
          status: 200,
          body: JSON.stringify({
            client_id: CIMD_CLIENT_ID,
            client_name: 'Fixture agent',
            redirect_uris: [CIMD_REDIRECT_URI],
            grant_types: ['authorization_code'],
            response_types: ['code'],
            token_endpoint_auth_method: 'none',
            ...extra,
          }),
          headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
        };
      });
    }

    function authorizeCimd() {
      const query = new URLSearchParams({
        response_type: 'code',
        client_id: CIMD_CLIENT_ID,
        redirect_uri: CIMD_REDIRECT_URI,
        scope: 'openid',
        state: 'state-509',
        code_challenge: pkcePair().challenge,
        code_challenge_method: 'S256',
      });
      return app().inject({ method: 'GET', url: `/oauth/authorize?${query}` });
    }

    it('a Client ID Metadata Document is accepted with an ordinary audience', async () => {
      serveDocument({ audience: 'https://api.example.com' });
      const response = await authorizeCimd();
      expect(response.statusCode).not.toBe(400);
      expect(await clientCount(CIMD_CLIENT_ID)).toBe(1);
    });

    it.each([
      { audience: API_FAMILY_AUDIENCES.developer },
      { resource: [API_FAMILY_AUDIENCES.admin] },
    ])(
      'a Client ID Metadata Document claiming %j is refused, and no client is materialised',
      async (extra) => {
        serveDocument(extra);
        const response = await authorizeCimd();
        expect(response.statusCode).toBe(400);
        expect(response.body).toContain('invalid_client');
        expect(ssrfSafeGet).toHaveBeenCalledTimes(1);
        expect(await clientCount(CIMD_CLIENT_ID)).toBe(0);
      }
    );
  });

  describe("the developer portal's token", () => {
    async function signInPortal(email: string): Promise<{ userId: string; token: string }> {
      const userId = await registerPasswordAccount(app(), email);
      const response = await app().inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email, password: 'Correct-Horse-Battery-Staple-42!' },
      });
      expect(response.statusCode).toBe(200);
      return { userId, token: response.json<{ access_token: string }>().access_token };
    }

    it('is minted with the developer audience, and works on the developer family and the legacy path', async () => {
      const { userId, token } = await signInPortal('portal-new@example.com');
      expect(decodeJwtClaims(token)).toMatchObject({
        aud: API_FAMILY_AUDIENCES.developer,
        client_id: 'system',
        sub: userId,
      });

      expect((await call(probePath('developer'), token)).statusCode).toBe(200);
      expect((await call(probePath('account'), token)).statusCode).toBe(401);
      expect((await call(probePath('admin'), token)).statusCode).toBe(401);
      expect((await call('/api/clients', token)).statusCode).toBe(200);
      expect((await call('/oauth/userinfo', token)).json()).toEqual({ sub: userId });

      const { rows } = await app().dbPool.query<{ audience: string[] | null }>(
        `SELECT audience FROM oauth_clients WHERE client_id = 'system'`
      );
      expect(rows).toEqual([{ audience: [API_FAMILY_AUDIENCES.developer] }]);
    });

    it('minted before #509 (the system client id as audience) still works on the legacy path', async () => {
      const { userId } = await signInPortal('portal-old@example.com');
      // The system client as #509 found it: no audience. The next read gives
      // it the developer audience; the old token keeps working until it expires.
      await app().dbPool.query(
        `UPDATE oauth_clients SET audience = NULL WHERE client_id = 'system'`
      );
      const legacy = await app().jwtUtils.signAccessToken({
        sub: userId,
        clientId: 'system',
        aud: 'system',
      });

      const clients = await call('/api/clients', legacy);
      expect(clients.statusCode).toBe(200);
      expect(clients.json()).toMatchObject({ clients: [] });
      expect((await call('/api/consents', legacy)).statusCode).toBe(200);
      expect((await call('/oauth/userinfo', legacy)).json()).toEqual({ sub: userId });
      // It was never a developer family token.
      expect((await call(probePath('developer'), legacy)).statusCode).toBe(401);

      const { rows } = await app().dbPool.query<{ audience: string[] | null }>(
        `SELECT audience FROM oauth_clients WHERE client_id = 'system'`
      );
      expect(rows).toEqual([{ audience: [API_FAMILY_AUDIENCES.developer] }]);
    });
  });

  describe('the RFC 6750 challenge', () => {
    it.each(API_FAMILIES)(
      'answers a bad token on the %s family with 401 invalid_token',
      async (family) => {
        for (const token of ['not-a-jwt', `${'e30'}.${'e30'}.`]) {
          const response = await call(probePath(family), token);
          expect(response.statusCode).toBe(401);
          expect(response.headers['content-type']).toMatch(/^application\/problem\+json/);
          expect(response.json()).toMatchObject({ status: 401, code: 'jwt_invalid' });
          expect(response.headers['www-authenticate']).toMatch(
            /^Bearer realm="OAuth", error="invalid_token", error_description="/
          );
        }
      }
    );

    it('answers a token without the scope a route needs with 403 insufficient_scope', async () => {
      await seedMachineClient(familyClientId('admin'), [API_FAMILY_AUDIENCES.admin]);
      const token = (await machineToken(familyClientId('admin'), API_FAMILY_AUDIENCES.admin)).json<{
        access_token: string;
      }>().access_token;

      const response = await call(probePath('admin', 'scoped'), token);
      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({ status: 403, code: 'insufficient_scope' });
      expect(response.headers['www-authenticate']).toBe(
        'Bearer realm="OAuth", error="insufficient_scope", scope="probe:write"'
      );
    });
  });
});
