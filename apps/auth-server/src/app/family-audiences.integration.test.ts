import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

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
  pkcePair,
  provisionRealmKeys,
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
 *   client_credentials and the authorization code grants; the gate itself
 *   refuses a self-registered client and a code whose client stopped listing
 *   it, and a user grant leaves a family audience out of its default.
 * - `POST /oauth/register` and a Client ID Metadata Document ignore a
 *   `urn:qauth:aud:` audience or resource, as they ignore a `qauth:` scope.
 * - The developer portal's token keeps the system client id as audience in
 *   this release, and a token with the developer audience is accepted where
 *   it is (expand, then contract: ADR-018 §5).
 * - The guard resolves the subject in the realm of the request host.
 * - A bad token gets the RFC 6750 challenge; a missing scope 403 `forbidden`
 *   with the `insufficient_scope` challenge.
 *
 * Only the network fetch of the metadata document is replaced (`egressGet`).
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const { egressGet } = vi.hoisted(() => ({ egressGet: vi.fn() }));
vi.mock('./helpers/egress-get', () => ({ egressGet }));

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
            {
              preHandler: requireFamilyToken(family, { subjects: ['user', 'client'] }),
              config: { surface: 'api' },
            },
            async (request) => ({ sub: request.jwtPayload?.sub })
          );
          scope.get(
            probePath(family, 'scoped'),
            {
              preHandler: requireFamilyToken(family, {
                subjects: ['user', 'client'],
                requiredScopes: ['probe:write'],
              }),
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
    egressGet.mockReset();
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
  async function seedMachineClient(
    clientId: string,
    audience: string[] | null,
    extra: { realmId?: string; enabled?: boolean; metadata?: Record<string, unknown> } = {}
  ): Promise<void> {
    await app().repositories.oauthClients.create({
      realmId: extra.realmId ?? (await realmId()),
      clientId,
      clientSecretHash: await app().passwordHasher.hashPassword(CLIENT_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: clientId,
      redirectUris: [],
      grantTypes: ['client_credentials'],
      scopes: [PROBE_SCOPE],
      audience,
      enabled: extra.enabled ?? true,
      ...(extra.metadata === undefined ? {} : { metadata: extra.metadata }),
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

  function call(path: string, token: string, host?: string): Promise<LightMyRequestResponse> {
    return app().inject({
      method: 'GET',
      url: path,
      headers: { authorization: `Bearer ${token}`, ...(host === undefined ? {} : { host }) },
    });
  }

  /** The `reason` of every `token.request_failed` event, in the order recorded. */
  async function tokenFailureReasons(): Promise<unknown[]> {
    const { rows } = await app().dbPool.query<{ data: Record<string, unknown> }>(
      `SELECT data FROM events WHERE type = 'urn:qauth:event:token.request_failed:v1-rc.0' ORDER BY seq`
    );
    return rows.map((row) => row.data['reason']);
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
        if (family === 'admin') {
          // A client_credentials token names no account, and only an account
          // with an admin grant gets the admin audience (#510): the guard is
          // tested here with a token signed directly.
          expect(response.statusCode).toBe(400);
          tokens[family] = await app().jwtUtils.signAccessToken(
            { id: await realmId() },
            {
              sub: familyClientId(family),
              clientId: familyClientId(family),
              aud: API_FAMILY_AUDIENCES[family],
            }
          );
          continue;
        }
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
    it("is refused by a client_credentials client's audience allowlist when it does not list it", async () => {
      await seedMachineClient('plain-machine', ['https://api.example.com']);
      for (const family of API_FAMILIES) {
        const response = await machineToken('plain-machine', API_FAMILY_AUDIENCES[family]);
        expect(response.statusCode).toBe(400);
        expect(response.json()).toMatchObject({ error: 'invalid_target' });
      }
      // The grant's own allowlist refuses first; the reserved-audience gate
      // is not what answered.
      expect(await tokenFailureReasons()).toEqual(
        API_FAMILIES.map(() => 'resource_outside_client_audience')
      );
    });

    it('reaches the reserved-audience gate for a self-registered client whose row lists it', async () => {
      // Written another way than dynamic registration, which stores no audience:
      // the allowlist lets the resource through, and the gate refuses it.
      await seedMachineClient('self-registered', [API_FAMILY_AUDIENCES.admin], {
        metadata: { registrationType: 'dynamic' },
      });
      const response = await machineToken('self-registered', API_FAMILY_AUDIENCES.admin);
      expect(response.statusCode).toBe(400);
      expect(response.json()).toMatchObject({ error: 'invalid_target' });
      expect(await tokenFailureReasons()).toEqual(['reserved_audience_not_listed']);
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
          realm,
          userId,
          client.id,
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

    it('refuses a code at the gate, unspent, once the client no longer lists it; a code without resource leaves it out', async () => {
      const email = 'family-gate@example.com';
      const userId = await registerPasswordAccount(app(), email);
      const jar = await signInWithPassword(app(), email);
      const realm = await realmId();
      const account = API_FAMILY_AUDIENCES.account;
      const client = await app().repositories.oauthClients.create({
        realmId: realm,
        clientId: 'account-console',
        clientSecretHash: 'unused-public-client',
        tokenEndpointAuthMethod: 'none',
        name: 'account-console',
        redirectUris: [REDIRECT_URI],
        scopes: ['openid'],
        grantTypes: ['authorization_code'],
        audience: [account],
        enabled: true,
        requirePkce: true,
        provisionedByOperator: true,
      });
      await app().repositories.oauthConsents.upsertGrant(
        realm,
        userId,
        client.id,
        ['openid'],
        [account]
      );
      const codeFor = async (resource: string | undefined, challenge: string) => {
        const response = await app().inject({
          method: 'GET',
          url: `/oauth/authorize?${new URLSearchParams({
            response_type: 'code',
            client_id: 'account-console',
            redirect_uri: REDIRECT_URI,
            scope: 'openid',
            ...(resource === undefined ? {} : { resource }),
            code_challenge: challenge,
            code_challenge_method: 'S256',
            state: 'family-state',
          })}`,
          headers: { cookie: jar.header() as string },
        });
        expect(response.statusCode).toBe(302);
        const code = new URL(response.headers['location'] as string).searchParams.get('code');
        expect(code).not.toBeNull();
        return code as string;
      };
      const redeem = (code: string, verifier: string) =>
        tokenRequest({
          grant_type: 'authorization_code',
          code,
          redirect_uri: REDIRECT_URI,
          client_id: 'account-console',
          code_verifier: verifier,
        });
      const setAudience = (audience: string[] | null) =>
        app().dbPool.query(`UPDATE oauth_clients SET audience = $1 WHERE id = $2`, [
          audience === null ? null : JSON.stringify(audience),
          client.id,
        ]);

      // The operator takes the family audience off the client between the
      // authorization and the redemption: the token endpoint's gate refuses.
      const bound = pkcePair();
      const code = await codeFor(account, bound.challenge);
      await setAudience(['https://api.example.com']);
      const refused = await redeem(code, bound.verifier);
      expect(refused.statusCode).toBe(400);
      expect(refused.json()).toMatchObject({ error: 'invalid_target' });
      expect(await tokenFailureReasons()).toEqual(['reserved_audience_not_listed']);

      // Not spent: listed again, the same code redeems.
      await setAudience([account]);
      const redeemed = await redeem(code, bound.verifier);
      expect(redeemed.statusCode).toBe(200);
      expect(decodeJwtClaims(redeemed.json<{ access_token: string }>().access_token)).toMatchObject(
        { aud: account }
      );

      // A code that binds no resource: the family audience is left out of the
      // client's default, so the token's `aud` is the client id.
      const unbound = pkcePair();
      const plain = await redeem(await codeFor(undefined, unbound.challenge), unbound.verifier);
      expect(plain.statusCode).toBe(200);
      expect(decodeJwtClaims(plain.json<{ access_token: string }>().access_token)['aud']).toBe(
        'account-console'
      );
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

    // One rule for QAuth's reserved namespaces (ADR-019, amended 2026-10-26):
    // registration drops a `qauth:` scope and ignores a `urn:qauth:aud:`
    // audience or resource, and registers the client with the rest.
    it.each([
      { audience: API_FAMILY_AUDIENCES.developer },
      { audience: ['https://api.example.com', API_FAMILY_AUDIENCES.admin] },
      { resource: API_FAMILY_AUDIENCES.account },
      { resource: ['URN:QAUTH:AUD:developer:v1-rc.0'] },
    ])('POST /oauth/register ignores %j and registers the client', async (metadata) => {
      const response = await register(metadata);
      expect(response.statusCode).toBe(201);
      expect(response.json()).not.toHaveProperty('audience');
      const clientId = response.json<{ client_id: string }>().client_id;
      const { rows } = await app().dbPool.query<{ audience: unknown }>(
        'SELECT audience FROM oauth_clients WHERE client_id = $1',
        [clientId]
      );
      expect(rows).toEqual([{ audience: null }]);
    });

    it('POST /oauth/register still ignores an ordinary audience', async () => {
      const response = await register({ audience: 'https://api.example.com' });
      expect(response.statusCode).toBe(201);
      expect(response.json()).not.toHaveProperty('audience');
    });

    function serveDocument(extra: Record<string, unknown>) {
      egressGet.mockImplementation(async (_fastify: unknown, url: string) => {
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
      'a Client ID Metadata Document naming %j resolves, and the value is ignored',
      async (extra) => {
        serveDocument(extra);
        const response = await authorizeCimd();
        expect(response.statusCode).not.toBe(400);
        expect(egressGet).toHaveBeenCalledTimes(1);
        const { rows } = await app().dbPool.query<{ audience: unknown }>(
          'SELECT audience FROM oauth_clients WHERE client_id = $1',
          [CIMD_CLIENT_ID]
        );
        expect(rows).toEqual([{ audience: null }]);
      }
    );
  });

  describe("the developer portal's token", () => {
    async function signInPortal(email: string): Promise<{ userId: string; token: string }> {
      const userId = await registerPasswordAccount(app(), email);
      const response = await app().inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email, password: E2E_PASSWORD },
      });
      expect(response.statusCode).toBe(200);
      return { userId, token: response.json<{ access_token: string }>().access_token };
    }

    async function systemClientAudience(): Promise<unknown> {
      const { rows } = await app().dbPool.query<{ audience: unknown }>(
        `SELECT audience FROM oauth_clients WHERE client_id = 'system'`
      );
      return rows.map((row) => row.audience);
    }

    // Expand, then contract (ADR-018 §5): this release does not mint the
    // developer audience, so a node of the previous release accepts every
    // portal token this one mints.
    it('keeps the system client id as audience, and leaves the system client row alone', async () => {
      const { userId, token } = await signInPortal('portal-now@example.com');
      expect(decodeJwtClaims(token)).toMatchObject({
        aud: 'system',
        client_id: 'system',
        sub: userId,
      });

      expect((await call('/api/clients', token)).statusCode).toBe(200);
      expect((await call('/oauth/userinfo', token)).json()).toEqual({ sub: userId });
      // It is not a developer family token.
      expect((await call(probePath('developer'), token)).statusCode).toBe(401);
      expect(await systemClientAudience()).toEqual([null]);
    });

    it('with the developer audience, is accepted wherever the legacy one is', async () => {
      const { userId } = await signInPortal('portal-next@example.com');
      // What #524's release mints: the system client, the developer audience.
      const next = await app().jwtUtils.signAccessToken(
        { id: await realmId() },
        {
          sub: userId,
          clientId: 'system',
          aud: API_FAMILY_AUDIENCES.developer,
        }
      );

      const clients = await call('/api/clients', next);
      expect(clients.statusCode).toBe(200);
      expect(clients.json()).toMatchObject({ clients: [] });
      expect((await call('/api/consents', next)).statusCode).toBe(200);
      expect((await call('/oauth/userinfo', next)).json()).toEqual({ sub: userId });
      expect((await call(probePath('developer'), next)).statusCode).toBe(200);
      expect((await call(probePath('account'), next)).statusCode).toBe(401);

      // A sign-out through it ends the session.
      const logout = await app().inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { authorization: `Bearer ${next}` },
      });
      expect(logout.statusCode).toBe(200);
      expect(logout.json()).toMatchObject({ success: true });
      expect(await systemClientAudience()).toEqual([null]);
    });
  });

  // ADR-019 Decision 1: a token from another realm is refused. Family
  // audiences and the issuer read the same in every realm, so the guard
  // resolves the subject in the realm of the request host.
  describe("the subject, in the request host's realm", () => {
    const HOST_B = 'beta.example.com';

    async function realmB(): Promise<string> {
      const { realm } = await app().repositories.realms.createWithPrimaryHost(
        { name: 'beta', issuer: `https://${HOST_B}`, enabled: true },
        HOST_B
      );
      return realm.id;
    }

    it("refuses a realm-A user's family token at realm B", async () => {
      await realmB();
      const userId = await registerPasswordAccount(app(), 'realm-a-dev@example.com');
      const token = await app().jwtUtils.signAccessToken(
        { id: await realmId() },
        {
          sub: userId,
          clientId: 'system',
          aud: API_FAMILY_AUDIENCES.developer,
        }
      );

      expect((await call(probePath('developer'), token)).statusCode).toBe(200);
      const atB = await call(probePath('developer'), token, HOST_B);
      expect(atB.statusCode).toBe(401);
      expect(atB.json()).toMatchObject({ code: 'invalid_access_token' });
    });

    it('resolves a client_credentials token as the client of that realm, by the same client_id', async () => {
      const b = await realmB();
      const developer = API_FAMILY_AUDIENCES.developer;
      // `twin` in both realms: enabled in A, disabled in B.
      await seedMachineClient('twin', [developer]);
      await seedMachineClient('twin', [developer], { realmId: b, enabled: false });
      const token = (await machineToken('twin', developer)).json<{ access_token: string }>()
        .access_token;

      expect((await call(probePath('developer'), token)).statusCode).toBe(200);
      const atB = await call(probePath('developer'), token, HOST_B);
      expect(atB.statusCode).toBe(401);
      expect(atB.json()).toMatchObject({ code: 'invalid_access_token' });
    });

    // #491: each realm signs with its own keys and names its own issuer, so a
    // `client_id` that both realms enable no longer lets a token of one realm
    // through at the other: the guard refuses it before it resolves a subject.
    it('refuses a token of a client_id that both realms enable at the realm that did not mint it', async () => {
      const b = await realmB();
      await provisionRealmKeys(app(), 'beta');
      // The developer family: since #510 a client_credentials token never gets
      // the admin audience, which names an account's admin grants.
      const developer = API_FAMILY_AUDIENCES.developer;
      await seedMachineClient('twin', [developer]);
      await seedMachineClient('twin', [developer], { realmId: b });

      const tokenOfA = (await machineToken('twin', developer)).json<{ access_token: string }>()
        .access_token;
      const tokenOfB = (
        await app().inject({
          method: 'POST',
          url: '/oauth/token',
          headers: { 'content-type': 'application/x-www-form-urlencoded', host: HOST_B },
          payload: new URLSearchParams({
            grant_type: 'client_credentials',
            client_id: 'twin',
            client_secret: CLIENT_SECRET,
            scope: PROBE_SCOPE,
            resource: developer,
          }).toString(),
        })
      ).json<{ access_token: string }>().access_token;
      expect(decodeJwtClaims(tokenOfA)['iss']).toBe('https://auth.example.com');
      expect(decodeJwtClaims(tokenOfB)['iss']).toBe(`https://${HOST_B}`);

      // Each token works in its own realm...
      expect((await call(probePath('developer'), tokenOfA)).statusCode).toBe(200);
      expect((await call(probePath('developer'), tokenOfB, HOST_B)).statusCode).toBe(200);
      // ...and is refused in the other, though `twin` is an active client there.
      for (const [token, host] of [
        [tokenOfA, HOST_B],
        [tokenOfB, undefined],
      ] as const) {
        const refused = await call(probePath('developer'), token, host);
        expect(refused.statusCode).toBe(401);
        expect(refused.json()).toMatchObject({ code: 'invalid_access_token' });
      }
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
          expect(response.json()).toMatchObject({ status: 401, code: 'invalid_access_token' });
          expect(response.headers['www-authenticate']).toMatch(
            /^Bearer realm="OAuth", error="invalid_token", error_description="/
          );
        }
      }
    );

    it.each(API_FAMILIES)(
      'answers a request with no token on the %s family with 401 unauthorized and a bare challenge',
      async (family) => {
        const response = await app().inject({ method: 'GET', url: probePath(family) });
        expect(response.statusCode).toBe(401);
        expect(response.headers['content-type']).toMatch(/^application\/problem\+json/);
        expect(response.json()).toMatchObject({ status: 401, code: 'unauthorized' });
        expect(response.headers['www-authenticate']).toBe('Bearer realm="OAuth"');
      }
    );

    it('answers a token without the scope a route needs with 403 forbidden and the insufficient_scope challenge', async () => {
      await seedMachineClient(familyClientId('developer'), [API_FAMILY_AUDIENCES.developer]);
      const token = (
        await machineToken(familyClientId('developer'), API_FAMILY_AUDIENCES.developer)
      ).json<{
        access_token: string;
      }>().access_token;

      const response = await call(probePath('developer', 'scoped'), token);
      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({ status: 403, code: 'forbidden' });
      expect(response.headers['www-authenticate']).toBe(
        'Bearer realm="OAuth", error="insufficient_scope", scope="probe:write"'
      );
    });
  });
});
