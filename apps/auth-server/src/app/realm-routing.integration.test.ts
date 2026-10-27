import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
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
  provisionRealmKeys,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import type { RealmRow } from './helpers/request-realm';

/**
 * HANDLERS TAKE THE REALM OF THE REQUEST HOST, AGAINST A REAL POSTGRES AND
 * REDIS (ADR-019 Decision 1, issue #487).
 *
 * Each test boots the real auth-server (whose boot step creates the default
 * realm `master` on `auth.example.com`, from `JWT_ISSUER`), empties its state,
 * and adds a second realm, `beta`, on its own host. Requests name their host;
 * nothing in a handler falls back to the default realm by name any more.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const HOST_A = 'auth.example.com';
const HOST_B = 'beta.example.com';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

interface TwoRealms {
  readonly app: FastifyInstance;
  readonly realmA: RealmRow;
  readonly realmB: RealmRow;
}

describe('handlers take the realm of the request host (#487)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];

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

  afterEach(async () => {
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
  });

  /** Boot the server on an empty state, with the default realm on HOST_A and `beta` on HOST_B. */
  async function boot(environment: Record<string, string> = {}): Promise<TwoRealms> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const server = await bootAuthServer({ ...baseEnvironment(infra, jwt), ...environment });
    booted.push(server);
    const { app } = server;
    await resetE2eState(app);

    const realmA = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realmA) throw new Error('the default realm boot step left no realm');
    const { realm: realmB } = await app.repositories.realms.createWithPrimaryHost(
      { name: 'beta', issuer: `https://${HOST_B}`, enabled: true },
      HOST_B
    );
    // Its own keys: the realm's tokens are signed with them (#491).
    await provisionRealmKeys(app, 'beta');
    return { app, realmA, realmB };
  }

  /** Seed a confidential `client_credentials` client whose tokens carry `audience`. */
  async function seedMachineClient(
    app: FastifyInstance,
    realm: RealmRow,
    client: { clientId: string; secret: string; audience: string }
  ): Promise<void> {
    await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: client.clientId,
      clientSecretHash: await app.passwordHasher.hashPassword(client.secret),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: `E2E ${client.clientId}`,
      redirectUris: [],
      scopes: ['reports:read'],
      grantTypes: ['client_credentials'],
      audience: [client.audience],
      enabled: true,
      requirePkce: false,
    });
  }

  async function clientCredentials(
    app: FastifyInstance,
    host: string,
    clientId: string,
    secret: string
  ) {
    return app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { ...FORM, host },
      payload: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: secret,
        scope: 'reports:read',
      }).toString(),
    });
  }

  async function passwordLogin(
    app: FastifyInstance,
    host: string,
    email: string,
    password: string
  ) {
    return app.inject({
      method: 'POST',
      url: '/auth/login',
      headers: { host },
      payload: { email, password },
    });
  }

  async function managementToken(app: FastifyInstance, host: string, email: string) {
    const login = await passwordLogin(app, host, email, E2E_PASSWORD);
    expect(login.statusCode, login.body).toBe(200);
    return login.json<{ access_token: string }>().access_token;
  }

  async function listClients(app: FastifyInstance, host: string, token: string) {
    return app.inject({
      method: 'GET',
      url: '/api/clients',
      headers: { host, authorization: `Bearer ${token}` },
    });
  }

  async function passwordCredential(app: FastifyInstance, realm: RealmRow, email: string) {
    return app.repositories.userCredentials.findByRealmProviderSub(realm.id, 'password', email);
  }

  describe('/oauth/token', () => {
    it('finds only the clients of the host’s realm, and the same client_id text resolves to each realm’s own client', async () => {
      const { app, realmA, realmB } = await boot();
      await seedMachineClient(app, realmA, {
        clientId: 'shared-client',
        secret: 'secret-of-the-realm-a-client-0123456789',
        audience: 'https://api.realm-a.example.com',
      });
      await seedMachineClient(app, realmB, {
        clientId: 'shared-client',
        secret: 'secret-of-the-realm-b-client-0123456789',
        audience: 'https://api.realm-b.example.com',
      });
      await seedMachineClient(app, realmA, {
        clientId: 'only-in-a',
        secret: 'secret-of-the-only-in-a-client-01234567',
        audience: 'https://api.realm-a.example.com',
      });

      const onB = await clientCredentials(
        app,
        HOST_B,
        'shared-client',
        'secret-of-the-realm-b-client-0123456789'
      );
      const onA = await clientCredentials(
        app,
        HOST_A,
        'shared-client',
        'secret-of-the-realm-a-client-0123456789'
      );

      expect(onB.statusCode, onB.body).toBe(200);
      expect(decodeJwtClaims(onB.json<{ access_token: string }>().access_token)).toMatchObject({
        sub: 'shared-client',
        aud: 'https://api.realm-b.example.com',
      });
      expect(onA.statusCode, onA.body).toBe(200);
      expect(decodeJwtClaims(onA.json<{ access_token: string }>().access_token)).toMatchObject({
        sub: 'shared-client',
        aud: 'https://api.realm-a.example.com',
      });

      // Realm A's secret is no secret of realm B's client of the same name.
      const crossed = await clientCredentials(
        app,
        HOST_B,
        'shared-client',
        'secret-of-the-realm-a-client-0123456789'
      );
      expect(crossed.statusCode).toBe(401);
      expect(crossed.json()).toMatchObject({ error: 'invalid_client' });

      // A client of realm A does not exist on realm B's host.
      const elsewhere = await clientCredentials(
        app,
        HOST_B,
        'only-in-a',
        'secret-of-the-only-in-a-client-01234567'
      );
      expect(elsewhere.statusCode).toBe(401);
      expect(elsewhere.json()).toMatchObject({ error: 'invalid_client' });
    });
  });

  describe('/auth/register', () => {
    it('creates the user in the realm of the host', async () => {
      const { app, realmA, realmB } = await boot();

      const response = await app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { host: HOST_B },
        payload: { email: 'new@example.com', password: E2E_PASSWORD },
      });

      expect(response.statusCode, response.body).toBe(202);
      const credential = await passwordCredential(app, realmB, 'new@example.com');
      expect(credential).toBeDefined();
      expect(
        await app.repositories.users.findById(realmB.id, credential?.userId ?? '')
      ).toMatchObject({
        realmId: realmB.id,
      });
      expect(await passwordCredential(app, realmA, 'new@example.com')).toBeUndefined();
    });

    it('refuses a body realmId that names another realm than the host’s', async () => {
      const { app, realmA, realmB } = await boot();

      const other = await app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { host: HOST_B },
        payload: { email: 'new@example.com', password: E2E_PASSWORD, realmId: realmA.id },
      });
      const same = await app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { host: HOST_B },
        payload: { email: 'same@example.com', password: E2E_PASSWORD, realmId: realmB.id },
      });

      expect(other.statusCode).toBe(400);
      expect(await passwordCredential(app, realmA, 'new@example.com')).toBeUndefined();
      expect(await passwordCredential(app, realmB, 'new@example.com')).toBeUndefined();
      expect(same.statusCode, same.body).toBe(202);
      expect(await passwordCredential(app, realmB, 'same@example.com')).toBeDefined();
    });
  });

  describe('the management API', () => {
    it('refuses a management token from realm A at realm B, and the other way round', async () => {
      const { app } = await boot();
      await registerPasswordAccount(app, 'dev-a@example.com');
      await registerPasswordAccount(app, 'dev-b@example.com', E2E_PASSWORD, { host: HOST_B });
      const tokenA = await managementToken(app, HOST_A, 'dev-a@example.com');
      const tokenB = await managementToken(app, HOST_B, 'dev-b@example.com');

      expect((await listClients(app, HOST_A, tokenA)).statusCode).toBe(200);
      expect((await listClients(app, HOST_B, tokenB)).statusCode).toBe(200);

      const aAtB = await listClients(app, HOST_B, tokenA);
      const bAtA = await listClients(app, HOST_A, tokenB);
      expect(aAtB.statusCode).toBe(401);
      expect(bAtA.statusCode).toBe(401);
    });

    it('does not let a realm A token sign a user out at realm B', async () => {
      const { app } = await boot();
      await registerPasswordAccount(app, 'dev-a@example.com');
      const tokenA = await managementToken(app, HOST_A, 'dev-a@example.com');

      const logout = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { host: HOST_B, authorization: `Bearer ${tokenA}` },
      });

      expect(logout.statusCode).toBe(401);
      // The token is still good where it was issued.
      expect((await listClients(app, HOST_A, tokenA)).statusCode).toBe(200);
    });
  });

  describe('per-realm keys', () => {
    it('keeps the login lockout of an address apart in two realms, for the same address and source', async () => {
      const { app, realmA, realmB } = await boot({ FAILED_LOGIN_MAX_ATTEMPTS: '2' });
      // The same address has an account in each realm.
      await registerPasswordAccount(app, 'shared@example.com');
      await registerPasswordAccount(app, 'shared@example.com', E2E_PASSWORD, { host: HOST_B });

      // Two wrong passwords on realm A reach the threshold; the third attempt is locked out.
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const wrong = await passwordLogin(app, HOST_A, 'shared@example.com', 'Wrong-Password-42!');
        expect(wrong.statusCode).toBe(401);
      }
      const locked = await passwordLogin(app, HOST_A, 'shared@example.com', E2E_PASSWORD);
      expect(locked.statusCode).toBe(429);

      // Realm B's account of the same address, from the same source, is not.
      const onB = await passwordLogin(app, HOST_B, 'shared@example.com', E2E_PASSWORD);
      expect(onB.statusCode, onB.body).toBe(200);

      const keys = await app.redis.keys('failed-login:*');
      expect(keys.some((key) => key.startsWith(`failed-login:lockout:${realmA.id}:email:`))).toBe(
        true
      );
      expect(keys.some((key) => key.startsWith(`failed-login:lockout:${realmA.id}:ip:`))).toBe(
        true
      );
      expect(keys.some((key) => key.startsWith(`failed-login:lockout:${realmB.id}:`))).toBe(false);
    });

    it('gives the same source address a rate-limit bucket in each realm', async () => {
      const { app, realmA, realmB } = await boot({ INTROSPECT_RATE_LIMIT: '2' });
      const introspect = async (host: string) =>
        app.inject({
          method: 'POST',
          url: '/oauth/introspect',
          headers: { ...FORM, host },
          remoteAddress: '203.0.113.7',
          payload: new URLSearchParams({ token: 'not-a-token' }).toString(),
        });

      expect((await introspect(HOST_A)).statusCode).not.toBe(429);
      expect((await introspect(HOST_A)).statusCode).not.toBe(429);
      expect((await introspect(HOST_A)).statusCode).toBe(429);
      // Realm B's bucket for the same address is untouched.
      expect((await introspect(HOST_B)).statusCode).not.toBe(429);

      const keys = await app.redis.keys('*/oauth/introspect*');
      expect(keys.sort()).toEqual(
        [
          expect.stringContaining(`${realmA.id}:203.0.113.7`),
          expect.stringContaining(`${realmB.id}:203.0.113.7`),
        ].sort()
      );
    });
  });
});
