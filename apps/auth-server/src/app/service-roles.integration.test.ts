import { randomUUID } from 'node:crypto';

import type { DeliveryRoute } from '@qauth-labs/fastify-plugin-event-delivery';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, RouteOptions } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { SERVICE_ROLE_NAMES } from './service-roles';

/**
 * SERVICE ROLES AGAINST A REAL POSTGRES AND REDIS (ADR-019 Decisions 8 and 9,
 * issue #495).
 *
 * Each test boots the real auth-server under one `SERVICE_ROLES` value and
 * reads what it registered and answers: the route set of each role, `/health`
 * on every role, the refusal of key material and of a missing signer address
 * on a process without the signer, and the repositories a role leaves
 * unbuilt.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

/**
 * The routes a default deployment registered before the route manifest
 * replaced the folder autoload (`HEAD` beside each `GET` is Fastify's own).
 */
const DEFAULT_ROUTES_BEFORE_THE_MANIFEST: readonly string[] = [
  'DELETE /api/clients/:clientId/api-keys/:keyId',
  'DELETE /api/clients/:id',
  'DELETE /api/consents/:id',
  'DELETE /consents/:id',
  'GET /',
  'GET /.well-known/jwks.json',
  'GET /.well-known/oauth-authorization-server',
  'GET /.well-known/openid-configuration',
  'GET /api/clients',
  'GET /api/clients/:clientId/api-keys',
  'GET /api/clients/:id',
  'GET /api/consents',
  'GET /consents',
  'GET /health',
  'GET /metrics',
  'GET /oauth/authorize',
  'GET /oauth/userinfo',
  'GET /ui/consent',
  'GET /ui/login',
  'GET /ui/resume/:handle',
  'OPTIONS *',
  'PATCH /api/clients/:id',
  'POST /api/clients',
  'POST /api/clients/:clientId/api-keys',
  'POST /api/clients/:id/regenerate-secret',
  'POST /auth/login',
  'POST /auth/logout',
  'POST /auth/register',
  'POST /auth/resend-verification',
  'POST /auth/verify',
  'POST /oauth/authorize',
  'POST /oauth/introspect',
  'POST /oauth/register',
  'POST /oauth/revoke',
  'POST /oauth/token',
  'POST /oauth/userinfo',
  'POST /ui/consent',
  'POST /ui/login',
];

const MACHINE_CLIENT_ID = 'roles-machine-client';
const MACHINE_SECRET = 'roles-machine-secret-of-at-least-32-characters';
const MACHINE_SCOPE = 'reports:read';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' } as const;

/** The signer service settings of a process without the signer; never dialled here. */
const SIGNER_SERVICE: Record<string, string> = {
  SIGNER_URL: 'https://signer.internal:3443',
  INTERNAL_TLS_CERT_PATH: '/run/secrets/internal.crt',
  INTERNAL_TLS_KEY_PATH: '/run/secrets/internal.key',
  INTERNAL_TLS_CA_PATH: '/run/secrets/internal-ca.crt',
};

/** `METHOD /url` for each method of each route. */
function operations(routes: readonly RouteOptions[]): Set<string> {
  return new Set(
    routes.flatMap((route) => [route.method].flat().map((method) => `${method} ${route.url}`))
  );
}

describe('service roles (#495)', () => {
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

  /**
   * The environment of a process with `serviceRoles`: the test deployment's,
   * and for a process without the signer, no KEK and no private key but the
   * signer service settings and the public key.
   */
  function environmentFor(serviceRoles: string): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const base = baseEnvironment(infra, jwt);
    if (serviceRoles === 'all' || serviceRoles.split(',').includes('signer')) {
      return { ...base, SERVICE_ROLES: serviceRoles };
    }
    const { KEK: _kek, JWT_PRIVATE_KEY: _privateKey, ...withoutKeys } = base;
    return { ...withoutKeys, ...SIGNER_SERVICE, SERVICE_ROLES: serviceRoles };
  }

  /** Boot under `serviceRoles`, collecting the routes the app registers. */
  async function boot(
    serviceRoles: string,
    extra: Record<string, string> = {},
    eventDeliveryRoutes?: readonly DeliveryRoute[]
  ): Promise<{ app: FastifyInstance; routes: RouteOptions[] }> {
    const routes: RouteOptions[] = [];
    const server = await bootAuthServer(
      { ...environmentFor(serviceRoles), ...extra },
      {
        onRoute: (route) => void routes.push(route),
        ...(eventDeliveryRoutes === undefined ? {} : { eventDeliveryRoutes }),
      }
    );
    booted.push(server);
    return { app: server.app, routes };
  }

  it("registers today's route set in a single process (SERVICE_ROLES=all)", async () => {
    const { routes } = await boot('all');
    const expected = new Set([
      ...DEFAULT_ROUTES_BEFORE_THE_MANIFEST,
      ...DEFAULT_ROUTES_BEFORE_THE_MANIFEST.filter((operation) => operation.startsWith('GET ')).map(
        (operation) => `HEAD ${operation.slice('GET '.length)}`
      ),
    ]);
    expect(operations(routes)).toEqual(expected);
    for (const route of routes) {
      expect(route.config?.serviceRoles, `${String(route.method)} ${route.url}`).toBeDefined();
    }
  });

  it('registers /oauth/token and not /oauth/authorize with SERVICE_ROLES=api', async () => {
    const { app } = await boot('api');
    expect(app.hasRoute({ method: 'POST', url: '/oauth/token' })).toBe(true);
    expect(app.hasRoute({ method: 'GET', url: '/oauth/authorize' })).toBe(false);
    expect(app.hasRoute({ method: 'GET', url: '/ui/login' })).toBe(false);

    // The browser endpoint answers as a path no route serves.
    const authorize = await app.inject({ method: 'GET', url: '/oauth/authorize' });
    const missing = await app.inject({ method: 'GET', url: '/no-such-route' });
    expect(authorize.statusCode).toBe(404);
    expect(authorize.json()).toMatchObject({ code: missing.json<{ code: string }>().code });
  });

  it('registers /oauth/authorize and not /oauth/token with SERVICE_ROLES=web', async () => {
    const { app } = await boot('web');
    expect(app.hasRoute({ method: 'POST', url: '/oauth/token' })).toBe(false);
    expect(app.hasRoute({ method: 'GET', url: '/oauth/authorize' })).toBe(true);

    const token = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: 'grant_type=client_credentials',
    });
    expect(token.statusCode).toBe(404);
  });

  it.each(['all', ...SERVICE_ROLE_NAMES])(
    'answers /health with SERVICE_ROLES=%s',
    async (serviceRoles) => {
      const { app } = await boot(serviceRoles);
      const health = await app.inject({ method: 'GET', url: '/health' });
      expect(health.statusCode).toBe(200);
      expect(health.json()).toMatchObject({
        status: 'ok',
        services: { database: 'connected', redis: 'connected' },
      });
    }
  );

  it('refuses to boot SERVICE_ROLES=api with KEK set, naming KEK', async () => {
    await expect(boot('api', { KEK: Buffer.alloc(32, 0xe2).toString('base64') })).rejects.toThrow(
      /KEK is set, but SERVICE_ROLES=api does not hold the signer role/
    );
  });

  it('refuses to boot SERVICE_ROLES=api with a JWT private key, naming it', async () => {
    if (!jwt) throw new Error('infrastructure not started');
    await expect(boot('api', { JWT_PRIVATE_KEY: jwt.privateKey })).rejects.toThrow(
      /JWT_PRIVATE_KEY is set, but SERVICE_ROLES=api/
    );
  });

  it('refuses to boot SERVICE_ROLES=api without SIGNER_URL', async () => {
    const environment = environmentFor('api');
    delete environment['SIGNER_URL'];
    await expect(bootAuthServer(environment)).rejects.toThrow(/SIGNER_URL is required/);
  });

  it('answers token issuance on a process without the signer with 503, failing closed', async () => {
    const { app } = await boot('api');
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('the default realm was not booted');
    await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: MACHINE_CLIENT_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(MACHINE_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Roles machine client',
      redirectUris: [],
      scopes: [MACHINE_SCOPE],
      grantTypes: ['client_credentials'],
      enabled: true,
    });

    const token = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: MACHINE_SCOPE,
        client_id: MACHINE_CLIENT_ID,
        client_secret: MACHINE_SECRET,
      }).toString(),
    });
    expect(token.json()).toMatchObject({ error: 'temporarily_unavailable' });
    expect(token.statusCode).toBe(503);

    // Verification and the JWKS read public material only, and still answer.
    const jwks = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    expect(jwks.statusCode).toBe(200);
    expect(jwks.json<{ keys: unknown[] }>().keys.length).toBeGreaterThan(0);
  });

  it('holds a delivery a process without the signer cannot sign, spending no attempt', async () => {
    // A route that signs a Security Event Token, as the SSF route does.
    const realm: { id?: string } = {};
    let calls = 0;
    const signing: DeliveryRoute = {
      kind: 'test',
      destinations: async () =>
        realm.id === undefined ? [] : [{ id: 'receiver', realmId: realm.id }],
      async deliver(delivery, _event, { signer }) {
        calls += 1;
        await signer.signEventToken({
          realmId: delivery.realmId,
          typ: 'secevent+jwt',
          claims: { jti: delivery.eventId },
        });
        return { ok: true, statusCode: 202 };
      },
    };
    const { app } = await boot('delivery', {}, [signing]);
    const found = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!found) throw new Error('the default realm was not booted');
    realm.id = found.id;
    await vi.waitFor(
      async () => {
        const { rows } = await app.dbPool.query(
          'SELECT 1 FROM event_delivery_positions WHERE realm_id = $1',
          [found.id]
        );
        expect(rows).toHaveLength(1);
      },
      { timeout: 10_000, interval: 50 }
    );

    await app.repositories.events.emitInOwnTransaction({
      type: 'urn:qauth:event:user.signed_in:v1-rc.0',
      realm: found.id,
      actor: { type: 'user', id: randomUUID() },
      data: { method: 'password' },
    });
    await vi.waitFor(() => expect(calls).toBeGreaterThan(0), { timeout: 15_000, interval: 100 });

    // Once the attempt is recorded, the lease is gone: a held delivery
    // spent no attempt and records no error, where a failed one would.
    await vi.waitFor(
      async () => {
        const { rows } = await app.dbPool.query<{
          status: string;
          attempt_count: number;
          last_error_class: string | null;
          locked_until: string | null;
        }>(
          `SELECT status, attempt_count, last_error_class, locked_until
             FROM event_deliveries WHERE realm_id = $1`,
          [found.id]
        );
        expect(rows).toEqual([
          { status: 'pending', attempt_count: 0, last_error_class: null, locked_until: null },
        ]);
      },
      { timeout: 15_000, interval: 100 }
    );
  });

  it('leaves the repositories a role does not use unbuilt', async () => {
    const { app } = await boot('delivery');
    expect(() => app.repositories.users).toThrow(/The users repository is not loaded/);
    expect(() => app.repositories.oauthClients).toThrow(/not loaded/);
    await expect(app.repositories.realms.findByName(E2E_REALM_NAME)).resolves.toBeDefined();
  });
});
