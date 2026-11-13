/**
 * EVERY ROUTE OF THE ASSEMBLED APP HAS ITS SERVICE ROLES (#495).
 *
 * Boots the app once per role, as `route-surfaces.test.ts` boots it: every
 * switch that registers a route on (the maximal surface of
 * `openapi-export.ts`), no database or Redis, no request sent. Each boot
 * collects the routes as they register and reads their `config.serviceRoles`
 * once every `onRoute` hook ran.
 *
 * - With `all`, the default, the route set is exactly the one the folder
 *   autoload registered before the manifest replaced it (pinned below), and
 *   the listing of every route with its roles fails for a route that has none.
 * - Each other role registers exactly its share: `web` the `browser` routes,
 *   `api` the `api` and `meta` routes, and every role `/health` and
 *   `/ready`. @fastify/cors's `OPTIONS *` belongs to the two with routes,
 *   `web` and `api`: a process of neither registers no CORS (#498). No role
 *   serves `/metrics` here: it is on the internal listener (#500).
 * - A route under `/admin` refuses the boot, a plugin's as well as a route
 *   module's (#511): it registers only on the admin listener.
 */
import { generateKeyPairSync } from 'node:crypto';

import Fastify, { type FastifyInstance, type FastifyPluginAsync, type RouteOptions } from 'fastify';
import fp from 'fastify-plugin';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { routeRolesProblem, SERVICE_ROLE_NAMES, type ServiceRole } from './service-roles';

/**
 * The routes the app registered with every route-registering switch on, as
 * the folder autoload registered them before #495 (`HEAD` beside each `GET`
 * is Fastify's own, added below).
 */
const ROUTES_BEFORE_THE_MANIFEST: readonly string[] = [
  'DELETE /api/clients/:clientId/api-keys/:keyId',
  'DELETE /api/clients/:id',
  'DELETE /api/consents/:id',
  'DELETE /consents/:id',
  'DELETE /ssf/stream',
  'GET /',
  'GET /.well-known/apple-app-site-association',
  'GET /.well-known/assetlinks.json',
  'GET /.well-known/jwks.json',
  'GET /.well-known/oauth-authorization-server',
  'GET /.well-known/openid-configuration',
  'GET /.well-known/ssf-configuration',
  'GET /api/clients',
  'GET /api/clients/:clientId/api-keys',
  'GET /api/clients/:id',
  'GET /api/consents',
  'GET /auth/link/wallet/:handle',
  'GET /auth/verify',
  'GET /consents',
  'GET /health',
  'GET /interaction/v1-rc.0/openapi.json',
  'GET /metrics',
  'GET /oauth/authorize',
  'GET /oauth/userinfo',
  'GET /oid4vp/request/:handle',
  'GET /ssf/jwks.json',
  'GET /ssf/status',
  'GET /ssf/stream',
  'GET /ui/consent',
  'GET /ui/login',
  'GET /ui/resume/:handle',
  'GET /ui/wallet-link',
  'GET /ui/wallet-link/:handle',
  'GET /ui/wallet-login',
  'GET /ui/wallet-login/:handle',
  'GET /ui/wallet-login/:handle/status',
  'GET /ui/wallet-login/return',
  'OPTIONS *',
  'PATCH /api/clients/:id',
  'PATCH /ssf/stream',
  'POST /api/clients',
  'POST /api/clients/:clientId/api-keys',
  'POST /api/clients/:id/regenerate-secret',
  'POST /auth/link/wallet',
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
  'POST /oid4vp/response',
  'POST /ssf/status',
  'POST /ssf/stream',
  'POST /ssf/subjects/add',
  'POST /ssf/subjects/remove',
  'POST /ssf/verify',
  'POST /ui/consent',
  'POST /ui/login',
  'POST /ui/verify',
  'POST /ui/wallet-link',
  'POST /ui/wallet-login',
  'PUT /ssf/stream',
];

/**
 * The routes added since the manifest replaced the autoload: the account and
 * developer APIs under their versioned prefixes (#524), with the account
 * API's later operations (#670, #1107, #1108).
 */
const ROUTES_ADDED_SINCE: readonly string[] = [
  'DELETE /account/v1-rc.0/consents/:consentId',
  'DELETE /account/v1-rc.0/linked-accounts/:linkedAccountId',
  'DELETE /account/v1-rc.0/passkeys/:passkeyId',
  'DELETE /developer/v1-rc.0/clients/:clientId',
  'DELETE /developer/v1-rc.0/clients/:clientId/api-keys/:keyId',
  'DELETE /developer/v1-rc.0/consents/:consentId',
  'GET /account/v1-rc.0/consents',
  'GET /account/v1-rc.0/linked-accounts',
  'GET /account/v1-rc.0/passkeys',
  'GET /account/v1-rc.0/passkeys/:passkeyId',
  'GET /account/v1-rc.0/sign-in-methods',
  'GET /developer/v1-rc.0/clients',
  'GET /developer/v1-rc.0/clients/:clientId',
  'GET /developer/v1-rc.0/clients/:clientId/api-keys',
  'GET /developer/v1-rc.0/consents',
  'PATCH /account/v1-rc.0/passkeys/:passkeyId',
  'PATCH /developer/v1-rc.0/clients/:clientId',
  'POST /account/v1-rc.0/password/change',
  'POST /developer/v1-rc.0/clients',
  'POST /developer/v1-rc.0/clients/:clientId/api-keys',
  'POST /developer/v1-rc.0/clients/:clientId/regenerate-secret',
  // Readiness, beside the liveness of /health (#500).
  'GET /ready',
  // The Interaction API's step read, personal read, answer and cancel (#616).
  'GET /interaction/v1-rc.0/:interactionId',
  'GET /interaction/v1-rc.0/:interactionId/personal',
  'POST /interaction/v1-rc.0/:interactionId/answer',
  'POST /interaction/v1-rc.0/:interactionId/cancel',
  // RP-initiated logout: the end-session endpoint and its status page (#675).
  'GET /oauth/end-session',
  'POST /oauth/end-session',
  'GET /oauth/end-session/status',
  // The landing of a mailed pass link (#637).
  'GET /auth/pass',
  // The upstream sign-in flow (#639): a provider button of the sign-in page,
  // the start of a routed provider, and the callbacks of the realm's OpenID
  // Connect providers.
  'GET /ui/upstream/:type',
  'GET /ui/upstream/:type/start',
  // The upstream account link (#670): the choice page and the refusal page.
  'GET /ui/upstream-link-refused',
  'GET /ui/upstream-link/:interactionId',
  'GET /upstream/:type/callback',
  'POST /upstream/:type/callback',
  // The recovery codes' pages (#649): "use a recovery code" and "save your
  // recovery codes".
  'GET /ui/recovery-code/:interactionId',
  'GET /ui/recovery-codes/:interactionId',
  // The passkey pages (#651): "sign in with a passkey" and "add a passkey".
  'GET /ui/passkey/:interactionId',
  'GET /ui/passkey-enrolment/:interactionId',
  // The authenticator app's pages (#653): "enter the code" and "set up an
  // authenticator app".
  'GET /ui/totp/:interactionId',
  'GET /ui/totp-setup/:interactionId',
  // The hosted account pages (#844), registered with the hosted pages.
  'GET /ui/account',
  'GET /ui/account/password',
  'POST /ui/account/password',
  'POST /ui/account/reauthenticate',
  'POST /ui/account/passkeys/add',
  'POST /ui/account/passkeys/:passkeyId/rename',
  'POST /ui/account/passkeys/:passkeyId/remove',
  'POST /ui/account/totp/setup',
  'POST /ui/account/totp/remove',
  'POST /ui/account/recovery-codes/regenerate',
  'POST /ui/account/recovery-codes/confirm',
  'POST /ui/account/sessions/:sessionId/end',
  'POST /ui/account/sessions/end-all',
  'POST /ui/account/linked-accounts/link',
  'POST /ui/account/linked-accounts/:linkedAccountId/unlink',
  // The server-rendered pages' stylesheet and fonts (#472).
  'GET /assets/ui/:file',
];

/**
 * The routes removed since: the metrics, which moved to the internal
 * listener as `GET /internal/metrics` (#500).
 */
const ROUTES_REMOVED_SINCE: ReadonlySet<string> = new Set(['GET /metrics']);

/**
 * The `GET` routes with no `HEAD` beside them: an AuthMethod's routes, which
 * mount exactly the methods the AuthMethod declares (#600, #639).
 */
const GET_ROUTES_WITHOUT_HEAD: ReadonlySet<string> = new Set(['GET /upstream/:type/callback']);

/** Every operation of both lists, less the removed ones, with Fastify's `HEAD` routes. */
const PINNED_OPERATIONS: ReadonlySet<string> = new Set(
  [...ROUTES_BEFORE_THE_MANIFEST, ...ROUTES_ADDED_SINCE]
    .filter((operation) => !ROUTES_REMOVED_SINCE.has(operation))
    .flatMap((operation) =>
      operation.startsWith('GET ') && !GET_ROUTES_WITHOUT_HEAD.has(operation)
        ? [operation, `HEAD ${operation.slice('GET '.length)}`]
        : [operation]
    )
);

/** The keys a boot sets or clears, restored after the file. */
const BOOT_KEYS =
  /^(OID4VP_|WALLET_|ACR_|WEBAUTHN_|SSF_|JWT_|KEK|SERVICE_ROLES$|SIGNER_URL$|INTERNAL_|INTERACTION_UI_ENABLED$|CEREMONY_APP_DEPLOYED$)/;

/** The environment of a deployment with every route-registering switch on. */
function maximalEnvironment(serviceRoles: string): Record<string, string> {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const holdsSigner = serviceRoles === 'all' || serviceRoles.split(',').includes('signer');
  return {
    NODE_ENV: 'test',
    SERVICE_ROLES: serviceRoles,
    JWT_ISSUER: 'https://auth.example.com',
    JWT_PUBLIC_KEY: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    ...(holdsSigner
      ? {
          JWT_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
          // A split process holding the signer serves it on the internal
          // listener (#496), over mutual TLS: never read, as this boot passes
          // the app no internal listener.
          ...(serviceRoles === 'all'
            ? {}
            : {
                INTERNAL_TLS_CERT_PATH: '/run/secrets/signer.crt',
                INTERNAL_TLS_KEY_PATH: '/run/secrets/signer.key',
                INTERNAL_TLS_CA_PATH: '/run/secrets/internal-ca.crt',
                INTERNAL_PEER_ROLES: JSON.stringify({
                  'spiffe://qauth.test/web': 'web',
                  'spiffe://qauth.test/prometheus': 'metrics',
                }),
              }),
        }
      : {
          // Never dialled or read: no request is sent.
          SIGNER_URL: 'https://signer.internal:3443',
          INTERNAL_TLS_CERT_PATH: '/run/secrets/internal.crt',
          INTERNAL_TLS_KEY_PATH: '/run/secrets/internal.key',
          INTERNAL_TLS_CA_PATH: '/run/secrets/internal-ca.crt',
          // The metrics are served to a scraper on the internal listener (#500).
          INTERNAL_PEER_ROLES: JSON.stringify({ 'spiffe://qauth.test/prometheus': 'metrics' }),
        }),
    SESSION_COOKIE_SECRET: 'service-roles-session-secret-of-at-least-32-characters',
    EMAIL_PROVIDER: 'mock',
    EMAIL_FROM_ADDRESS: 'no-reply@auth.example.com',
    EMAIL_BASE_URL: 'https://auth.example.com',
    DEFAULT_REALM_NAME: 'master',
    ENABLE_SWAGGER: 'false',
    LOG_LEVEL: 'fatal',
    // Never dialled: no request is sent.
    DATABASE_URL: 'postgres://qauth:qauth@127.0.0.1:1/qauth-unreachable',
    REDIS_URL: 'redis://127.0.0.1:1',
    RATE_LIMIT_ENABLED: 'false',
    METRICS_ENABLED: 'true',
    SSF_TRANSMITTER_ENABLED: 'true',
    INTERACTION_UI_ENABLED: 'true',
    CEREMONY_APP_DEPLOYED: 'true',
    WALLET_FEDERATION_ENABLED: 'true',
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
    OID4VP_SUBJECT_RESOLUTION: 'asserted-lookup',
    OID4VP_SUBJECT_BINDING_CLAIMS: 'family_name,given_name,birth_date',
    WEBAUTHN_RP_ID: '',
    WEBAUTHN_APPLE_APP_IDS: 'ABCDE12345.com.example.app',
    WEBAUTHN_ANDROID_APPS: JSON.stringify({
      'com.example.app': [
        'FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C',
      ],
    }),
  };
}

/** One booted process: its routes as they registered. */
interface BootedRoles {
  readonly routes: readonly RouteOptions[];
  readonly server: FastifyInstance;
}

const savedEnv = new Map<string, string | undefined>();
const booted = new Map<string, BootedRoles>();

/**
 * Boot the app under `serviceRoles`, with a fresh copy of its modules:
 * `overrides` changes the environment, and `collected` receives the routes
 * as they register.
 */
async function bootRoles(
  serviceRoles: string,
  overrides: Record<string, string> = {},
  collected: RouteOptions[] = []
): Promise<BootedRoles> {
  for (const key of Object.keys(process.env)) {
    if (BOOT_KEYS.test(key)) {
      if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
      delete process.env[key];
    }
  }
  for (const [key, value] of Object.entries({
    ...maximalEnvironment(serviceRoles),
    ...overrides,
  })) {
    if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
    process.env[key] = value;
  }
  // `config/env.ts` parses the environment at load.
  vi.resetModules();
  const { app } = await import('./app');
  const routes = collected;
  const server = Fastify({ logger: false, routerOptions: { ignoreTrailingSlash: true } });
  server.setValidatorCompiler(validatorCompiler);
  server.setSerializerCompiler(serializerCompiler);
  try {
    await server.register(async (scope) => {
      scope.addHook('onRoute', (route) => {
        routes.push(route);
      });
      await app(scope, { defaultRealmBoot: false, realmLookup: async () => undefined });
    });
    await server.ready();
  } catch (error) {
    // A boot the app refused leaves nothing open behind it.
    await server.close().catch(() => undefined);
    throw error;
  }
  return { routes, server };
}

/** `METHOD /url` for each method of each route. */
function operations(routes: readonly RouteOptions[]): Set<string> {
  return new Set(
    routes.flatMap((route) => [route.method].flat().map((method) => `${method} ${route.url}`))
  );
}

/** The roles that register a route module, and so @fastify/cors (#498). */
const CORS_ROLES: readonly ServiceRole[] = SERVICE_ROLE_NAMES.filter(
  (role) => role === 'web' || role === 'api'
);

/**
 * The roles a route of the pinned set belongs to, from its surface class:
 * @fastify/cors's `OPTIONS *` belongs to the roles with routes of their own.
 */
function expectedRoles(route: RouteOptions): readonly ServiceRole[] {
  if (route.url === '*') return CORS_ROLES;
  switch (route.config?.surface) {
    case 'browser':
      return ['web'];
    case 'api':
    case 'meta':
      return ['api'];
    default:
      return SERVICE_ROLE_NAMES;
  }
}

/**
 * Every route with its roles, as `METHOD /url → roles`, and the problem of
 * each route that has none: the listing this file's first test checks.
 */
function listRouteRoles(routes: readonly RouteOptions[]): {
  listing: string[];
  problems: string[];
} {
  const listing: string[] = [];
  const problems: string[] = [];
  for (const route of routes) {
    const problem = routeRolesProblem(route, SERVICE_ROLE_NAMES);
    if (problem !== undefined) problems.push(problem);
    for (const method of [route.method].flat()) {
      listing.push(`${method} ${route.url} → ${(route.config?.serviceRoles ?? []).join(',')}`);
    }
  }
  return { listing: listing.sort(), problems };
}

beforeAll(async () => {
  for (const roles of ['all', ...SERVICE_ROLE_NAMES]) {
    booted.set(roles, await bootRoles(roles));
  }
}, 600_000);

afterAll(async () => {
  for (const { server } of booted.values()) await server.close();
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

function bootOf(roles: string): BootedRoles {
  const result = booted.get(roles);
  if (result === undefined) throw new Error(`no boot for ${roles}`);
  return result;
}

describe('the routes of a single process (SERVICE_ROLES=all)', () => {
  it('lists every route with its roles, and no route without one', () => {
    const { listing, problems } = listRouteRoles(bootOf('all').routes);
    expect(problems).toEqual([]);
    expect(listing).toContain('POST /oauth/token → api');
    expect(listing).toContain('GET /oauth/authorize → web');
    expect(listing).toContain(`GET /health → ${SERVICE_ROLE_NAMES.join(',')}`);
  });

  it('would fail the listing for a route that has no role', () => {
    const unassigned = { method: 'GET', url: '/unlisted', config: { surface: 'api' } };
    const { problems } = listRouteRoles([
      ...bootOf('all').routes,
      unassigned as unknown as RouteOptions,
    ]);
    expect(problems).toEqual([expect.stringContaining('GET /unlisted has no service role')]);
  });

  it('registers exactly the routes the folder autoload registered', () => {
    expect(operations(bootOf('all').routes)).toEqual(PINNED_OPERATIONS);
  });

  it('gives every route the roles of its surface', () => {
    for (const route of bootOf('all').routes) {
      expect(route.config?.serviceRoles, `${String(route.method)} ${route.url}`).toEqual(
        expectedRoles(route)
      );
    }
  });
});

describe.each(SERVICE_ROLE_NAMES.map((role) => [role] as const))(
  'the routes of SERVICE_ROLES=%s',
  (role) => {
    it('registers exactly the routes of its role', () => {
      const expected = bootOf('all').routes.filter((route) => expectedRoles(route).includes(role));
      expect(operations(bootOf(role).routes)).toEqual(operations(expected));
    });

    it('answers /health and /ready, as every role does, and serves no /metrics here', () => {
      const registered = operations(bootOf(role).routes);
      expect(registered).toContain('GET /health');
      expect(registered).toContain('GET /ready');
      expect(registered).not.toContain('GET /metrics');
    });

    it('tags every route with its own role', () => {
      for (const route of bootOf(role).routes) {
        expect(routeRolesProblem(route, [role])).toBeUndefined();
        expect(route.config?.serviceRoles).toContain(role);
      }
    });
  }
);

describe("the issue's route criteria (#495)", () => {
  it('serves /oauth/token and not /oauth/authorize with SERVICE_ROLES=api', () => {
    const server = bootOf('api').server;
    expect(server.hasRoute({ method: 'POST', url: '/oauth/token' })).toBe(true);
    expect(server.hasRoute({ method: 'GET', url: '/oauth/authorize' })).toBe(false);
  });

  it('serves /oauth/authorize and not /oauth/token with SERVICE_ROLES=web', () => {
    const server = bootOf('web').server;
    expect(server.hasRoute({ method: 'POST', url: '/oauth/token' })).toBe(false);
    expect(server.hasRoute({ method: 'GET', url: '/oauth/authorize' })).toBe(true);
  });
});

describe('an internal route on the public listener (#496)', () => {
  it('refuses to boot when a plugin of the app registers one, whatever roles it names', async () => {
    vi.doMock('./plugins/security-headers', async (importOriginal) => {
      const original = await importOriginal<{ securityHeadersPlugin: FastifyPluginAsync }>();
      const withInternalRoute = fp(
        async (fastify: FastifyInstance) => {
          await fastify.register(original.securityHeadersPlugin);
          fastify.post(
            '/internal/signer/v1-rc.0/sign',
            { config: { surface: 'api', serviceRoles: ['api'] } },
            async () => ({})
          );
        },
        { name: 'internal-route-fixture' }
      );
      return { ...original, securityHeadersPlugin: withInternalRoute, default: withInternalRoute };
    });
    try {
      await expect(bootRoles('api')).rejects.toThrow(
        'POST /internal/signer/v1-rc.0/sign is an internal route: it registers only on the internal listener'
      );
    } finally {
      vi.doUnmock('./plugins/security-headers');
    }
  });

  it('is never among the routes any role registers', () => {
    for (const [roles, { routes }] of booted) {
      expect(
        routes.filter((route) => /^\/internal(?:\/|$)/.test(route.url)),
        roles
      ).toEqual([]);
    }
  });
});

describe('a split process holding the signer without mutual TLS (#496)', () => {
  it('refuses to boot, naming each setting, and registers no route', async () => {
    const routes: RouteOptions[] = [];
    await expect(
      bootRoles(
        'api,signer',
        {
          INTERNAL_TLS_CERT_PATH: '',
          INTERNAL_TLS_KEY_PATH: '',
          INTERNAL_TLS_CA_PATH: '',
          INTERNAL_PEER_ROLES: '',
        },
        routes
      )
    ).rejects.toThrow(
      /INTERNAL_TLS_CERT_PATH is required: SERVICE_ROLES=api,signer serves the signer to the other roles on the internal listener, over mutual TLS only while the roles are split, so no internal route is registered without it/
    );
    expect(routes).toEqual([]);
  });
});

describe('an admin route on the public listener (#511)', () => {
  it('refuses to boot when a plugin of the app registers one, whatever roles it names', async () => {
    // The security headers plugin, registered in the app's own scope, with a
    // route under /admin beside it that names its roles itself.
    vi.doMock('./plugins/security-headers', async (importOriginal) => {
      const original = await importOriginal<{ securityHeadersPlugin: FastifyPluginAsync }>();
      const withAdminRoute = fp(
        async (fastify: FastifyInstance) => {
          await fastify.register(original.securityHeadersPlugin);
          fastify.get(
            '/admin/v1-rc.0/realms/:realmId',
            { config: { surface: 'api', serviceRoles: ['api'] } },
            async () => ({})
          );
        },
        { name: 'admin-route-fixture' }
      );
      return { ...original, securityHeadersPlugin: withAdminRoute, default: withAdminRoute };
    });
    try {
      await expect(bootRoles('api')).rejects.toThrow(
        'GET /admin/v1-rc.0/realms/:realmId is an admin API route'
      );
    } finally {
      vi.doUnmock('./plugins/security-headers');
    }
  });
});
