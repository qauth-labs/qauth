import rateLimit from '@fastify/rate-limit';
import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { API_FAMILY_AUDIENCES } from '../api-conventions/families';
import {
  type AdminOperation,
  createAdminOperationRegistry,
  createOperationRegistry,
  defineOperation,
  operationSchemaExtensions,
} from '../helpers/admin-operations';
import { ADMIN_SCOPE_LIST } from '../helpers/admin-scopes';
import {
  AdminCallsInFlight,
  adminPipeline,
  type AdminRateLimitCheck,
  adminTransaction,
  recordAdminChange,
  requestAdminCaller,
} from './pipeline';

/**
 * What the admin pipeline refuses at boot (#511): a route that names no realm
 * in its path, and a route with a hook of its own that would run before the
 * pipeline authorizes the caller. And the request ceiling its routes get on a
 * listener with no rate limit of its own. No database: nothing here takes a
 * request.
 */

const READ = defineOperation({
  id: 'realms.get',
  class: 'read',
  effects: [],
  permissions: ['realms.read'],
  description: 'Read a realm (fixture).',
});
const REGISTRY = createOperationRegistry([READ] as AdminOperation[], { reserved: [] });

let instance: FastifyInstance | undefined;

afterEach(async () => {
  await instance?.close();
  instance = undefined;
});

/** A count that never holds a call back. */
const UNCOUNTED: AdminRateLimitCheck = async () => ({ isAllowed: true, key: 'uncounted' });

/**
 * Boot a bare listener with the pipeline in front of `route`, after what
 * `listener` registers on it.
 */
async function boot(
  route: (scope: FastifyInstance) => void,
  listener?: (app: FastifyInstance) => Promise<void>,
  refusalsByAddress: AdminRateLimitCheck = UNCOUNTED
): Promise<void> {
  const app = Fastify({ logger: false });
  instance = app;
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  await listener?.(app);
  await app.register(adminPipeline, {
    registry: REGISTRY,
    refusalsByAddress,
    callsBySubject: UNCOUNTED,
    routes: route,
  });
  await app.ready();
}

const options = { config: { operation: READ.id }, schema: operationSchemaExtensions(READ) };

describe('the admin pipeline at boot', () => {
  it('boots a route on the realm its path names', async () => {
    await expect(
      boot((scope) => {
        scope.get('/admin/v1-rc.0/realms/:realmId', options, async () => ({}));
      })
    ).resolves.toBeUndefined();
  });

  it('refuses a route that names no realm in its path', async () => {
    await expect(
      boot((scope) => {
        scope.get('/admin/v1-rc.0/realms', options, async () => ({}));
      })
    ).rejects.toThrow('every admin route acts on the realm its path names');
  });

  it.each(['onRequest', 'preParsing', 'preValidation'] as const)(
    'refuses a route with its own %s hook, which would run before authorization',
    async (hook) => {
      await expect(
        boot((scope) => {
          scope.get(
            '/admin/v1-rc.0/realms/:realmId',
            { ...options, [hook]: [async () => undefined] },
            async () => ({})
          );
        })
      ).rejects.toThrow(`has its own ${hook} hook`);
    }
  );

  it('boots a route with its own preHandler hook, which runs after the approval gate', async () => {
    await expect(
      boot((scope) => {
        scope.get(
          '/admin/v1-rc.0/realms/:realmId',
          { ...options, preHandler: [async () => undefined] },
          async () => ({})
        );
      })
    ).resolves.toBeUndefined();
  });

  /** `scope.addHook(hook, …)`, for a hook name the overloads cannot take as a union. */
  const addEarlyHook = (scope: FastifyInstance, hook: string) =>
    (scope.addHook as (name: string, fn: () => Promise<void>) => unknown)(
      hook,
      async () => undefined
    );

  it.each(['onRequest', 'preParsing', 'preValidation'] as const)(
    'refuses a route module that adds an %s hook to its scope, or to a scope of its own',
    async (hook) => {
      await expect(
        boot((scope) => {
          addEarlyHook(scope, hook);
          scope.get('/admin/v1-rc.0/realms/:realmId', options, async () => ({}));
        })
      ).rejects.toThrow(`adds an ${hook} hook`);
      await instance?.close();
      await expect(
        boot((scope) => {
          void scope.register(async (module) => {
            addEarlyHook(module, hook);
            module.get('/admin/v1-rc.0/realms/:realmId', options, async () => ({}));
          });
        })
      ).rejects.toThrow(`adds an ${hook} hook`);
    }
  );

  it('lets a route module add its own preHandler and onRoute hooks', async () => {
    await expect(
      boot((scope) => {
        void scope.register(async (module) => {
          module.addHook('onRoute', () => undefined);
          module.addHook('preHandler', async () => undefined);
          module.get('/admin/v1-rc.0/realms/:realmId', options, async () => ({}));
        });
      })
    ).resolves.toBeUndefined();
  });

  it('wraps every handler, whatever mark it carries', async () => {
    const own = Object.assign(async () => ({}), {
      [Symbol.for('qauth.adminPipeline.wrappedHandler')]: true,
    });
    let handler: unknown;
    await boot((scope) => {
      scope.addHook('onRoute', (route) => {
        handler = route.handler;
      });
      scope.get('/admin/v1-rc.0/realms/:realmId', options, own);
    });
    expect(handler).toBeTypeOf('function');
    expect(handler).not.toBe(own);
  });
});

describe('the routes of security operations at boot (#512)', () => {
  const rotate = (render?: () => { title: string }) =>
    defineOperation({
      id: 'fixtureKeys.rotate',
      class: 'security',
      effects: ['key-custody'],
      permissions: ['realms.policies.security'],
      description: 'A security operation (fixture).',
      ...(render === undefined ? {} : { render }),
    });

  /** Boot `routes` behind the pipeline, with a registry of `operation` and the approval operations. */
  async function bootSecurity(
    operation: AdminOperation,
    routes: (scope: FastifyInstance, extensions: object) => void
  ): Promise<FastifyInstance> {
    const app = Fastify({ logger: false });
    instance = app;
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    const registry = createAdminOperationRegistry([operation], { reserved: [] });
    await app.register(adminPipeline, {
      registry,
      refusalsByAddress: UNCOUNTED,
      callsBySubject: UNCOUNTED,
      routes: (scope) =>
        routes(scope, operationSchemaExtensions(registry.get(operation.id) as AdminOperation)),
    });
    await app.ready();
    return app;
  }

  const path = '/admin/v1-rc.0/realms/:realmId/keys/rotate';

  // Acceptance criterion: the boot fails for a security operation without a
  // renderer (also against the real listener, admin-listener.integration.test.ts).
  it('refuses the route of a security operation without a renderer', async () => {
    await expect(
      bootSecurity(rotate(), (scope, schema) => {
        scope.post(path, { config: { operation: 'fixtureKeys.rotate' }, schema }, async () => ({}));
      })
    ).rejects.toThrow(/fixtureKeys.rotate, which has no renderer/);
  });

  it('boots it with a renderer, and keeps its route for the approvals filed against it', async () => {
    const params = z.object({ realmId: z.uuid() });
    let context: FastifyInstance['adminApi'] | undefined;
    await bootSecurity(
      rotate(() => ({ title: 'Rotate' })),
      (scope, schema) => {
        context = scope.adminApi;
        scope.post(
          path,
          { config: { operation: 'fixtureKeys.rotate' }, schema: { ...schema, params } },
          async () => ({})
        );
      }
    );
    expect(context?.routeOf('fixtureKeys.rotate')).toEqual({ method: 'POST', url: path, params });
    expect(context?.routeOf('realms.get')).toBeUndefined();
  });

  it('refuses a second route of one operation, and a security route under several methods', async () => {
    const operation = rotate(() => ({ title: 'Rotate' }));
    const params = z.object({ realmId: z.uuid() });
    await expect(
      bootSecurity(operation, (scope, schema) => {
        const options = {
          config: { operation: 'fixtureKeys.rotate' },
          schema: { ...schema, params },
        };
        scope.post(path, options, async () => ({}));
        scope.put(path, options, async () => ({}));
      })
    ).rejects.toThrow(/an operation has one route/);
    await instance?.close();
    await expect(
      bootSecurity(operation, (scope, schema) => {
        scope.route({
          method: ['POST', 'PUT'],
          url: path,
          config: { operation: 'fixtureKeys.rotate' },
          schema,
          handler: async () => ({}),
        });
      })
    ).rejects.toThrow(/under several methods/);
  });

  it('refuses a security route whose schemas a filed request cannot be parsed with', async () => {
    const params = z.object({ realmId: z.uuid() });
    const withSchema = (extra: object) => (scope: FastifyInstance, schema: object) => {
      scope.post(
        path,
        { config: { operation: 'fixtureKeys.rotate' }, schema: { ...schema, ...extra } },
        async () => ({})
      );
    };
    const operation = rotate(() => ({ title: 'Rotate' }));
    // The path always holds the realm, so the route parses its parameters.
    await expect(bootSecurity(operation, withSchema({}))).rejects.toThrow(
      /fixtureKeys.rotate has no Zod params schema/
    );
    await instance?.close();
    await expect(
      bootSecurity(operation, withSchema({ params, body: { type: 'object' } }))
    ).rejects.toThrow(
      /body schema of the security operation fixtureKeys.rotate is not a Zod schema/
    );
    await instance?.close();
    // Fastify's `query`, which it folds into `querystring` after onRoute.
    await expect(
      bootSecurity(operation, withSchema({ params, query: { type: 'object' } }))
    ).rejects.toThrow(/querystring schema of the security operation fixtureKeys.rotate/);
  });

  it("files a request against a route's `query` schema as its querystring", async () => {
    const params = z.object({ realmId: z.uuid() });
    const query = z.object({ dryRun: z.enum(['true', 'false']) });
    let context: FastifyInstance['adminApi'] | undefined;
    await bootSecurity(
      rotate(() => ({ title: 'Rotate' })),
      (scope, schema) => {
        context = scope.adminApi;
        scope.post(
          path,
          { config: { operation: 'fixtureKeys.rotate' }, schema: { ...schema, params, query } },
          async () => ({})
        );
      }
    );
    expect(context?.routeOf('fixtureKeys.rotate')).toEqual({
      method: 'POST',
      url: path,
      params,
      querystring: query,
    });
  });

  it('checks a HEAD route of a security operation, but never files against it', async () => {
    await expect(
      bootSecurity(rotate(), (scope, schema) => {
        scope.route({
          method: 'HEAD',
          url: path,
          config: { operation: 'fixtureKeys.rotate' },
          schema,
          handler: async () => ({}),
        });
      })
    ).rejects.toThrow(/fixtureKeys.rotate, which has no renderer/);
  });
});

describe('the token guard', () => {
  const ISSUER = 'https://alpha.example.com';
  const REALM = { id: '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f', issuer: ISSUER, enabled: true };

  /**
   * A request's credential (`none` for none), its claims before
   * verification, what verification does, and its address's count of refusals.
   */
  interface Presented {
    readonly scheme?: 'Bearer' | 'DPoP' | 'none';
    readonly iss: unknown;
    readonly verify?: () => Promise<never>;
    readonly refusals?: AdminRateLimitCheck;
  }

  /**
   * Send one request through a bare listener whose token guard reads the
   * stubs: one realm, `alpha`, and a token that claims `iss`.
   */
  async function present(presented: Presented) {
    const findByIssuer = vi.fn(async (issuer: string) => (issuer === ISSUER ? REALM : undefined));
    const decodeTokenUnsafe = vi.fn(() => ({ iss: presented.iss }));
    await boot(
      (scope) => {
        scope.get('/admin/v1-rc.0/realms/:realmId', options, async () => ({}));
      },
      async (app) => {
        app.decorate('jwtUtils', {
          extractCredentialFromHeader: () =>
            presented.scheme === 'none'
              ? null
              : { scheme: presented.scheme ?? 'Bearer', token: 'token' },
          decodeTokenUnsafe,
        } as never);
        app.decorate('repositories', { realms: { findByIssuer } } as never);
        app.decorate(
          'verifyRequestAccessToken',
          (presented.verify ??
            (async () => {
              throw new Error('no verification expected');
            })) as never
        );
      },
      presented.refusals
    );
    const app = instance;
    if (app === undefined) throw new Error('not booted');
    const response = await app.inject({
      method: 'GET',
      url: `/admin/v1-rc.0/realms/${REALM.id}`,
      headers: { authorization: 'Bearer token' },
    });
    await app.close();
    instance = undefined;
    return { response, findByIssuer, decodeTokenUnsafe };
  }

  /** An address's count of refusals: `count` when read, `counted` once a refusal is added. */
  const refusalCount = (count: 'under' | 'over', counted: 'under' | 'over') => {
    const of = (where: 'under' | 'over') => ({
      isAllowed: false as const,
      key: 'admin:address:203.0.113.9',
      max: 100,
      timeWindow: 60_000,
      remaining: where === 'over' ? 0 : 50,
      ttl: 30_000,
      ttlInSeconds: 30,
      isExceeded: where === 'over',
      isBanned: false,
    });
    return vi.fn<AdminRateLimitCheck>(async (_request, callOptions) =>
      callOptions?.increment === false ? of(count) : of(counted)
    );
  };

  const REFUSAL = 'The request carries no admin access token this listener accepts';

  it('answers every refusal alike, whether the issuer names a realm or not', async () => {
    const unknown = await present({ iss: 'https://unknown.example.com' });
    const wrongKey = await present({
      iss: ISSUER,
      verify: async () => {
        throw new JWTInvalidError('Invalid JWT token: no key of this realm verifies it');
      },
    });
    const expired = await present({
      iss: ISSUER,
      verify: async () => {
        throw new JWTExpiredError();
      },
    });

    expect(unknown.response.statusCode).toBe(401);
    expect(unknown.response.json()).toEqual(wrongKey.response.json());
    expect(unknown.response.json()).toMatchObject({
      code: 'INVALID_ACCESS_TOKEN',
      message: REFUSAL,
    });
    expect(expired.response.statusCode).toBe(401);
    expect(expired.response.json()).toMatchObject({
      code: 'ACCESS_TOKEN_EXPIRED',
      message: REFUSAL,
    });
  });

  it('answers the DPoP scheme as no credential until #520, before it reads the token', async () => {
    const { response, decodeTokenUnsafe, findByIssuer } = await present({
      scheme: 'DPoP',
      iss: ISSUER,
    });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ code: 'UNAUTHORIZED', message: REFUSAL });
    expect(decodeTokenUnsafe).not.toHaveBeenCalled();
    expect(findByIssuer).not.toHaveBeenCalled();
  });

  it.each([
    ['a NUL character', '\u0000'],
    ['a control character', `${ISSUER}\n`],
    ['more than 2048 characters', `${ISSUER}/${'a'.repeat(2048)}`],
  ])('refuses an issuer with %s before it looks the issuer up', async (_what, iss) => {
    const { response, findByIssuer } = await present({ iss });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ code: 'INVALID_ACCESS_TOKEN', message: REFUSAL });
    expect(findByIssuer).not.toHaveBeenCalled();
  });

  it('leaves a failure that is no refusal of the token as it is', async () => {
    const { response } = await present({
      iss: ISSUER,
      verify: async () => {
        throw new Error('the database is down');
      },
    });
    expect(response.statusCode).toBe(500);
  });

  it('counts each refusal against the address, and answers 401 below its count', async () => {
    const refusals = refusalCount('under', 'under');
    const { response } = await present({ scheme: 'none', iss: ISSUER, refusals });
    expect(response.statusCode).toBe(401);
    expect(refusals.mock.calls.map(([, callOptions]) => callOptions)).toEqual([
      { increment: false },
      undefined,
    ]);
  });

  it('refuses a call with no token from an address past its count, before the guard', async () => {
    const refusals = refusalCount('over', 'over');
    const { response, decodeTokenUnsafe } = await present({
      scheme: 'none',
      iss: ISSUER,
      refusals,
    });
    expect(response.statusCode).toBe(429);
    expect(response.headers['retry-after']).toBe('30');
    expect(decodeTokenUnsafe).not.toHaveBeenCalled();
    // Read, not counted: only a refusal of the guard counts.
    expect(refusals.mock.calls.map(([, callOptions]) => callOptions)).toEqual([
      { increment: false },
    ]);
  });

  it("lets a call with a token on to the guard, whatever its address's count", async () => {
    const refusals = refusalCount('over', 'under');
    const verify = vi.fn(async () => {
      throw new JWTInvalidError('Invalid JWT token: no key of this realm verifies it');
    });
    const { response } = await present({ iss: ISSUER, verify, refusals });
    expect(verify).toHaveBeenCalledOnce();
    expect(response.statusCode).toBe(401);
    expect(refusals.mock.calls.map(([, callOptions]) => callOptions)).toEqual([undefined]);
  });

  it("answers 429 for a refusal of the guard past its address's count", async () => {
    const { response } = await present({
      iss: 'https://unknown.example.com',
      refusals: refusalCount('over', 'over'),
    });
    expect(response.statusCode).toBe(429);
    expect(response.headers['retry-after']).toBe('30');
  });
});

describe('the request ceiling of the routes behind the pipeline', () => {
  /** A route's `onRequest` hooks once every other `onRoute` hook of the scope ran. */
  async function routeOnRequestHooks(
    listener?: (app: FastifyInstance) => Promise<void>
  ): Promise<unknown[]> {
    let hooks: unknown[] = [];
    await boot((scope) => {
      // Added last, so it runs after the pipeline's and the rate limit's.
      scope.addHook('onRoute', (route) => {
        hooks = [route.onRequest ?? []].flat();
      });
      scope.get('/admin/v1-rc.0/realms/:realmId', options, async () => ({}));
    }, listener);
    return hooks;
  }

  it('limits every route, once, on a listener that has no rate limit of its own', async () => {
    expect(await routeOnRequestHooks()).toHaveLength(1);
  });

  it("keeps the listener's own rate limit and adds none", async () => {
    expect(
      await routeOnRequestHooks(async (app) => {
        await app.register(rateLimit, { global: false, max: 1, timeWindow: 60_000 });
      })
    ).toEqual([]);
  });
});

describe('the calls that owe an audit row', () => {
  it('drains once every call has settled its row, and gives up at its deadline', async () => {
    const calls = new AdminCallsInFlight();
    const request = {
      adminPipeline: { handlerStarted: false, committed: false },
    } as unknown as FastifyRequest;
    calls.open(request);
    expect(calls.size).toBe(1);
    expect(await calls.drained(30)).toBe(false);

    setTimeout(() => request.adminPipeline?.rowSettled?.(), 20);
    expect(await calls.drained(1_000)).toBe(true);
    expect(calls.size).toBe(0);
    // Settling again changes nothing.
    request.adminPipeline?.rowSettled?.();
    expect(calls.size).toBe(0);
  });
});

/**
 * Calls the pipeline admits, end to end through a bare listener whose
 * database, token verification and repositories are stubs: an operator-realm
 * viewer with a grant on one realm, and a transaction that is a plain object.
 * A stage that refused every call would fail here, not only in the suite
 * against real containers.
 */
describe('a call the pipeline admits', () => {
  const ISSUER = 'https://operator.example.com';
  const OPERATOR = {
    id: '018f2d6e-0000-7000-8000-000000000001',
    issuer: ISSUER,
    enabled: true,
    isOperator: true,
  };
  const TARGET = {
    id: '018f2d6e-0000-7000-8000-000000000002',
    issuer: 'https://alpha.example.com',
    enabled: true,
    isOperator: false,
  };
  const USER = '018f2d6e-0000-7000-8000-000000000003';
  const TX = Object.freeze({ fixture: 'transaction' });

  /** The rows the stub audit log received, with the transaction each came in. */
  let rows: { outcome: string; transaction: unknown }[] = [];

  /** Boot the stubbed listener with `routes` behind the pipeline, and call `path` on it. */
  async function admit(
    routes: (scope: FastifyInstance) => void,
    path = ''
  ): Promise<{ statusCode: number; body: string }> {
    rows = [];
    await boot(routes, async (app) => {
      app.decorate('jwtUtils', {
        extractCredentialFromHeader: () => ({ scheme: 'Bearer', token: 'token' }),
        decodeTokenUnsafe: () => ({ iss: ISSUER }),
      } as never);
      app.decorate('verifyRequestAccessToken', (async () => ({
        iss: ISSUER,
        sub: USER,
        exp: Math.floor(Date.now() / 1000) + 300,
        jti: 'jti-1',
        aud: API_FAMILY_AUDIENCES.admin,
        scope: ADMIN_SCOPE_LIST.join(' '),
        clientId: 'admin-console',
      })) as never);
      app.decorate('repositories', {
        realms: {
          findByIssuer: async (issuer: string) => (issuer === ISSUER ? OPERATOR : undefined),
          findById: async (id: string) => (id === TARGET.id ? TARGET : undefined),
        },
        users: {
          findById: async (realmId: string, id: string) =>
            realmId === OPERATOR.id && id === USER
              ? { id: USER, enabled: true, realmId: OPERATOR.id }
              : undefined,
        },
        adminGrants: {
          listLive: async () => [
            {
              grant: {
                id: 'grant-1',
                builtInRole: 'viewer',
                roleId: null,
                targetRealmId: TARGET.id,
              },
              role: null,
            },
          ],
        },
        adminAuditLog: {
          appendAdminAudit: async (transaction: unknown, entry: { outcome: string }) => {
            rows.push({ outcome: entry.outcome, transaction });
          },
        },
      } as never);
      app.decorate('db', {
        transaction: async (work: (transaction: unknown) => Promise<unknown>) => work(TX),
      } as never);
    });
    const app = instance;
    if (app === undefined) throw new Error('not booted');
    const response = await app.inject({
      method: 'GET',
      url: `/admin/v1-rc.0/realms/${TARGET.id}${path}`,
      headers: { authorization: 'Bearer token' },
    });
    return { statusCode: response.statusCode, body: response.body };
  }

  it('runs the handler in its transaction, answers 200 and writes one succeeded row in it', async () => {
    const seen: unknown[] = [];
    const response = await admit((scope) => {
      scope.get('/admin/v1-rc.0/realms/:realmId', options, async (request) => {
        seen.push(adminTransaction(request));
        return { realm: requestAdminCaller(request).targetRealm.id };
      });
    });
    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ realm: TARGET.id });
    expect(seen).toEqual([TX]);
    expect(rows).toEqual([{ outcome: 'succeeded', transaction: TX }]);
  });

  it('runs a handler a later onRoute hook put back in the transaction all the same', async () => {
    const seen: unknown[] = [];
    const own = async (request: FastifyRequest) => {
      seen.push(adminTransaction(request));
      return { own: true };
    };
    const response = await admit((scope) => {
      void scope.register(async (module) => {
        module.addHook('onRoute', (route) => {
          route.handler = own;
        });
        module.get('/admin/v1-rc.0/realms/:realmId', options, own);
      });
    });
    expect(response.statusCode).toBe(200);
    expect(seen).toEqual([TX]);
    expect(rows).toEqual([{ outcome: 'succeeded', transaction: TX }]);
  });

  it("fails a call whose route's own preHandler sends the reply, before its handler", async () => {
    const ran: string[] = [];
    const response = await admit((scope) => {
      scope.get(
        '/admin/v1-rc.0/realms/:realmId',
        {
          ...options,
          preHandler: [
            async (_request, reply) => {
              ran.push('preHandler');
              return reply.send({ early: true });
            },
          ],
        },
        async () => {
          ran.push('handler');
          return {};
        }
      );
    });
    expect(response.statusCode).toBe(500);
    expect(ran).toEqual(['preHandler']);
    expect(rows.map((row) => row.outcome)).toEqual(['failed']);
  });

  it('fails a call whose preHandler a module added sends the reply, and lets one that throws refuse', async () => {
    const sending = await admit((scope) => {
      void scope.register(async (module) => {
        module.addHook('preHandler', async (_request, reply) => reply.send({ early: true }));
        module.get('/admin/v1-rc.0/realms/:realmId', options, async () => ({}));
      });
    });
    expect(sending.statusCode).toBe(500);
    expect(rows.map((row) => row.outcome)).toEqual(['failed']);
    await instance?.close();

    const throwing = await admit((scope) => {
      void scope.register(async (module) => {
        module.addHook('preHandler', async () => {
          throw new JWTInvalidError('refused by the module');
        });
        module.get('/admin/v1-rc.0/realms/:realmId', options, async () => ({}));
      });
    });
    expect(throwing.statusCode).toBe(401);
    expect(rows.map((row) => row.outcome)).toEqual(['denied']);
  });

  it('fails a call whose body its response schema refuses, before the commit, with no succeeded row', async () => {
    const response = await admit((scope) => {
      scope.get(
        '/admin/v1-rc.0/realms/:realmId',
        {
          ...options,
          schema: { ...options.schema, response: { 200: z.object({ id: z.uuid() }) } },
        },
        async (request) => {
          recordAdminChange(request, {
            change: { before: null, after: { id: 'x' } },
            annotations: {},
          });
          return { id: 'not-a-uuid' };
        }
      );
    });
    expect(response.statusCode).toBe(500);
    expect(rows.map((row) => row.outcome)).toEqual(['failed']);
  });
});
