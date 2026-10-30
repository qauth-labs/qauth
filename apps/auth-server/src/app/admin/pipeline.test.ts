import rateLimit from '@fastify/rate-limit';
import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  type AdminOperation,
  createOperationRegistry,
  defineOperation,
  operationSchemaExtensions,
} from '../helpers/admin-operations';
import { AdminCallsInFlight, adminPipeline, type AdminRateLimitCheck } from './pipeline';

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
