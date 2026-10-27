import { createHash } from 'node:crypto';

import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  type AdminOperation,
  type Classification,
  createOperationRegistry,
  defineOperation,
  type OperationClassification,
  operationSchemaExtensions,
} from '../helpers/admin-operations';
import {
  adminOperationsPlugin,
  adminRouteProblem,
  requestClassification,
} from './admin-operations';

/**
 * The classification stage of the admin pipeline (#508): the boot check on
 * every route, and a classification per request that the handler receives
 * and cannot lower.
 */

const WRITE: Classification = {
  class: 'write',
  effects: [],
  permissions: ['realms.policies.write'],
};

const READ_OPERATION = defineOperation({
  id: 'widgets.get',
  class: 'read',
  effects: [],
  permissions: ['realms.read'],
  description: 'Read a widget.',
});

/** Write for a `lifespan` change, security for anything that touches `password`. */
const PATCH_OPERATION = defineOperation<{ minScore: number }>({
  id: 'widgets.policies.update',
  class: 'security',
  effects: ['credential-path'],
  permissions: ['realms.policies.write', 'realms.policies.security'],
  description: 'Change widget policies.',
  classify: (request) => {
    const body = request.body as Record<string, unknown>;
    if (Object.keys(body).every((key) => key === 'lifespan')) return WRITE;
    if ('broken' in body) throw new Error('no rule');
    return {
      class: 'security',
      effects: ['credential-path'],
      permissions: ['realms.policies.security'],
    };
  },
  loadState: async () => ({ minScore: 2 }),
  stateVersion: (state) => `v${state.minScore}`,
});

/** An authorization stage that lets every classified request through. */
const ALLOW = () => undefined;

/** The `If-Match` of a request written against the fixture state. */
const IF_MATCH = { 'if-match': '"v2"' };

const REGISTRY = createOperationRegistry([READ_OPERATION, PATCH_OPERATION] as AdminOperation[], {
  reserved: [],
});

const schemaOf = (operation: AdminOperation) => ({ ...operationSchemaExtensions(operation) });

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

/** A listener with the stage and whatever routes `routes` adds after it. */
async function listener(
  routes: (instance: FastifyInstance) => void,
  options: { logger?: boolean } = {}
): Promise<FastifyInstance> {
  app = Fastify({ logger: options.logger ?? false });
  await app.register(adminOperationsPlugin, { registry: REGISTRY, authorize: ALLOW });
  await app.register(async (scope) => routes(scope));
  return app;
}

describe('request ceiling', () => {
  it('limits a listener that has no rate limit of its own', async () => {
    app = Fastify({ logger: false });
    await app.register(adminOperationsPlugin, {
      registry: REGISTRY,
      authorize: ALLOW,
      rateLimit: { max: 2, timeWindow: 60_000 },
    });
    expect(app.hasDecorator('rateLimit')).toBe(true);
    await app.register(async (scope) => {
      scope.get(
        '/admin/v1-rc.0/widgets',
        { config: { operation: 'widgets.get' }, schema: schemaOf(READ_OPERATION) },
        async () => ({})
      );
    });
    await app.ready();
    const statuses: number[] = [];
    for (let i = 0; i < 3; i++) {
      statuses.push(
        (await app.inject({ method: 'GET', url: '/admin/v1-rc.0/widgets' })).statusCode
      );
    }
    expect(statuses.slice(0, 2)).not.toContain(429);
    expect(statuses[2]).toBe(429);
  });

  it("keeps a listener's own rate limit and registers none of its own", async () => {
    app = Fastify({ logger: false });
    await app.register(rateLimit, { global: true, max: 1, timeWindow: 60_000 });
    await app.register(adminOperationsPlugin, { registry: REGISTRY, authorize: ALLOW });
    await app.register(async (scope) => {
      scope.get(
        '/admin/v1-rc.0/widgets',
        { config: { operation: 'widgets.get' }, schema: schemaOf(READ_OPERATION) },
        async () => ({})
      );
    });
    await app.ready();
    await app.inject({ method: 'GET', url: '/admin/v1-rc.0/widgets' });
    expect((await app.inject({ method: 'GET', url: '/admin/v1-rc.0/widgets' })).statusCode).toBe(
      429
    );
  });
});

/** `listener(routes)` and `ready()`, as one promise for `rejects`. */
const boot = (routes: (instance: FastifyInstance) => void) =>
  (async () => {
    const instance = await listener(routes);
    await instance.ready();
  })();

describe('the boot check (#508)', () => {
  it('refuses a route that names no operation', async () => {
    await expect(
      boot((scope) => scope.get('/admin/v1-rc.0/widgets', async () => ({})))
    ).rejects.toThrow(/GET \/admin\/v1-rc.0\/widgets has no admin operation/);
  });

  it('refuses a route that names an operation the registry does not hold', async () => {
    await expect(
      boot((scope) =>
        scope.get(
          '/admin/v1-rc.0/widgets',
          { config: { operation: 'widgets.list' }, schema: { operationId: 'widgets.list' } },
          async () => ({})
        )
      )
    ).rejects.toThrow(
      /names the admin operation "widgets.list", which the operation registry does not hold/
    );
  });

  it.each([
    ['no schema', undefined],
    ['another operationId', { ...schemaOf(READ_OPERATION), operationId: 'widgets.read' }],
    ['another class', { ...schemaOf(READ_OPERATION), 'x-qauth-class': 'write' as const }],
    ['another permission', { ...schemaOf(READ_OPERATION), 'x-qauth-permission': 'realms.export' }],
    [
      'an effect on a read operation',
      { ...schemaOf(READ_OPERATION), 'x-qauth-effects': ['import' as const] },
    ],
  ])('refuses a route whose schema disagrees with the registry: %s', async (_label, schema) => {
    await expect(
      boot((scope) =>
        scope.get(
          '/admin/v1-rc.0/widgets/:id',
          { config: { operation: 'widgets.get' }, ...(schema ? { schema } : {}) },
          async () => ({})
        )
      )
    ).rejects.toThrow(/widgets\/:id/);
  });

  it('reads the effects as a set, as the conventions check does', () => {
    const multi = createOperationRegistry(
      [
        defineOperation({
          ...PATCH_OPERATION,
          effects: ['credential-path', 'posture-loosening'],
        }) as AdminOperation,
      ],
      { reserved: [] }
    );
    expect(
      adminRouteProblem(
        {
          method: 'PATCH',
          url: '/x',
          config: { operation: 'widgets.policies.update' },
          schema: {
            ...operationSchemaExtensions(multi.get('widgets.policies.update') as AdminOperation),
            'x-qauth-effects': ['posture-loosening', 'credential-path'],
          },
        },
        multi
      )
    ).toBeUndefined();
  });

  it('refuses a security route without its effects or its two-admin marker', async () => {
    const withoutMarker: Record<string, unknown> = schemaOf(PATCH_OPERATION);
    delete withoutMarker['x-qauth-two-admin'];
    await expect(
      boot((scope) =>
        scope.patch(
          '/admin/v1-rc.0/widgets/policies',
          { config: { operation: 'widgets.policies.update' }, schema: withoutMarker },
          async () => ({})
        )
      )
    ).rejects.toThrow(/x-qauth-two-admin/);
  });

  it('boots routes whose schemas carry the registry members, with a permission list in any order', async () => {
    const schema = schemaOf(PATCH_OPERATION);
    await expect(
      boot((scope) => {
        scope.get(
          '/admin/v1-rc.0/widgets/:id',
          { config: { operation: 'widgets.get' }, schema: schemaOf(READ_OPERATION) },
          async () => ({})
        );
        scope.patch(
          '/admin/v1-rc.0/widgets/policies',
          {
            config: { operation: 'widgets.policies.update' },
            schema: {
              ...schema,
              'x-qauth-permission': [...(schema['x-qauth-permission'] as string[])].reverse(),
            },
          },
          async () => ({})
        );
      })
    ).resolves.toBeUndefined();
  });

  // onRoute is not retroactive: a route registered before the stage would
  // never pass the boot check, so the stage refuses to load after one.
  it('refuses to load on an instance that already has a route, in any scope', async () => {
    app = Fastify({ logger: false });
    app.get('/admin/v1-rc.0/early', async () => ({}));
    await expect(
      app.register(adminOperationsPlugin, { registry: REGISTRY, authorize: ALLOW })
    ).rejects.toThrow(/must be registered before any route of the admin listener/);
    await app.close();

    app = Fastify({ logger: false });
    await app.register(async (scope) => {
      scope.get('/admin/v1-rc.0/early', async () => ({}));
    });
    await expect(
      app.register(adminOperationsPlugin, { registry: REGISTRY, authorize: ALLOW })
    ).rejects.toThrow(/must be registered before any route of the admin listener/);
  });

  it('names the problem without Fastify', () => {
    expect(
      adminRouteProblem({ method: ['GET', 'HEAD'], url: '/x', config: {}, schema: {} }, REGISTRY)
    ).toMatch(/^GET,HEAD \/x has no admin operation/);
    expect(
      adminRouteProblem(
        {
          method: 'GET',
          url: '/x',
          config: { operation: 'widgets.get' },
          schema: schemaOf(READ_OPERATION),
        },
        REGISTRY
      )
    ).toBeUndefined();
  });
});

describe('the classification per request (#508)', () => {
  /** The listener with both fixture routes; each handler records what it received. */
  async function withFixtureRoutes(onClassified?: (c: OperationClassification) => void) {
    return listener((scope) => {
      scope.get(
        '/admin/v1-rc.0/widgets/:id',
        { config: { operation: 'widgets.get' }, schema: schemaOf(READ_OPERATION) },
        async (request) => {
          onClassified?.(requestClassification(request));
          return { ok: true };
        }
      );
      scope.patch(
        '/admin/v1-rc.0/widgets/policies',
        { config: { operation: 'widgets.policies.update' }, schema: schemaOf(PATCH_OPERATION) },
        async (request) => {
          onClassified?.(requestClassification(request));
          return { ok: true };
        }
      );
    });
  }

  it('hands a static operation its declaration', async () => {
    const seen: OperationClassification[] = [];
    const instance = await withFixtureRoutes((classification) => seen.push(classification));
    const response = await instance.inject({ method: 'GET', url: '/admin/v1-rc.0/widgets/1' });
    expect(response.statusCode).toBe(200);
    expect(seen).toEqual([
      {
        operationId: 'widgets.get',
        class: 'read',
        effects: [],
        permissions: ['realms.read'],
        failedClosed: null,
        stateVersion: null,
        bodyDigest: null,
      },
    ]);
  });

  it('classifies the same HEAD route Fastify adds for a GET', async () => {
    const seen: OperationClassification[] = [];
    const instance = await withFixtureRoutes((classification) => seen.push(classification));
    const response = await instance.inject({ method: 'HEAD', url: '/admin/v1-rc.0/widgets/1' });
    expect(response.statusCode).toBe(200);
    expect(seen.map((classification) => classification.operationId)).toEqual(['widgets.get']);
  });

  it('classifies a request-dependent operation by its body', async () => {
    const seen: OperationClassification[] = [];
    const instance = await withFixtureRoutes((classification) => seen.push(classification));
    await instance.inject({
      method: 'PATCH',
      url: '/admin/v1-rc.0/widgets/policies',
      headers: IF_MATCH,
      payload: { lifespan: 600 },
    });
    await instance.inject({
      method: 'PATCH',
      url: '/admin/v1-rc.0/widgets/policies',
      headers: IF_MATCH,
      payload: { password: 1 },
    });
    expect(seen.map(({ class: c, permissions }) => [c, permissions])).toEqual([
      ['write', ['realms.policies.write']],
      ['security', ['realms.policies.security']],
    ]);
  });

  it('fails a throwing classify closed and logs the reason, not the body', async () => {
    const seen: OperationClassification[] = [];
    const lines: string[] = [];
    app = Fastify({
      logger: { level: 'warn', stream: { write: (line: string) => void lines.push(line) } },
    });
    await app.register(adminOperationsPlugin, { registry: REGISTRY, authorize: ALLOW });
    app.patch(
      '/admin/v1-rc.0/widgets/policies',
      { config: { operation: 'widgets.policies.update' }, schema: schemaOf(PATCH_OPERATION) },
      async (request) => {
        seen.push(requestClassification(request));
        return {};
      }
    );
    await app.inject({
      method: 'PATCH',
      url: '/admin/v1-rc.0/widgets/policies',
      headers: IF_MATCH,
      payload: { broken: 'secret-value' },
    });
    expect(seen).toEqual([
      {
        operationId: 'widgets.policies.update',
        class: 'security',
        effects: ['credential-path'],
        permissions: ['realms.policies.write', 'realms.policies.security'],
        failedClosed: 'threw',
        stateVersion: 'v2',
        bodyDigest: null,
      },
    ]);
    const warning = lines.map((line) => JSON.parse(line)).find((line) => line.level === 40);
    expect(warning).toMatchObject({ operation: 'widgets.policies.update', reason: 'threw' });
    expect(lines.join('\n')).not.toContain('secret-value');
  });

  // Acceptance criterion: the pipeline hands the handler a classification it
  // cannot lower. The handler below tries every way to make its request look
  // like a read; the stage after it (the audit row, the approval
  // consumption) still sees the security classification.
  it('hands a hostile handler a classification it cannot lower', async () => {
    const attempts: Record<string, string> = {};
    let afterHandler: OperationClassification | null | undefined = null;
    const weaker: OperationClassification = Object.freeze({
      operationId: 'widgets.policies.update',
      class: 'read',
      effects: [],
      permissions: ['realms.read'],
      failedClosed: null,
      stateVersion: null,
      bodyDigest: null,
    });

    app = Fastify({ logger: false });
    await app.register(adminOperationsPlugin, { registry: REGISTRY, authorize: ALLOW });
    app.addHook('onResponse', async (request) => {
      afterHandler = request.adminOperation;
    });
    app.patch(
      '/admin/v1-rc.0/widgets/policies',
      { config: { operation: 'widgets.policies.update' }, schema: schemaOf(PATCH_OPERATION) },
      async (request: FastifyRequest) => {
        const tryTo = (name: string, attempt: () => unknown) => {
          try {
            const result = attempt();
            attempts[name] = result === false ? 'refused' : 'ran';
          } catch (error) {
            attempts[name] = (error as Error).name;
          }
        };
        const held = request.adminOperation as OperationClassification;
        const asWritable = held as unknown as Record<string, unknown>;
        tryTo('assign the property', () => {
          (request as unknown as Record<string, unknown>).adminOperation = weaker;
        });
        tryTo('redefine the property', () =>
          Object.defineProperty(request, 'adminOperation', { value: weaker })
        );
        tryTo('delete the property', () => {
          delete (request as unknown as Record<string, unknown>).adminOperation;
        });
        tryTo('Reflect.set', () => Reflect.set(request, 'adminOperation', weaker));
        tryTo('Reflect.defineProperty', () =>
          Reflect.defineProperty(request, 'adminOperation', { value: weaker })
        );
        tryTo('lower the class', () => {
          asWritable.class = 'read';
        });
        tryTo('drop the effects', () => {
          (held.effects as string[]).length = 0;
        });
        tryTo('pop an effect', () => (held.effects as string[]).pop());
        tryTo('replace the permissions', () => {
          asWritable.permissions = ['realms.read'];
        });
        tryTo('splice a permission', () => (held.permissions as string[]).splice(0, 2));
        tryTo('clear failedClosed', () => {
          asWritable.failedClosed = 'threw';
        });
        tryTo('swap the prototype', () => Object.setPrototypeOf(held, weaker));
        return { class: request.adminOperation?.class };
      }
    );

    const response = await app.inject({
      method: 'PATCH',
      url: '/admin/v1-rc.0/widgets/policies',
      headers: IF_MATCH,
      payload: { password: 1 },
    });

    const expected = {
      operationId: 'widgets.policies.update',
      class: 'security',
      effects: ['credential-path'],
      permissions: ['realms.policies.security'],
      failedClosed: null,
      stateVersion: 'v2',
      bodyDigest: null,
    };
    expect(response.json()).toEqual({ class: 'security' });
    expect(afterHandler).toEqual(expected);
    expect(attempts).toEqual({
      'assign the property': 'TypeError',
      'redefine the property': 'TypeError',
      'delete the property': 'TypeError',
      'Reflect.set': 'refused',
      'Reflect.defineProperty': 'refused',
      'lower the class': 'TypeError',
      'drop the effects': 'TypeError',
      'pop an effect': 'TypeError',
      'replace the permissions': 'TypeError',
      'splice a permission': 'TypeError',
      'clear failedClosed': 'TypeError',
      'swap the prototype': 'TypeError',
    });

    // The next request is classified afresh, by its own body.
    const next = await app.inject({
      method: 'PATCH',
      url: '/admin/v1-rc.0/widgets/policies',
      headers: IF_MATCH,
      payload: { lifespan: 1 },
    });
    expect(next.json()).toEqual({ class: 'write' });
  });

  it('runs nothing when an earlier stage took the property first', async () => {
    const handler = vi.fn(async () => ({}));
    app = Fastify({ logger: false });
    // Registered before the stage, so it runs first.
    app.addHook('preHandler', async (request) => {
      Object.defineProperty(request, 'adminOperation', {
        value: null,
        writable: false,
        configurable: false,
      });
    });
    await app.register(adminOperationsPlugin, { registry: REGISTRY, authorize: ALLOW });
    app.get(
      '/admin/v1-rc.0/widgets/:id',
      { config: { operation: 'widgets.get' }, schema: schemaOf(READ_OPERATION) },
      handler
    );
    const response = await app.inject({ method: 'GET', url: '/admin/v1-rc.0/widgets/1' });
    expect(response.statusCode).toBe(500);
    expect(handler).not.toHaveBeenCalled();
  });

  it('runs nothing for a route a later onRoute hook changed after the boot check', async () => {
    const handler = vi.fn(async () => ({}));
    app = Fastify({ logger: false });
    await app.register(adminOperationsPlugin, { registry: REGISTRY, authorize: ALLOW });
    // Runs after the stage's own onRoute hook, so the boot check saw the
    // route as declared.
    app.addHook('onRoute', (route) => {
      if (route.url === '/admin/v1-rc.0/swapped') {
        route.config = { ...route.config, operation: 'widgets.policies.update' };
      }
      if (route.url === '/admin/v1-rc.0/cleared') {
        route.config = {};
      }
    });
    for (const url of ['/admin/v1-rc.0/swapped', '/admin/v1-rc.0/cleared']) {
      app.get(
        url,
        { config: { operation: 'widgets.get' }, schema: schemaOf(READ_OPERATION) },
        handler
      );
    }
    await app.ready();
    for (const url of ['/admin/v1-rc.0/swapped', '/admin/v1-rc.0/cleared']) {
      const response = await app.inject({ method: 'GET', url });
      expect(response.statusCode, url).toBe(500);
    }
    expect(handler).not.toHaveBeenCalled();
  });

  // What runs is what was classified: no stage after the classification may
  // change the parts of the request classify read.
  it('freezes the parameters, query and body it classified', async () => {
    const seen: unknown[] = [];
    const attempts: Record<string, string> = {};
    app = Fastify({ logger: false });
    await app.register(adminOperationsPlugin, { registry: REGISTRY, authorize: ALLOW });
    app.patch(
      '/admin/v1-rc.0/widgets/policies',
      { config: { operation: 'widgets.policies.update' }, schema: schemaOf(PATCH_OPERATION) },
      async (request) => {
        const tryTo = (name: string, attempt: () => void) => {
          try {
            attempt();
            attempts[name] = 'ran';
          } catch (error) {
            attempts[name] = (error as Error).name;
          }
        };
        tryTo('add a body member', () => {
          (request.body as Record<string, unknown>).password = 1;
        });
        tryTo('replace the body', () => {
          (request as unknown as Record<string, unknown>).body = { password: 1 };
        });
        tryTo('change a query member', () => {
          (request.query as Record<string, unknown>).dryRun = 'false';
        });
        tryTo('replace the parameters', () => {
          (request as unknown as Record<string, unknown>).params = {};
        });
        seen.push(request.body, requestClassification(request).class);
        return {};
      }
    );
    const response = await app.inject({
      method: 'PATCH',
      url: '/admin/v1-rc.0/widgets/policies?dryRun=true',
      headers: IF_MATCH,
      payload: { lifespan: 600 },
    });
    expect(response.statusCode).toBe(200);
    expect(seen).toEqual([{ lifespan: 600 }, 'write']);
    expect(attempts).toEqual({
      'add a body member': 'TypeError',
      'replace the body': 'TypeError',
      'change a query member': 'TypeError',
      'replace the parameters': 'TypeError',
    });
  });

  it('runs nothing when a later stage changes the classified body', async () => {
    const handler = vi.fn(async () => ({}));
    app = Fastify({ logger: false });
    await app.register(adminOperationsPlugin, { registry: REGISTRY, authorize: ALLOW });
    app.addHook('preHandler', async (request) => {
      (request.body as Record<string, unknown>).password = 1;
    });
    app.patch(
      '/admin/v1-rc.0/widgets/policies',
      { config: { operation: 'widgets.policies.update' }, schema: schemaOf(PATCH_OPERATION) },
      handler
    );
    const response = await app.inject({
      method: 'PATCH',
      url: '/admin/v1-rc.0/widgets/policies',
      headers: IF_MATCH,
      payload: { lifespan: 600 },
    });
    expect(response.statusCode).toBe(500);
    expect(handler).not.toHaveBeenCalled();
  });

  it('runs nothing when the state cannot be read', async () => {
    const handler = vi.fn(async () => ({}));
    const failing = defineOperation({
      ...PATCH_OPERATION,
      loadState: async () => {
        throw new Error('database unavailable');
      },
    });
    app = Fastify({ logger: false });
    await app.register(adminOperationsPlugin, {
      registry: createOperationRegistry([failing] as AdminOperation[], { reserved: [] }),
      authorize: ALLOW,
    });
    app.patch(
      '/admin/v1-rc.0/widgets/policies',
      { config: { operation: failing.id }, schema: schemaOf(failing as AdminOperation) },
      handler
    );
    const response = await app.inject({
      method: 'PATCH',
      url: '/admin/v1-rc.0/widgets/policies',
      headers: IF_MATCH,
      payload: { lifespan: 1 },
    });
    expect(response.statusCode).toBe(500);
    expect(handler).not.toHaveBeenCalled();
  });

  it('leaves a request that matches no route alone', async () => {
    const instance = await withFixtureRoutes();
    const response = await instance.inject({ method: 'GET', url: '/admin/v1-rc.0/unknown' });
    expect(response.statusCode).toBe(404);
  });

  it('never gives a request without a classification a default', () => {
    expect(() =>
      requestClassification({ adminOperation: null } as unknown as FastifyRequest)
    ).toThrow(/no admin operation classification/);
  });
});

describe('the state version, If-Match and the authorization stage (#508)', () => {
  /** A listener with the PATCH route, whose handler records its classification. */
  async function patchListener(
    seen: OperationClassification[],
    authorize: (request: FastifyRequest, classification: OperationClassification) => unknown = ALLOW
  ) {
    app = Fastify({ logger: false });
    await app.register(adminOperationsPlugin, { registry: REGISTRY, authorize });
    await app.register(async (scope) => {
      scope.addContentTypeParser(
        'application/octet-stream',
        { parseAs: 'buffer' },
        (_request, body, done) => done(null, body)
      );
      scope.patch(
        '/admin/v1-rc.0/widgets/policies',
        { config: { operation: PATCH_OPERATION.id }, schema: schemaOf(PATCH_OPERATION) },
        async (request) => {
          seen.push(requestClassification(request));
          return { ok: true };
        }
      );
    });
    return app;
  }

  const patch = (instance: FastifyInstance, headers: Record<string, string> = IF_MATCH) =>
    instance.inject({
      method: 'PATCH',
      url: '/admin/v1-rc.0/widgets/policies',
      headers,
      payload: { lifespan: 1 },
    });

  it('refuses to load without an authorization stage', async () => {
    app = Fastify({ logger: false });
    await expect(
      app.register(adminOperationsPlugin, { registry: REGISTRY } as unknown as Parameters<
        typeof adminOperationsPlugin
      >[1])
    ).rejects.toThrow(/needs authorize\(request, classification\)/);
  });

  it('puts the version of the state it classified against on the classification', async () => {
    const seen: OperationClassification[] = [];
    const instance = await patchListener(seen);
    expect((await patch(instance)).statusCode).toBe(200);
    expect((await patch(instance, { 'if-match': '"v1", "v2"' })).statusCode).toBe(200);
    expect((await patch(instance, { 'if-match': '*' })).statusCode).toBe(200);
    expect(seen.map((classification) => classification.stateVersion)).toEqual(['v2', 'v2', 'v2']);
  });

  it('answers 428 before reading the state when the request has no If-Match', async () => {
    const seen: OperationClassification[] = [];
    const loadState = vi.fn(async () => ({ minScore: 2 }));
    const authorize = vi.fn();
    const operation = defineOperation({ ...PATCH_OPERATION, loadState });
    app = Fastify({ logger: false });
    await app.register(adminOperationsPlugin, {
      registry: createOperationRegistry([operation] as AdminOperation[], { reserved: [] }),
      authorize,
    });
    app.patch(
      '/admin/v1-rc.0/widgets/policies',
      { config: { operation: operation.id }, schema: schemaOf(operation as AdminOperation) },
      async (request) => {
        seen.push(requestClassification(request));
        return { ok: true };
      }
    );
    expect((await patch(app, {})).statusCode).toBe(428);
    expect(loadState).not.toHaveBeenCalled();
    expect(authorize).not.toHaveBeenCalled();
    expect(seen).toEqual([]);
    // An operation that reads no state needs none: the GET tests above send none.
  });

  // The route keeps If-Match required in its schema (and so in OpenAPI);
  // the stage answers 428 before validation would answer 400.
  it('answers 428, not 400, when the route requires If-Match in its header schema', async () => {
    const handler = vi.fn(async () => ({ ok: true }));
    app = Fastify({ logger: false });
    await app.register(adminOperationsPlugin, { registry: REGISTRY, authorize: ALLOW });
    app.patch(
      '/admin/v1-rc.0/widgets/policies',
      {
        config: { operation: PATCH_OPERATION.id },
        schema: {
          ...schemaOf(PATCH_OPERATION),
          headers: {
            type: 'object',
            required: ['if-match'],
            properties: { 'if-match': { type: 'string' } },
          },
        },
      },
      handler
    );
    expect((await patch(app, {})).statusCode).toBe(428);
    expect((await patch(app)).statusCode).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('answers 412 before the handler when If-Match names another version', async () => {
    const seen: OperationClassification[] = [];
    const authorize = vi.fn();
    const instance = await patchListener(seen, authorize);
    for (const ifMatch of ['"v1"', 'W/"v2"', 'v2']) {
      expect((await patch(instance, { 'if-match': ifMatch })).statusCode, ifMatch).toBe(412);
    }
    expect(seen).toEqual([]);
    expect(authorize).not.toHaveBeenCalled();
  });

  it('authorizes every classified request before the handler, and a refusal runs nothing', async () => {
    const seen: OperationClassification[] = [];
    const authorize = vi.fn((_request: FastifyRequest, classification: OperationClassification) => {
      if (classification.class === 'security') {
        throw Object.assign(new Error('forbidden'), { statusCode: 403 });
      }
    });
    const instance = await patchListener(seen, authorize);
    expect((await patch(instance)).statusCode).toBe(200);
    expect(authorize).toHaveBeenCalledTimes(1);
    expect(authorize.mock.calls[0][1]).toBe(seen[0]);

    const response = await instance.inject({
      method: 'PATCH',
      url: '/admin/v1-rc.0/widgets/policies',
      headers: IF_MATCH,
      payload: { password: 'x' },
    });
    expect(response.statusCode).toBe(403);
    expect(seen).toHaveLength(1);
  });

  it('carries the digest of a binary body, which cannot be frozen', async () => {
    const seen: OperationClassification[] = [];
    const instance = await patchListener(seen);
    const bytes = Buffer.from('a realm file');
    const response = await instance.inject({
      method: 'PATCH',
      url: '/admin/v1-rc.0/widgets/policies',
      headers: { 'content-type': 'application/octet-stream', ...IF_MATCH },
      payload: bytes,
    });
    expect(response.statusCode).toBe(200);
    expect(seen[0].bodyDigest).toBe(createHash('sha256').update(bytes).digest('base64url'));
    expect((await patch(instance)).statusCode).toBe(200);
    expect(seen[1].bodyDigest).toBeNull();
  });
});
