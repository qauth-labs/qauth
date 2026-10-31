import {
  AUTH_METHOD_CONTRACT,
  type AuthMethod,
  AuthMethodConfigError,
  AuthMethodContractError,
  AuthMethodFaultError,
  type AuthMethodRoute,
  completeUpstreamStep,
  createPasswordProvider,
  UPSTREAM_STEP_URN,
} from '@qauth-labs/server-federation';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  type AuthMethodRouteHost,
  authMethodRoutesPlugin,
  mountAuthMethodRoutes,
} from './auth-method-routes';
import { createConfiguredProviders } from './configured-providers';
import { federationPlugin } from './federation-plugin';

/**
 * The route mount (#599): a method's routes go under `/upstream/<type>` on the
 * realm host and nowhere else. The method is a minimal inline one; the
 * contract's own sample and its kit are tested in `server-federation`.
 */

// A careless callback: it hands back a result for anything. The host's own
// checks are what these tests are about.
const callbackHandle = vi.fn(async (request: { transaction: unknown; query: unknown }) => ({
  kind: 'result' as const,
  result: { query: request.query },
}));

function method(type = 'oidc_corp', routes?: readonly AuthMethodRoute[]): AuthMethod {
  return {
    contract: AUTH_METHOD_CONTRACT,
    type,
    id: 'corp',
    display: { name: 'Corp' },
    // A schema with the one member the registry checks; this lib does not
    // depend on zod.
    configSchema: {
      safeParse: (value: unknown) => ({ success: true, data: value }),
    } as unknown as AuthMethod['configSchema'],
    steps: [UPSTREAM_STEP_URN],
    start: async () => ({ redirectTo: 'https://idp.example/authorize', transaction: {} }),
    verify: async () => Promise.reject(new Error('not a result of this method')),
    extractAttributes: () => [],
    routes: routes ?? [
      { kind: 'callback', method: 'GET', path: '/callback', handle: callbackHandle },
      {
        kind: 'bounce',
        method: 'POST',
        path: '/callback',
        handle: async (request) => ({
          to: '/callback',
          query: { code: String(request.form['code']), state: String(request.form['state']) },
        }),
      },
    ],
  };
}

function host(): AuthMethodRouteHost & {
  complete: ReturnType<typeof vi.fn>;
  takeTransaction: ReturnType<typeof vi.fn>;
} {
  return {
    contextFor: vi.fn(async () => ({}) as never),
    takeTransaction: vi.fn(async () => ({ state: 'kept' })),
    complete: vi.fn(async (_method, outcome, _request, reply) => reply.send({ handed: outcome })),
  };
}

describe('AuthMethod routes', () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
    callbackHandle.mockClear();
  });

  async function boot(
    methods: readonly AuthMethod[],
    routeHost: AuthMethodRouteHost = host()
  ): Promise<{ app: FastifyInstance; urls: string[] }> {
    const urls: string[] = [];
    app = Fastify({ logger: false });
    app.addContentTypeParser(
      'application/x-www-form-urlencoded',
      { parseAs: 'string' },
      (_request, body, done) => done(null, Object.fromEntries(new URLSearchParams(String(body))))
    );
    app.addHook('onRoute', (route) => {
      urls.push(`${String(route.method)} ${route.url} ${JSON.stringify(route.config)}`);
    });
    await app.register(federationPlugin, {
      providers: createConfiguredProviders({
        walletFederationEnabled: false,
        verifierProfileId: undefined,
        cryptoCapabilities: { signingAlgs: ['EdDSA'], responseEncryption: false },
        authMethods: methods,
      }),
    });
    await app.register(authMethodRoutesPlugin, { host: routeHost });
    await app.ready();
    return { app, urls };
  }

  it("mounts a method's routes under /upstream/<type> on the realm host, and nothing else", async () => {
    const booted = await boot([method('oidc_corp'), method('oidc_other')]);
    expect(booted.urls).toEqual([
      'GET /upstream/oidc_corp/callback {"surface":"browser"}',
      'POST /upstream/oidc_corp/callback {"surface":"browser"}',
      'GET /upstream/oidc_other/callback {"surface":"browser"}',
      'POST /upstream/oidc_other/callback {"surface":"browser"}',
    ]);
    // The password provider sits beside them in the registry, with no route.
    expect(booted.app.providerRegistry.resolve('password')).toBeDefined();
    expect(booted.app.providerRegistry.authMethods().map((m) => m.type)).toEqual([
      'oidc_corp',
      'oidc_other',
    ]);
  });

  it('mounts nothing when no method is registered', async () => {
    const booted = await boot([]);
    expect(booted.urls).toEqual([]);
  });

  it('refuses at mount a method whose route would leave its prefix, even one that skipped the registry', () => {
    const fastify = Fastify({ logger: false });
    for (const path of ['/../../oauth/token', '/%2e%2e/oauth/token', '/:param', 'callback']) {
      const escaping = method('oidc_corp', [
        { kind: 'callback', method: 'GET', path, handle: callbackHandle },
      ]);
      expect(() => mountAuthMethodRoutes(fastify, escaping, host())).toThrow(
        AuthMethodContractError
      );
    }
  });

  it('fails the boot when a registered method breaks the contract', async () => {
    const broken = method('oidc_corp', [
      { kind: 'callback', method: 'GET', path: '/../admin', handle: callbackHandle },
    ]);
    await expect(boot([broken])).rejects.toThrow(AuthMethodContractError);
  });

  it('fails the boot for an authMethods entry with no contract member, under a reserved type', async () => {
    // Without the check it would register as a plain provider: as the wallet
    // provider itself, while wallet federation is off.
    const impostor = {
      type: 'wallet',
      verify: async () => ({ externalSub: 'anyone', assuranceLevel: 'high', rawClaims: {} }),
      extractAttributes: () => [],
    };
    await expect(boot([impostor as unknown as AuthMethod])).rejects.toThrow(
      AuthMethodContractError
    );
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: false,
        verifierProfileId: undefined,
        cryptoCapabilities: { signingAlgs: ['EdDSA'], responseEncryption: false },
        authMethods: [impostor as unknown as AuthMethod],
      })
    ).toThrow(/type wallet is reserved/);
  });

  it('fails the boot when a method takes the type of another', async () => {
    await expect(boot([method('oidc_corp'), method('oidc_corp')])).rejects.toThrow(
      /already registered/
    );
  });

  it('hands the callback the query and the taken transaction, and the engine its outcome', async () => {
    const routeHost = host();
    const booted = await boot([method()], routeHost);

    const response = await booted.app.inject({
      method: 'GET',
      url: '/upstream/oidc_corp/callback?code=c1&state=s1&state=s2',
      headers: { cookie: '__Host-qauth_flow=secret-flow', authorization: 'Bearer token' },
    });

    expect(response.statusCode).toBe(200);
    expect(routeHost.takeTransaction).toHaveBeenCalledTimes(1);
    const [request] = callbackHandle.mock.calls[0];
    // The method sees parameters only: no header, no cookie.
    expect(Object.keys(request).sort()).toEqual(['form', 'method', 'query', 'transaction']);
    expect(request).toEqual({
      method: 'GET',
      query: { code: 'c1', state: ['s1', 's2'] },
      form: {},
      transaction: { state: 'kept' },
    });
    expect(response.json()).toEqual({
      handed: { kind: 'result', result: { query: { code: 'c1', state: ['s1', 's2'] } } },
    });
  });

  it('answers transaction_mismatch itself when no transaction is pending, and never runs the method', async () => {
    const routeHost = host();
    routeHost.takeTransaction.mockResolvedValue(undefined);
    const booted = await boot([method()], routeHost);

    const response = await booted.app.inject({
      method: 'GET',
      url: '/upstream/oidc_corp/callback?code=attacker&state=forged',
    });

    expect(response.json()).toEqual({ handed: { kind: 'failed', reason: 'transaction_mismatch' } });
    expect(callbackHandle).not.toHaveBeenCalled();
    expect(routeHost.contextFor).not.toHaveBeenCalled();
  });

  it.each([
    ['null, as a cache answers a missing key', null],
    ['a string', 'state-value'],
  ])('treats a taken transaction that is %s as none', async (_label, taken) => {
    const routeHost = host();
    routeHost.takeTransaction.mockResolvedValue(taken);
    const booted = await boot([method()], routeHost);
    const response = await booted.app.inject({
      method: 'GET',
      url: '/upstream/oidc_corp/callback?code=attacker',
    });
    expect(response.json()).toEqual({ handed: { kind: 'failed', reason: 'transaction_mismatch' } });
    expect(callbackHandle).not.toHaveBeenCalled();
  });

  it('refuses at mount a method under a reserved type, even one that skipped the registry', () => {
    const fastify = Fastify({ logger: false });
    for (const type of ['wallet', 'password', 'self_reported']) {
      expect(() => mountAuthMethodRoutes(fastify, { ...method(), type }, host())).toThrow(
        AuthMethodContractError
      );
    }
  });

  it('hands a POST callback only a urlencoded form, never a JSON body', async () => {
    const routes: AuthMethodRoute[] = [
      { kind: 'callback', method: 'GET', path: '/callback', handle: callbackHandle },
      { kind: 'callback', method: 'POST', path: '/post', handle: callbackHandle },
    ];
    const booted = await boot([method('oidc_corp', routes)]);
    await booted.app.inject({
      method: 'POST',
      url: '/upstream/oidc_corp/post',
      headers: { 'content-type': 'application/json' },
      payload: { code: 'c1', state: 's1' },
    });
    await booted.app.inject({
      method: 'POST',
      url: '/upstream/oidc_corp/post',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: 'code=c2&state=s2',
    });
    expect(
      callbackHandle.mock.calls.map(([request]) => (request as unknown as { form: unknown }).form)
    ).toEqual([{}, { code: 'c2', state: 's2' }]);
  });

  it('drops parameters past the caps', async () => {
    const booted = await boot([method()]);
    const many = Array.from({ length: 80 }, (_, i) => `p${i}=v`).join('&');
    await booted.app.inject({
      method: 'GET',
      url: `/upstream/oidc_corp/callback?long=${'x'.repeat(8193)}&${many}`,
    });
    const [request] = callbackHandle.mock.calls[0];
    const query = (request as { query: Record<string, unknown> }).query;
    expect(query['long']).toBeUndefined();
    expect(Object.keys(query)).toHaveLength(64);
  });

  it("bounces a form_post to the method's own GET route on the same origin, with no transaction taken", async () => {
    const routeHost = host();
    const booted = await boot([method()], routeHost);

    const response = await booted.app.inject({
      method: 'POST',
      url: '/upstream/oidc_corp/callback',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: 'code=c1&state=s1',
    });

    expect(response.statusCode).toBe(303);
    expect(response.headers['location']).toBe('/upstream/oidc_corp/callback?code=c1&state=s1');
    expect(response.headers['cache-control']).toBe('no-store');
    expect(routeHost.takeTransaction).not.toHaveBeenCalled();
    expect(routeHost.complete).not.toHaveBeenCalled();
    // A bounce holds no egress client and no signer: it gets no context.
    expect(routeHost.contextFor).not.toHaveBeenCalled();
  });

  it.each([
    ['an absolute URL', { to: 'https://evil.example/', query: {} }],
    ['a path outside the prefix', { to: '/../../oauth/authorize', query: {} }],
    ['a route the method does not have', { to: '/elsewhere', query: {} }],
    ['its own POST route', { to: '/start', query: {} }],
    ['its own GET bounce route', { to: '/loop', query: {} }],
    ['a query that is not strings', { to: '/callback', query: { code: 1 } }],
    ['a query that is a list', { to: '/callback', query: ['ab'] }],
    ['a query that is a class instance', { to: '/callback', query: new URL('https://x.example') }],
    ['nothing', undefined],
  ])('never bounces to %s, and hands the fault to the engine', async (_label, bounce) => {
    const routes: AuthMethodRoute[] = [
      { kind: 'callback', method: 'GET', path: '/callback', handle: callbackHandle },
      { kind: 'bounce', method: 'POST', path: '/start', handle: async () => bounce as never },
      { kind: 'bounce', method: 'GET', path: '/loop', handle: async () => bounce as never },
    ];
    const routeHost = host();
    const booted = await boot([method('oidc_corp', routes)], routeHost);
    const response = await booted.app.inject({ method: 'POST', url: '/upstream/oidc_corp/start' });
    expect(response.headers['location']).toBeUndefined();
    expect(routeHost.complete).toHaveBeenCalledTimes(1);
    const [, outcome] = routeHost.complete.mock.calls[0];
    expect(outcome).toBeInstanceOf(AuthMethodFaultError);
    expect((outcome as AuthMethodFaultError).methodType).toBe('oidc_corp');
    expect(routeHost.takeTransaction).not.toHaveBeenCalled();
  });

  it('hands a bounce route that throws to the engine as a fault with its cause', async () => {
    const thrown = new Error('bounce broke');
    const routes: AuthMethodRoute[] = [
      { kind: 'callback', method: 'GET', path: '/callback', handle: callbackHandle },
      {
        kind: 'bounce',
        method: 'POST',
        path: '/callback',
        handle: async () => {
          throw thrown;
        },
      },
    ];
    const routeHost = host();
    const booted = await boot([method('oidc_corp', routes)], routeHost);
    const response = await booted.app.inject({
      method: 'POST',
      url: '/upstream/oidc_corp/callback',
    });
    expect(response.statusCode).toBe(200);
    const [, outcome] = routeHost.complete.mock.calls[0];
    expect(outcome).toBeInstanceOf(AuthMethodFaultError);
    expect((outcome as Error).cause).toBe(thrown);
  });

  it('hands a callback that throws after the transaction was taken to the engine as a fault', async () => {
    const thrown = new TypeError('handler broke');
    const routes: AuthMethodRoute[] = [
      {
        kind: 'callback',
        method: 'GET',
        path: '/callback',
        handle: () => {
          throw thrown;
        },
      },
    ];
    const routeHost = host();
    const corp = method('oidc_corp', routes);
    const booted = await boot([corp], routeHost);
    const response = await booted.app.inject({
      method: 'GET',
      url: '/upstream/oidc_corp/callback?code=c1&state=s1',
    });
    // The host's completion answers, not a raw 500.
    expect(response.statusCode).toBe(200);
    expect(routeHost.takeTransaction).toHaveBeenCalledTimes(1);
    const [, outcome] = routeHost.complete.mock.calls[0];
    expect(outcome).toBeInstanceOf(AuthMethodFaultError);
    expect((outcome as Error).message).toBe('AuthMethod oidc_corp: the callback route threw');
    expect((outcome as Error).cause).toBe(thrown);
    // The engine ends the step with that fault, as with any other fault.
    await expect(completeUpstreamStep(corp, outcome)).rejects.toBe(outcome);
  });

  it('hands a context that could not be built to the engine as a fault, and never runs the method', async () => {
    const routeHost = host();
    const refused = new AuthMethodConfigError('oidc_corp', ['clientSecret: too_small']);
    routeHost.contextFor = vi.fn(async () => Promise.reject(refused));
    const booted = await boot([method()], routeHost);
    const response = await booted.app.inject({
      method: 'GET',
      url: '/upstream/oidc_corp/callback?code=c1&state=s1',
    });
    expect(response.statusCode).toBe(200);
    expect(callbackHandle).not.toHaveBeenCalled();
    const [, outcome] = routeHost.complete.mock.calls[0];
    expect(outcome).toBeInstanceOf(AuthMethodFaultError);
    expect((outcome as Error).message).toBe(
      "AuthMethod oidc_corp: the method's context could not be built"
    );
    expect((outcome as Error).cause).toBe(refused);
  });

  it('keeps a parameter named __proto__ a parameter', async () => {
    const booted = await boot([method()]);
    await booted.app.inject({
      method: 'GET',
      url: '/upstream/oidc_corp/callback?__proto__=x&state=s',
    });
    const [request] = callbackHandle.mock.calls[0];
    expect(Object.getPrototypeOf(request.query)).toBeNull();
    // Built with defineProperty: an own member named __proto__, as the query
    // the handler sees holds it.
    const expected = Object.defineProperty(Object.create(null), '__proto__', {
      value: 'x',
      enumerable: true,
      writable: true,
      configurable: true,
    }) as Record<string, string>;
    expected['state'] = 's';
    expect(request.query).toEqual(expected);
  });

  it('registers a method beside the password provider through the single registration point', () => {
    const corp = method();
    const providers = createConfiguredProviders({
      walletFederationEnabled: false,
      verifierProfileId: undefined,
      cryptoCapabilities: { signingAlgs: ['EdDSA'], responseEncryption: false },
      authMethods: [corp],
    });
    expect(providers.map((provider) => provider.type)).toEqual(['password', 'oidc_corp']);
    expect(providers[1]).toBe(corp);
    expect(createPasswordProvider().type).toBe(providers[0].type);
  });
});
