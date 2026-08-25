import { OID4VP_REQUEST_OBJECT_MEDIA_TYPE } from '@qauth-labs/fastify-plugin-federation';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { envMock } = vi.hoisted(() => ({
  envMock: {
    WALLET_FEDERATION_ENABLED: true,
    OID4VP_REQUEST_OBJECT_RATE_LIMIT: 30,
    OID4VP_REQUEST_OBJECT_RATE_WINDOW: 60,
  },
}));

vi.mock('../../../config/env', () => ({ env: envMock }));

import { storeWalletRequestObject } from '../../helpers/wallet-login-flow';
import requestObjectRoute from './request-object';

/**
 * The JAR Request Object Endpoint (RFC 9101, HAIP §5.1, issue #377).
 *
 * Two properties dominate and are asserted repeatedly on purpose:
 *   - it CONSUMES nothing and WRITES nothing, so an anonymous GET is not a
 *     write primitive and a wallet's retry is not a failed login;
 *   - every miss is byte-identical on the wire, so a caller sweeping handles
 *     learns nothing about which ones exist.
 */

const REQUEST_OBJECT = 'eyJhbGciOiJFUzI1NiJ9.eyJjbGllbnRfaWQiOiJ4NTA5X2hhc2g6YWJjIn0.c2ln';

interface RouteOptions {
  readonly config?: {
    readonly rateLimit?: {
      readonly max?: number;
      readonly timeWindow?: number;
      readonly keyGenerator?: (request: { ip?: string }) => string;
    };
  };
}

interface TestContext {
  handler?: (request: never, reply: never) => Promise<unknown>;
  routeUrl?: string;
  routeOptions?: RouteOptions;
  registered: boolean;
}

function createFastifyStub() {
  const ctx: TestContext = { registered: false };
  const store = new Map<string, unknown>();

  const fastify = {
    get: (url: string, opts: RouteOptions, handler: TestContext['handler']) => {
      ctx.registered = true;
      ctx.routeUrl = url;
      ctx.routeOptions = opts;
      ctx.handler = handler;
      return fastify;
    },
    sessionUtils: {
      setSession: vi.fn(async (key: string, value: unknown) => {
        store.set(key, value);
      }),
      getSession: vi.fn(async (key: string) => store.get(key) ?? null),
      deleteSession: vi.fn(async (key: string) => {
        store.delete(key);
      }),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };

  return { fastify: fastify as unknown as FastifyInstance, ctx, store };
}

/** A reply recorder shaped like the subset the handler touches. */
function makeReply() {
  const headers: Record<string, string> = {};
  let statusCode = 200;
  let body: unknown;

  const reply = {
    header(name: string, value: string) {
      headers[name] = value;
      return reply;
    },
    code(value: number) {
      statusCode = value;
      return reply;
    },
    send(value?: unknown) {
      body = value;
      return reply;
    },
    get statusCode() {
      return statusCode;
    },
    get headers() {
      return headers;
    },
    get body() {
      return body;
    },
  };

  return reply;
}

async function invoke(ctx: TestContext, handle: unknown): Promise<ReturnType<typeof makeReply>> {
  const reply = makeReply();
  await (ctx.handler as (r: unknown, p: unknown) => Promise<unknown>)(
    { params: { handle }, ip: '203.0.113.7' },
    reply
  );
  return reply;
}

beforeEach(() => {
  envMock.WALLET_FEDERATION_ENABLED = true;
});

describe('the registration gate', () => {
  it('does not register the endpoint when wallet federation is off', async () => {
    envMock.WALLET_FEDERATION_ENABLED = false;
    const { fastify, ctx } = createFastifyStub();

    await requestObjectRoute(fastify);

    // A 404 because the endpoint does not exist, not because it refused —
    // a default deployment should not grow an unauthenticated GET surface.
    expect(ctx.registered).toBe(false);
  });

  it('registers at /request/:handle, i.e. /oid4vp/request/:handle', async () => {
    const { fastify, ctx } = createFastifyStub();

    await requestObjectRoute(fastify);

    // @fastify/autoload turns the directory name into the prefix, so the route
    // declares the path relative to it. Declaring the prefix here would double it.
    expect(ctx.routeUrl).toBe('/request/:handle');
  });

  it('caps an unauthenticated caller with its own IP-scoped budget', async () => {
    const { fastify, ctx } = createFastifyStub();

    await requestObjectRoute(fastify);

    expect(ctx.routeOptions?.config?.rateLimit?.max).toBe(30);
    expect(ctx.routeOptions?.config?.rateLimit?.timeWindow).toBe(60_000);
    expect(ctx.routeOptions?.config?.rateLimit?.keyGenerator?.({ ip: '203.0.113.7' })).toBe(
      '203.0.113.7'
    );
    expect(ctx.routeOptions?.config?.rateLimit?.keyGenerator?.({})).toBe('unknown');
  });

  it('declares NO response schema, so the JWT is not JSON-quoted', async () => {
    // The Zod serializer compiler is global; a declared `response` schema would
    // emit `"eyJ..."` instead of the compact JWS a wallet parses.
    const { fastify, ctx } = createFastifyStub();

    await requestObjectRoute(fastify);

    expect((ctx.routeOptions as { schema?: Record<string, unknown> }).schema).not.toHaveProperty(
      'response'
    );
  });
});

describe('serving a parked request object', () => {
  it('returns the compact JWS verbatim under the JAR media type', async () => {
    const { fastify, ctx } = createFastifyStub();
    await requestObjectRoute(fastify);
    const handle = await storeWalletRequestObject(fastify, REQUEST_OBJECT);

    const reply = await invoke(ctx, handle);

    expect(reply.statusCode).toBe(200);
    expect(reply.body).toBe(REQUEST_OBJECT);
    expect(reply.headers['Content-Type']).toBe(OID4VP_REQUEST_OBJECT_MEDIA_TYPE);
  });

  it("forbids caching — the body carries this flow's state and nonce", async () => {
    const { fastify, ctx } = createFastifyStub();
    await requestObjectRoute(fastify);
    const handle = await storeWalletRequestObject(fastify, REQUEST_OBJECT);

    expect((await invoke(ctx, handle)).headers['Cache-Control']).toBe('no-store');
  });

  it('CONSUMES nothing, so a wallet may retry the fetch', async () => {
    // A dropped connection or a backgrounded app is a retry, not an attack.
    // Single use is enforced at `state` redemption, not here.
    const { fastify, ctx } = createFastifyStub();
    await requestObjectRoute(fastify);
    const handle = await storeWalletRequestObject(fastify, REQUEST_OBJECT);

    expect((await invoke(ctx, handle)).body).toBe(REQUEST_OBJECT);
    expect((await invoke(ctx, handle)).body).toBe(REQUEST_OBJECT);
    expect(fastify.sessionUtils.deleteSession).not.toHaveBeenCalled();
  });

  it('WRITES nothing on the anonymous path', async () => {
    const { fastify, ctx } = createFastifyStub();
    await requestObjectRoute(fastify);
    const handle = await storeWalletRequestObject(fastify, REQUEST_OBJECT);
    (fastify.sessionUtils.setSession as ReturnType<typeof vi.fn>).mockClear();

    await invoke(ctx, handle);

    expect(fastify.sessionUtils.setSession).not.toHaveBeenCalled();
  });
});

describe('every miss is the same miss', () => {
  const CASES: ReadonlyArray<readonly [string, unknown]> = [
    ['an unknown handle', 'wRDlPCVLwlfHrCsMgTNMHfxYbUpKfANMlQaBcDeFgHi'],
    ['a malformed handle', 'not-a-handle'],
    ['an empty handle', ''],
    ['a non-string handle', 42],
    // Longer than the handler's own bound but inside the router's, so this is
    // the band the in-handler guard actually covers.
    ['an over-long handle', 'x'.repeat(96)],
  ];

  it.each(CASES)('answers %s with a bare 404', async (_label, handle) => {
    const { fastify, ctx } = createFastifyStub();
    await requestObjectRoute(fastify);

    const reply = await invoke(ctx, handle);

    expect(reply.statusCode).toBe(404);
    expect(reply.body).toBeUndefined();
    expect(reply.headers['Content-Type']).toBeUndefined();
  });

  it('answers an unreachable store the same way', async () => {
    const { fastify, ctx } = createFastifyStub();
    await requestObjectRoute(fastify);
    (fastify.sessionUtils.getSession as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('redis down')
    );

    const reply = await invoke(ctx, 'wRDlPCVLwlfHrCsMgTNMHfxYbUpKfANMlQaBcDeFgHi');

    expect(reply.statusCode).toBe(404);
    expect(reply.body).toBeUndefined();
  });

  it('logs the miss server-side without echoing the handle to the wire', async () => {
    const { fastify, ctx } = createFastifyStub();
    await requestObjectRoute(fastify);

    await invoke(ctx, 'not-a-handle');

    expect(fastify.log.warn).toHaveBeenCalled();
  });
});

/**
 * The same route, through REAL Fastify.
 *
 * The stub above proves what the handler decides; this proves what actually goes
 * on the wire, and it exists because of one specific hazard: the Zod serializer
 * compiler is installed globally in `main.ts`, and a route that declared a
 * `response` schema would emit `"eyJ..."` — a JSON-quoted string — instead of the
 * compact JWS a wallet parses. That failure is invisible to a stub, because the
 * stub never serializes anything.
 */
describe('through real Fastify serialization', () => {
  /** The production compilers, registered exactly as `main.ts` registers them. */
  async function buildApp(): Promise<{ app: FastifyInstance; handle: string }> {
    const store = new Map<string, unknown>();
    const app = Fastify({ logger: false });

    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    app.decorate('sessionUtils', {
      setSession: async (key: string, value: unknown) => {
        store.set(key, value);
      },
      getSession: async (key: string) => store.get(key) ?? null,
      deleteSession: async (key: string) => {
        store.delete(key);
      },
    } as never);

    await app.register(requestObjectRoute, { prefix: '/oid4vp' });
    await app.ready();

    const handle = await storeWalletRequestObject(app, REQUEST_OBJECT);
    return { app, handle };
  }

  it('serves the compact JWS as raw bytes, not as a JSON string', async () => {
    const { app, handle } = await buildApp();

    try {
      const response = await app.inject({ method: 'GET', url: `/oid4vp/request/${handle}` });

      expect(response.statusCode).toBe(200);
      // The assertion the stub cannot make: the body IS the token, with no
      // surrounding quotes and no JSON escaping.
      expect(response.body).toBe(REQUEST_OBJECT);
      expect(response.body.startsWith('"')).toBe(false);
      expect(response.headers['content-type']).toBe(OID4VP_REQUEST_OBJECT_MEDIA_TYPE);
      expect(response.headers['cache-control']).toBe('no-store');
    } finally {
      await app.close();
    }
  });

  it('answers an unknown handle with a bare 404 over the wire', async () => {
    const { app } = await buildApp();

    try {
      const response = await app.inject({
        method: 'GET',
        url: '/oid4vp/request/wRDlPCVLwlfHrCsMgTNMHfxYbUpKfANMlQaBcDeFgHi',
      });

      expect(response.statusCode).toBe(404);
      expect(response.body).toBe('');
    } finally {
      await app.close();
    }
  });

  it("is routed under the directory's prefix, not a doubled one", async () => {
    const { app, handle } = await buildApp();

    try {
      // Declaring `/oid4vp/request/:handle` inside the file would produce
      // `/oid4vp/oid4vp/request/:handle` once autoload applies the directory
      // prefix, which is the mistake `routes/consents/index.ts` warns about.
      expect(
        (await app.inject({ method: 'GET', url: `/oid4vp/request/${handle}` })).statusCode
      ).toBe(200);
      expect((await app.inject({ method: 'GET', url: `/request/${handle}` })).statusCode).toBe(404);
    } finally {
      await app.close();
    }
  });

  it('lets the ROUTER reject a param past maxParamLength, before the handler runs', async () => {
    // Fastify's default `maxParamLength` is 100 and this app does not raise it,
    // so a very long candidate is answered 414 by the router and the store is
    // never touched. Recorded rather than normalised to 404: 414 is a function
    // of the URL the caller sent and tells them nothing they did not already
    // know, so it is not the state oracle the 404 path exists to deny.
    const { app } = await buildApp();

    try {
      const response = await app.inject({
        method: 'GET',
        url: `/oid4vp/request/${'x'.repeat(512)}`,
      });

      expect(response.statusCode).toBe(414);
    } finally {
      await app.close();
    }
  });

  it('answers a handle inside the router bound but past the handler bound with the same 404', async () => {
    // The band the in-handler guard covers: long enough that the handler
    // refuses it, short enough that the router does not.
    const { app } = await buildApp();

    try {
      const response = await app.inject({
        method: 'GET',
        url: `/oid4vp/request/${'x'.repeat(96)}`,
      });

      expect(response.statusCode).toBe(404);
      expect(response.body).toBe('');
    } finally {
      await app.close();
    }
  });
});
