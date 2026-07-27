import {
  hashOid4vpState,
  OID4VP_REJECTION_DESCRIPTION,
} from '@qauth-labs/fastify-plugin-federation';
import { InvalidRequestError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Route tests for the OID4VP `direct_post` response endpoint (#233).
 *
 * Two properties dominate here and are asserted repeatedly on purpose:
 *   - EVERY refusal is byte-identical on the wire (non-enumerating).
 *   - NOTHING on the accepted path authenticates anyone.
 */

const ISSUER_JWT = 'eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJwaWQifQ.c2ln';
const PRESENTATION = `${ISSUER_JWT}~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0~`;
const VP_TOKEN = JSON.stringify({ pid: [PRESENTATION] });

const STATE = 'state-value';

interface RouteOptions {
  config?: {
    rateLimit?: {
      max?: number;
      timeWindow?: number;
      keyGenerator?: (request: { ip?: string }) => string;
    };
  };
}

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
  routeUrl?: string;
  routeOptions?: RouteOptions;
}

function createFastifyStub() {
  const ctx: TestContext = {};
  /**
   * In-memory stand-in for the Redis-backed session store — the one this
   * endpoint touches, via the wallet-login transport signal (#239).
   *
   * It is decorated deliberately rather than left off: without it,
   * `fastify.sessionUtils` is undefined, the property access throws a TypeError
   * that `publishWalletPresentationSignal`'s try/catch swallows as a warning,
   * and the suite passes while exercising none of the wiring.
   */
  const store = new Map<string, unknown>();

  const fastify: any = {
    withTypeProvider: () => ({
      post: (url: string, opts: RouteOptions, handler: TestContext['handler']) => {
        ctx.routeUrl = url;
        ctx.routeOptions = opts;
        ctx.handler = handler;
        return fastify;
      },
    }),
    repositories: {
      oid4vpRequestStates: {
        redeem: vi.fn(),
      },
      auditLogs: {
        create: vi.fn().mockResolvedValue(undefined),
      },
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

  return { fastify: fastify as FastifyInstance, ctx, store };
}

function makeReply() {
  const sent: unknown[] = [];
  let statusCode = 200;
  const reply = {
    code(c: number) {
      statusCode = c;
      return reply;
    },
    send(body: unknown) {
      sent.push(body);
      return body;
    },
    get statusCode() {
      return statusCode;
    },
  };
  return { reply, sent };
}

function makeRequest(body: Record<string, unknown>) {
  return { body, ip: '203.0.113.9', headers: { 'user-agent': 'test-wallet/1.0' } };
}

function pendingState(overrides: Record<string, unknown> = {}) {
  return {
    id: 'req-state-1',
    realmId: 'realm-1',
    nonce: 'nonce-value',
    verifierProfile: 'oid4vp-1.0-base',
    responseMode: 'direct_post',
    dcqlQuery: { credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] },
    expiresAt: Date.now() + 300_000,
    redeemedAt: Date.now(),
    createdAt: Date.now(),
    stateHash: hashOid4vpState(STATE),
    ...overrides,
  };
}

/**
 * Load the route module against a specific env. The flag is read at
 * REGISTRATION time, so it has to be mocked before the module is imported.
 */
async function loadRoute(env: Record<string, unknown>) {
  vi.resetModules();
  vi.doMock('../../../config/env', () => ({ env }));
  const mod = await import('./response');
  return mod.default;
}

const ENABLED_ENV = {
  WALLET_FEDERATION_ENABLED: true,
  OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
  OID4VP_RESPONSE_RATE_LIMIT: 30,
  OID4VP_RESPONSE_RATE_WINDOW: 60,
};

async function register(env: Record<string, unknown> = ENABLED_ENV) {
  const route = await loadRoute(env);
  const { fastify, ctx, store } = createFastifyStub();
  await route(fastify);
  return { fastify: fastify as any, ctx, store };
}

afterEach(() => {
  vi.doUnmock('../../../config/env');
  vi.resetModules();
});

describe('POST /oid4vp/response — registration gate', () => {
  it('does not register at all when WALLET_FEDERATION_ENABLED is off', async () => {
    const { ctx, fastify } = await register({
      WALLET_FEDERATION_ENABLED: false,
      OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
    });

    expect(ctx.handler).toBeUndefined();
    expect(ctx.routeUrl).toBeUndefined();
    expect(fastify.log.debug).toHaveBeenCalled();
  });

  it('registers POST /response when the flag is on', async () => {
    const { ctx } = await register();

    expect(ctx.routeUrl).toBe('/response');
    expect(ctx.handler).toBeDefined();
  });

  it('carries an IP-scoped per-route rate limit (the endpoint is unauthenticated)', async () => {
    // Without this the only bound on an anonymous caller sweeping candidate
    // `state` values is the global default. Same shape as every other
    // unauthenticated surface in this app (/oauth/token, /auth/login).
    const { ctx } = await register();
    const rateLimit = ctx.routeOptions?.config?.rateLimit;

    expect(rateLimit).toBeDefined();
    expect(rateLimit?.max).toBe(30);
    // Configured in seconds, handed to @fastify/rate-limit in milliseconds.
    expect(rateLimit?.timeWindow).toBe(60 * 1000);
    expect(rateLimit?.keyGenerator?.({ ip: '203.0.113.7' })).toBe('203.0.113.7');
    expect(rateLimit?.keyGenerator?.({ ip: undefined })).toBe('unknown');
  });

  it('takes the limit and window from configuration, not from a hardcoded literal', async () => {
    const { ctx } = await register({
      ...ENABLED_ENV,
      OID4VP_RESPONSE_RATE_LIMIT: 7,
      OID4VP_RESPONSE_RATE_WINDOW: 120,
    });
    const rateLimit = ctx.routeOptions?.config?.rateLimit;

    expect(rateLimit?.max).toBe(7);
    expect(rateLimit?.timeWindow).toBe(120 * 1000);
  });
});

describe('POST /oid4vp/response — accepted submission', () => {
  let fastify: any;
  let handler: NonNullable<TestContext['handler']>;

  beforeEach(async () => {
    const registered = await register();
    fastify = registered.fastify;
    handler = registered.ctx.handler as NonNullable<TestContext['handler']>;
    fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(pendingState());
  });

  it('redeems by state HASH, never by the raw state', async () => {
    const { reply } = makeReply();

    await handler(makeRequest({ vp_token: VP_TOKEN, state: STATE }), reply);

    expect(fastify.repositories.oid4vpRequestStates.redeem).toHaveBeenCalledWith(
      hashOid4vpState(STATE)
    );
    expect(fastify.repositories.oid4vpRequestStates.redeem).not.toHaveBeenCalledWith(STATE);
  });

  it('answers 200 with a bare transport ack (OID4VP §8.3)', async () => {
    const { reply, sent } = makeReply();

    await handler(makeRequest({ vp_token: VP_TOKEN, state: STATE }), reply);

    expect(reply.statusCode).toBe(200);
    expect(sent).toEqual([{}]);
  });

  it('issues no token, session, user or subject of any kind', async () => {
    const { reply, sent } = makeReply();

    await handler(makeRequest({ vp_token: VP_TOKEN, state: STATE }), reply);

    const body = JSON.stringify(sent[0]);

    expect(body).toBe('{}');
    expect(fastify.providerRegistry).toBeUndefined();
    // The stub has no jwtUtils and no users repository at all: if the handler
    // ever tried to mint a token or upsert an identity, this suite would crash
    // rather than quietly pass.
    expect(fastify.repositories.users).toBeUndefined();
  });

  it('audits the accepted submission, marked as NOT an authentication', async () => {
    const { reply } = makeReply();

    await handler(makeRequest({ vp_token: VP_TOKEN, state: STATE }), reply);

    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: null,
        event: 'oid4vp.response.received',
        success: true,
        metadata: expect.objectContaining({
          requestStateId: 'req-state-1',
          presentationCount: 1,
          authenticated: false,
        }),
      })
    );
  });

  it('consumes the state and acks a wallet-reported error, without parsing a vp_token', async () => {
    const { reply, sent } = makeReply();

    await handler(makeRequest({ state: STATE, error: 'access_denied' }), reply);

    expect(fastify.repositories.oid4vpRequestStates.redeem).toHaveBeenCalledOnce();
    expect(reply.statusCode).toBe(200);
    expect(sent).toEqual([{}]);
    // An error response is not an accepted presentation, so it is not audited
    // as one.
    expect(fastify.repositories.auditLogs.create).not.toHaveBeenCalled();
  });

  it('never echoes the wallet-supplied error text back to the wallet', async () => {
    const { reply, sent } = makeReply();

    await handler(makeRequest({ state: STATE, error: '<script>alert(1)</script>' }), reply);

    expect(JSON.stringify(sent[0])).not.toContain('script');
  });
});

/**
 * The join between this endpoint and the wallet-login screens (#239).
 *
 * `direct_post` is the ONLY production writer of the transport signal, and
 * `helpers/wallet-login-flow.ts` reads it back under `wallet-login-signal:` +
 * the SAME `sha256(state)` the request state is stored under. The two halves are
 * tested in two files — `wallet-login.test.ts` writes the key into its fake
 * store by hand and never comes through here — so this is what keeps them
 * joined. Publishing the raw `state`, or moving the publish above the `redeem()`
 * guard, has to fail here rather than in production, where it would hang every
 * wallet sign-in with CI green.
 */
describe('POST /oid4vp/response — the wallet-login transport signal (#239)', () => {
  const SIGNAL_KEY = `wallet-login-signal:${hashOid4vpState(STATE)}`;

  it('publishes `received` for an accepted vp_token, keyed by the state HASH', async () => {
    const { fastify, ctx, store } = await register();
    fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(pendingState());
    const handler = ctx.handler as NonNullable<TestContext['handler']>;
    const { reply } = makeReply();

    await handler(makeRequest({ vp_token: VP_TOKEN, state: STATE }), reply);

    expect(store.get(SIGNAL_KEY)).toMatchObject({ signal: 'received' });
    // The raw `state` is a bearer value and must never become a key — nor may
    // anything else be written by an endpoint nobody authenticated.
    expect([...store.keys()]).toEqual([SIGNAL_KEY]);
  });

  it('publishes `wallet_error` for a wallet-reported error, carrying none of its text', async () => {
    const { fastify, ctx, store } = await register();
    fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(pendingState());
    const handler = ctx.handler as NonNullable<TestContext['handler']>;
    const { reply } = makeReply();

    await handler(makeRequest({ state: STATE, error: 'access_denied' }), reply);

    expect(store.get(SIGNAL_KEY)).toMatchObject({ signal: 'wallet_error' });
    expect(JSON.stringify(store.get(SIGNAL_KEY))).not.toContain('access_denied');
  });

  it('writes NOTHING at all when the state does not redeem', async () => {
    // The signal write is the one store mutation an anonymous POST can cause.
    // It is reachable only AFTER redemption, which is what stops it being an
    // unbounded unauthenticated write primitive.
    const { fastify, ctx, store } = await register();
    fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(undefined);
    const handler = ctx.handler as NonNullable<TestContext['handler']>;
    const { reply } = makeReply();

    await expect(
      handler(makeRequest({ vp_token: VP_TOKEN, state: STATE }), reply)
    ).rejects.toThrow();

    expect(store.size).toBe(0);
    expect(fastify.sessionUtils.setSession).not.toHaveBeenCalled();
  });
});

describe('POST /oid4vp/response — refusals are indistinguishable', () => {
  async function refusalOf(
    body: Record<string, unknown>,
    redeemResult: unknown,
    env: Record<string, unknown> = ENABLED_ENV
  ) {
    const { fastify, ctx } = await register(env);
    fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(redeemResult);
    const handler = ctx.handler as NonNullable<TestContext['handler']>;
    const { reply } = makeReply();

    try {
      await handler(makeRequest(body), reply);
    } catch (error) {
      return { error: error as InvalidRequestError, fastify };
    }

    throw new Error('expected the handler to reject');
  }

  const good = { vp_token: VP_TOKEN, state: STATE };

  it('refuses an unknown / expired / already-redeemed state (all one outcome)', async () => {
    const { error } = await refusalOf(good, undefined);

    // `name`, not `instanceof`: each `vi.resetModules()` re-instantiates the
    // error module, so the class identity legitimately differs from this file's
    // import. The wire contract is the shape, and that is what is asserted.
    expect(error.name).toBe('InvalidRequestError');
    expect(error.statusCode).toBe(400);
    expect(error.message).toBe('invalid_request');
    expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
  });

  it('refuses when the deployment has no VerifierProfile selected (fail-closed)', async () => {
    const { error } = await refusalOf(good, pendingState(), {
      ...ENABLED_ENV,
      OID4VP_VERIFIER_PROFILE: undefined,
    });

    expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
  });

  it('refuses an unusable stored dcql_query with the SAME wire response, not a 500', async () => {
    // The stored query is server-written, so a parse failure is a data-integrity
    // bug rather than a client error — but it is only detectable AFTER the state
    // has been redeemed. Letting it surface as a distinct status would make it
    // the one response shape only a real, live, unconsumed `state` can produce,
    // handing a state-sweeping attacker the oracle every other path denies.
    const { error } = await refusalOf(
      good,
      pendingState({ dcqlQuery: { credentials: 'not-an-array' } })
    );

    expect(error.name).toBe('InvalidRequestError');
    expect(error.statusCode).toBe(400);
    expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
  });

  it('logs an unusable stored dcql_query at error level, with the row and the cause', async () => {
    // Uniform on the wire must not mean silent: a corrupt row is an operator
    // problem and has to be loud in the log, above the `warn` a routine refusal
    // gets.
    const { fastify } = await refusalOf(good, pendingState({ dcqlQuery: { credentials: 42 } }));

    expect(fastify.log.error).toHaveBeenCalledWith(
      expect.objectContaining({
        err: expect.any(Error),
        requestStateId: 'req-state-1',
        realmId: 'realm-1',
      }),
      expect.stringContaining('dcql_query')
    );
  });

  it('does not audit or authenticate anything when the stored dcql_query is unusable', async () => {
    const { fastify } = await refusalOf(
      good,
      pendingState({ dcqlQuery: { credentials: [{ id: 'pid' }] } })
    );

    expect(fastify.repositories.auditLogs.create).not.toHaveBeenCalled();
  });

  it('refuses when the posture changed between request and response', async () => {
    const { error } = await refusalOf(good, pendingState({ verifierProfile: 'haip-1.0' }));

    expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
  });

  it('refuses a malformed vp_token', async () => {
    const { error } = await refusalOf({ vp_token: '{not json', state: STATE }, pendingState());

    expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
  });

  it('refuses a vp_token answering a query we never sent', async () => {
    const { error } = await refusalOf(
      { vp_token: JSON.stringify({ other: [PRESENTATION] }), state: STATE },
      pendingState()
    );

    expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
  });

  it('refuses a submission carrying neither vp_token nor error', async () => {
    const { error } = await refusalOf({ state: STATE }, pendingState());

    expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
  });

  it('renders every refusal identically on the wire', async () => {
    const cases: Array<[Record<string, unknown>, unknown, Record<string, unknown>]> = [
      [good, undefined, ENABLED_ENV],
      [good, pendingState({ verifierProfile: 'haip-1.0' }), ENABLED_ENV],
      [{ vp_token: '{not json', state: STATE }, pendingState(), ENABLED_ENV],
      [{ state: STATE }, pendingState(), ENABLED_ENV],
      // Reached only after the state is redeemed — the case most likely to leak
      // a distinguishable shape, and the reason it is in this set.
      [good, pendingState({ dcqlQuery: { credentials: 'not-an-array' } }), ENABLED_ENV],
      [good, pendingState(), { ...ENABLED_ENV, OID4VP_VERIFIER_PROFILE: undefined }],
    ];

    const wire = new Set<string>();

    for (const [body, redeemResult, env] of cases) {
      const { error } = await refusalOf(body, redeemResult, env);
      wire.add(
        JSON.stringify({
          error: error.message,
          statusCode: error.statusCode,
          code: error.code,
          error_description: error.errorDescription,
        })
      );
    }

    expect(wire.size).toBe(1);
  });

  it('keeps the specific reason in the server log only, and audits nothing', async () => {
    const { error, fastify } = await refusalOf(good, undefined);

    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ reason: expect.stringContaining('state did not redeem') }),
      expect.any(String)
    );
    expect(fastify.repositories.auditLogs.create).not.toHaveBeenCalled();
    expect(JSON.stringify(error)).not.toContain('already consumed');
  });

  it('attempts redemption exactly once per submission, even on refusal', async () => {
    const { fastify } = await refusalOf(good, undefined);

    expect(fastify.repositories.oid4vpRequestStates.redeem).toHaveBeenCalledOnce();
  });
});
