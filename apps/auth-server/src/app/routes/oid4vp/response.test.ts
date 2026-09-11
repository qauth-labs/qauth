import { createHash } from 'node:crypto';

import formbody from '@fastify/formbody';
import {
  exportEncryptionPrivateJwk,
  exportEncryptionPublicJwk,
  generateEphemeralEncryptionKeyPair,
} from '@qauth-labs/core-crypto';
import {
  hashOid4vpState,
  OID4VP_REJECTION_DESCRIPTION,
} from '@qauth-labs/fastify-plugin-federation';
import { InvalidRequestError } from '@qauth-labs/shared-errors';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { CompactEncrypt, importJWK, type JWK } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createMockVerifierPki } from '../../../testing/mock-verifier-pki';
import { WALLET_RETURN_CODE_TTL_MS } from '../../constants/security';

/**
 * Route tests for the OID4VP `direct_post` response endpoint (#233).
 *
 * Two properties dominate here and are asserted repeatedly on purpose:
 *   - EVERY refusal is byte-identical on the wire (non-enumerating).
 *   - NOTHING on the accepted path authenticates anyone.
 *
 * A third joined them with the same-device return leg (#405): the 200 body
 * carries a `redirect_uri` with a fresh Response Code for a SAME-DEVICE row
 * and nothing at all for a cross-device one — and the code's plaintext exists
 * nowhere but in that body.
 */

const ISSUER_JWT = 'eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJwaWQifQ.c2ln';
const PRESENTATION = `${ISSUER_JWT}~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0~`;
const VP_TOKEN = JSON.stringify({ pid: [PRESENTATION] });

const STATE = 'state-value';

/** The deployment's public origin, as `JWT_ISSUER` names it (trailing slash canonicalised away). */
const ISSUER = 'https://auth.example.com';

/**
 * The exact wire shape of a Response Code: 32 bytes base64url, no padding —
 * 43 characters, nothing else. Stated here independently of the module that
 * mints it, so the test pins what OID4VP 1.0 §8.2 asks for ("fresh,
 * cryptographically random", ≥ 128 bits) rather than what the code happens
 * to export.
 */
const RESPONSE_CODE_SHAPE = /^[A-Za-z0-9_-]{43}$/;

/**
 * What the repository may see of a Response Code (#405): the SHA-256 hex
 * digest and a deadline — never the code. The argument every redemption in
 * this file is asserted to have been called with.
 */
const RESPONSE_CODE_DIGEST = expect.objectContaining({
  codeHash: expect.stringMatching(/^[0-9a-f]{64}$/),
  codeExpiresAt: expect.any(Number),
});

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
        redeemByEncryptionKid: vi.fn(),
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
    // Chainable, as Fastify's is: the handler sets `Cache-Control` on the
    // acknowledgement and the assertion is on what it was called with.
    header: vi.fn().mockReturnThis(),
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
    // The encrypted-response columns (#377 Phase C), NULL on a plain row.
    responseEncryptionKid: null,
    responseEncryptionPrivateJwk: null,
    responseEncryptionKeyProtection: null,
    // The device choice (#405), as written with the row at flow start. The
    // default is the cross-device (QR) path every test written before #405
    // exercised: no return leg, `{}` on the wire.
    sameDevice: false,
    // The Response Code columns (#405), left NULL on purpose: the handler
    // never reads them back. What it WROTE is asserted on the mock's
    // arguments, and the plaintext it emitted on the body.
    responseCodeHash: null,
    responseCodeExpiresAt: null,
    responseCodeRedeemedAt: null,
    ...overrides,
  };
}

/** A row whose flow was started with `device=this` — the return leg is expected. */
function sameDeviceState(overrides: Record<string, unknown> = {}) {
  return pendingState({ sameDevice: true, ...overrides });
}

/** SHA-256 hex, computed here and not by the module under test. */
function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/**
 * Pull the Response Code out of an acknowledgement body, refusing to guess:
 * the body must carry exactly the `redirect_uri` shape §8.2 describes.
 */
function responseCodeOf(body: unknown): string {
  const redirectUri = (body as { redirect_uri?: unknown }).redirect_uri;
  expect(typeof redirectUri).toBe('string');
  const code = new URL(redirectUri as string).searchParams.get('response_code');
  expect(code).not.toBeNull();
  return code as string;
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

/**
 * The verifier-identity variables at their parsed DEFAULTS (#377).
 *
 * Stated rather than omitted because the handler resolves the profile with the
 * deployment's provisioned material, and `resolveVerifierCertificateChainPems`
 * reads `.length` off the array forms — which the real parsed env always
 * supplies (Zod defaults them to `[]`) and an env stub silently would not. An
 * omission here is a TypeError on every test in this file, not a narrower one.
 */
const VERIFIER_IDENTITY_UNSET = {
  OID4VP_VERIFIER_SIGNING_KEY: undefined,
  OID4VP_VERIFIER_SIGNING_KEY_PATH: undefined,
  OID4VP_VERIFIER_CERTIFICATE_CHAIN: [] as readonly string[],
  OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: [] as readonly string[],
  OID4VP_VERIFIER_TRUST_ANCHORS: [] as readonly string[],
  OID4VP_VERIFIER_TRUST_ANCHORS_PATH: [] as readonly string[],
};

const ENABLED_ENV = {
  WALLET_FEDERATION_ENABLED: true,
  OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
  OID4VP_RESPONSE_RATE_LIMIT: 30,
  OID4VP_RESPONSE_RATE_WINDOW: 60,
  // The origin the same-device `redirect_uri` is built on (#405) — the ONLY
  // source of it; the handler never reads `Host`. With the trailing slash the
  // real config would canonicalise away, so the test proves it does.
  JWT_ISSUER: `${ISSUER}/`,
  // The at-rest secret for the per-request decryption key (#377 Phase C):
  // unset, the default, so a stored key is the JWK document itself.
  OID4VP_RESPONSE_KEY_SECRET: undefined,
  ...VERIFIER_IDENTITY_UNSET,
};

/** Split a concatenated PEM bundle the way the env schema does. */
function pemBlocks(bundle: string): readonly string[] {
  return (bundle.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []).map(
    (pem) => pem.trim()
  );
}

const VERIFIER_PKI = createMockVerifierPki();

/**
 * A deployment that provisioned a verifier identity and selected `haip-1.0`.
 *
 * The only configuration under which this endpoint's `resolveVerifierProfile`
 * call can differ from the boot gate's — see the describe block that uses it.
 */
const HAIP_ENV = {
  ...ENABLED_ENV,
  OID4VP_VERIFIER_PROFILE: 'haip-1.0',
  OID4VP_VERIFIER_SIGNING_KEY: VERIFIER_PKI.signingKeyPem,
  OID4VP_VERIFIER_SIGNING_KEY_PATH: undefined,
  OID4VP_VERIFIER_CERTIFICATE_CHAIN: pemBlocks(VERIFIER_PKI.certificateChainPem),
  OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: [],
  OID4VP_VERIFIER_TRUST_ANCHORS: pemBlocks(VERIFIER_PKI.trustAnchorPem),
  OID4VP_VERIFIER_TRUST_ANCHORS_PATH: [],
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
      hashOid4vpState(STATE),
      RESPONSE_CODE_DIGEST
    );
    expect(fastify.repositories.oid4vpRequestStates.redeem).not.toHaveBeenCalledWith(
      STATE,
      expect.anything()
    );
  });

  it('(OID4VP 1.0 §8.2) answers 200 with a bare transport ack — the empty JSON object — for a cross-device request', async () => {
    // The row is the cross-device default: no return leg, so the object §8.2
    // requires is empty, and the wallet "is not required to perform any
    // further steps". The same-device shape is pinned in its own block.
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
 * The profile is resolved WITH the provisioned material (#377, #379 review).
 *
 * `resolveVerifierProfile` folds in `assertVerifierIdentityProvisioned`, and its
 * third argument defaults to `NO_VERIFIER_MATERIAL` — which THROWS for a profile
 * whose Client Identifier Prefixes need an X.509 identity. `haip-1.0` declares
 * exactly one prefix, `x509_hash`, so this endpoint omitting the argument meant
 * that the moment such a profile could START, every presentation reaching it
 * died on an error the deployment had already proved wrong at boot: the chain
 * validated, `app.ts` threaded it into the provider gate, and this handler asked
 * the same question with the answer missing.
 *
 * It could not bite under `oid4vp-1.0-base` — `redirect_uri` needs no material —
 * which is why nothing caught it. This block is the deployment where it does.
 */
describe('POST /oid4vp/response — the profile gate on a provisioned deployment', () => {
  it('accepts a presentation under haip-1.0 rather than throwing an unprovisioned-profile error', async () => {
    const { fastify, ctx } = await register(HAIP_ENV);
    const handler = ctx.handler as NonNullable<TestContext['handler']>;
    (fastify as any).repositories.oid4vpRequestStates.redeem.mockResolvedValue(
      pendingState({ verifierProfile: 'haip-1.0' })
    );
    const { reply, sent } = makeReply();

    // Without the material threaded this REJECTS with a plain Error — not an
    // `Oid4vpTransportRejection`, so it escapes the uniform-refusal catch and
    // surfaces as a 500 on every single wallet submission.
    await handler(makeRequest({ vp_token: VP_TOKEN, state: STATE }), reply);

    expect(reply.statusCode).toBe(200);
    expect(sent).toEqual([{}]);
  });

  it('still refuses when the deployment provisioned nothing, so the gate is not disabled', async () => {
    // The control. The same profile with no material is a half-configured
    // verifier, and `resolveVerifierProfile` must still refuse it — the fix
    // threads the real answer through, it does not stop asking the question.
    const { fastify, ctx } = await register({
      ...ENABLED_ENV,
      OID4VP_VERIFIER_PROFILE: 'haip-1.0',
    });
    const handler = ctx.handler as NonNullable<TestContext['handler']>;
    (fastify as any).repositories.oid4vpRequestStates.redeem.mockResolvedValue(
      pendingState({ verifierProfile: 'haip-1.0' })
    );
    const { reply } = makeReply();

    await expect(
      handler(makeRequest({ vp_token: VP_TOKEN, state: STATE }), reply)
    ).rejects.toThrow();
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
  const PRESENTATION_KEY = `wallet-presentation:${hashOid4vpState(STATE)}`;

  it('publishes `received` for an accepted vp_token, keyed by the state HASH', async () => {
    const { fastify, ctx, store } = await register();
    fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(pendingState());
    const handler = ctx.handler as NonNullable<TestContext['handler']>;
    const { reply } = makeReply();

    await handler(makeRequest({ vp_token: VP_TOKEN, state: STATE }), reply);

    expect(store.get(SIGNAL_KEY)).toMatchObject({ signal: 'received' });
    // The raw `state` is a bearer value and must never become a key — nor may
    // anything be written by an endpoint nobody authenticated beyond the two
    // digest-addressed records this exchange produces: the transport signal, and
    // the presented bytes parked for the waiting browser (#238).
    expect([...store.keys()].sort()).toEqual([SIGNAL_KEY, PRESENTATION_KEY].sort());
    expect([...store.keys()].some((key) => key.includes(STATE))).toBe(false);
  });

  it('parks the presented credentials for the browser, unvalidated and digest-keyed (#238)', async () => {
    // The endpoint's posture is unchanged by parking them: it decides nothing
    // about the bytes, and everything they will be CHECKED against — the nonce,
    // the client_id, the DCQL query — lives on the browser's flow record, which
    // a wallet cannot reach. See `helpers/wallet-login-flow.ts`.
    const { fastify, ctx, store } = await register();
    fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(pendingState());
    const handler = ctx.handler as NonNullable<TestContext['handler']>;
    const { reply } = makeReply();

    await handler(makeRequest({ vp_token: VP_TOKEN, state: STATE }), reply);

    expect(store.get(PRESENTATION_KEY)).toMatchObject({
      presentations: [expect.objectContaining({ format: 'dc+sd-jwt' })],
    });
  });

  it('parks nothing for a wallet-reported error — there are no bytes to hold', async () => {
    const { fastify, ctx, store } = await register();
    fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(pendingState());
    const handler = ctx.handler as NonNullable<TestContext['handler']>;
    const { reply } = makeReply();

    await handler(makeRequest({ error: 'access_denied', state: STATE }), reply);

    expect(store.get(PRESENTATION_KEY)).toBeUndefined();
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

  it('(OID4VP 1.0 §14.3.2) refuses an unknown / expired / already-redeemed state — only a recent, unconsumed request is honoured (all one outcome)', async () => {
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

/**
 * The ENCRYPTED intake — `response_mode=direct_post.jwt` (#377 Phase C,
 * OID4VP 1.0 §8.3, HAIP 1.0 §5.1).
 *
 * The wallet side (the helpers above) is written against `jose` directly,
 * with no import of the code under test, so what the handler decrypts is what
 * a conformant wallet would have sent rather than a round trip through
 * QAuth's own encoder.
 *
 * Two properties dominate, as on the cleartext path, plus one more that only
 * exists here: the row is CONSUMED by its `kid` before the ciphertext is
 * touched, so a failed decrypt has already spent the request and cannot be
 * retried against a still-live key.
 */
/**
 * The wallet side of the ENCRYPTED intake (`direct_post.jwt`, #377 Phase C),
 * written against `jose` directly with no import of the code under test, so
 * what the handler decrypts is what a conformant wallet would have sent. At
 * module scope because two blocks drive it: the encrypted-intake block below,
 * and the same-device block, which must prove the return leg on BOTH modes.
 */

/** A per-request pair, as the request helper mints and stores it. */
interface MintedPair {
  readonly kid: string;
  readonly publicJwk: JWK;
  /** The `response_encryption_private_jwk` column under `plain`. */
  readonly storedPrivateJwk: string;
}

async function mintPair(): Promise<MintedPair> {
  const pair = await generateEphemeralEncryptionKeyPair({ extractable: true });
  return {
    kid: pair.kid,
    publicJwk: await exportEncryptionPublicJwk(pair),
    storedPrivateJwk: JSON.stringify(await exportEncryptionPrivateJwk(pair)),
  };
}

/** A `direct_post.jwt` row, carrying the pair's private half in the clear. */
function encryptedState(pair: MintedPair, overrides: Record<string, unknown> = {}) {
  return pendingState({
    verifierProfile: 'haip-1.0',
    responseMode: 'direct_post.jwt',
    responseEncryptionKid: pair.kid,
    responseEncryptionPrivateJwk: pair.storedPrivateJwk,
    responseEncryptionKeyProtection: 'plain',
    ...overrides,
  });
}

/**
 * Encrypt an Authorization Response the way a wallet does (§8.3): ECDH-ES to
 * the published key, `kid` echoed in the protected header, the parameters as
 * a JSON object with `vp_token` as an OBJECT.
 */
async function encryptResponse(
  to: JWK,
  payload: Record<string, unknown>,
  header: Record<string, unknown> = {}
): Promise<string> {
  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', kid: to.kid as string, ...header })
    .encrypt(await importJWK(to, 'ECDH-ES'));
}

const SUCCESS_PAYLOAD = { state: STATE, vp_token: { pid: [PRESENTATION] } };

async function registerHaip() {
  const registered = await register(HAIP_ENV);
  return {
    fastify: registered.fastify,
    store: registered.store,
    handler: registered.ctx.handler as NonNullable<TestContext['handler']>,
  };
}

describe('POST /oid4vp/response — the encrypted direct_post.jwt intake (#377 Phase C)', () => {
  it('redeems by the JWE kid — read from the header alone — and never by a state hash', async () => {
    const pair = await mintPair();
    const { fastify, handler } = await registerHaip();
    fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid.mockResolvedValue(
      encryptedState(pair)
    );
    const { reply, sent } = makeReply();

    await handler(
      makeRequest({ response: await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD) }),
      reply
    );

    expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).toHaveBeenCalledWith(
      pair.kid,
      RESPONSE_CODE_DIGEST
    );
    expect(fastify.repositories.oid4vpRequestStates.redeem).not.toHaveBeenCalled();
    expect(reply.statusCode).toBe(200);
    expect(sent).toEqual([{}]);
  });

  it("parks the decrypted presentation and the signal under the ROW's state hash", async () => {
    // No cleartext state was posted; the digest the browser polls on has to
    // come from the row, and the row's digest has to match the `state` inside
    // the ciphertext — which is what makes this the same key the flow record
    // was written under.
    const pair = await mintPair();
    const { fastify, store, handler } = await registerHaip();
    fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid.mockResolvedValue(
      encryptedState(pair)
    );
    const { reply } = makeReply();

    await handler(
      makeRequest({ response: await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD) }),
      reply
    );

    expect(store.get(`wallet-login-signal:${hashOid4vpState(STATE)}`)).toMatchObject({
      signal: 'received',
    });
    expect(store.get(`wallet-presentation:${hashOid4vpState(STATE)}`)).toMatchObject({
      presentations: [expect.objectContaining({ format: 'dc+sd-jwt' })],
    });
  });

  it('audits the accepted encrypted submission exactly as a cleartext one', async () => {
    const pair = await mintPair();
    const { fastify, handler } = await registerHaip();
    fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid.mockResolvedValue(
      encryptedState(pair)
    );
    const { reply } = makeReply();

    await handler(
      makeRequest({ response: await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD) }),
      reply
    );

    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'oid4vp.response.received',
        metadata: expect.objectContaining({
          verifierProfile: 'haip-1.0',
          presentationCount: 1,
          authenticated: false,
        }),
      })
    );
  });

  it('accepts vp_token as a JSON STRING inside the JWE as well as an object', async () => {
    // The form-encoding shape, re-used by a wallet that did not special-case
    // the encrypted mode. Unambiguous, so accepted; one structural parser sees
    // both.
    const pair = await mintPair();
    const { fastify, handler } = await registerHaip();
    fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid.mockResolvedValue(
      encryptedState(pair)
    );
    const { reply } = makeReply();

    await handler(
      makeRequest({
        response: await encryptResponse(pair.publicJwk, { state: STATE, vp_token: VP_TOKEN }),
      }),
      reply
    );

    expect(reply.statusCode).toBe(200);
  });

  it('acks a wallet error carried inside the JWE, signalling wallet_error without its text', async () => {
    const pair = await mintPair();
    const { fastify, store, handler } = await registerHaip();
    fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid.mockResolvedValue(
      encryptedState(pair)
    );
    const { reply, sent } = makeReply();

    await handler(
      makeRequest({
        response: await encryptResponse(pair.publicJwk, { state: STATE, error: 'access_denied' }),
      }),
      reply
    );

    expect(reply.statusCode).toBe(200);
    expect(sent).toEqual([{}]);
    expect(store.get(`wallet-login-signal:${hashOid4vpState(STATE)}`)).toMatchObject({
      signal: 'wallet_error',
    });
    expect(JSON.stringify([...store.values()])).not.toContain('access_denied');
    expect(fastify.repositories.auditLogs.create).not.toHaveBeenCalled();
  });

  describe('refusals are indistinguishable, and the row is always consumed first', () => {
    async function encryptedRefusalOf(
      body: Record<string, unknown>,
      redeemByKidResult: unknown,
      redeemResult: unknown = undefined
    ) {
      const { fastify, store, handler } = await registerHaip();
      fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid.mockResolvedValue(
        redeemByKidResult
      );
      fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(redeemResult);
      const { reply } = makeReply();

      try {
        await handler(makeRequest(body), reply);
      } catch (error) {
        return { error: error as InvalidRequestError, fastify, store };
      }

      throw new Error('expected the handler to reject');
    }

    it('refuses an unknown / expired / already-consumed kid', async () => {
      const pair = await mintPair();
      const { error, fastify } = await encryptedRefusalOf(
        { response: await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD) },
        undefined
      );

      expect(error.name).toBe('InvalidRequestError');
      expect(error.statusCode).toBe(400);
      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
      expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).toHaveBeenCalledOnce();
    });

    it('refuses a JWE with no kid without touching the database at all', async () => {
      // §8.3 makes the kid mandatory when the published key has one, and it is
      // the ONLY correlator. Nothing to look up means nothing is looked up.
      const pair = await mintPair();
      const jwe = await new CompactEncrypt(
        new TextEncoder().encode(JSON.stringify(SUCCESS_PAYLOAD))
      )
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM' })
        .encrypt(await importJWK(pair.publicJwk, 'ECDH-ES'));

      const { error, fastify } = await encryptedRefusalOf({ response: jwe }, encryptedState(pair));

      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
      expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).not.toHaveBeenCalled();
    });

    it('refuses a kid outside the base64url alphabet with the uniform 400, without touching the database', async () => {
      // A NUL in the kid used to reach `WHERE response_encryption_kid = $1`,
      // where Postgres raises 22021 and the route answered 500 — the one status
      // this endpoint promises never to produce on attacker input (#377 Phase C
      // review, F4). No published kid was ever outside base64url, so the value
      // is refused before any query.
      const pair = await mintPair();
      const jwe = await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD, { kid: '\u0000' });

      const { error, fastify } = await encryptedRefusalOf({ response: jwe }, encryptedState(pair));

      expect(error.name).toBe('InvalidRequestError');
      expect(error.statusCode).toBe(400);
      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
      expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).not.toHaveBeenCalled();
    });

    it('refuses garbage that is not a JOSE object, without touching the database', async () => {
      const { error, fastify } = await encryptedRefusalOf({ response: 'not.a.jwe' }, undefined);

      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
      expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).not.toHaveBeenCalled();
    });

    it('CONSUMES the row before a failed decrypt — a wrong key is not a retry', async () => {
      // The invariant this path adds. A response encrypted to some OTHER key
      // but naming this row's kid finds the row, spends it, and then fails to
      // open. Leaving the row live here would let anyone who read
      // client_metadata keep posting until something decrypted.
      const pair = await mintPair();
      const other = await mintPair();
      const jwe = await encryptResponse({ ...other.publicJwk, kid: pair.kid }, SUCCESS_PAYLOAD);

      const { error, fastify, store } = await encryptedRefusalOf(
        { response: jwe },
        encryptedState(pair)
      );

      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
      expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).toHaveBeenCalledWith(
        pair.kid,
        RESPONSE_CODE_DIGEST
      );
      expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).toHaveBeenCalledOnce();
      expect(store.size).toBe(0);
      expect(fastify.log.warn).toHaveBeenCalledWith(
        expect.objectContaining({ reason: expect.stringContaining('did not decrypt') }),
        expect.any(String)
      );
    });

    it('refuses a tampered ciphertext, having consumed the row', async () => {
      const pair = await mintPair();
      const jwe = await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD);
      const segments = jwe.split('.');
      // Flip a character in the ciphertext segment; the AEAD tag refuses it.
      const ciphertext = segments[3] as string;
      segments[3] = `${ciphertext.slice(0, -2)}${ciphertext.endsWith('AA') ? 'BB' : 'AA'}`;

      const { error, fastify } = await encryptedRefusalOf(
        { response: segments.join('.') },
        encryptedState(pair)
      );

      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
      expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).toHaveBeenCalledOnce();
    });

    it('refuses a decrypted state that is not the one the row was issued with (§5.3)', async () => {
      // The binding the kid cannot make (§14.5): the row was found by an index
      // anyone could read; only the state inside the ciphertext ties the
      // response to THIS request, and here it names another.
      const pair = await mintPair();
      const jwe = await encryptResponse(pair.publicJwk, {
        ...SUCCESS_PAYLOAD,
        state: 'some-other-state',
      });

      const { error, fastify, store } = await encryptedRefusalOf(
        { response: jwe },
        encryptedState(pair)
      );

      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
      expect(store.size).toBe(0);
      expect(fastify.log.warn).toHaveBeenCalledWith(
        expect.objectContaining({ reason: expect.stringContaining('§5.3') }),
        expect.any(String)
      );
    });

    it('refuses a decrypted response carrying no state at all', async () => {
      const pair = await mintPair();
      const jwe = await encryptResponse(pair.publicJwk, { vp_token: { pid: [PRESENTATION] } });

      const { error } = await encryptedRefusalOf({ response: jwe }, encryptedState(pair));

      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
    });

    it('refuses a compressed JWE (zip), the CRIME/BREACH shape RFC 8725 §3.5 forbids', async () => {
      const pair = await mintPair();
      const jwe = await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD, { zip: 'DEF' });

      const { error } = await encryptedRefusalOf({ response: jwe }, encryptedState(pair));

      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
    });

    it('refuses an encrypted submission against a row built for plain direct_post', async () => {
      // Cannot correlate in production — a plain row has a NULL kid — but the
      // mode check is stated symmetrically, and a repository that returned such
      // a row must still be refused rather than decrypted with nothing.
      const pair = await mintPair();
      const jwe = await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD);

      const { error } = await encryptedRefusalOf(
        { response: jwe },
        encryptedState(pair, { responseMode: 'direct_post' })
      );

      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
    });

    it('refuses a CLEARTEXT post against a row that asked for direct_post.jwt — and consumes it', async () => {
      // The downgrade: whoever read the signed request object holds its state.
      // Under a profile whose encryption is REQUIRED, posting it plain must not
      // work, and it must not leave the row live for the real wallet either —
      // the exchange was answered in a way its posture forbids, so it is over.
      const pair = await mintPair();

      const { error, fastify } = await encryptedRefusalOf(
        { vp_token: VP_TOKEN, state: STATE },
        undefined,
        encryptedState(pair)
      );

      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
      expect(fastify.repositories.oid4vpRequestStates.redeem).toHaveBeenCalledOnce();
      expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).not.toHaveBeenCalled();
      expect(fastify.log.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          reason: expect.stringContaining("asked for response_mode 'direct_post.jwt'"),
        }),
        expect.any(String)
      );
    });

    /**
     * OID4VP 1.0 §8.3.1: "If a Wallet is unable to generate an encrypted
     * response, it MAY send an error response without encryption as per
     * Section 8.2." (#377 Phase C review, F3.) Two branches, both pinned: the
     * unencrypted ERROR is accepted against an encrypted request — the browser
     * must learn the wallet declined — and an unencrypted PRESENTATION against
     * the same row is still the downgrade.
     */
    it('accepts a CLEARTEXT error against a direct_post.jwt row (§8.3.1), consuming it and signalling wallet_error', async () => {
      const pair = await mintPair();
      const { fastify, store, handler } = await registerHaip();
      fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(encryptedState(pair));
      const { reply, sent } = makeReply();

      await handler(makeRequest({ error: 'access_denied', state: STATE }), reply);

      expect(reply.statusCode).toBe(200);
      expect(sent).toEqual([{}]);
      expect(fastify.repositories.oid4vpRequestStates.redeem).toHaveBeenCalledWith(
        hashOid4vpState(STATE),
        RESPONSE_CODE_DIGEST
      );
      expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).not.toHaveBeenCalled();
      // The browser learns the wallet said no — and nothing else: no bytes are
      // parked, the wallet's own text is not carried, nothing is audited.
      expect(store.get(`wallet-login-signal:${hashOid4vpState(STATE)}`)).toMatchObject({
        signal: 'wallet_error',
      });
      expect(store.get(`wallet-presentation:${hashOid4vpState(STATE)}`)).toBeUndefined();
      expect(JSON.stringify([...store.values()])).not.toContain('access_denied');
      expect(fastify.repositories.auditLogs.create).not.toHaveBeenCalled();
      expect(fastify.log.info).toHaveBeenCalledWith(
        expect.objectContaining({ requestStateId: 'req-state-1' }),
        expect.stringContaining('§8.3.1')
      );
    });

    it('still refuses a CLEARTEXT error that carries a vp_token beside it against a direct_post.jwt row', async () => {
      // §8.3.1 permits an unencrypted ERROR, not an unencrypted presentation
      // with an error label on it. A `vp_token` in the clear is the downgrade
      // whatever else the body says.
      const pair = await mintPair();

      const { error, fastify, store } = await encryptedRefusalOf(
        { error: 'access_denied', vp_token: VP_TOKEN, state: STATE },
        undefined,
        encryptedState(pair)
      );

      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
      expect(fastify.repositories.oid4vpRequestStates.redeem).toHaveBeenCalledOnce();
      expect(store.size).toBe(0);
      expect(fastify.log.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          reason: expect.stringContaining("asked for response_mode 'direct_post.jwt'"),
        }),
        expect.any(String)
      );
    });

    it('refuses an unreadable stored key with the SAME wire response, logging it as a server failure', async () => {
      // Reachable only after redemption, so a distinct status would be the one
      // shape only a real kid can produce — the same reasoning as the corrupt
      // dcql_query case on the cleartext path.
      const pair = await mintPair();
      const jwe = await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD);

      const { error, fastify } = await encryptedRefusalOf(
        { response: jwe },
        encryptedState(pair, { responseEncryptionPrivateJwk: 'not json at all' })
      );

      expect(error.name).toBe('InvalidRequestError');
      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
      expect(fastify.log.error).toHaveBeenCalledWith(
        expect.objectContaining({ err: expect.any(Error), requestStateId: 'req-state-1' }),
        expect.stringContaining('ephemeral encryption key')
      );
    });

    it('refuses a stored key under a protection scheme this build cannot read', async () => {
      const pair = await mintPair();
      const jwe = await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD);

      const { error } = await encryptedRefusalOf(
        { response: jwe },
        encryptedState(pair, { responseEncryptionKeyProtection: 'rot13' })
      );

      expect(error.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
    });

    it('renders every encrypted refusal identically on the wire — and identically to the cleartext ones', async () => {
      const pair = await mintPair();
      const other = await mintPair();
      const good = await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD);

      const cases: Array<[Record<string, unknown>, unknown, unknown]> = [
        [{ response: good }, undefined, undefined],
        [{ response: 'not.a.jwe' }, undefined, undefined],
        [
          {
            response: await encryptResponse({ ...other.publicJwk, kid: pair.kid }, SUCCESS_PAYLOAD),
          },
          encryptedState(pair),
          undefined,
        ],
        [
          { response: await encryptResponse(pair.publicJwk, { ...SUCCESS_PAYLOAD, state: 'x' }) },
          encryptedState(pair),
          undefined,
        ],
        [{ response: good }, encryptedState(pair, { responseMode: 'direct_post' }), undefined],
        [
          { response: good },
          encryptedState(pair, { responseEncryptionPrivateJwk: '{' }),
          undefined,
        ],
        // The cleartext refusals, through the same handler: one wire shape.
        [{ vp_token: VP_TOKEN, state: STATE }, undefined, undefined],
        [{ vp_token: VP_TOKEN, state: STATE }, undefined, encryptedState(pair)],
      ];

      const wire = new Set<string>();

      for (const [body, byKid, byState] of cases) {
        const { error } = await encryptedRefusalOf(body, byKid, byState);
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
  });

  /**
   * The body union is ENCRYPTED-FIRST (#377 Phase C review, F2). OID4VP 1.0 is
   * silent on whether `state` may ride beside `response` under
   * `direct_post.jwt`, so a conformant wallet may send both — and a
   * cleartext-first union parsed that body as cleartext, stripped the JWE,
   * consumed the row by the stray `state`, and refused the login as a mode
   * downgrade. These are schema-level properties, so they are exercised
   * through the schema: the handler sees only what the validator hands it.
   */
  describe('a stray cleartext state beside the JWE', () => {
    it('parses a body carrying response AND state as the ENCRYPTED member, state stripped', async () => {
      const { oid4vpDirectPostRequestSchema } = await import('../../schemas/oid4vp');

      const parsed = oid4vpDirectPostRequestSchema.parse({
        response: 'eyJ.something',
        state: STATE,
        vp_token: VP_TOKEN,
      });

      expect(parsed).toEqual({ response: 'eyJ.something' });
      expect(parsed).not.toHaveProperty('state');
    });

    it('still parses a base-profile body — no response parameter — exactly as before', async () => {
      // The base profile's wire contract, bit for bit: a `direct_post` wallet
      // never sends `response`, so nothing it posts reaches the encrypted
      // member and the cleartext member sees what it always saw.
      const { oid4vpDirectPostRequestSchema } = await import('../../schemas/oid4vp');

      expect(oid4vpDirectPostRequestSchema.parse({ state: STATE, vp_token: VP_TOKEN })).toEqual({
        state: STATE,
        vp_token: VP_TOKEN,
      });
      expect(oid4vpDirectPostRequestSchema.parse({ state: STATE, error: 'access_denied' })).toEqual(
        { state: STATE, error: 'access_denied' }
      );
    });

    it('completes a haip-1.0 login from a JWE posted with a stray cleartext state', async () => {
      // End to end through the validator: the body a conformant wallet MAY
      // send, redeemed by the kid, opened, and bound by the state INSIDE.
      const pair = await mintPair();
      const { fastify, store, handler } = await registerHaip();
      fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid.mockResolvedValue(
        encryptedState(pair)
      );
      const { oid4vpDirectPostRequestSchema } = await import('../../schemas/oid4vp');
      const body = oid4vpDirectPostRequestSchema.parse({
        response: await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD),
        state: STATE,
      });
      const { reply, sent } = makeReply();

      await handler(makeRequest(body), reply);

      expect(reply.statusCode).toBe(200);
      expect(sent).toEqual([{}]);
      expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).toHaveBeenCalledWith(
        pair.kid,
        RESPONSE_CODE_DIGEST
      );
      // The stray state found nothing: the cleartext correlator was never used.
      expect(fastify.repositories.oid4vpRequestStates.redeem).not.toHaveBeenCalled();
      expect(store.get(`wallet-login-signal:${hashOid4vpState(STATE)}`)).toMatchObject({
        signal: 'received',
      });
    });
  });
});

/**
 * The same-device return leg (#405, ADR-013) — OID4VP 1.0 §8.2 / §14.2 /
 * §13.3, HAIP 1.0 §5.1.
 *
 * What the endpoint adds for a row whose flow was started with `device=this`
 * is ONE member on the 200 body: `redirect_uri`, an absolute URI under the
 * issuer carrying a fresh Response Code. Everything else about the endpoint
 * is unchanged and re-asserted here on purpose: the row is still consumed
 * first, the refusals are still uniform, nothing new is written to the
 * store, and nothing is authenticated. Titles cite the section each row of
 * the conformance matrix pins.
 *
 * Both 200 paths (accepted presentation, wallet-reported error) on both modes
 * (cleartext `direct_post`, encrypted `direct_post.jwt`) are driven, because
 * the emitting decision is made once and must hold on all four.
 */
describe('POST /oid4vp/response — the same-device return leg (#405)', () => {
  /** Drive one cleartext submission against a given row; hand back everything observable. */
  async function submit(
    body: Record<string, unknown>,
    row: unknown,
    env: Record<string, unknown> = ENABLED_ENV
  ) {
    const { fastify, ctx, store } = await register(env);
    fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(row);
    const handler = ctx.handler as NonNullable<TestContext['handler']>;
    const { reply, sent } = makeReply();

    await handler(makeRequest(body), reply);

    return { fastify, store, reply, sent, body: sent[0] as Record<string, unknown> };
  }

  /** Drive one encrypted submission against a given `direct_post.jwt` row. */
  async function submitEncrypted(pair: MintedPair, payload: Record<string, unknown>, row: unknown) {
    const { fastify, store, handler } = await registerHaip();
    fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid.mockResolvedValue(row);
    const { reply, sent } = makeReply();

    await handler(makeRequest({ response: await encryptResponse(pair.publicJwk, payload) }), reply);

    return { fastify, store, reply, sent, body: sent[0] as Record<string, unknown> };
  }

  const accepted = { vp_token: VP_TOKEN, state: STATE };
  const declined = { error: 'access_denied', state: STATE };

  it('(OID4VP 1.0 §8.2) answers 200 with Content-Type application/json and a JSON object on both direct_post and direct_post.jwt', async () => {
    // Through REAL Fastify, because a stub cannot see a Content-Type the
    // handler never sets by hand: it is the serializer, driven by the route's
    // declared Zod response schema, that writes `application/json`. This is
    // the pattern `request-object.test.ts` uses for the same reason.
    const pair = await mintPair();

    for (const [env, row, post] of [
      [
        ENABLED_ENV,
        sameDeviceState(),
        { payload: `vp_token=${encodeURIComponent(VP_TOKEN)}&state=${STATE}`, byKid: false },
      ],
      [
        HAIP_ENV,
        encryptedState(pair, { sameDevice: true }),
        {
          payload: `response=${await encryptResponse(pair.publicJwk, SUCCESS_PAYLOAD)}`,
          byKid: true,
        },
      ],
      [
        ENABLED_ENV,
        pendingState(),
        { payload: `error=access_denied&state=${STATE}`, byKid: false },
      ],
    ] as const) {
      const route = await loadRoute(env);
      const store = new Map<string, unknown>();
      const app = Fastify({ logger: false });
      app.setValidatorCompiler(validatorCompiler);
      app.setSerializerCompiler(serializerCompiler);
      await app.register(formbody);
      app.decorate('repositories', {
        oid4vpRequestStates: {
          redeem: vi.fn().mockResolvedValue(post.byKid ? undefined : row),
          redeemByEncryptionKid: vi.fn().mockResolvedValue(post.byKid ? row : undefined),
        },
        auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
      } as never);
      app.decorate('sessionUtils', {
        setSession: async (key: string, value: unknown) => {
          store.set(key, value);
        },
        getSession: async (key: string) => store.get(key) ?? null,
        deleteSession: async (key: string) => {
          store.delete(key);
        },
      } as never);
      await app.register(route, { prefix: '/oid4vp' });
      await app.ready();

      try {
        const response = await app.inject({
          method: 'POST',
          url: '/oid4vp/response',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          payload: post.payload,
        });

        expect(response.statusCode).toBe(200);
        expect(response.headers['content-type']).toMatch(/^application\/json\b/);
        expect(response.headers['cache-control']).toBe('no-store');
        const parsed: unknown = JSON.parse(response.body);
        expect(typeof parsed).toBe('object');
        expect(parsed).not.toBeNull();
        expect(Array.isArray(parsed)).toBe(false);
        // The serializer wrote the schema's members and nothing else — and on
        // the wire, not just in the handler, a same-device row carries the
        // `redirect_uri` while a cross-device one is the empty object.
        expect(parsed).toEqual(
          (row as { sameDevice: boolean }).sameDevice
            ? {
                redirect_uri: expect.stringMatching(
                  /^https:\/\/auth\.example\.com\/ui\/wallet-login\/return\?response_code=[A-Za-z0-9_-]{43}$/
                ),
              }
            : {}
        );
      } finally {
        await app.close();
      }
    }
  });

  it('(OID4VP 1.0 §8.2, HAIP 1.0 §5.1) returns redirect_uri carrying a fresh Response Code for a same-device request', async () => {
    const { reply, body } = await submit(accepted, sameDeviceState());

    expect(reply.statusCode).toBe(200);
    expect(Object.keys(body)).toEqual(['redirect_uri']);
    expect(responseCodeOf(body)).toMatch(RESPONSE_CODE_SHAPE);
  });

  it('(OID4VP 1.0 §8.2, HAIP 1.0 §5.1) returns redirect_uri for a same-device request on the encrypted direct_post.jwt path too', async () => {
    // The same decision on the other correlator: the row was found by its
    // kid, and its `sameDevice` — not anything in the ciphertext — is what
    // puts the member on the body.
    const pair = await mintPair();
    const { fastify, reply, body } = await submitEncrypted(
      pair,
      SUCCESS_PAYLOAD,
      encryptedState(pair, { sameDevice: true })
    );

    expect(reply.statusCode).toBe(200);
    expect(Object.keys(body)).toEqual(['redirect_uri']);
    expect(responseCodeOf(body)).toMatch(RESPONSE_CODE_SHAPE);
    expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).toHaveBeenCalledWith(
      pair.kid,
      RESPONSE_CODE_DIGEST
    );
  });

  it('(OID4VP 1.0 §8.2) mints a fresh, cryptographically random Response Code per response — 43 base64url chars, never repeated across responses', async () => {
    const { fastify, ctx } = await register();
    fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(sameDeviceState());
    const handler = ctx.handler as NonNullable<TestContext['handler']>;
    const codes = new Set<string>();

    for (let i = 0; i < 50; i += 1) {
      const { reply, sent } = makeReply();
      await handler(makeRequest(accepted), reply);

      const code = responseCodeOf(sent[0]);
      expect(code).toMatch(RESPONSE_CODE_SHAPE);
      // The digest the row was consumed WITH is the digest of the code the
      // wallet was handed — the two halves of the return leg meet on it.
      const [, written] = fastify.repositories.oid4vpRequestStates.redeem.mock.calls[i];
      expect(written.codeHash).toBe(sha256Hex(code));
      codes.add(code);
    }

    expect(codes.size).toBe(50);
  });

  it('(OID4VP 1.0 §8.2) Response Code carries at least 128 bits — 32 CSPRNG bytes', async () => {
    // §8.2 RECOMMENDS "a cryptographic random value of 128 bits or more"; the
    // code decodes to twice that. That the bytes come from `randomBytes` is
    // pinned where they are drawn (`response-code.test.ts`); what this
    // endpoint can prove is that it hands out that value undiminished.
    const { body } = await submit(accepted, sameDeviceState());
    const decoded = Buffer.from(responseCodeOf(body), 'base64url');

    expect(decoded.length).toBe(32);
    expect(decoded.length * 8).toBeGreaterThanOrEqual(128);
  });

  it('(OID4VP 1.0 §14.2) persists only the Response Code digest — the plaintext never reaches the repository', async () => {
    const { fastify, store, body } = await submit(accepted, sameDeviceState());
    const code = responseCodeOf(body);

    const [stateHash, written] = fastify.repositories.oid4vpRequestStates.redeem.mock.calls[0];
    expect(stateHash).toBe(hashOid4vpState(STATE));
    expect(written).toEqual({ codeHash: sha256Hex(code), codeExpiresAt: expect.any(Number) });
    expect(written.codeHash).not.toBe(code);
    // Nowhere in anything the handler handed to a repository, the audit log
    // or the store does the plaintext appear — only the wallet sees it.
    const everythingPersisted = JSON.stringify([
      fastify.repositories.oid4vpRequestStates.redeem.mock.calls,
      fastify.repositories.auditLogs.create.mock.calls,
      [...store.entries()],
    ]);
    expect(everythingPersisted).not.toContain(code);
    expect(everythingPersisted).toContain(sha256Hex(code));
  });

  it('gives the code its own deadline, WALLET_RETURN_CODE_TTL_MS from now — not the request expiry', async () => {
    const before = Date.now();
    const { fastify } = await submit(accepted, sameDeviceState({ expiresAt: before + 999_999 }));
    const after = Date.now();

    const [, written] = fastify.repositories.oid4vpRequestStates.redeem.mock.calls[0];
    expect(written.codeExpiresAt).toBeGreaterThanOrEqual(before + WALLET_RETURN_CODE_TTL_MS);
    expect(written.codeExpiresAt).toBeLessThanOrEqual(after + WALLET_RETURN_CODE_TTL_MS);
  });

  it('(OID4VP 1.0 §14.2, §13.3) answers {} with no redirect_uri for a cross-device request', async () => {
    // §14.2: the technique "is not applicable to cross-device scenarios";
    // §13.3 step 6: without a redirect_uri "processing at the Wallet stops".
    // The digest is still written — the repository has one shape — but the
    // code never leaves the server.
    const { fastify, reply, sent } = await submit(accepted, pendingState({ sameDevice: false }));

    expect(reply.statusCode).toBe(200);
    expect(sent).toEqual([{}]);
    expect(JSON.stringify(sent[0])).toBe('{}');
    expect(fastify.repositories.oid4vpRequestStates.redeem).toHaveBeenCalledWith(
      hashOid4vpState(STATE),
      RESPONSE_CODE_DIGEST
    );
  });

  it('(OID4VP 1.0 §14.2, §13.3) answers {} for a cross-device request on the encrypted path and on a wallet-reported error', async () => {
    const pair = await mintPair();
    const encrypted = await submitEncrypted(pair, SUCCESS_PAYLOAD, encryptedState(pair));
    expect(encrypted.sent).toEqual([{}]);

    const errored = await submit(declined, pendingState());
    expect(errored.sent).toEqual([{}]);
  });

  it('(OID4VP 1.0 §8.2) returns redirect_uri on a wallet-reported error for a same-device request', async () => {
    // §8.2: the Response URI "MAY return the redirect_uri parameter in
    // response to successful Authorization Responses or for Error Responses",
    // and HAIP's MUST has no success qualifier. The user who declined on this
    // device is looking at the tab that waits; the return leg is how it
    // learns to stop.
    const { fastify, store, reply, body } = await submit(declined, sameDeviceState());

    expect(reply.statusCode).toBe(200);
    expect(Object.keys(body)).toEqual(['redirect_uri']);
    expect(responseCodeOf(body)).toMatch(RESPONSE_CODE_SHAPE);
    // Still an error: signalled as one, nothing parked, nothing audited, the
    // wallet's text nowhere.
    expect(store.get(`wallet-login-signal:${hashOid4vpState(STATE)}`)).toMatchObject({
      signal: 'wallet_error',
    });
    expect(store.get(`wallet-presentation:${hashOid4vpState(STATE)}`)).toBeUndefined();
    expect(fastify.repositories.auditLogs.create).not.toHaveBeenCalled();
    expect(JSON.stringify(body)).not.toContain('access_denied');
  });

  it('(OID4VP 1.0 §8.2) returns redirect_uri on a wallet error inside the JWE for a same-device request', async () => {
    const pair = await mintPair();
    const { store, body } = await submitEncrypted(
      pair,
      { state: STATE, error: 'access_denied' },
      encryptedState(pair, { sameDevice: true })
    );

    expect(Object.keys(body)).toEqual(['redirect_uri']);
    expect(responseCodeOf(body)).toMatch(RESPONSE_CODE_SHAPE);
    expect(store.get(`wallet-login-signal:${hashOid4vpState(STATE)}`)).toMatchObject({
      signal: 'wallet_error',
    });
  });

  it('(OID4VP 1.0 §8.2, §8.3.1) returns redirect_uri on an unencrypted error against a same-device direct_post.jwt row', async () => {
    // The §8.3.1 carve-out on a same-device row: the wallet that could not
    // encrypt declined in the clear, the row was consumed by its state, and
    // the user is still brought back to the waiting tab.
    const pair = await mintPair();
    const { fastify, ctx, store } = await register(HAIP_ENV);
    fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(
      encryptedState(pair, { sameDevice: true })
    );
    const handler = ctx.handler as NonNullable<TestContext['handler']>;
    const { reply, sent } = makeReply();

    await handler(makeRequest(declined), reply);

    expect(reply.statusCode).toBe(200);
    expect(Object.keys(sent[0] as object)).toEqual(['redirect_uri']);
    expect(responseCodeOf(sent[0])).toMatch(RESPONSE_CODE_SHAPE);
    expect(fastify.repositories.oid4vpRequestStates.redeem).toHaveBeenCalledWith(
      hashOid4vpState(STATE),
      RESPONSE_CODE_DIGEST
    );
    expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).not.toHaveBeenCalled();
    expect(store.get(`wallet-login-signal:${hashOid4vpState(STATE)}`)).toMatchObject({
      signal: 'wallet_error',
    });
  });

  it('(OID4VP 1.0 §8.2) redirect_uri is an absolute URI under the issuer and carries nothing but the Response Code', async () => {
    const { body } = await submit(accepted, sameDeviceState());
    const redirectUri = body.redirect_uri as string;
    const url = new URL(redirectUri);

    // Absolute (RFC 3986 §4.3), on the ISSUER's origin — `JWT_ISSUER` with its
    // trailing slash canonicalised away, never the request's `Host`.
    expect(url.origin).toBe(ISSUER);
    expect(url.protocol).toBe('https:');
    expect(url.pathname).toBe('/ui/wallet-login/return');
    expect(url.username).toBe('');
    expect(url.password).toBe('');
    expect(url.hash).toBe('');
    // Exactly one query parameter, and it is the code.
    expect([...url.searchParams.keys()]).toEqual(['response_code']);
    expect(url.searchParams.get('response_code')).toMatch(RESPONSE_CODE_SHAPE);
    expect(redirectUri).toBe(
      `${ISSUER}/ui/wallet-login/return?response_code=${url.searchParams.get('response_code')}`
    );
    // Nothing browser- or request-derived rides along: not the state, not its
    // digest, not the row, not the caller's address or agent.
    for (const forbidden of [
      STATE,
      hashOid4vpState(STATE),
      'req-state-1',
      'realm-1',
      'nonce-value',
      '203.0.113.9',
      'test-wallet',
    ]) {
      expect(redirectUri).not.toContain(forbidden);
    }
  });

  it('builds redirect_uri from JWT_ISSUER — a different issuer moves the origin, nothing else', async () => {
    const { body } = await submit(accepted, sameDeviceState(), {
      ...ENABLED_ENV,
      JWT_ISSUER: 'https://id.other.example',
    });

    expect(new URL(body.redirect_uri as string).origin).toBe('https://id.other.example');
    expect(new URL(body.redirect_uri as string).pathname).toBe('/ui/wallet-login/return');
  });

  it('never returns redirect_uri on a refusal', async () => {
    // Every refusal throws BEFORE `send`, so no body — and no code — ever
    // leaves for an exchange that was not accepted. Two families, stated
    // precisely: refusals reached AFTER redemption (the row is consumed and
    // its digest written, but the code is dropped with the handler's stack),
    // and refusals reached BEFORE any lookup (nothing touched at all).
    const pair = await mintPair();
    const other = await mintPair();

    const afterRedemption: Array<[Record<string, unknown>, unknown, Record<string, unknown>]> = [
      // Same-device rows throughout: the case where a code WOULD have been
      // emitted had the exchange been accepted.
      [{ vp_token: '{not json', state: STATE }, sameDeviceState(), ENABLED_ENV],
      [{ state: STATE }, sameDeviceState(), ENABLED_ENV],
      [accepted, sameDeviceState({ verifierProfile: 'haip-1.0' }), ENABLED_ENV],
      [accepted, sameDeviceState({ dcqlQuery: { credentials: 'not-an-array' } }), ENABLED_ENV],
      [accepted, sameDeviceState(), { ...ENABLED_ENV, OID4VP_VERIFIER_PROFILE: undefined }],
      // The downgrade: a cleartext presentation against an encrypted row.
      [accepted, encryptedState(pair, { sameDevice: true }), HAIP_ENV],
    ];

    for (const [body, row, env] of afterRedemption) {
      const { fastify, ctx, store } = await register(env);
      fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(row);
      const handler = ctx.handler as NonNullable<TestContext['handler']>;
      const { reply, sent } = makeReply();

      await expect(handler(makeRequest(body), reply)).rejects.toMatchObject({
        statusCode: 400,
        errorDescription: OID4VP_REJECTION_DESCRIPTION,
      });

      expect(sent).toEqual([]);
      expect(reply.header).not.toHaveBeenCalled();
      expect(fastify.repositories.oid4vpRequestStates.redeem).toHaveBeenCalledOnce();
      expect(fastify.repositories.oid4vpRequestStates.redeem).toHaveBeenCalledWith(
        hashOid4vpState(STATE),
        RESPONSE_CODE_DIGEST
      );
      expect(store.size).toBe(0);
    }

    // Unknown state: the redemption ran (with a digest — the code is minted
    // before the lookup, one shape) and found nothing.
    {
      const { fastify, ctx } = await register();
      fastify.repositories.oid4vpRequestStates.redeem.mockResolvedValue(undefined);
      const handler = ctx.handler as NonNullable<TestContext['handler']>;
      const { reply, sent } = makeReply();

      await expect(handler(makeRequest(accepted), reply)).rejects.toMatchObject({
        statusCode: 400,
      });

      expect(sent).toEqual([]);
      expect(fastify.repositories.oid4vpRequestStates.redeem).toHaveBeenCalledWith(
        hashOid4vpState(STATE),
        RESPONSE_CODE_DIGEST
      );
    }

    // Encrypted, wrong key on a same-device row: consumed by kid, decrypt
    // fails, nothing sent.
    {
      const { fastify, handler } = await registerHaip();
      fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid.mockResolvedValue(
        encryptedState(pair, { sameDevice: true })
      );
      const { reply, sent } = makeReply();

      await expect(
        handler(
          makeRequest({
            response: await encryptResponse({ ...other.publicJwk, kid: pair.kid }, SUCCESS_PAYLOAD),
          }),
          reply
        )
      ).rejects.toMatchObject({ statusCode: 400 });

      expect(sent).toEqual([]);
      expect(reply.header).not.toHaveBeenCalled();
      expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).toHaveBeenCalledWith(
        pair.kid,
        RESPONSE_CODE_DIGEST
      );
    }

    // Not a JOSE object: refused before any lookup — no redemption, no digest,
    // no body.
    {
      const { fastify, handler } = await registerHaip();
      const { reply, sent } = makeReply();

      await expect(handler(makeRequest({ response: 'not.a.jwe' }), reply)).rejects.toMatchObject({
        statusCode: 400,
      });

      expect(sent).toEqual([]);
      expect(fastify.repositories.oid4vpRequestStates.redeem).not.toHaveBeenCalled();
      expect(fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid).not.toHaveBeenCalled();
    }
  });

  it('sets Cache-Control: no-store on the transport acknowledgement', async () => {
    // The spec's own example of the 200 carries it, and the body is a bearer
    // secret on a same-device row. Pinned on all four 200 paths.
    const pair = await mintPair();
    const otherPair = await mintPair();

    const cleartextAccepted = await submit(accepted, sameDeviceState());
    const cleartextDeclined = await submit(declined, pendingState());
    const encryptedAccepted = await submitEncrypted(
      pair,
      SUCCESS_PAYLOAD,
      encryptedState(pair, { sameDevice: true })
    );
    const encryptedDeclined = await submitEncrypted(
      otherPair,
      { state: STATE, error: 'access_denied' },
      encryptedState(otherPair)
    );

    for (const { reply } of [
      cleartextAccepted,
      cleartextDeclined,
      encryptedAccepted,
      encryptedDeclined,
    ]) {
      expect(reply.statusCode).toBe(200);
      expect(reply.header).toHaveBeenCalledWith('Cache-Control', 'no-store');
    }
  });

  it('writes nothing new to the store — the signal and the parked presentation only, as before', async () => {
    // The endpoint's one store contract (#239) is unchanged by the return leg:
    // no Redis record of the code, no flow handle, nothing addressed by it.
    const { store, body } = await submit(accepted, sameDeviceState());
    const code = responseCodeOf(body);

    expect([...store.keys()].sort()).toEqual(
      [
        `wallet-login-signal:${hashOid4vpState(STATE)}`,
        `wallet-presentation:${hashOid4vpState(STATE)}`,
      ].sort()
    );
    expect(JSON.stringify([...store.entries()])).not.toContain(code);
  });

  it('still authenticates nobody: no session, no token, no user on a same-device acceptance', async () => {
    const { fastify, body } = await submit(accepted, sameDeviceState());

    expect(Object.keys(body)).toEqual(['redirect_uri']);
    expect(fastify.providerRegistry).toBeUndefined();
    expect(fastify.repositories.users).toBeUndefined();
    expect(fastify.jwtUtils).toBeUndefined();
  });
});
