/**
 * ASSEMBLED-APP regression suite for the global error handler (#365).
 *
 * ## What regressed, and why nothing caught it
 *
 * `plugins/error-handler.ts` is `fp()`-wrapped and calls `setErrorHandler`. It
 * used to be registered *after* both `AutoLoad` calls in `app.ts`, under a
 * comment claiming the last position "catches all unhandled errors" — which is
 * exactly backwards. A route does not resolve its error handler at request
 * time: Fastify snapshots it while the route's enclosing plugin finishes
 * loading (`context.errorHandler = this[kErrorHandler]`, in the `after()`
 * callback of `fastify/lib/route.js`). avvio runs queued plugins in
 * registration order, so a `setErrorHandler` that runs later reaches NO route
 * that already loaded. The handler existed, was unit-tested, and was reachable
 * from nothing.
 *
 * Every route therefore answered with Fastify's built-in
 * `{statusCode, code, error, message}` envelope, silently reverting:
 *
 *  - the F-01 register-enumeration fix (PR #212) — the built-in envelope echoes
 *    `error.message`, and `UniqueConstraintError`'s message embeds the DB
 *    constraint name;
 *  - the RFC 6750 §3 `WWW-Authenticate: Bearer` challenge that a
 *    bearer-protected resource MUST return on 401;
 *  - the RFC 6749 §5.2 OAuth error shapes;
 *  - the `error_description` sanitisation that keeps that challenge well-formed.
 *
 * The bug survived review because `apps/auth-server`'s route tests build
 * STUBBED Fastify instances (`Fastify()` + the one route under test + a mocked
 * `../../config/env`), and `plugins/error-handler.test.ts` exercises the handler
 * in isolation, where it works perfectly. Nothing asserted the handler was
 * REACHABLE from a route in the assembled application — which is the only place
 * the defect lived.
 *
 * So this file boots the REAL `app` plugin from `./app.ts`, with the real
 * plugin registration order and the real `AutoLoad`-mounted routes, and asserts
 * on the wire. A stubbed Fastify instance is worthless here by construction: it
 * cannot reproduce the registration order that is the bug.
 *
 * ## Ordering guard
 *
 * The tests tagged `[#365 ORDERING GUARD]` FAIL if `await
 * fastify.register(errorHandler)` is moved back after either `AutoLoad` call in
 * `app.ts`. Verified by doing exactly that: every one of them flips to
 * Fastify's built-in envelope (`code: 'FST_ERR_VALIDATION'`, `error: 'Bad
 * Request'`, and no `WWW-Authenticate` header at all). Do not "simplify" them
 * into `error-handler.test.ts` — an isolated handler test passes under the bug.
 */
import { generateKeyPairSync } from 'node:crypto';

import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import Fastify, { type FastifyInstance, type InjectOptions } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/** Test-only route that raises a real `UniqueConstraintError`. See {@link buildAssembledApp}. */
const UNIQUE_CONSTRAINT_ROUTE = '/__error-handler-wiring__/unique-constraint';

/**
 * A realistic constraint name. Post-#230 this is the index a duplicate
 * registration actually violates, and it is precisely the string F-01 says must
 * never reach the wire — naming it makes an account an enumeration oracle.
 */
const LEAKY_CONSTRAINT_NAME = 'user_credentials_realm_provider_sub_unique';

const FORM: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };

/**
 * The environment the assembled app boots under.
 *
 * Mirrors `src/testing/e2e-harness.ts`'s `REQUIRED_TEST_ENVIRONMENT`, inlined
 * rather than imported because that module pulls `@qauth-labs/shared-testing`
 * (testcontainers) into the graph, and this suite is part of the FAST unit run
 * that must stay free of Docker.
 *
 * `DATABASE_URL` / `REDIS_URL` point at a closed port on purpose. Both plugins
 * only probe their connection in an `onReady` hook and downgrade a failure to
 * `fastify.log.warn` (see `fastify-plugin-db.ts` / `fastify-plugin-cache.ts`),
 * so the app boots fully — and pointing them at an unreachable port guarantees
 * this suite can never reach a developer's live database, whatever a local
 * `.env` happens to contain.
 */
function testEnvironment(): Record<string, string> {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    NODE_ENV: 'test',
    JWT_ISSUER: 'https://auth.example.com',
    JWT_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    JWT_PUBLIC_KEY: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    SESSION_COOKIE_SECRET: 'error-handler-wiring-session-secret-of-at-least-32-characters',
    EMAIL_PROVIDER: 'mock',
    EMAIL_FROM_ADDRESS: 'no-reply@auth.example.com',
    EMAIL_BASE_URL: 'https://auth.example.com',
    DEFAULT_REALM_NAME: 'master',
    ENABLE_SWAGGER: 'false',
    LOG_LEVEL: 'fatal',
    DATABASE_URL: 'postgres://qauth:qauth@127.0.0.1:1/qauth-unreachable',
    REDIS_URL: 'redis://127.0.0.1:1',
    // The ONLY deviation from a default deployment, and it is forced: the rate
    // limiter is backed by `fastify.redis`, and with an unreachable Redis every
    // request dies in its `onRequest` hook with a MaxRetriesPerRequestError
    // before reaching any route — a uniform 500 that would hide the very
    // responses this file asserts on. Nothing here depends on the limiter, and
    // the error handler's reachability is independent of whether it registered.
    // The rate limiter's OWN ordering constraint (it must precede the routes
    // AutoLoad, because `onRoute` is not retroactive) is a separate invariant
    // documented at its registration site in `app.ts`.
    RATE_LIMIT_ENABLED: 'false',
  };
}

let server: FastifyInstance;
/** Every `process.env` key this suite touches, with its pre-suite value. */
const savedEnv = new Map<string, string | undefined>();

/**
 * Boot the REAL auth-server application.
 *
 * Two details are load-bearing:
 *
 * 1. `./app` is imported DYNAMICALLY, after `process.env` is populated, because
 *    `src/config/env.ts` parses `process.env` at MODULE LOAD — a static import
 *    would parse before `beforeAll` runs and throw on the missing
 *    `DATABASE_URL`. Same reason `e2e-harness.ts` imports it dynamically. No
 *    `vi.resetModules()` here on purpose: this file must share ONE
 *    `@qauth-labs/shared-errors` module instance with the app, or the
 *    `error instanceof UniqueConstraintError` branch in the handler would test
 *    a different class object than the one the test route throws.
 *
 * 2. `app()` is CALLED directly on the wrapper's instance rather than passed to
 *    `register()`. `app` is not `fp()`-wrapped, so `register(app)` would create
 *    a child context — and the wrapper here IS that child context, so the two
 *    are structurally identical. Calling it directly is what lets the
 *    `UniqueConstraintError` test route be added to the SAME encapsulation
 *    scope in which `error-handler.ts` ran `setErrorHandler`, i.e. the scope
 *    every autoloaded route inherits from. Registering that route on the root
 *    instance instead would give it the ROOT's error handler (Fastify's
 *    default), and the test would assert nothing about this app.
 *
 * The framing around the app (`validatorCompiler` / `serializerCompiler`,
 * `ignoreTrailingSlash`) is copied from `src/main.ts` so routes validate through
 * the same Zod compiler production uses — `FST_ERR_VALIDATION` vs. the custom
 * shape is exactly what test (a) discriminates on.
 */
async function buildAssembledApp(): Promise<FastifyInstance> {
  const { app } = await import('./app');

  const instance = Fastify({ logger: false, routerOptions: { ignoreTrailingSlash: true } });
  instance.setValidatorCompiler(validatorCompiler);
  instance.setSerializerCompiler(serializerCompiler);

  await instance.register(async (scope, opts) => {
    await app(scope, opts as object);

    // ── Acceptance criterion (c): how the F-01 guarantee is exercised.
    //
    // APPROACH: a throwaway route on the assembled app that throws a real
    // `UniqueConstraintError`, rather than a real duplicate registration.
    //
    // WHY: the genuine path (POST /auth/register twice) needs a live Postgres
    // to raise the constraint violation, which would move this suite into the
    // Docker-backed `*.integration.test.ts` run and out of the fast unit suite
    // that guards the wiring. Faking it at the repository layer instead would
    // mean stubbing `db.transaction`, the realms repo, and two more
    // repositories — a large fake surface whose only purpose is to reach the
    // one `throw` this route performs directly. The property under test is the
    // HANDLER's, not the route's: given a `UniqueConstraintError` from a route,
    // the constraint name must not reach the wire.
    //
    // CAVEAT, stated because it is easy to misread: this route is NOT an
    // ordering guard. It loads after both AutoLoads, so it inherits the final
    // `kErrorHandler` either way and stays green even with the #365 bug
    // reintroduced (verified). The ordering guards are the tests marked
    // `[#365 ORDERING GUARD]`, which run against real autoloaded routes.
    scope.post(UNIQUE_CONSTRAINT_ROUTE, async () => {
      throw new UniqueConstraintError(LEAKY_CONSTRAINT_NAME);
    });
  });

  await instance.ready();
  return instance;
}

beforeAll(async () => {
  for (const [key, value] of Object.entries(testEnvironment())) {
    savedEnv.set(key, process.env[key]);
    process.env[key] = value;
  }
  // Wallet federation (ADR-004) is default-off, but an inherited
  // `WALLET_FEDERATION_ENABLED` / `OID4VP_*` from a developer's shell or `.env`
  // makes `app()` refuse to boot on a missing VerifierProfile. Clear the whole
  // family so this suite fails only for its own reasons — the same guard
  // `e2e-harness.ts` applies.
  for (const key of Object.keys(process.env)) {
    if (key.startsWith('OID4VP_') || key.startsWith('WALLET_') || key.startsWith('ACR_')) {
      savedEnv.set(key, process.env[key]);
      delete process.env[key];
    }
  }

  server = await buildAssembledApp();
}, 60_000);

afterAll(async () => {
  await server?.close();
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
});

/**
 * Assert a response is NOT Fastify's built-in error envelope.
 *
 * The built-in serializer emits `{statusCode, code, error, message}` where
 * `error` is the HTTP status phrase ("Bad Request", "Unauthorized") and
 * `message` carries `error.message` verbatim — the leak vector in F-01. Every
 * branch of `error-handler.ts` emits `error` as the DOMAIN message and never
 * emits `message` at all, so the presence of `message` (or an `FST_ERR_*`
 * code) is a positive signal that the built-in handler answered.
 */
function expectNotFastifyBuiltinEnvelope(body: Record<string, unknown>): void {
  expect(body).not.toHaveProperty('message');
  expect(String(body['code'] ?? '')).not.toMatch(/^FST_ERR/);
  expect(body['error']).not.toBe('Bad Request');
  expect(body['error']).not.toBe('Unauthorized');
  expect(body['error']).not.toBe('Internal Server Error');
}

describe('assembled app — global error handler reachability (#365)', () => {
  it('[#365 ORDERING GUARD] (a) POST /oauth/token with an invalid body returns the CUSTOM validation shape, not FST_ERR_VALIDATION', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: 'grant_type=not-a-real-grant',
    });

    expect(res.statusCode).toBe(400);
    const body = res.json() as Record<string, unknown>;

    // The custom handler's `'validation' in error` branch.
    expect(body).toMatchObject({
      error: 'Validation error',
      code: 'VALIDATION_ERROR',
      statusCode: 400,
    });
    expect(Array.isArray(body['details'])).toBe(true);

    // ...and specifically NOT Fastify's built-in
    // `{statusCode: 400, code: 'FST_ERR_VALIDATION', error: 'Bad Request', message: 'body/grant_type …'}`,
    // which is what this endpoint returned for as long as the handler was
    // registered after the AutoLoads.
    expectNotFastifyBuiltinEnvelope(body);
  });

  it('[#365 ORDERING GUARD] (b) unauthenticated GET /oauth/userinfo answers 401 with an RFC 6750 §3 WWW-Authenticate: Bearer challenge', async () => {
    const res = await server.inject({ method: 'GET', url: '/oauth/userinfo' });

    expect(res.statusCode).toBe(401);

    // RFC 6750 §3: a bearer-protected resource rejecting a token MUST return
    // this header. Only `error-handler.ts` sets it, so under the #365 bug the
    // header was absent entirely — a spec violation invisible to a status-code
    // assertion.
    const challenge = res.headers['www-authenticate'];
    expect(challenge).toBeDefined();
    expect(challenge).toContain('Bearer ');
    expect(challenge).toContain('realm="OAuth"');
    expect(challenge).toContain('error="invalid_token"');

    // RFC 6750 §3's `error_description` is a quoted-string permitting only
    // %x20-21 / %x23-5B / %x5D-7E, i.e. no `"` and no `\`. The handler's
    // `sanitizeChallengeDescription` is what enforces that, and it is the other
    // thing #365 skipped — so assert the emitted value is well-formed rather
    // than merely present.
    const description = /error_description="([^"]*)"/.exec(String(challenge))?.[1];
    expect(description).toBeDefined();
    expect(description).not.toMatch(/[^\x20-\x21\x23-\x5b\x5d-\x7e]/);

    const body = res.json() as Record<string, unknown>;
    expect(body).toMatchObject({ code: 'JWT_INVALID', statusCode: 401 });
    expectNotFastifyBuiltinEnvelope(body);
  });

  it('(c) a UniqueConstraintError from a route is genericised — the constraint name never reaches the wire (F-01, PR #212)', async () => {
    const res = await server.inject({ method: 'POST', url: UNIQUE_CONSTRAINT_ROUTE });

    expect(res.statusCode).toBe(409);

    const body = res.json() as Record<string, unknown>;
    // Code + status survive so a legitimate client can still branch on the
    // conflict; only the human-readable message is genericised.
    expect(body).toMatchObject({
      error: 'Resource already exists',
      code: 'UNIQUE_CONSTRAINT_VIOLATION',
      statusCode: 409,
    });

    // The F-01 guarantee, asserted on the RAW body: the constraint name must
    // appear nowhere — not as a field, not embedded in a message, not in a
    // stack trace. Under the built-in envelope the `message` key carried
    // `Unique constraint violated: user_credentials_realm_provider_sub_unique`
    // verbatim (see `libs/shared/errors/src/lib/database/unique-constraint.error.ts`),
    // turning a duplicate registration into an account-enumeration oracle.
    expect(res.body).not.toContain(LEAKY_CONSTRAINT_NAME);
    expect(body['constraint']).toBeUndefined();
    expectNotFastifyBuiltinEnvelope(body);
  });

  it("[#365 ORDERING GUARD] (d) no autoloaded route in the assembled app answers with Fastify's built-in error envelope", async () => {
    // A cross-section of the routes AutoLoad: both mounted prefixes, both
    // methods, and both failure kinds the handler covers (schema validation and
    // a thrown domain error). Every one of these flips to
    // `{statusCode, code: 'FST_ERR_VALIDATION', error: 'Bad Request', message}`
    // the moment `register(errorHandler)` moves back below the AutoLoad calls,
    // so this is the broad guard: it does not depend on any single endpoint
    // keeping its current schema.
    const probes: ReadonlyArray<readonly [string, InjectOptions]> = [
      ['POST /oauth/token', { method: 'POST', url: '/oauth/token', headers: FORM, payload: 'x=1' }],
      [
        'POST /oauth/introspect',
        { method: 'POST', url: '/oauth/introspect', headers: FORM, payload: 'x=1' },
      ],
      [
        'POST /oauth/revoke',
        { method: 'POST', url: '/oauth/revoke', headers: FORM, payload: 'x=1' },
      ],
      ['GET /oauth/authorize', { method: 'GET', url: '/oauth/authorize' }],
      ['GET /oauth/userinfo', { method: 'GET', url: '/oauth/userinfo' }],
      ['POST /auth/login', { method: 'POST', url: '/auth/login', payload: { bad: true } }],
      ['POST /auth/register', { method: 'POST', url: '/auth/register', payload: { bad: true } }],
      ['POST /auth/logout', { method: 'POST', url: '/auth/logout', payload: { bad: true } }],
      ['GET /auth/verify', { method: 'GET', url: '/auth/verify' }],
      [
        'POST /auth/resend-verification',
        { method: 'POST', url: '/auth/resend-verification', payload: { bad: true } },
      ],
      ['GET /api/clients', { method: 'GET', url: '/api/clients' }],
    ];

    for (const [label, options] of probes) {
      const res = await server.inject(options);
      const body = res.json() as Record<string, unknown>;

      // Every probe is a deliberate failure; a 2xx means the probe stopped
      // testing what it was written to test.
      expect(res.statusCode, label).toBeGreaterThanOrEqual(400);
      // The custom handler always emits a numeric `statusCode` mirroring the
      // HTTP status, and an `error` that is the DOMAIN message.
      expect(body['statusCode'], label).toBe(res.statusCode);
      expect(typeof body['error'], label).toBe('string');
      expect(body, label).not.toHaveProperty('message');
      expect(String(body['code'] ?? ''), label).not.toMatch(/^FST_ERR/);
    }
  });
});
