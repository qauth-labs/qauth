import { Writable } from 'node:stream';

import rateLimit from '@fastify/rate-limit';
import {
  ForbiddenError,
  InvalidClientError,
  InvalidRequestError,
  JWTExpiredError,
  JWTInvalidError,
  NotFoundError,
  UnauthorizedClientError,
  UniqueConstraintError,
  WeakPasswordError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import Fastify, { LogController } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
  type ZodTypeProvider,
} from 'fastify-type-provider-zod';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { LOG_REDACT_CENSOR } from '../../config/logger';

// F-05: error-handler now reads the validated `env.NODE_ENV` instead of the
// raw `process.env.NODE_ENV`. Mock the env module so the test doesn't trigger
// full env parsing (DATABASE_URL etc. are not set in the test environment).
vi.mock('../../config/env', () => ({
  env: {
    NODE_ENV: 'development',
  },
}));

import { pageQuerySchema, pageSchema } from '../api-conventions/paging';
import { PROBLEM_CODES, problemResponses } from '../api-conventions/problem';
import errorHandler from './error-handler';

async function buildTestApp(): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  await app.register(errorHandler);

  app.get('/test-jwt-expired', async () => {
    throw new JWTExpiredError('JWT token has expired');
  });

  app.get('/test-jwt-invalid', async () => {
    throw new JWTInvalidError('Invalid JWT token');
  });

  app.post('/test-invalid-client', async () => {
    throw new InvalidClientError();
  });

  app.post('/test-invalid-client-described', async () => {
    throw new InvalidClientError('CIMD document is not valid JSON');
  });

  app.post('/test-unauthorized-client', async () => {
    throw new UnauthorizedClientError('client is not registered for the refresh_token grant');
  });

  app.post(
    '/test-validation',
    {
      schema: {
        body: {
          type: 'object',
          required: ['grant_type'],
          properties: { grant_type: { type: 'string', pattern: '^[a-z_]+$' } },
        },
      },
    },
    async () => ({ ok: true })
  );

  app.get('/test-unknown', async () => {
    throw new Error('something came apart');
  });

  app.post('/test-forbidden', async () => {
    throw new ForbiddenError('Static API keys are disabled for production clients.');
  });

  app.post('/test-unique-constraint', async () => {
    // The DB layer surfaces the offending constraint name; the handler must NOT
    // leak it (account-enumeration oracle, e.g. duplicate-email registration).
    throw new UniqueConstraintError('users_email_realm_key');
  });

  return app;
}

/**
 * The media type, with the `charset` parameter Fastify appends to every JSON
 * body it serializes. JSON has no charset parameter (RFC 8259 §11), so a
 * recipient ignores it.
 */
const PROBLEM_CONTENT_TYPE = /^application\/problem\+json(?:;|$)/;

/**
 * A Fastify instance with the error handler and API family routes, validated
 * by the Zod compiler production uses, so a validation failure carries the
 * issues the problem formatter projects (#506).
 */
async function buildProblemApp(): Promise<FastifyInstance> {
  const app = Fastify({ logger: false, requestIdHeader: 'x-request-id' });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  await app.register(errorHandler);
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.get(
    '/developer/v1/widgets',
    {
      schema: {
        querystring: pageQuerySchema,
        response: {
          200: pageSchema(z.object({ id: z.uuid() })),
          ...problemResponses(400, 401, 404),
        },
      },
    },
    async () => ({ items: [], nextCursor: null })
  );
  typed.get(
    '/developer/v1/widgets/:id',
    { schema: { response: { ...problemResponses(404) } } },
    async () => {
      throw new NotFoundError('Widget', 'missing');
    }
  );
  typed.post('/developer/v1/widgets', async () => ({ created: true }));
  app.get('/admin/v1/fail', async () => {
    throw new Error('connection string postgres://secret@db');
  });
  app.get('/admin/v1/conflict', async () => {
    throw new UniqueConstraintError('users_email_realm_key');
  });
  app.get('/account/v1/token', async () => {
    throw new JWTInvalidError('Invalid JWT token');
  });
  app.post('/account/v1/password', async () => {
    throw new WeakPasswordError(undefined, ['Add another word or two.', 'Avoid common phrases.']);
  });
  app.get('/account/v1/oauth-class', async () => {
    throw new InvalidRequestError('the cursor has expired');
  });
  app.get('/account/v1/odd-code', async () => {
    throw Object.assign(new Error('mismatched'), { statusCode: 400, code: 'NOT_FOUND' });
  });
  app.get('/opt-in', { config: { errorFormat: 'problem' } }, async () => {
    throw new ForbiddenError('No.');
  });
  app.get('/developer/v1/opt-out', { config: { errorFormat: 'oauth' } }, async () => {
    throw new ForbiddenError('No.');
  });
  app.get('/legacy', async () => {
    throw new ForbiddenError('No.');
  });

  return app;
}

describe('error-handler plugin', () => {
  it('maps JWTExpiredError to 401 response', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'GET',
      url: '/test-jwt-expired',
    });

    expect(response.statusCode).toBe(401);

    const json = response.json();
    expect(json).toMatchObject({
      statusCode: 401,
      error: 'JWT token has expired',
      code: 'JWT_EXPIRED',
    });

    await app.close();
  });

  it('maps JWTInvalidError to 401 response', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'GET',
      url: '/test-jwt-invalid',
    });

    expect(response.statusCode).toBe(401);

    const json = response.json();
    expect(json).toMatchObject({
      statusCode: 401,
      error: 'Invalid JWT token',
      code: 'JWT_INVALID',
    });

    await app.close();
  });

  it('maps ForbiddenError to a 403 response (ADR-008 static-API-key gate)', async () => {
    const app = await buildTestApp();

    const response = await app.inject({ method: 'POST', url: '/test-forbidden' });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({
      statusCode: 403,
      error: 'Static API keys are disabled for production clients.',
      code: 'FORBIDDEN',
    });

    await app.close();
  });

  it('sets WWW-Authenticate: Basic on InvalidClientError when request used Basic auth (RFC 6749 §5.2)', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'POST',
      url: '/test-invalid-client',
      headers: {
        authorization: `Basic ${Buffer.from('cid:bad').toString('base64')}`,
      },
    });

    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBe('Basic realm="OAuth"');
    expect(response.json()).toMatchObject({
      error: 'invalid_client',
      code: 'INVALID_CLIENT',
      statusCode: 401,
    });

    await app.close();
  });

  it('sets WWW-Authenticate: Bearer with invalid_token on a JWT failure (RFC 6750 §3)', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'GET',
      url: '/test-jwt-invalid',
      headers: { authorization: 'Bearer bad-token' },
    });

    expect(response.statusCode).toBe(401);
    const challenge = response.headers['www-authenticate'];
    expect(challenge).toContain('Bearer ');
    expect(challenge).toContain('realm="OAuth"');
    expect(challenge).toContain('error="invalid_token"');
    expect(challenge).toContain('error_description="Invalid JWT token"');

    await app.close();
  });

  it('sets WWW-Authenticate: Bearer with invalid_token on an expired token (RFC 6750 §3)', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'GET',
      url: '/test-jwt-expired',
      headers: { authorization: 'Bearer expired-token' },
    });

    expect(response.statusCode).toBe(401);
    const challenge = response.headers['www-authenticate'];
    expect(challenge).toContain('Bearer ');
    expect(challenge).toContain('error="invalid_token"');

    await app.close();
  });

  it('does NOT set the Bearer challenge on the client-auth Basic case (scoping)', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'POST',
      url: '/test-invalid-client',
      headers: { authorization: `Basic ${Buffer.from('cid:bad').toString('base64')}` },
    });

    // The Basic client-auth failure keeps its Basic challenge and never emits a
    // Bearer one — the two paths are distinct (InvalidClientError vs JWT errors).
    expect(response.headers['www-authenticate']).toBe('Basic realm="OAuth"');

    await app.close();
  });

  it('omits WWW-Authenticate on InvalidClientError when request did not use Basic auth', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'POST',
      url: '/test-invalid-client',
    });

    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBeUndefined();
    expect(response.json()).toMatchObject({
      error: 'invalid_client',
      code: 'INVALID_CLIENT',
      statusCode: 401,
    });

    await app.close();
  });

  it('does not leak the constraint name on UniqueConstraintError (enumeration defence)', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'POST',
      url: '/test-unique-constraint',
    });

    expect(response.statusCode).toBe(409);

    const json = response.json();
    // Code + status preserved so legitimate clients can branch on the conflict.
    expect(json).toMatchObject({
      error: 'Resource already exists',
      code: 'UNIQUE_CONSTRAINT_VIOLATION',
      statusCode: 409,
    });
    // The constraint name must NOT appear anywhere in the response — not as a
    // dedicated field, and not embedded in the generic error message.
    expect(json.constraint).toBeUndefined();
    expect(JSON.stringify(json)).not.toContain('users_email_realm_key');

    await app.close();
  });
  /**
   * RFC 6749 §5.2 error CODES, not prose (#365).
   *
   * `InvalidClientError` and `UnauthorizedClientError` took their detail as a
   * MESSAGE, and the handler put the message in `error` — so a described
   * failure shipped `{"error": "CIMD document is not valid JSON"}` where the
   * specification requires the registered token and a separate
   * `error_description`. An OAuth client library branching on
   * `error === 'invalid_client'` saw a different string depending on which call
   * site threw.
   */
  describe('problem details on the API families (#506)', () => {
    it('answers application/problem+json with type, title, status, code and trace_id', async () => {
      const app = await buildProblemApp();

      const response = await app.inject({
        method: 'GET',
        url: '/developer/v1/widgets/9b2b',
        headers: { 'x-request-id': 'trace-123' },
      });

      expect(response.statusCode).toBe(404);
      expect(response.headers['content-type']).toMatch(PROBLEM_CONTENT_TYPE);
      expect(response.json()).toMatchObject({
        type: 'about:blank',
        title: 'Not Found',
        status: 404,
        code: 'not_found',
        trace_id: 'trace-123',
      });
      // The legacy members are gone, so a client cannot branch on them.
      expect(response.json()).not.toHaveProperty('error');
      expect(response.json()).not.toHaveProperty('statusCode');

      await app.close();
    });

    it('lists each failing field in errors[] with a pointer, and refuses a limit above 200', async () => {
      const app = await buildProblemApp();

      const response = await app.inject({ method: 'GET', url: '/developer/v1/widgets?limit=201' });

      expect(response.statusCode).toBe(400);
      expect(response.headers['content-type']).toMatch(PROBLEM_CONTENT_TYPE);
      const body = response.json();
      expect(body).toMatchObject({ status: 400, code: 'validation_error' });
      expect(body.errors).toEqual([{ pointer: '/limit', message: expect.any(String) }]);
      for (const internal of ['schemaPath', 'keyword', 'params', 'instancePath', 'FST_ERR']) {
        expect(response.body).not.toContain(internal);
      }

      await app.close();
    });

    it('pages with limit and cursor and answers { items, nextCursor }', async () => {
      const app = await buildProblemApp();

      const response = await app.inject({ method: 'GET', url: '/developer/v1/widgets' });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ items: [], nextCursor: null });
      for (const limit of ['0', '1.5', 'abc', '0x10', '']) {
        const refused = await app.inject({
          method: 'GET',
          url: `/developer/v1/widgets?limit=${limit}`,
        });
        expect(refused.statusCode).toBe(400);
        expect(refused.json().code).toBe('validation_error');
      }

      await app.close();
    });

    it('never sends a framework code: a 415 answers unsupported_media_type', async () => {
      const app = await buildProblemApp();

      const response = await app.inject({
        method: 'POST',
        url: '/developer/v1/widgets',
        headers: { 'content-type': 'text/x-unknown' },
        payload: 'hello',
      });

      expect(response.statusCode).toBe(415);
      expect(response.json()).toMatchObject({ status: 415, code: 'unsupported_media_type' });

      await app.close();
    });

    it('sends a 500 with no detail and no stack, even outside production', async () => {
      const app = await buildProblemApp();

      const response = await app.inject({ method: 'GET', url: '/admin/v1/fail' });

      expect(response.statusCode).toBe(500);
      expect(response.json()).toMatchObject({ status: 500, code: 'internal_error' });
      expect(response.json()).not.toHaveProperty('detail');
      expect(response.body).not.toContain('postgres://');
      expect(response.body).not.toContain('stack');

      await app.close();
    });

    it('does not leak the constraint name of a UniqueConstraintError', async () => {
      const app = await buildProblemApp();

      const response = await app.inject({ method: 'GET', url: '/admin/v1/conflict' });

      expect(response.statusCode).toBe(409);
      expect(response.json().code).toBe('unique_constraint_violation');
      expect(response.body).not.toContain('users_email_realm_key');

      await app.close();
    });

    it('keeps the RFC 6750 Bearer challenge beside the problem document', async () => {
      const app = await buildProblemApp();

      const response = await app.inject({ method: 'GET', url: '/account/v1/token' });

      expect(response.statusCode).toBe(401);
      expect(response.json().code).toBe('jwt_invalid');
      expect(response.headers['www-authenticate']).toContain('error="invalid_token"');

      await app.close();
    });

    it('puts weak-password feedback in errors[] under /password', async () => {
      const app = await buildProblemApp();

      const response = await app.inject({ method: 'POST', url: '/account/v1/password' });

      expect(response.statusCode).toBe(422);
      expect(response.json().code).toBe('weak_password');
      expect(response.json().errors).toEqual([
        { pointer: '/password', message: expect.any(String) },
        { pointer: '/password', message: expect.any(String) },
      ]);

      await app.close();
    });

    it('sends only published codes, each with its own status', async () => {
      const app = await buildProblemApp();

      // An OAuth error class is not a published problem code: its status decides.
      const oauthClass = await app.inject({ method: 'GET', url: '/account/v1/oauth-class' });
      expect(oauthClass.json()).toMatchObject({ status: 400, code: 'bad_request' });
      // A published code thrown with another status is not sent with it.
      const odd = await app.inject({ method: 'GET', url: '/account/v1/odd-code' });
      expect(odd.json()).toMatchObject({ status: 400, code: 'bad_request' });

      for (const response of [oauthClass, odd]) {
        const { code, status } = response.json() as {
          code: keyof typeof PROBLEM_CODES;
          status: number;
        };
        expect(PROBLEM_CODES[code].status).toBe(status);
      }

      await app.close();
    });

    it('follows config.errorFormat over the path: opt in outside a family, opt out inside one', async () => {
      const app = await buildProblemApp();

      const optIn = await app.inject({ method: 'GET', url: '/opt-in' });
      expect(optIn.headers['content-type']).toMatch(PROBLEM_CONTENT_TYPE);
      expect(optIn.json()).toMatchObject({ status: 403, code: 'forbidden' });

      for (const url of ['/developer/v1/opt-out', '/legacy']) {
        const response = await app.inject({ method: 'GET', url });
        expect(response.headers['content-type']).toMatch(/^application\/json/);
        expect(response.json()).toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
      }

      await app.close();
    });
  });

  describe('OAuth §5.2 error codes', () => {
    it('renders a DESCRIBED InvalidClientError as the token plus error_description', async () => {
      const app = await buildTestApp();

      const response = await app.inject({ method: 'POST', url: '/test-invalid-client-described' });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({
        error: 'invalid_client',
        error_description: 'CIMD document is not valid JSON',
        code: 'INVALID_CLIENT',
        statusCode: 401,
      });

      await app.close();
    });

    it('emits NO error_description for a bare InvalidClientError', async () => {
      // What `helpers/client-auth.ts` throws, deliberately: an authentication
      // failure that describes itself is a client-enumeration oracle. The
      // absence has to survive the move into the described branch.
      const app = await buildTestApp();

      const response = await app.inject({ method: 'POST', url: '/test-invalid-client' });

      expect(response.json()).not.toHaveProperty('error_description');

      await app.close();
    });

    it('still sets WWW-Authenticate: Basic on a DESCRIBED InvalidClientError', async () => {
      // The header is set in its own branch now and falls through to the shared
      // body. A refactor that lost the fall-through would drop either the
      // header or the description, so assert both on one response.
      const app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/test-invalid-client-described',
        headers: { authorization: `Basic ${Buffer.from('cid:bad').toString('base64')}` },
      });

      expect(response.headers['www-authenticate']).toBe('Basic realm="OAuth"');
      expect(response.json()).toMatchObject({
        error: 'invalid_client',
        error_description: 'CIMD document is not valid JSON',
      });

      await app.close();
    });

    it('renders UnauthorizedClientError as unauthorized_client with a 400', async () => {
      const app = await buildTestApp();

      const response = await app.inject({ method: 'POST', url: '/test-unauthorized-client' });

      expect(response.statusCode).toBe(400);
      expect(response.json()).toMatchObject({
        error: 'unauthorized_client',
        error_description: 'client is not registered for the refresh_token grant',
        code: 'UNAUTHORIZED_CLIENT',
        statusCode: 400,
      });

      await app.close();
    });
  });

  /**
   * Validation `details` is PROJECTED, not forwarded (#365).
   *
   * The compiler's own issue objects carry `schemaPath`, `keyword` and a
   * `params` bag — on `POST /oauth/token`, the discriminator name and the full
   * option list. That is the internal shape of the schema, and it was handed to
   * an unauthenticated caller the moment this handler became reachable.
   */
  describe('validation details', () => {
    it('carries only the path and the message', async () => {
      const app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/test-validation',
        payload: { grant_type: 'NOT LOWERCASE' },
      });

      expect(response.statusCode).toBe(400);
      const body = response.json();

      expect(body).toMatchObject({
        error: 'Validation error',
        code: 'VALIDATION_ERROR',
        statusCode: 400,
      });
      expect(Array.isArray(body.details)).toBe(true);
      expect(body.details.length).toBeGreaterThan(0);

      for (const detail of body.details) {
        expect(Object.keys(detail).sort()).toEqual(['message', 'path']);
      }
    });

    it('does not ship the STRUCTURAL fields the raw issues carry', async () => {
      // Asserted on the serialised body rather than per key, so an issue shape
      // this projection does not know about cannot slip a new internal field
      // through.
      //
      // Note what is NOT asserted here: the constraint itself. A validator's
      // `message` quotes the rule it enforced (`must match pattern "…"`), and
      // that stays — the schemas are published in `openapi.json`, so the rule
      // is documentation rather than disclosure, and stripping it would leave a
      // caller a path and no way to know what is wrong with it. The structural
      // fields are the ones that describe how QAuth is BUILT rather than what
      // it accepts, and those are what a caller has no business receiving.
      const app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/test-validation',
        payload: { grant_type: 'NOT LOWERCASE' },
      });

      const serialised = response.body;

      expect(serialised).not.toContain('schemaPath');
      expect(serialised).not.toContain('keyword');
      expect(serialised).not.toContain('params');
      expect(serialised).not.toContain('instancePath');
    });

    it('still names the offending field, which is what a caller needs', async () => {
      const app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/test-validation',
        payload: { grant_type: 'NOT LOWERCASE' },
      });

      expect(response.json().details[0].path).toContain('grant_type');
      expect(response.json().details[0].message).toBeTruthy();
    });

    it('degrades to an empty list rather than throwing on an unreadable shape', async () => {
      // The error handler is the one place a throw produces no response at all,
      // and `error.validation` is typed `unknown` by Fastify — its shape
      // depends on which validator compiler is installed.
      const app = Fastify({ logger: false });
      await app.register(errorHandler);
      app.get('/odd', async () => {
        const error = new Error('bad') as Error & { validation: unknown };
        error.validation = 'not-an-array';
        throw error;
      });

      const response = await app.inject({ method: 'GET', url: '/odd' });

      expect(response.statusCode).toBe(400);
      expect(response.json().details).toEqual([]);

      await app.close();
    });

    it('bounds how many issues it returns and logs, however many there are', async () => {
      // The schemas bound how many issues a request can produce (`boundedArray`
      // in schemas/common.ts). This is the backstop for a schema that misses it:
      // one entry per issue is ~190 bytes of answer, and the error object holds
      // every issue three times over (`validation`, the joined `message`, and
      // `stack`, which starts with that message), ~750 bytes of log each.
      const lines: string[] = [];
      const stream = new Writable({
        write(chunk, _enc, cb) {
          lines.push(chunk.toString());
          cb();
        },
      });
      const app = Fastify({
        logger: { level: 'warn', stream },
        logController: new LogController({ disableRequestLogging: true }),
      });
      await app.register(errorHandler);
      app.get('/many', async () => {
        // Shaped as Fastify builds it from the Zod compiler's output.
        const validation = Array.from({ length: 5000 }, (_, i) => ({
          instancePath: `/grant_types/${i}`,
          message: 'Invalid option',
        }));
        const message = validation.map((v) => `body${v.instancePath} ${v.message}`).join(', ');
        throw Object.assign(new Error(message), { validation, validationContext: 'body' });
      });

      const response = await app.inject({ method: 'GET', url: '/many' });
      await app.close();

      expect(response.statusCode).toBe(400);
      expect(response.json().details).toHaveLength(20);
      expect(response.body.length).toBeLessThan(4096);

      const logged = lines.join('');
      expect(logged).toContain('"issues":5000');
      expect(logged).not.toContain('/grant_types/20 ');
      expect(logged).not.toContain('"/grant_types/20"');
      expect(logged.length).toBeLessThan(8192);
    });
  });

  /**
   * The log line, on the REQUEST logger and at a level that matches the answer
   * (#365).
   *
   * `fastify.log` carries no `reqId` — `request.log` is the child logger the
   * request id is bound to, and propagating it is the entire point of
   * `plugins/request-id.ts` (#128). And every error was `error` level, so an
   * unauthenticated stranger controlled the volume of the stream that pages
   * someone.
   */
  describe('logging', () => {
    /** Capture what the handler logs, by level, through the REQUEST logger. */
    async function captureLogs(url: string, method: 'GET' | 'POST' = 'POST') {
      const app = Fastify({ logger: false });
      await app.register(errorHandler);
      app.post('/client-error', async () => {
        throw new InvalidClientError('nope');
      });
      app.get('/server-error', async () => {
        throw new Error('something came apart');
      });

      const calls: Array<{ level: string; payload: Record<string, unknown> }> = [];
      app.addHook('onRequest', async (request) => {
        for (const level of ['error', 'warn'] as const) {
          const original = request.log[level].bind(request.log);
          request.log[level] = ((payload: unknown, message?: string) => {
            calls.push({ level, payload: payload as Record<string, unknown> });
            return original(payload as never, message as never);
          }) as typeof request.log.error;
        }
      });

      const response = await app.inject({ method, url });
      await app.close();
      return { calls, response };
    }

    it('logs a 4xx at warn, not error', async () => {
      const { calls, response } = await captureLogs('/client-error');

      expect(response.statusCode).toBe(401);
      expect(calls.map((call) => call.level)).toContain('warn');
      expect(calls.map((call) => call.level)).not.toContain('error');
    });

    it('logs a 5xx at error', async () => {
      const { calls, response } = await captureLogs('/server-error', 'GET');

      expect(response.statusCode).toBe(500);
      expect(calls.map((call) => call.level)).toContain('error');
    });

    it('logs through the REQUEST logger, so the line carries a reqId', async () => {
      // The capture hook patches `request.log` specifically. A handler that
      // logged on `fastify.log` would produce no captured call at all — which
      // is exactly the pre-#365 behaviour, and exactly why the correlation id
      // was missing from the one line an operator needs it on.
      const { calls } = await captureLogs('/client-error');

      expect(calls).not.toHaveLength(0);
    });

    it('records the status it is about to send', async () => {
      const { calls } = await captureLogs('/client-error');

      expect(calls[0]?.payload['statusCode']).toBe(401);
    });

    it('(OID4VP 1.0 §14.2) redacts the response_code query value from the error log line too', async () => {
      // The `url` on the handler's line is a plain string key: pino's path
      // redaction cannot reach inside it and the `req` serializer never sees
      // it, so before #405's follow-up a 429 / 5xx / 409 on
      // `/ui/wallet-login/return` wrote the same-device Response Code to the
      // sink in the clear — and the 429 is thrown by `@fastify/rate-limit`
      // from an `onRequest` hook BEFORE the route burns the code, so that
      // line carried a code still redeemable for up to 3 min.
      //
      // Asserted on the serialised stream through a REAL pino logger, as
      // `config/logger.test.ts` does, with Fastify's own request/response
      // lines switched off: every line that carries a `url` below is one this
      // handler wrote, so nothing else can be censoring on its behalf. The
      // limiter is the real plugin on its in-memory store, `max: 2`, so the
      // third arrival is the genuine hook-thrown 429.
      const captured: string[] = [];
      const stream = new Writable({
        write(chunk, _enc, cb) {
          captured.push(chunk.toString());
          cb();
        },
      });

      const app = Fastify({
        logger: { level: 'info', stream },
        logController: new LogController({ disableRequestLogging: true }),
      });
      await app.register(errorHandler);
      await app.register(rateLimit, { max: 2, timeWindow: 60_000 });
      app.get('/ui/wallet-login/return', async (request) => {
        if (request.headers['x-fail'] === 'unique') {
          throw new UniqueConstraintError('oid4vp_request_states_response_code_hash_unique');
        }
        throw new Error('redemption store unavailable');
      });

      const code = 'gLDFeWTVs5PTZcgEjhwwPpTmxIkXIv0CpyHiURdO_-A';
      const url = `/ui/wallet-login/return?response_code=${code}`;

      const thrown = await app.inject({ method: 'GET', url });
      const conflict = await app.inject({ method: 'GET', url, headers: { 'x-fail': 'unique' } });
      const limited = await app.inject({ method: 'GET', url });
      await app.close();

      expect(thrown.statusCode).toBe(500);
      expect(conflict.statusCode).toBe(409);
      expect(limited.statusCode).toBe(429);

      const serialized = captured.join('');
      expect(serialized).not.toContain(code);

      // Each of the three errors logged its line, the 409 logged its
      // operator-only constraint line as well, and every one of them carries
      // the path with the value censored — never the raw request-target.
      const lines = captured
        .map((line) => JSON.parse(line) as { msg?: string; url?: string; statusCode?: number })
        .filter((line) => typeof line.url === 'string');
      const redactedUrl = `/ui/wallet-login/return?response_code=${LOG_REDACT_CENSOR}`;

      expect(lines.map((line) => line.msg)).toEqual([
        'Error occurred',
        'Error occurred',
        'Unique constraint violation',
        'Error occurred',
      ]);
      expect(lines.map((line) => line.url)).toEqual(Array(4).fill(redactedUrl));
      expect(
        lines.filter((line) => line.msg === 'Error occurred').map((line) => line.statusCode)
      ).toEqual([500, 409, 429]);
    });
  });
});
