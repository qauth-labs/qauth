import {
  ForbiddenError,
  InvalidClientError,
  JWTExpiredError,
  JWTInvalidError,
  UnauthorizedClientError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

// F-05: error-handler now reads the validated `env.NODE_ENV` instead of the
// raw `process.env.NODE_ENV`. Mock the env module so the test doesn't trigger
// full env parsing (DATABASE_URL etc. are not set in the test environment).
vi.mock('../../config/env', () => ({
  env: {
    NODE_ENV: 'development',
  },
}));

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
  });
});
