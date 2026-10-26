import { Writable } from 'node:stream';

import rateLimit from '@fastify/rate-limit';
import {
  EmailNotVerifiedError,
  ForbiddenError,
  InsufficientScopeError,
  InvalidClientError,
  InvalidClientMetadataError,
  InvalidCredentialsError,
  InvalidDpopProofError,
  InvalidRequestError,
  JWTExpiredError,
  JWTInvalidError,
  MisdirectedRequestError,
  MissingAccessTokenError,
  NotFoundError,
  TemporarilyUnavailableError,
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

// The handler no longer reads the environment, but `config/logger` does at
// import; mock it so the test does not parse a full environment.
vi.mock('../../config/env', () => ({
  env: {
    NODE_ENV: 'development',
  },
}));

import { ERROR_CLASSES } from '../api-conventions/error-classes';
import { OAUTH_ERROR_CODES, oauthErrorResponses } from '../api-conventions/oauth-error';
import { pageQuerySchema, pageSchema } from '../api-conventions/paging';
import { PROBLEM_CODES, PROBLEM_TYPE_BASE, problemResponses } from '../api-conventions/problem';
import { SignInRequiredError } from '../helpers/sign-in-required';
import errorHandler from './error-handler';

/**
 * The media type, with the `charset` parameter Fastify appends to every JSON
 * body it serializes. JSON has no charset parameter (RFC 8259 §11), so a
 * recipient ignores it.
 */
const PROBLEM_CONTENT_TYPE = /^application\/problem\+json(?:;|$)/;
const JSON_CONTENT_TYPE = /^application\/json(?:;|$)/;

/** The members of the body every route answered before #513. */
const LEGACY_MEMBERS = ['error', 'statusCode', 'message', 'details', 'feedback', 'retryAfter'];

/** The route option that makes a test route an OAuth protocol endpoint. */
const OAUTH = { config: { errorFormat: 'oauth' as const } };

/**
 * A Fastify instance with the error handler, validated by the Zod compiler
 * production uses, so a validation failure carries the issues both formatters
 * project. `/oauth/*` routes here are OAuth protocol endpoints; every other
 * route answers the default problem format.
 */
async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify({ logger: false, requestIdHeader: 'x-request-id' });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  await app.register(errorHandler);
  const typed = app.withTypeProvider<ZodTypeProvider>();

  // Problem routes.
  typed.get(
    '/developer/v1-rc.0/widgets',
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
    '/developer/v1-rc.0/widgets/:id',
    { schema: { response: { ...problemResponses(404) } } },
    async () => {
      throw new NotFoundError('Widget', 'missing');
    }
  );
  typed.post('/developer/v1-rc.0/widgets', async () => ({ created: true }));
  typed.post(
    '/auth/thing',
    {
      schema: {
        body: z.object({ email: z.email(), name: z.string().regex(/^[a-z_]+$/) }),
        response: { 200: z.object({ ok: z.boolean() }), ...problemResponses(400) },
      },
    },
    async () => ({ ok: true })
  );
  app.get('/admin/v1-rc.0/fail', async () => {
    throw new Error('connection string postgres://secret@db');
  });
  app.get('/auth/conflict', async () => {
    throw new UniqueConstraintError('users_email_realm_key');
  });
  app.get('/account/v1-rc.0/token', async () => {
    throw new JWTInvalidError('Invalid JWT token');
  });
  app.get('/account/v1-rc.0/no-token', async () => {
    throw new MissingAccessTokenError('Missing or malformed Authorization header');
  });
  app.post('/auth/password', async () => {
    throw new WeakPasswordError(undefined, ['Add another word or two.', 'Avoid common phrases.']);
  });
  app.get('/auth/oauth-class', async () => {
    throw new InvalidRequestError('the cursor has expired');
  });
  app.get('/auth/odd-code', async () => {
    throw Object.assign(new Error('mismatched'), { statusCode: 400, code: 'NOT_FOUND' });
  });
  app.get('/auth/proof-for-a-token-request', async () => {
    throw new InvalidDpopProofError();
  });
  app.get('/auth/misdirected', async () => {
    throw new MisdirectedRequestError({ host: 'unknown.example' });
  });
  app.get('/admin/v1-rc.0/scoped', async () => {
    throw new InsufficientScopeError(
      ['qauth:admin:read', 'qauth:admin:write'],
      'the token lacks qauth:admin:write'
    );
  });
  app.get('/auth/shed', async () => {
    throw new TemporarilyUnavailableError(3, { reason: 'argon2_queue_full' });
  });
  app.get('/auth/forbidden', async () => {
    throw new ForbiddenError('No.');
  });
  app.get('/admin/v1-rc.0/forbidden', async () => {
    throw new ForbiddenError('No.');
  });
  app.get('/admin/v1-rc.0/needs-scope', async () => {
    throw new ForbiddenError('This operation needs qauth:admin:read.', {
      requiredScope: 'qauth:admin:read',
    });
  });
  app.get('/auth/credentials', async () => {
    throw new InvalidCredentialsError();
  });
  app.get('/auth/unverified', async () => {
    throw new EmailNotVerifiedError();
  });
  app.get('/api/bearer-forbidden', { schema: { security: [{ bearerAuth: [] }] } }, async () => {
    throw new ForbiddenError('Static API keys are disabled for production clients.');
  });
  app.get('/api/bearer-unauthorized', { schema: { security: [{ bearerAuth: [] }] } }, async () => {
    throw Object.assign(new Error('Unauthorized'), { statusCode: 401 });
  });
  app.get('/consents/cookie-only', async () => {
    throw new SignInRequiredError('Sign in to manage your consents.');
  });

  // OAuth protocol endpoints.
  typed.post(
    '/oauth/token',
    {
      ...OAUTH,
      schema: {
        body: z.object({ grant_type: z.string().regex(/^[a-z_]+$/) }),
        response: { 200: z.object({ ok: z.boolean() }), ...oauthErrorResponses(400, 401) },
      },
    },
    async () => ({ ok: true })
  );
  app.post('/oauth/invalid-client', OAUTH, async () => {
    throw new InvalidClientError();
  });
  app.post('/oauth/invalid-client-described', OAUTH, async () => {
    throw new InvalidClientError('CIMD document is not valid JSON');
  });
  app.post('/oauth/unauthorized-client', OAUTH, async () => {
    throw new UnauthorizedClientError('client is not registered for the refresh_token grant');
  });
  app.get('/oauth/userinfo', OAUTH, async () => {
    throw new JWTExpiredError('JWT token has expired');
  });
  app.post('/oauth/shed', OAUTH, async () => {
    throw new TemporarilyUnavailableError(1, { reason: 'argon2_queue_full', queued: 32 });
  });
  app.post('/oauth/fail', OAUTH, async () => {
    throw new Error('connection string postgres://secret@db');
  });
  app.post('/oauth/conflict', OAUTH, async () => {
    throw new UniqueConstraintError('oauth_clients_client_id_key');
  });
  app.post('/oauth/not-found', OAUTH, async () => {
    throw new NotFoundError('User', '0b9f7d4e-5c1a-4f7e-9d2b-3a6c8e1f0a42');
  });
  app.post('/oauth/forbidden', OAUTH, async () => {
    throw new ForbiddenError('Developer has reached the client limit');
  });
  app.post('/oauth/quoted', OAUTH, async () => {
    throw new InvalidRequestError('the "scope" is \\ not valid');
  });
  app.post('/oauth/bad-request', OAUTH, async () => {
    throw Object.assign(new Error('Body is not valid JSON'), { statusCode: 400 });
  });
  typed.post(
    '/oauth/register',
    {
      ...OAUTH,
      schema: { body: z.object({ redirect_uris: z.array(z.url()) }) },
      schemaErrorFormatter: () => new InvalidClientMetadataError('redirect_uris: not a list'),
    },
    async () => ({ ok: true })
  );

  return app;
}

/** The body of `response`, as an object. */
function bodyOf(response: { json: () => unknown }): Record<string, unknown> {
  return response.json() as Record<string, unknown>;
}

describe('error-handler plugin (#513)', () => {
  describe('the problem formatter, the default', () => {
    it('answers application/problem+json with type, title, status, instance, code and trace_id', async () => {
      const app = await buildApp();

      const response = await app.inject({
        method: 'GET',
        url: '/developer/v1-rc.0/widgets/9b2b?expand=all',
        headers: { 'x-request-id': 'trace-123' },
      });

      expect(response.statusCode).toBe(404);
      expect(response.headers['content-type']).toMatch(PROBLEM_CONTENT_TYPE);
      const body = bodyOf(response);
      expect(body).toMatchObject({
        type: `${PROBLEM_TYPE_BASE}not-found`,
        title: PROBLEM_CODES.not_found.title,
        status: 404,
        instance: '/developer/v1-rc.0/widgets/9b2b',
        code: 'not_found',
        trace_id: 'trace-123',
      });
      for (const member of LEGACY_MEMBERS) expect(body).not.toHaveProperty(member);

      await app.close();
    });

    it('is the default on a route that names no format', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'GET', url: '/auth/forbidden' });

      expect(response.statusCode).toBe(403);
      expect(response.headers['content-type']).toMatch(PROBLEM_CONTENT_TYPE);
      expect(bodyOf(response)).toMatchObject({ status: 403, code: 'forbidden' });
      // Not a bearer-protected route: no challenge.
      expect(response.headers['www-authenticate']).toBeUndefined();

      await app.close();
    });

    it("gives each domain error class its registry entry's code, type and title", async () => {
      const app = await buildApp();
      const cases: [string, number, keyof typeof PROBLEM_CODES][] = [
        ['/auth/credentials', 401, 'invalid_credentials'],
        ['/auth/unverified', 403, 'email_not_verified'],
        ['/auth/oauth-class', 400, 'invalid_request'],
        ['/auth/misdirected', 421, 'misdirected_request'],
        ['/auth/shed', 503, 'service_unavailable'],
      ];

      for (const [url, status, code] of cases) {
        const response = await app.inject({ method: 'GET', url });
        expect(response.statusCode, url).toBe(status);
        expect(bodyOf(response), url).toMatchObject({
          status,
          code,
          type: `${PROBLEM_TYPE_BASE}${PROBLEM_CODES[code].type}`,
          title: PROBLEM_CODES[code].title,
        });
      }

      await app.close();
    });

    it('answers a shed request with 503, service_unavailable and Retry-After (#751)', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'GET', url: '/auth/shed' });

      expect(response.statusCode).toBe(503);
      expect(response.headers['retry-after']).toBe('3');
      expect(bodyOf(response)).toMatchObject({ status: 503, code: 'service_unavailable' });
      expect(bodyOf(response)).not.toHaveProperty('detail');
      // The reason is the operator's, in the log line.
      expect(response.body).not.toContain('argon2');

      await app.close();
    });

    it('answers a 421 with misdirected_request and names no host (#486)', async () => {
      const app = await buildApp();

      const response = await app.inject({
        method: 'GET',
        url: '/auth/misdirected',
        headers: { host: 'unknown.example' },
      });

      expect(response.statusCode).toBe(421);
      expect(bodyOf(response)).toMatchObject({ status: 421, code: 'misdirected_request' });
      expect(response.body).not.toContain('unknown.example');

      await app.close();
    });

    it('lists each failing field in errors[] with a pointer and a message, and no schema internals', async () => {
      const app = await buildApp();

      const response = await app.inject({
        method: 'POST',
        url: '/auth/thing',
        payload: { email: 'not-an-address', name: 'NOT LOWER' },
      });

      expect(response.statusCode).toBe(400);
      expect(response.headers['content-type']).toMatch(PROBLEM_CONTENT_TYPE);
      const body = bodyOf(response);
      expect(body).toMatchObject({ status: 400, code: 'validation_error' });
      expect(body['errors']).toEqual([
        { pointer: '/email', message: expect.any(String) },
        { pointer: '/name', message: expect.any(String) },
      ]);
      for (const internal of ['schemaPath', 'keyword', 'params', 'instancePath', 'FST_ERR']) {
        expect(response.body).not.toContain(internal);
      }

      await app.close();
    });

    it('points at a query parameter, and refuses a limit above 200', async () => {
      const app = await buildApp();

      const response = await app.inject({
        method: 'GET',
        url: '/developer/v1-rc.0/widgets?limit=201',
      });

      expect(response.statusCode).toBe(400);
      expect(bodyOf(response)).toMatchObject({ status: 400, code: 'validation_error' });
      expect(bodyOf(response)['errors']).toEqual([
        { pointer: '/limit', message: expect.any(String) },
      ]);

      await app.close();
    });

    it('pages with limit and cursor and answers { items, nextCursor }', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'GET', url: '/developer/v1-rc.0/widgets' });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ items: [], nextCursor: null });
      for (const limit of ['0', '1.5', 'abc', '0x10', '']) {
        const refused = await app.inject({
          method: 'GET',
          url: `/developer/v1-rc.0/widgets?limit=${limit}`,
        });
        expect(refused.statusCode).toBe(400);
        expect(bodyOf(refused)['code']).toBe('validation_error');
      }

      await app.close();
    });

    it('never sends a framework code: a 415 answers unsupported_media_type', async () => {
      const app = await buildApp();

      const response = await app.inject({
        method: 'POST',
        url: '/developer/v1-rc.0/widgets',
        headers: { 'content-type': 'text/x-unknown' },
        payload: 'hello',
      });

      expect(response.statusCode).toBe(415);
      expect(bodyOf(response)).toMatchObject({ status: 415, code: 'unsupported_media_type' });

      await app.close();
    });

    it('sends a 500 with no detail and no stack, even outside production', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'GET', url: '/admin/v1-rc.0/fail' });

      expect(response.statusCode).toBe(500);
      expect(bodyOf(response)).toMatchObject({ status: 500, code: 'internal_error' });
      expect(bodyOf(response)).not.toHaveProperty('detail');
      expect(response.body).not.toContain('postgres://');
      expect(response.body).not.toContain('stack');

      await app.close();
    });

    it('does not leak the constraint name of a UniqueConstraintError (enumeration defence)', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'GET', url: '/auth/conflict' });

      expect(response.statusCode).toBe(409);
      // Code + status preserved so legitimate clients can branch on the conflict.
      expect(bodyOf(response)['code']).toBe('already_exists');
      expect(bodyOf(response)).not.toHaveProperty('detail');
      expect(response.body).not.toContain('users_email_realm_key');

      await app.close();
    });

    it('keeps the RFC 6750 Bearer challenge beside the problem document', async () => {
      const app = await buildApp();

      const response = await app.inject({
        method: 'GET',
        url: '/account/v1-rc.0/token',
        headers: { authorization: 'Bearer bad-token' },
      });

      expect(response.statusCode).toBe(401);
      expect(bodyOf(response)['code']).toBe('invalid_access_token');
      expect(response.headers['www-authenticate']).toMatch(
        /^Bearer realm="OAuth", error="invalid_token", error_description="[^"]*"$/
      );

      await app.close();
    });

    it('answers a missing scope with 403 insufficient_scope and a challenge naming the scopes (#509)', async () => {
      const app = await buildApp();

      const response = await app.inject({
        method: 'GET',
        url: '/admin/v1-rc.0/scoped',
        headers: { authorization: 'Bearer a.b.c' },
      });

      expect(response.statusCode).toBe(403);
      expect(response.headers['content-type']).toMatch(PROBLEM_CONTENT_TYPE);
      expect(response.json()).toMatchObject({
        type: 'https://docs.qauth.dev/reference/problem-types/#insufficient-scope',
        title: 'Insufficient scope',
        status: 403,
        code: 'insufficient_scope',
        detail: 'the token lacks qauth:admin:write',
      });
      expect(response.headers['www-authenticate']).toBe(
        'Bearer realm="OAuth", error="insufficient_scope", scope="qauth:admin:read qauth:admin:write"'
      );

      await app.close();
    });

    it('puts weak-password feedback in errors[] under /password', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'POST', url: '/auth/password' });

      expect(response.statusCode).toBe(422);
      expect(bodyOf(response)['code']).toBe('weak_password');
      expect(bodyOf(response)['errors']).toEqual([
        { pointer: '/password', message: expect.any(String) },
        { pointer: '/password', message: expect.any(String) },
      ]);
      expect(bodyOf(response)).not.toHaveProperty('feedback');

      await app.close();
    });

    it('sends only published codes, each with its own status', async () => {
      const app = await buildApp();

      // A published code thrown with another status is not sent with it.
      const odd = await app.inject({ method: 'GET', url: '/auth/odd-code' });
      expect(bodyOf(odd)).toMatchObject({ status: 400, code: 'bad_request' });
      // A class thrown with a status its entry does not list gets its status's code.
      const proof = await app.inject({ method: 'GET', url: '/auth/proof-for-a-token-request' });
      expect(bodyOf(proof)).toMatchObject({ status: 400, code: 'bad_request' });

      await app.close();
    });

    describe('the challenge on a bearer-protected route (RFC 6750 §3, RFC 9449 §7.1)', () => {
      it('answers a 403 no scope can lift with a challenge that names no error', async () => {
        const app = await buildApp();

        const response = await app.inject({
          method: 'GET',
          url: '/api/bearer-forbidden',
          headers: { authorization: 'Bearer a.b.c' },
        });

        expect(response.statusCode).toBe(403);
        expect(bodyOf(response)['code']).toBe('forbidden');
        // Not insufficient_scope: a client reading it would go back for a
        // wider token that cannot help (RFC 6750 §3.1).
        expect(response.headers['www-authenticate']).toBe('Bearer realm="OAuth"');

        await app.close();
      });

      it('answers a 403 that names the scope it needs with insufficient_scope and the scope', async () => {
        const app = await buildApp();

        const response = await app.inject({
          method: 'GET',
          url: '/admin/v1-rc.0/needs-scope',
          headers: { authorization: 'Bearer a.b.c' },
        });

        expect(response.statusCode).toBe(403);
        expect(bodyOf(response)['code']).toBe('forbidden');
        expect(response.headers['www-authenticate']).toBe(
          'Bearer realm="OAuth", error="insufficient_scope", scope="qauth:admin:read"'
        );

        await app.close();
      });

      it('answers a 401 with no credentials with a challenge that names no error', async () => {
        const app = await buildApp();

        const bare = await app.inject({ method: 'GET', url: '/api/bearer-unauthorized' });
        expect(bare.headers['www-authenticate']).toBe('Bearer realm="OAuth"');
        expect(bodyOf(bare)['code']).toBe('unauthorized');

        const presented = await app.inject({
          method: 'GET',
          url: '/api/bearer-unauthorized',
          headers: { authorization: 'Bearer a.b.c' },
        });
        expect(presented.headers['www-authenticate']).toBe(
          'Bearer realm="OAuth", error="invalid_token"'
        );

        await app.close();
      });

      it('answers a request that presented no access token with unauthorized and no error in the challenge (RFC 6750 §3.1)', async () => {
        const app = await buildApp();

        // What `requireJwt` throws for a request without a credential.
        const missing = await app.inject({ method: 'GET', url: '/account/v1-rc.0/no-token' });
        expect(missing.statusCode).toBe(401);
        expect(bodyOf(missing)).toMatchObject({ status: 401, code: 'unauthorized' });
        expect(missing.headers['www-authenticate']).toBe('Bearer realm="OAuth"');

        // A refused-token class met by a request that sent no Authorization
        // header: the code is the class's, the challenge still names no error.
        const unsent = await app.inject({ method: 'GET', url: '/account/v1-rc.0/token' });
        expect(bodyOf(unsent)['code']).toBe('invalid_access_token');
        expect(unsent.headers['www-authenticate']).toBe('Bearer realm="OAuth"');

        await app.close();
      });

      it('answers a route of an API family the same way, whatever its schema declares', async () => {
        const app = await buildApp();

        const forbidden = await app.inject({ method: 'GET', url: '/admin/v1-rc.0/forbidden' });
        expect(forbidden.statusCode).toBe(403);
        expect(forbidden.headers['www-authenticate']).toBe('Bearer realm="OAuth"');
        // Not a 401 or 403: no challenge.
        const missing = await app.inject({ method: 'GET', url: '/developer/v1-rc.0/widgets/x' });
        expect(missing.headers['www-authenticate']).toBeUndefined();

        await app.close();
      });

      it('gives no challenge on a route that takes no bearer token', async () => {
        const app = await buildApp();

        const response = await app.inject({ method: 'GET', url: '/consents/cookie-only' });

        expect(response.statusCode).toBe(401);
        expect(response.headers['www-authenticate']).toBeUndefined();
        // A missing browser session is the `unauthorized` problem, not a body
        // of the route's own (#513).
        expect(response.headers['content-type']).toMatch(PROBLEM_CONTENT_TYPE);
        expect(response.json()).toMatchObject({
          status: 401,
          code: 'unauthorized',
          type: `${PROBLEM_TYPE_BASE}unauthorized`,
          detail: 'Sign in to manage your consents.',
          instance: '/consents/cookie-only',
        });

        await app.close();
      });

      it('answers in the DPoP scheme when the request used it while DPoP is on', async () => {
        const app = Fastify({ logger: false });
        app.decorate('dpop', { algorithms: ['ES256', 'EdDSA'] } as never);
        await app.register(errorHandler);
        app.get('/api/x', { schema: { security: [{ bearerAuth: [] }] } }, async () => {
          throw new ForbiddenError('Needs a scope.', { requiredScope: 'clients:write' });
        });

        const response = await app.inject({
          method: 'GET',
          url: '/api/x',
          headers: { authorization: 'DPoP a.b.c' },
        });

        expect(response.headers['www-authenticate']).toBe(
          'DPoP error="insufficient_scope", scope="clients:write", algs="ES256 EdDSA"'
        );

        await app.close();
      });
    });
  });

  describe('the oauth formatter, on the OAuth protocol endpoints (RFC 6749 §5.2)', () => {
    it('sends only error and error_description, as application/json', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'POST', url: '/oauth/invalid-client-described' });

      expect(response.statusCode).toBe(401);
      expect(response.headers['content-type']).toMatch(JSON_CONTENT_TYPE);
      const body = bodyOf(response);
      expect(body['error']).toBe('invalid_client');
      expect(typeof body['error_description']).toBe('string');
      expect(Object.keys(body).sort()).toEqual(['error', 'error_description']);

      await app.close();
    });

    it('emits NO error_description for a bare InvalidClientError', async () => {
      // What `helpers/client-auth.ts` throws, deliberately: an authentication
      // failure that describes itself is a client-enumeration oracle.
      const app = await buildApp();

      const response = await app.inject({ method: 'POST', url: '/oauth/invalid-client' });

      expect(response.json()).toEqual({ error: 'invalid_client' });
      expect(response.headers['www-authenticate']).toBeUndefined();

      await app.close();
    });

    it('sets WWW-Authenticate: Basic on InvalidClientError when the request used Basic', async () => {
      const app = await buildApp();

      const response = await app.inject({
        method: 'POST',
        url: '/oauth/invalid-client-described',
        headers: { authorization: `Basic ${Buffer.from('cid:bad').toString('base64')}` },
      });

      expect(response.statusCode).toBe(401);
      // The Basic client-auth failure keeps its Basic challenge and never emits a
      // Bearer one — the two paths are distinct (InvalidClientError vs JWT errors).
      expect(response.headers['www-authenticate']).toBe('Basic realm="OAuth"');
      expect(bodyOf(response)['error']).toBe('invalid_client');

      await app.close();
    });

    it('renders UnauthorizedClientError as unauthorized_client with a 400', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'POST', url: '/oauth/unauthorized-client' });

      expect(response.statusCode).toBe(400);
      expect(bodyOf(response)['error']).toBe('unauthorized_client');

      await app.close();
    });

    it('answers an expired access token with invalid_token and the Bearer challenge (RFC 6750 §3.1)', async () => {
      const app = await buildApp();

      const response = await app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: { authorization: 'Bearer expired-token' },
      });

      expect(response.statusCode).toBe(401);
      expect(bodyOf(response)['error']).toBe('invalid_token');
      const challenge = response.headers['www-authenticate'];
      expect(challenge).toContain('Bearer ');
      expect(challenge).toContain('realm="OAuth"');
      expect(challenge).toContain('error="invalid_token"');

      await app.close();
    });

    it('answers a schema failure with invalid_request, naming the field', async () => {
      const app = await buildApp();

      const response = await app.inject({
        method: 'POST',
        url: '/oauth/token',
        payload: { grant_type: 'NOT LOWERCASE' },
      });

      expect(response.statusCode).toBe(400);
      const body = bodyOf(response);
      expect(body['error']).toBe('invalid_request');
      expect(String(body['error_description'])).toContain('/grant_type');
      expect(Object.keys(body).sort()).toEqual(['error', 'error_description']);
      for (const internal of ['schemaPath', 'keyword', 'params', 'instancePath', 'FST_ERR']) {
        expect(response.body).not.toContain(internal);
      }

      await app.close();
    });

    it("answers a schema failure with the OAuth error a route's schemaErrorFormatter raises (RFC 7591 §3.2.2)", async () => {
      const app = await buildApp();

      const response = await app.inject({
        method: 'POST',
        url: '/oauth/register',
        payload: { redirect_uris: 'https://app.example.com/cb' },
      });

      expect(response.statusCode).toBe(400);
      expect(bodyOf(response)['error']).toBe('invalid_client_metadata');

      await app.close();
    });

    it('answers a shed request with temporarily_unavailable and Retry-After, and no description (#751)', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'POST', url: '/oauth/shed' });

      expect(response.statusCode).toBe(503);
      expect(response.headers['retry-after']).toBe('1');
      expect(response.json()).toEqual({ error: 'temporarily_unavailable' });

      await app.close();
    });

    it('answers a 5xx with server_error and nothing of the failure', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'POST', url: '/oauth/fail' });

      expect(response.statusCode).toBe(500);
      expect(response.json()).toEqual({ error: 'server_error' });

      await app.close();
    });

    it('does not leak the constraint name of a UniqueConstraintError', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'POST', url: '/oauth/conflict' });

      expect(response.statusCode).toBe(409);
      expect(response.json()).toEqual({ error: 'invalid_request' });

      await app.close();
    });

    it('names no internal row id: a NotFoundError carries no description', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'POST', url: '/oauth/not-found' });

      expect(response.statusCode).toBe(404);
      expect(response.json()).toEqual({ error: 'invalid_request' });

      await app.close();
    });

    it("answers a class with no token of its own with its registry entry's OAuth error", async () => {
      const app = await buildApp();

      const forbidden = await app.inject({ method: 'POST', url: '/oauth/forbidden' });
      expect(forbidden.statusCode).toBe(403);
      expect(bodyOf(forbidden)['error']).toBe('access_denied');

      const framework = await app.inject({ method: 'POST', url: '/oauth/bad-request' });
      expect(framework.statusCode).toBe(400);
      expect(bodyOf(framework)['error']).toBe('invalid_request');

      await app.close();
    });

    it('keeps error_description inside the character set RFC 6749 §5.2 allows', async () => {
      const app = await buildApp();

      const response = await app.inject({ method: 'POST', url: '/oauth/quoted' });

      const description = String(bodyOf(response)['error_description']);
      expect(description).toMatch(/^[\x20-\x21\x23-\x5b\x5d-\x7e]+$/);

      await app.close();
    });

    it('answers the rate limiter with temporarily_unavailable and Retry-After', async () => {
      const app = Fastify({ logger: false });
      await app.register(errorHandler);
      await app.register(rateLimit, { max: 1, timeWindow: 60_000 });
      app.post('/oauth/token', OAUTH, async () => ({ ok: true }));
      app.post('/auth/login', async () => ({ ok: true }));

      for (const url of ['/oauth/token', '/auth/login']) {
        await app.inject({ method: 'POST', url });
      }
      const oauth = await app.inject({ method: 'POST', url: '/oauth/token' });
      const problem = await app.inject({ method: 'POST', url: '/auth/login' });
      await app.close();

      expect(oauth.statusCode).toBe(429);
      expect(oauth.headers['retry-after']).toMatch(/^\d+$/);
      expect(bodyOf(oauth)['error']).toBe('temporarily_unavailable');
      expect(bodyOf(oauth)).not.toHaveProperty('statusCode');
      expect(problem.statusCode).toBe(429);
      expect(problem.headers['retry-after']).toMatch(/^\d+$/);
      expect(bodyOf(problem)).toMatchObject({ status: 429, code: 'too_many_requests' });
    });

    it('sends only error values the OAuth error schema lists', () => {
      for (const { oauthError } of ERROR_CLASSES) {
        expect(Object.hasOwn(OAUTH_ERROR_CODES, oauthError)).toBe(true);
      }
    });
  });

  /**
   * DPoP (RFC 9449, #480). The handler reads `fastify.dpop`: null while
   * DPOP_ENABLED is off, the verifier's service while it is on.
   */
  describe('DPoP challenges (RFC 9449 §5, §7.1)', () => {
    async function buildDpopApp(dpopOn: boolean): Promise<FastifyInstance> {
      const app = Fastify({ logger: false });
      app.decorate('dpop', dpopOn ? ({ algorithms: ['ES256', 'EdDSA'] } as never) : null);
      await app.register(errorHandler);
      app.post('/token', OAUTH, async () => {
        throw new InvalidDpopProofError();
      });
      app.get('/resource-proof', OAUTH, async () => {
        throw new InvalidDpopProofError(undefined, { atResource: true });
      });
      app.get('/resource-token', OAUTH, async () => {
        throw new JWTInvalidError('Invalid DPoP key binding');
      });
      app.get('/resource-scope', OAUTH, async () => {
        throw new InsufficientScopeError(['account:read', 'bad"scope']);
      });
      return app;
    }

    it('answers invalid_dpop_proof at the token endpoint with a 400 OAuth body and no challenge', async () => {
      const app = await buildDpopApp(true);
      const response = await app.inject({ method: 'POST', url: '/token' });
      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({ error: 'invalid_dpop_proof' });
      expect(response.headers['www-authenticate']).toBeUndefined();
      await app.close();
    });

    it('answers a refused proof at a resource with 401 and a DPoP challenge naming the algorithms', async () => {
      const app = await buildDpopApp(true);
      const response = await app.inject({ method: 'GET', url: '/resource-proof' });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({ error: 'invalid_dpop_proof' });
      expect(response.headers['www-authenticate']).toBe(
        'DPoP error="invalid_dpop_proof", algs="ES256 EdDSA"'
      );
      await app.close();
    });

    it('answers a token refused under the DPoP scheme with a DPoP invalid_token challenge', async () => {
      const app = await buildDpopApp(true);
      const response = await app.inject({
        method: 'GET',
        url: '/resource-token',
        headers: { authorization: 'DPoP some.token.value' },
      });
      expect(response.statusCode).toBe(401);
      expect(response.headers['www-authenticate']).toMatch(
        /^DPoP error="invalid_token", error_description="[^"]*", algs="ES256 EdDSA"$/
      );
      await app.close();
    });

    it('keeps the Bearer challenge for a Bearer request, with DPoP on or off', async () => {
      for (const dpopOn of [true, false]) {
        const app = await buildDpopApp(dpopOn);
        const response = await app.inject({
          method: 'GET',
          url: '/resource-token',
          headers: { authorization: 'Bearer some.token.value' },
        });
        expect(response.headers['www-authenticate']).toMatch(
          /^Bearer realm="OAuth", error="invalid_token", error_description="[^"]*"$/
        );
        await app.close();
      }
    });

    it('answers a missing scope under the scheme the request used (#509)', async () => {
      const app = await buildDpopApp(true);
      const dpop = await app.inject({
        method: 'GET',
        url: '/resource-scope',
        headers: { authorization: 'DPoP some.token.value' },
      });
      expect(dpop.statusCode).toBe(403);
      // A scope outside the scope-token grammar never reaches the quoted string.
      expect(dpop.headers['www-authenticate']).toBe(
        'DPoP error="insufficient_scope", scope="account:read", algs="ES256 EdDSA"'
      );
      const bearer = await app.inject({
        method: 'GET',
        url: '/resource-scope',
        headers: { authorization: 'Bearer some.token.value' },
      });
      expect(bearer.headers['www-authenticate']).toBe(
        'Bearer realm="OAuth", error="insufficient_scope", scope="account:read"'
      );
      // An OAuth protocol endpoint answers the RFC 6750 body, and nothing more.
      expect(bearer.json()).toEqual({ error: 'insufficient_scope' });
      await app.close();
    });

    it('answers a DPoP-scheme request without a token with a DPoP challenge that names no error', async () => {
      const app = Fastify({ logger: false });
      app.decorate('dpop', { algorithms: ['ES256', 'EdDSA'] } as never);
      await app.register(errorHandler);
      app.get('/resource-none', OAUTH, async () => {
        throw new MissingAccessTokenError();
      });

      const response = await app.inject({
        method: 'GET',
        url: '/resource-none',
        headers: { authorization: 'DPoP ' },
      });

      expect(response.statusCode).toBe(401);
      expect(response.headers['www-authenticate']).toBe('DPoP algs="ES256 EdDSA"');
      expect(response.json()).toMatchObject({ error: 'invalid_token' });
      await app.close();
    });

    it('keeps the Bearer challenge for a DPoP-scheme request while DPoP is off', async () => {
      const app = await buildDpopApp(false);
      const response = await app.inject({
        method: 'GET',
        url: '/resource-token',
        headers: { authorization: 'DPoP some.token.value' },
      });
      expect(response.headers['www-authenticate']).toMatch(/^Bearer realm="OAuth"/);
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
    /** A route whose body schema the request below fails, in JSON Schema form. */
    async function buildValidationApp(): Promise<FastifyInstance> {
      const app = Fastify({ logger: false });
      await app.register(errorHandler);
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
      return app;
    }

    it('carries only the pointer and the message', async () => {
      const app = await buildValidationApp();

      const response = await app.inject({
        method: 'POST',
        url: '/test-validation',
        payload: { grant_type: 'NOT LOWERCASE' },
      });

      expect(response.statusCode).toBe(400);
      const body = bodyOf(response);

      expect(body).toMatchObject({ status: 400, code: 'validation_error' });
      const errors = body['errors'] as Record<string, unknown>[];
      expect(Array.isArray(errors)).toBe(true);
      expect(errors.length).toBeGreaterThan(0);

      for (const detail of errors) {
        expect(Object.keys(detail).sort()).toEqual(['message', 'pointer']);
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
      const app = await buildValidationApp();

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
      const app = await buildValidationApp();

      const response = await app.inject({
        method: 'POST',
        url: '/test-validation',
        payload: { grant_type: 'NOT LOWERCASE' },
      });

      const [first] = bodyOf(response)['errors'] as { pointer: string; message: string }[];
      expect(first?.pointer).toBe('/grant_type');
      expect(first?.message).toBeTruthy();
    });

    it('degrades to no list rather than throwing on an unreadable shape', async () => {
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
      expect(bodyOf(response)['code']).toBe('validation_error');
      expect(bodyOf(response)).not.toHaveProperty('errors');

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
      expect(bodyOf(response)['errors']).toHaveLength(20);
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
      app.post('/client-error', OAUTH, async () => {
        throw new InvalidClientError('nope');
      });
      app.get('/server-error', async () => {
        throw new Error('something came apart');
      });
      app.post('/shed', async () => {
        throw new TemporarilyUnavailableError(1, { reason: 'argon2_queue_full', queued: 32 });
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

    it('logs a request shed under load at warn, with its details (#751)', async () => {
      // A burst anyone can send is shed by design; at `error` it would flood
      // the level that pages someone.
      const { calls, response } = await captureLogs('/shed');

      expect(response.statusCode).toBe(503);
      expect(calls.map((call) => call.level)).toEqual(['warn']);
      expect(calls[0]?.payload['statusCode']).toBe(503);
      expect(calls[0]?.payload['err']).toMatchObject({
        details: { reason: 'argon2_queue_full', queued: 32 },
      });
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
