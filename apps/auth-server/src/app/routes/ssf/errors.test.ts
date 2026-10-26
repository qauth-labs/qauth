import { SsfRequestError } from '@qauth-labs/fastify-plugin-ssf';
import { JWTInvalidError, MissingAccessTokenError } from '@qauth-labs/shared-errors';
import Fastify, {
  type FastifyInstance,
  type FastifyRequest,
  type LightMyRequestResponse,
} from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it, vi } from 'vitest';

// The event emitter's module and the error handler's logger import
// `config/env`, which validates required env at module load. Stub it so the
// unit run needs no real environment.
vi.mock('../../../config/env', () => ({
  env: {
    NODE_ENV: 'test',
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
    DEFAULT_REALM_NAME: 'master',
  },
}));

import { PROBLEM_TYPE_BASE } from '../../api-conventions/problem';
import { answerUnknownRouteBeforeBody } from '../../helpers/request-bounds';
import errorHandler from '../../plugins/error-handler';
import ssfRoutes from './index';

/**
 * THE SSF STREAM MANAGEMENT ROUTES ANSWER PROBLEM DOCUMENTS (#513).
 *
 * SSF 1.0 §8.1 and RFC 8935 give stream management statuses but no error
 * body, so the `/ssf/` routes are not OAuth protocol endpoints: each refusal
 * is an RFC 9457 problem document with the code the error registry gives its
 * class (ADR-019 Decision 7). A refused token keeps its RFC 6750 §3 challenge.
 * The end-to-end suite (`ssf-transmitter.integration.test.ts`) drives the same
 * refusals against a real database; this one pins the answers.
 */

const REALM_ID = '0192a000-0000-7000-8000-000000000001';
const ISSUER = 'https://auth.example.com';
const STREAM_ID = '0192a000-0000-7000-8000-0000000000aa';
const PUSH = 'urn:ietf:rfc:8935';
const PROBLEM_CONTENT_TYPE = /^application\/problem\+json(?:;|$)/;

/** The claims of each test token, by its value. */
const TOKENS: Record<string, Record<string, unknown>> = {
  receiver: { sub: 'receiver', clientId: 'receiver', scope: 'ssf:stream', aud: ISSUER },
  'no-scope': { sub: 'receiver', clientId: 'receiver', scope: 'reports:read', aud: ISSUER },
  'for-a-user': { sub: 'some-user', clientId: 'receiver', scope: 'ssf:stream', aud: ISSUER },
};

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function buildApp(options: { switchOn?: boolean } = {}) {
  const app = Fastify({ logger: false });
  apps.push(app);
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  await app.register(errorHandler);
  app.addHook('onRequest', answerUnknownRouteBeforeBody);

  const checkEndpoint = vi.fn(async (): Promise<void> => undefined);
  const streams = {
    find: vi.fn(async () => undefined as unknown),
    create: vi.fn(async () => null as unknown),
    list: vi.fn(async () => []),
    addSubject: vi.fn(async () => 'added'),
  };
  app.decorate('ssf', { eventsSupported: [], checkEndpoint } as never);
  app.decorate('signer', { encrypt: vi.fn() } as unknown as never);
  app.decorate('repositories', {
    ssfStreams: streams,
    realms: { anotherRealmHasIssuer: vi.fn(async () => false) },
    oauthClients: {
      findByClientId: vi.fn(async () => ({
        id: 'receiver-row',
        clientId: 'receiver',
        enabled: true,
        suspended: false,
        scopes: ['ssf:stream'],
      })),
    },
  } as unknown as never);
  app.decorate('requireJwt', (async (request: FastifyRequest) => {
    // As the JWT plugin's `requireJwt`: no credential is not a refused token.
    if (request.headers.authorization === undefined) throw new MissingAccessTokenError();
    const token = request.headers.authorization.replace(/^Bearer /, '');
    const claims = TOKENS[token];
    if (claims === undefined) throw new JWTInvalidError('Invalid access token');
    request.jwtPayload = claims as never;
  }) as never);
  app.decorateRequest('realm', null);
  app.addHook('onRequest', async (request) => {
    request.realm = {
      id: REALM_ID,
      issuer: ISSUER,
      ssfTransmitterEnabled: options.switchOn ?? true,
    } as never;
  });
  await app.register(ssfRoutes, { prefix: '/ssf' });
  await app.ready();
  return { app, checkEndpoint, streams };
}

function call(
  app: FastifyInstance,
  method: 'GET' | 'POST',
  url: string,
  options: { token?: string; payload?: Record<string, unknown> } = {}
) {
  return app.inject({
    method,
    url,
    headers: options.token === undefined ? {} : { authorization: `Bearer ${options.token}` },
    ...(options.payload === undefined ? {} : { payload: options.payload }),
  });
}

/** The body of a problem answer, after checking its status, media type and code. */
function problemOf(
  response: LightMyRequestResponse,
  status: number,
  code: string
): Record<string, unknown> {
  expect(response.statusCode, response.body).toBe(status);
  expect(response.headers['content-type']).toMatch(PROBLEM_CONTENT_TYPE);
  const body = response.json<Record<string, unknown>>();
  expect(body).toMatchObject({
    type: `${PROBLEM_TYPE_BASE}${code.replaceAll('_', '-')}`,
    status,
    code,
    trace_id: expect.any(String),
  });
  for (const member of ['error', 'statusCode', 'message']) expect(body).not.toHaveProperty(member);
  return body;
}

describe('SSF stream management errors (#513)', () => {
  it('answers a realm that does not run the transmitter as an unknown path, before validation', async () => {
    const { app } = await buildApp({ switchOn: false });

    const unknown = await app.inject({ method: 'POST', url: '/ssf/no-such-route', payload: {} });
    const response = await call(app, 'POST', '/ssf/stream', { token: 'receiver', payload: {} });

    const expected = problemOf(unknown, 404, 'not_found');
    const body = problemOf(response, 404, 'not_found');
    expect(body).toEqual({
      ...expected,
      detail: 'No route serves POST /ssf/stream.',
      instance: '/ssf/stream',
      trace_id: body['trace_id'],
    });
    expect(response.headers['www-authenticate']).toBeUndefined();
  });

  it('answers a request without a token with 401 unauthorized and a challenge that names no error', async () => {
    const { app } = await buildApp();

    const response = await call(app, 'GET', '/ssf/stream');

    problemOf(response, 401, 'unauthorized');
    expect(response.headers['www-authenticate']).toBe('Bearer realm="OAuth"');
  });

  it('answers a token that is not a receiver’s with 401 invalid_access_token and an invalid_token challenge', async () => {
    const { app } = await buildApp();

    for (const token of ['not-a-token', 'for-a-user']) {
      const response = await call(app, 'GET', '/ssf/stream', { token });

      problemOf(response, 401, 'invalid_access_token');
      expect(response.headers['www-authenticate'], token).toMatch(
        /^Bearer realm="OAuth", error="invalid_token"/
      );
    }
  });

  it('answers a token without ssf:stream with 403 forbidden, naming the scope in the challenge', async () => {
    const { app } = await buildApp();

    const response = await call(app, 'GET', '/ssf/stream', { token: 'no-scope' });

    problemOf(response, 403, 'forbidden');
    expect(response.headers['www-authenticate']).toBe(
      'Bearer realm="OAuth", error="insufficient_scope", scope="ssf:stream"'
    );
  });

  it('answers a stream the receiver does not have with 404 not_found', async () => {
    const { app } = await buildApp();

    const response = await call(app, 'GET', `/ssf/stream?stream_id=${STREAM_ID}`, {
      token: 'receiver',
    });

    expect(problemOf(response, 404, 'not_found')).toMatchObject({
      detail: 'Stream not found',
      instance: '/ssf/stream',
    });
  });

  it('answers a second stream with 409 conflict (SSF 1.0 §8.1.1.1)', async () => {
    const { app } = await buildApp();

    const response = await call(app, 'POST', '/ssf/stream', {
      token: 'receiver',
      payload: { delivery: { method: PUSH, endpoint_url: 'https://receiver.example/events' } },
    });

    problemOf(response, 409, 'conflict');
  });

  it('answers a request the protocol refuses with 400 bad_request, the reason as the detail', async () => {
    const { app, checkEndpoint } = await buildApp();

    const poll = await call(app, 'POST', '/ssf/stream', {
      token: 'receiver',
      payload: { delivery: { method: 'urn:ietf:rfc:8936' } },
    });
    expect(problemOf(poll, 400, 'bad_request')['detail']).toMatch(/^poll delivery is not offered/);

    checkEndpoint.mockRejectedValueOnce(new SsfRequestError('endpoint_url is refused'));
    const refused = await call(app, 'POST', '/ssf/stream', {
      token: 'receiver',
      payload: { delivery: { method: PUSH, endpoint_url: 'https://internal.example/events' } },
    });
    expect(problemOf(refused, 400, 'bad_request')['detail']).toBe('endpoint_url is refused');
  });

  it('answers a subject whose stored form is too long with 400 bad_request', async () => {
    const { app, streams } = await buildApp();
    streams.find.mockResolvedValue({ id: STREAM_ID });

    const response = await call(app, 'POST', '/ssf/subjects/add', {
      token: 'receiver',
      payload: {
        stream_id: STREAM_ID,
        subject: { format: 'uri', uri: `https://receiver.example/${'a'.repeat(2023)}` },
      },
    });

    expect(problemOf(response, 400, 'bad_request')['detail']).toBe('The subject is too long');
    expect(streams.addSubject).not.toHaveBeenCalled();
  });

  it('answers a body the schema refuses with 400 validation_error and the fields in errors', async () => {
    const { app } = await buildApp();

    const response = await call(app, 'POST', '/ssf/status', {
      token: 'receiver',
      payload: { stream_id: STREAM_ID, status: 'sleeping' },
    });

    const body = problemOf(response, 400, 'validation_error');
    expect(body['errors']).toEqual(
      expect.arrayContaining([expect.objectContaining({ pointer: '/status' })])
    );
  });
});
