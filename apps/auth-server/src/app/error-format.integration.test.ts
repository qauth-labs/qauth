import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_PASSWORD,
  type E2eInfrastructure,
  generateJwtPem,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE OAUTH PROTOCOL ENDPOINTS KEEP THE ERROR SHAPE THEIR RFC DEFINES, AND
 * EVERY OTHER ROUTE ANSWERS A PROBLEM DOCUMENT (ADR-019 Decision 7, #506, #513).
 *
 * The admin, account and developer APIs answer an error with an RFC 9457
 * problem document. An OAuth protocol endpoint does not: the clients and
 * libraries written to its specification parse the shape that specification
 * defines. `error-handler-wiring.test.ts` asserts the problem half on API family
 * routes in the assembled app; this suite asserts the protocol half on the
 * token and revocation endpoints, which resolve the realm from the database
 * before they refuse a client, so they need a real one.
 *
 * Assertions read the machine-readable member (`error`) and the status, never
 * the wording.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

/** Problem-document members that must never appear in an RFC 6749 §5.2 body. */
const PROBLEM_MEMBERS = ['type', 'title', 'status', 'trace_id'];

/** The members of the body every route answered before #513. */
const LEGACY_MEMBERS = ['error', 'statusCode', 'message', 'details', 'feedback'];

type InjectResponse = Awaited<ReturnType<FastifyInstance['inject']>>;

/** Headers that differ between any two requests: the id, the date, the rate-limit counters. */
const PER_REQUEST_HEADERS = new Set([
  'date',
  'x-request-id',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
]);

describe('OAuth protocol endpoints keep their RFC error shape (real containers, #506)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer(baseEnvironment(infra, await generateJwtPem()));
    await resetE2eState(booted.app);
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  function app(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  /**
   * RFC 6749 §5.2: a JSON object whose `error` is the registered token, and no
   * member QAuth used to add (#513).
   */
  function expectOAuthError(response: InjectResponse, status: number, error: string): void {
    expect(response.statusCode).toBe(status);
    expect(response.headers['content-type']).toMatch(/^application\/json(?:;|$)/);
    const body = response.json() as Record<string, unknown>;
    expect(body['error']).toBe(error);
    for (const member of PROBLEM_MEMBERS) expect(body).not.toHaveProperty(member);
    for (const member of ['code', 'statusCode', 'feedback', 'retryAfter']) {
      expect(body).not.toHaveProperty(member);
    }
  }

  /** RFC 9457: a problem document with its `code`, and none of the old members (#513). */
  function expectProblem(response: InjectResponse, status: number, code: string) {
    expect(response.statusCode).toBe(status);
    expect(response.headers['content-type']).toMatch(/^application\/problem\+json(?:;|$)/);
    const body = response.json() as Record<string, unknown>;
    expect(body).toMatchObject({ status, code });
    expect(String(body['type'])).toMatch(
      /^https:\/\/docs\.qauth\.dev\/reference\/problem-types\/#/
    );
    expect(typeof body['title']).toBe('string');
    // The request id the response header carries: the app's request-id
    // plugin sets it on every route, and the root's own answers echo it too.
    expect(typeof body['trace_id']).toBe('string');
    expect(body['trace_id']).toBe(response.headers['x-request-id']);
    for (const member of LEGACY_MEMBERS) expect(body).not.toHaveProperty(member);
    return body;
  }

  /** A problem document without its `trace_id`, the one member that differs per request. */
  function withoutTraceId(response: InjectResponse): Record<string, unknown> {
    const { trace_id: traceId, ...rest } = response.json() as Record<string, unknown>;
    expect(typeof traceId).toBe('string');
    return rest;
  }

  /**
   * The headers that may not tell two refusals apart: all but the per-request
   * ones (the rate-limit counters count every request), with the CSP's
   * per-response nonces masked.
   */
  function stableHeaders(response: InjectResponse): Record<string, unknown> {
    return Object.fromEntries(
      Object.entries(response.headers)
        .filter(([name]) => !PER_REQUEST_HEADERS.has(name))
        .map(([name, value]) =>
          name === 'content-security-policy' && typeof value === 'string'
            ? [name, value.replace(/'nonce-[^']+'/g, "'nonce-*'")]
            : [name, value]
        )
    );
  }

  function login(email: string, password: string): Promise<InjectResponse> {
    return app().inject({ method: 'POST', url: '/auth/login', payload: { email, password } });
  }

  it('POST /oauth/token answers invalid_client for an unknown client (RFC 6749 §5.2)', async () => {
    const response = await app().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload:
        'grant_type=client_credentials&client_id=no-such-client&client_secret=wrong&scope=read',
    });

    expectOAuthError(response, 401, 'invalid_client');
  });

  it('POST /oauth/token answers invalid_client with a Basic challenge for two authentication methods (RFC 6749 §2.3, §5.2)', async () => {
    const response = await app().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: {
        ...FORM,
        authorization: `Basic ${Buffer.from('a-client:a-secret').toString('base64')}`,
      },
      payload: 'grant_type=client_credentials&client_secret=another-secret',
    });

    expectOAuthError(response, 401, 'invalid_client');
    expect(response.headers['www-authenticate']).toBe('Basic realm="OAuth"');
  });

  it('POST /oauth/revoke answers invalid_client for an unknown client (RFC 7009 §2.2.1)', async () => {
    const response = await app().inject({
      method: 'POST',
      url: '/oauth/revoke',
      headers: FORM,
      payload: 'token=anything&client_id=no-such-client&client_secret=wrong',
    });

    expectOAuthError(response, 401, 'invalid_client');
  });

  it('POST /oauth/token answers an unknown grant_type with unsupported_grant_type and no code or statusCode (RFC 6749 §5.2)', async () => {
    const response = await app().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: 'grant_type=password&username=u&password=p',
    });

    expectOAuthError(response, 400, 'unsupported_grant_type');
  });

  it('POST /oauth/register answers invalid client metadata with invalid_client_metadata (RFC 7591 §3.2.2)', async () => {
    // A value the schema refuses...
    const refusedBySchema = await app().inject({
      method: 'POST',
      url: '/oauth/register',
      payload: {
        redirect_uris: ['https://app.example.com/cb'],
        token_endpoint_auth_method: 'not-a-method',
      },
    });
    expectOAuthError(refusedBySchema, 400, 'invalid_client_metadata');

    // ...and a redirect URI the registration policy refuses.
    const refusedByPolicy = await app().inject({
      method: 'POST',
      url: '/oauth/register',
      payload: { redirect_uris: ['http://app.example.com/cb'] },
    });
    expectOAuthError(refusedByPolicy, 400, 'invalid_redirect_uri');
  });

  it('answers a 404 on a route that is not an OAuth endpoint with a problem document (RFC 9457 §3)', async () => {
    // A path no route serves, answered by the root instance...
    const unknown = await app().inject({
      method: 'GET',
      url: '/no-such-route?x=1',
      headers: { 'x-request-id': 'trace-from-the-caller' },
    });
    expect(expectProblem(unknown, 404, 'not_found')['trace_id']).toBe('trace-from-the-caller');

    // ...and a resource a route does not find, for the portal's own token.
    await registerPasswordAccount(app(), 'portal-dev@example.com');
    const signedIn = await login('portal-dev@example.com', E2E_PASSWORD);
    expect(signedIn.statusCode).toBe(200);
    const { access_token: token } = signedIn.json() as { access_token: string };
    const missing = await app().inject({
      method: 'GET',
      url: '/api/clients/7f0d6a4e-2c1b-4e8f-9a3d-5b6c7d8e9f01',
      headers: { authorization: `Bearer ${token}` },
    });
    const body = expectProblem(missing, 404, 'not_found');
    expect(body['instance']).toBe('/api/clients/7f0d6a4e-2c1b-4e8f-9a3d-5b6c7d8e9f01');
  });

  it('answers the consent routes without a browser session with the unauthorized problem and no challenge (RFC 9457 §3)', async () => {
    // Before, the list answered `{ "consents": [] }` and the revocation an
    // empty body: a second format on a route that is not an OAuth endpoint.
    for (const request of [
      { method: 'GET', url: '/consents' },
      { method: 'DELETE', url: '/consents/7f0d6a4e-2c1b-4e8f-9a3d-5b6c7d8e9f01' },
    ] as const) {
      const response = await app().inject(request);

      const body = expectProblem(response, 401, 'unauthorized');
      expect(body['instance'], request.url).toBe(request.url);
      expect(body, request.url).not.toHaveProperty('consents');
      // The credential is a cookie: no authentication scheme to challenge in.
      expect(response.headers['www-authenticate'], request.url).toBeUndefined();
    }
  });

  it('answers a validation failure with errors[] that point at each field and carry no schema internals (RFC 9457 §3)', async () => {
    const response = await app().inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'not-an-address' },
    });

    const body = expectProblem(response, 400, 'validation_error');
    const errors = body['errors'] as { pointer: string; message: string }[];
    expect(errors.map(({ pointer }) => pointer).sort()).toEqual(['/email', '/password']);
    for (const entry of errors) {
      expect(Object.keys(entry).sort()).toEqual(['message', 'pointer']);
      expect(typeof entry.message).toBe('string');
    }
    for (const internal of ['schemaPath', 'keyword', 'params', 'instancePath', 'FST_ERR']) {
      expect(response.body).not.toContain(internal);
    }
  });

  it('answers an unknown address, a wrong password and an unverified account alike, apart from trace_id', async () => {
    // A verified account, signed in with the wrong password.
    await registerPasswordAccount(app(), 'known@example.com');
    // An account that never verified its address, signed in with its own
    // password: REQUIRE_VERIFIED_ACCOUNT is on by default.
    const registered = await app().inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email: 'unverified@example.com', password: E2E_PASSWORD },
    });
    expect(registered.statusCode).toBe(202);

    const unknown = await login('nobody@example.com', E2E_PASSWORD);
    const wrongPassword = await login('known@example.com', `${E2E_PASSWORD}-wrong`);
    const unverified = await login('unverified@example.com', E2E_PASSWORD);

    expectProblem(unknown, 401, 'invalid_credentials');
    for (const response of [wrongPassword, unverified]) {
      expect(response.statusCode).toBe(unknown.statusCode);
      expect(withoutTraceId(response)).toEqual(withoutTraceId(unknown));
      expect(stableHeaders(response)).toEqual(stableHeaders(unknown));
    }
  });
});
