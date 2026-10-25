import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { expectOAuthError, expectProblem } from '../../helpers/error-shape';

/**
 * No route answers with the envelope QAuth sent before #513 (`{ error,
 * statusCode, code? }`, plus `feedback` or `details`). Each request below
 * fails on purpose, and each answer is checked against the format its route
 * belongs to (ADR-019 Decision 7): an RFC 9457 problem document on every route
 * but the OAuth protocol endpoints, the RFC 6749 §5.2 body on those.
 *
 * Nothing here creates anything on the server: every request is refused by a
 * schema, a missing credential or an unknown grant type before a handler
 * writes.
 */

const { baseUrl } = wireConfig();

function post(path: string, contentType: string, body: string): Promise<Response> {
  return fetch(serverPath(baseUrl, path), {
    method: 'POST',
    headers: { 'content-type': contentType },
    body,
    redirect: 'manual',
  });
}

function postJson(path: string, body: unknown): Promise<Response> {
  return post(path, 'application/json', JSON.stringify(body));
}

function postForm(path: string, fields: Record<string, string>): Promise<Response> {
  return post(path, 'application/x-www-form-urlencoded', new URLSearchParams(fields).toString());
}

function get(path: string): Promise<Response> {
  return fetch(serverPath(baseUrl, path), { method: 'GET', redirect: 'manual' });
}

describe('RFC 9457 §3 — every route but the protocol endpoints answers a problem document', () => {
  it('answers a login body the schema refuses with a 400 validation_error problem (§3.1)', async () => {
    const problem = await expectProblem(await postJson('/auth/login', {}), {
      status: 400,
      code: 'validation_error',
    });

    expect(problem).not.toHaveProperty('statusCode');
    expect(problem.errors?.length ?? 0).toBeGreaterThan(0);
  });

  it('answers a registration body the schema refuses with a 400 validation_error problem (§3.1)', async () => {
    const problem = await expectProblem(await postJson('/auth/register', {}), {
      status: 400,
      code: 'validation_error',
    });

    expect(problem).not.toHaveProperty('statusCode');
  });

  // RFC 6750 §3: a bearer-protected resource answers a refused request with a
  // challenge, whichever body format it uses.
  it('answers the developer API without an access token with a 401 problem and a Bearer challenge (§3.1)', async () => {
    const response = await get('/api/clients');
    expect(response.headers.get('www-authenticate') ?? '').toMatch(/^Bearer\b/);

    const problem = await expectProblem(response, { status: 401, code: 'jwt_invalid' });

    expect(problem).not.toHaveProperty('statusCode');
  });

  it('answers a path no route serves with a 404 not_found problem (§3.1)', async () => {
    const problem = await expectProblem(await get(`/wire-suite/no-such-route/${randomUUID()}`), {
      status: 404,
      code: 'not_found',
    });

    expect(problem).not.toHaveProperty('statusCode');
  });
});

// GET /consents is the portal's cookie-authenticated list: without a browser
// session it answers 401 with an empty list, not an error document. Whatever
// it answers, it is not the old envelope.
describe('the consent list without a browser session', () => {
  it('answers 401 without a member of the old envelope', async () => {
    const response = await get('/consents');
    const text = await response.text();

    expect(response.status, text).toBe(401);
    const body = JSON.parse(text) as Record<string, unknown>;
    expect(body, text).not.toHaveProperty('statusCode');
    expect(body, text).not.toHaveProperty('error');
    expect(body, text).not.toHaveProperty('code');
    expect(body, text).not.toHaveProperty('stack');
  });
});

describe('RFC 6749 §5.2 — the token endpoint answers the error response body', () => {
  it('answers a grant type it does not serve with 400 unsupported_grant_type (§5.2)', async () => {
    const error = await expectOAuthError(
      await postForm('/oauth/token', {
        grant_type: 'password',
        username: 'wire-suite@example.com',
        password: 'not-a-password',
      }),
      { status: 400, error: 'unsupported_grant_type' }
    );

    expect(error).not.toHaveProperty('statusCode');
  });

  it('answers a request without a grant type with 400 invalid_request (§5.2)', async () => {
    const error = await expectOAuthError(await postForm('/oauth/token', { scope: 'openid' }), {
      status: 400,
      error: 'invalid_request',
    });

    expect(error).not.toHaveProperty('statusCode');
  });
});

describe('RFC 7662 §2.3 — introspection answers the error response body', () => {
  it('answers a caller that does not authenticate with 401 invalid_client (RFC 6749 §5.2)', async () => {
    const error = await expectOAuthError(
      await postForm('/oauth/introspect', { token: 'wire-suite-not-a-token' }),
      { status: 401, error: 'invalid_client' }
    );

    expect(error).not.toHaveProperty('statusCode');
  });
});

describe('RFC 7009 §2.2.1 — revocation answers the error response body', () => {
  it('answers a caller that does not authenticate with 401 invalid_client (RFC 6749 §5.2)', async () => {
    const error = await expectOAuthError(
      await postForm('/oauth/revoke', { token: 'wire-suite-not-a-token' }),
      { status: 401, error: 'invalid_client' }
    );

    expect(error).not.toHaveProperty('statusCode');
  });
});

describe('RFC 7591 §3.2.2 — dynamic registration answers the error response body', () => {
  it('answers redirect_uris that are not an array with 400 invalid_redirect_uri (§3.2.2)', async () => {
    const error = await expectOAuthError(
      await postJson('/oauth/register', { redirect_uris: 'https://wire-suite.example/cb' }),
      { status: 400, error: 'invalid_redirect_uri' }
    );

    expect(error).not.toHaveProperty('statusCode');
  });

  it('answers a metadata value it does not accept with 400 invalid_client_metadata (§3.2.2)', async () => {
    const error = await expectOAuthError(
      await postJson('/oauth/register', {
        redirect_uris: ['https://wire-suite.example/cb'],
        token_endpoint_auth_method: 'wire-suite-unknown-method',
      }),
      { status: 400, error: 'invalid_client_metadata' }
    );

    expect(error).not.toHaveProperty('statusCode');
  });
});

describe('RFC 6750 §3.1 — userinfo answers the error response body and a challenge', () => {
  it('answers a request without an access token with 401 invalid_token (§3, §3.1)', async () => {
    const response = await get('/oauth/userinfo');
    expect(response.headers.get('www-authenticate') ?? '').toMatch(/^Bearer\b/);

    const error = await expectOAuthError(response, { status: 401, error: 'invalid_token' });

    expect(error).not.toHaveProperty('statusCode');
  });
});
