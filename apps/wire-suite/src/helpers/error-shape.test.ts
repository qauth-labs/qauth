import { describe, expect, it } from 'vitest';

import { expectOAuthError, expectProblem } from './error-shape';

const PROBLEM = 'application/problem+json; charset=utf-8';
const JSON_TYPE = 'application/json; charset=utf-8';

function respond(status: number, body: unknown, contentType: string) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': contentType },
  });
}

function problem(status: number, members: Record<string, unknown> = {}) {
  return {
    type: 'https://docs.qauth.dev/reference/problem-types/#not-found',
    title: 'Not found',
    status,
    detail: 'No route serves GET /x.',
    instance: '/x',
    code: 'not_found',
    trace_id: 'req-1',
    ...members,
  };
}

describe('expectProblem', () => {
  it('accepts a problem document and returns it', async () => {
    const body = await expectProblem(respond(404, problem(404), PROBLEM), {
      status: 404,
      code: 'not_found',
    });

    expect(body.code).toBe('not_found');
    expect(body.trace_id).toBe('req-1');
  });

  it('accepts the bare media type and members beyond the document (RFC 9457 §3.2)', async () => {
    await expect(
      expectProblem(
        respond(
          400,
          problem(400, {
            code: 'validation_error',
            errors: [{ pointer: '/email', message: 'Invalid email address' }],
          }),
          'application/problem+json'
        ),
        { status: 400 }
      )
    ).resolves.toMatchObject({ code: 'validation_error' });
  });

  it.each([
    ['a different status', respond(500, problem(500), PROBLEM), 404],
    ['an application/json content type', respond(404, problem(404), JSON_TYPE), 404],
    ['a body that is not JSON', respond(404, 'oops', PROBLEM), 404],
    ['a JSON array', respond(404, [problem(404)], PROBLEM), 404],
    ['JSON null', respond(404, 'null', PROBLEM), 404],
    ['no type', respond(404, problem(404, { type: undefined }), PROBLEM), 404],
    [
      'a type outside the problem types page',
      respond(404, problem(404, { type: 'about:blank' }), PROBLEM),
      404,
    ],
    ['no title', respond(404, problem(404, { title: undefined }), PROBLEM), 404],
    [
      'a status member that disagrees with the status',
      respond(404, problem(404, { status: 400 }), PROBLEM),
      404,
    ],
    ['no code', respond(404, problem(404, { code: undefined }), PROBLEM), 404],
    ['an upper-case code', respond(404, problem(404, { code: 'NOT_FOUND' }), PROBLEM), 404],
    ['no trace_id', respond(404, problem(404, { trace_id: undefined }), PROBLEM), 404],
    ['an empty trace_id', respond(404, problem(404, { trace_id: '' }), PROBLEM), 404],
    [
      'a stack trace',
      respond(500, problem(500, { code: 'internal_error', stack: 'Error: x\n    at y' }), PROBLEM),
      500,
    ],
    ['a legacy error', respond(404, problem(404, { error: 'Not Found' }), PROBLEM), 404],
    ['a legacy statusCode', respond(404, problem(404, { statusCode: 404 }), PROBLEM), 404],
    ['a legacy message', respond(404, problem(404, { message: 'x' }), PROBLEM), 404],
    ['legacy details', respond(400, problem(400, { details: [] }), PROBLEM), 400],
    ['legacy feedback', respond(422, problem(422, { feedback: ['x'] }), PROBLEM), 422],
    [
      'the legacy envelope',
      respond(404, { error: 'Not Found', statusCode: 404, code: 'NOT_FOUND' }, JSON_TYPE),
      404,
    ],
  ])('rejects %s', async (_label, response, status) => {
    await expect(expectProblem(response, { status })).rejects.toThrow();
  });

  it('rejects a code other than the one expected', async () => {
    await expect(
      expectProblem(respond(404, problem(404), PROBLEM), { status: 404, code: 'forbidden' })
    ).rejects.toThrow();
  });
});

describe('expectOAuthError', () => {
  it('accepts an OAuth error body and returns it', async () => {
    const body = await expectOAuthError(
      respond(400, { error: 'invalid_request', error_description: 'x' }, JSON_TYPE),
      { status: 400, error: 'invalid_request' }
    );

    expect(body.error).toBe('invalid_request');
  });

  it('accepts error_uri and a body with error alone', async () => {
    await expect(
      expectOAuthError(
        respond(400, { error: 'invalid_grant', error_uri: 'https://example.com/e' }, JSON_TYPE),
        { status: 400 }
      )
    ).resolves.toMatchObject({ error: 'invalid_grant' });
    await expect(
      expectOAuthError(respond(401, { error: 'invalid_client' }, 'application/json'), {
        status: 401,
      })
    ).resolves.toEqual({ error: 'invalid_client' });
  });

  it.each([
    ['a different status', respond(500, { error: 'server_error' }, JSON_TYPE), 400],
    ['a problem content type', respond(400, { error: 'invalid_request' }, PROBLEM), 400],
    ['a text content type', respond(400, { error: 'invalid_request' }, 'text/html'), 400],
    ['a body that is not JSON', respond(400, 'oops', JSON_TYPE), 400],
    ['a JSON array', respond(400, [{ error: 'x' }], JSON_TYPE), 400],
    ['JSON null', respond(400, 'null', JSON_TYPE), 400],
    ['no error member', respond(400, { error_description: 'x' }, JSON_TYPE), 400],
    ['an empty error', respond(400, { error: '' }, JSON_TYPE), 400],
    ['a non-string error', respond(400, { error: 400 }, JSON_TYPE), 400],
    [
      'a non-string error_description',
      respond(400, { error: 'invalid_request', error_description: 1 }, JSON_TYPE),
      400,
    ],
    ['a statusCode', respond(400, { error: 'invalid_request', statusCode: 400 }, JSON_TYPE), 400],
    ['a code', respond(400, { error: 'invalid_request', code: 'INVALID_REQUEST' }, JSON_TYPE), 400],
    [
      'a stack trace',
      respond(500, { error: 'server_error', stack: 'Error: x\n    at y' }, JSON_TYPE),
      500,
    ],
  ])('rejects %s', async (_label, response, status) => {
    await expect(expectOAuthError(response, { status })).rejects.toThrow();
  });

  it('rejects an error other than the one expected', async () => {
    await expect(
      expectOAuthError(respond(400, { error: 'invalid_grant' }, JSON_TYPE), {
        status: 400,
        error: 'invalid_request',
      })
    ).rejects.toThrow();
  });
});
