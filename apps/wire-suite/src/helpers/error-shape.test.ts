import { describe, expect, it } from 'vitest';

import { expectStandardError } from './error-shape';

function json(status: number, body: unknown, contentType = 'application/json; charset=utf-8') {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': contentType },
  });
}

describe('expectStandardError', () => {
  it('accepts the envelope and returns the body', async () => {
    const body = await expectStandardError(
      json(400, { error: 'invalid_request', statusCode: 400, code: 'INVALID_REQUEST' }),
      { status: 400, error: 'invalid_request', code: 'INVALID_REQUEST' }
    );

    expect(body.error).toBe('invalid_request');
  });

  it('allows members beyond the envelope', async () => {
    await expect(
      expectStandardError(
        json(404, { message: 'Route GET:/x not found', error: 'Not Found', statusCode: 404 }),
        { status: 404 }
      )
    ).resolves.toMatchObject({ error: 'Not Found' });
  });

  it.each([
    ['a different status', json(500, { error: 'x', statusCode: 500 }), 400],
    ['a non-JSON content type', json(400, { error: 'x', statusCode: 400 }, 'text/html'), 400],
    ['a body that is not JSON', json(400, 'oops'), 400],
    ['a JSON array', json(400, [{ error: 'x' }]), 400],
    ['JSON null', json(400, 'null'), 400],
    ['no error member', json(400, { message: 'x', statusCode: 400 }), 400],
    ['an empty error', json(400, { error: '', statusCode: 400 }), 400],
    [
      'a statusCode that disagrees with the status',
      json(400, { error: 'x', statusCode: 401 }),
      400,
    ],
    [
      'a code that is not UPPER_SNAKE',
      json(400, { error: 'x', statusCode: 400, code: 'bad code' }),
      400,
    ],
    ['a stack trace', json(500, { error: 'x', statusCode: 500, stack: 'Error: x\n    at y' }), 500],
  ])('rejects %s', async (_label, response, status) => {
    await expect(expectStandardError(response, { status })).rejects.toThrow();
  });

  it('rejects an error or code other than the one expected', async () => {
    await expect(
      expectStandardError(json(400, { error: 'invalid_grant', statusCode: 400 }), {
        status: 400,
        error: 'invalid_request',
      })
    ).rejects.toThrow();
    await expect(
      expectStandardError(json(400, { error: 'x', statusCode: 400, code: 'A' }), {
        status: 400,
        code: 'B',
      })
    ).rejects.toThrow();
  });
});
