import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { expectProblem } from '../../helpers/error-shape';

/**
 * The account API's sessions (#1110; ADR-017 Decision 8, ADR-019 Decisions 3
 * and 7, ADR-020 §3): the list, the end of one session and "sign out
 * everywhere". Each needs an access token with the account API audience,
 * which only an operator can give a client, and the wire suite's seed
 * provisions no such client. So these tests check what every caller can
 * reach: a request with no token is refused with the 401 problem and the
 * bare Bearer challenge of a bearer-protected resource (RFC 6750 §3.1),
 * uncacheable, and names no session. Nothing is ended.
 */

const { baseUrl } = wireConfig();

function request(
  method: 'GET' | 'POST' | 'DELETE',
  path: string,
  init: RequestInit = {}
): Promise<Response> {
  return fetch(serverPath(baseUrl, path), { ...init, method, redirect: 'manual' });
}

/** The 401 of a request that presented no credentials: a bare challenge, and no data. */
async function expectUnauthorized(response: Response): Promise<void> {
  expect(response.headers.get('www-authenticate') ?? '').toMatch(/^Bearer\b/);
  expect(response.headers.get('www-authenticate') ?? '').not.toMatch(/error=/);
  expect(response.headers.get('cache-control')).toBe('no-store');
  const problem = await expectProblem(response, { status: 401, code: 'unauthorized' });
  for (const field of ['items', 'nextCursor', 'sid']) {
    expect(problem).not.toHaveProperty(field);
  }
}

describe('[GET /account/v1-rc.0/sessions] the live sessions', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(await request('GET', '/account/v1-rc.0/sessions'));
  });
});

describe('[DELETE /account/v1-rc.0/sessions/{sessionId}] the end of one session', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(await request('DELETE', `/account/v1-rc.0/sessions/${randomUUID()}`));
  });
});

describe('[POST /account/v1-rc.0/sessions/end-all] sign out everywhere', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge, with a body or none', async () => {
    await expectUnauthorized(await request('POST', '/account/v1-rc.0/sessions/end-all'));
    await expectUnauthorized(
      await request('POST', '/account/v1-rc.0/sessions/end-all', {
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ keepCurrent: true }),
      })
    );
  });
});
