import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { expectProblem } from '../../helpers/error-shape';

/**
 * The account API's passkeys (#1108; ADR-020 §3, ADR-017 Decision 8): the
 * list, one passkey, its rename and its removal. Each needs an access token
 * with the account API audience, which only an operator can give a client,
 * and the wire suite's seed provisions no such client. So these tests check
 * what every caller can reach: a request with no token is refused with the
 * 401 problem and the bare Bearer challenge of a bearer-protected resource
 * (RFC 6750 §3.1), and names nothing of any account. The rename and the
 * removal change nothing.
 */

const { baseUrl } = wireConfig();

function request(
  method: 'GET' | 'PATCH' | 'DELETE',
  path: string,
  init: RequestInit = {}
): Promise<Response> {
  return fetch(serverPath(baseUrl, path), { ...init, method, redirect: 'manual' });
}

/** The 401 of a request that presented no credentials: a bare challenge, and no data. */
async function expectUnauthorized(response: Response): Promise<void> {
  expect(response.headers.get('www-authenticate') ?? '').toMatch(/^Bearer\b/);
  expect(response.headers.get('www-authenticate') ?? '').not.toMatch(/error=/);
  expect(response.headers.get('etag')).toBeNull();
  const problem = await expectProblem(response, { status: 401, code: 'unauthorized' });
  expect(problem).not.toHaveProperty('items');
  expect(problem).not.toHaveProperty('nickname');
}

describe('[GET /account/v1-rc.0/passkeys] the passkeys of the account', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(await request('GET', '/account/v1-rc.0/passkeys'));
  });
});

describe('[GET /account/v1-rc.0/passkeys/{passkeyId}] one passkey', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(await request('GET', `/account/v1-rc.0/passkeys/${randomUUID()}`));
  });
});

describe('[PATCH /account/v1-rc.0/passkeys/{passkeyId}] the rename of a passkey', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(
      await request('PATCH', `/account/v1-rc.0/passkeys/${randomUUID()}`, {
        headers: { 'content-type': 'application/merge-patch+json', 'if-match': '"any"' },
        body: JSON.stringify({ nickname: 'Work laptop' }),
      })
    );
  });
});

describe('[DELETE /account/v1-rc.0/passkeys/{passkeyId}] the removal of a passkey', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(await request('DELETE', `/account/v1-rc.0/passkeys/${randomUUID()}`));
  });
});
