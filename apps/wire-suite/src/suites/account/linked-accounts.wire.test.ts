import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { expectProblem } from '../../helpers/error-shape';

/**
 * The account API's linked upstream accounts (#670; ADR-019 Decision 7): the
 * list, and the unlink. Both need an access token with the account API
 * audience, which only an operator can give a client, and the wire suite's
 * seed provisions no such client. So these tests check what every caller can
 * reach: a request with no token is refused with the 401 problem and the
 * bare Bearer challenge of a bearer-protected resource (RFC 6750 §3.1), and
 * names nothing of any account. The unlink deletes nothing.
 */

const { baseUrl } = wireConfig();

function request(method: 'GET' | 'DELETE', path: string): Promise<Response> {
  return fetch(serverPath(baseUrl, path), { method, redirect: 'manual' });
}

/** The 401 of a request that presented no credentials: a bare challenge, and no data. */
async function expectUnauthorized(response: Response): Promise<void> {
  expect(response.headers.get('www-authenticate') ?? '').toMatch(/^Bearer\b/);
  expect(response.headers.get('www-authenticate') ?? '').not.toMatch(/error=/);
  const problem = await expectProblem(response, { status: 401, code: 'unauthorized' });
  expect(problem).not.toHaveProperty('items');
}

describe('[GET /account/v1-rc.0/linked-accounts] the linked upstream accounts', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(await request('GET', '/account/v1-rc.0/linked-accounts'));
  });
});

describe('[DELETE /account/v1-rc.0/linked-accounts/{linkedAccountId}] the unlink of an upstream account', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(
      await request('DELETE', `/account/v1-rc.0/linked-accounts/${randomUUID()}`)
    );
  });
});
