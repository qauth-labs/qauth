import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { expectProblem } from '../../helpers/error-shape';

/**
 * The account API's authenticator app and recovery codes (#1109; ADR-017
 * Decision 8, ADR-020 §3): the enrolment, its confirmation, the removal, the
 * recovery codes' status and their regeneration. Each needs an access token
 * with the account API audience, which only an operator can give a client,
 * and the wire suite's seed provisions no such client. So these tests check
 * what every caller can reach: a request with no token is refused with the
 * 401 problem and the bare Bearer challenge of a bearer-protected resource
 * (RFC 6750 §3.1), uncacheable, and holds no secret, URI or code. Nothing is
 * started, bound, removed or issued.
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
  for (const field of ['secret', 'otpauthUri', 'codes', 'recoveryCodes', 'remaining']) {
    expect(problem).not.toHaveProperty(field);
  }
}

const JSON_BODY = { 'content-type': 'application/json' };

describe('[POST /account/v1-rc.0/totp/enrollment] the start of an authenticator-app enrolment', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(await request('POST', '/account/v1-rc.0/totp/enrollment'));
  });
});

describe('[POST /account/v1-rc.0/totp/enrollment/confirm] the confirmation of an enrolment', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(
      await request('POST', '/account/v1-rc.0/totp/enrollment/confirm', {
        headers: JSON_BODY,
        body: JSON.stringify({ code: '492039' }),
      })
    );
  });
});

describe('[DELETE /account/v1-rc.0/totp] the removal of the authenticator app', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(await request('DELETE', '/account/v1-rc.0/totp'));
  });
});

describe('[GET /account/v1-rc.0/recovery-codes] the recovery codes’ status', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(await request('GET', '/account/v1-rc.0/recovery-codes'));
  });
});

describe('[POST /account/v1-rc.0/recovery-codes/regenerate] a new set of recovery codes', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(await request('POST', '/account/v1-rc.0/recovery-codes/regenerate'));
  });
});
