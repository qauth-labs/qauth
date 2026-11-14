import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { expectProblem } from '../../helpers/error-shape';

/**
 * The account API's sign-in methods and password change (#1107; ADR-020 §3,
 * ADR-017 Decision 8, ADR-019 Decision 7). Both need an access token with
 * the account API audience, which only an operator can give a client, and
 * the wire suite's seed provisions no such client. So these tests check what
 * every caller can reach: a request with no token is refused with the 401
 * problem and the bare Bearer challenge of a bearer-protected resource
 * (RFC 6750 §3.1), and names nothing of any account. The change checks no
 * password and changes nothing.
 */

const { baseUrl } = wireConfig();

/** The 401 of a request that presented no credentials: a bare challenge, and no data. */
async function expectUnauthorized(response: Response): Promise<void> {
  expect(response.headers.get('www-authenticate') ?? '').toMatch(/^Bearer\b/);
  expect(response.headers.get('www-authenticate') ?? '').not.toMatch(/error=/);
  const problem = await expectProblem(response, { status: 401, code: 'unauthorized' });
  expect(problem).not.toHaveProperty('password');
}

describe('[GET /account/v1-rc.0/sign-in-methods] the sign-in methods', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(
      await fetch(serverPath(baseUrl, '/account/v1-rc.0/sign-in-methods'), { redirect: 'manual' })
    );
  });
});

describe('[POST /account/v1-rc.0/password/change] the password change', () => {
  it('answers a request without an access token with 401 and a bare Bearer challenge', async () => {
    await expectUnauthorized(
      await fetch(serverPath(baseUrl, '/account/v1-rc.0/password/change'), {
        method: 'POST',
        redirect: 'manual',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          currentPassword: 'not-the-password-of-any-account',
          newPassword: 'Copper-Heron-Lattice-Orchard-81',
        }),
      })
    );
  });
});
