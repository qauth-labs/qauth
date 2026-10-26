import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { basicAuthorization, confidentialClient } from '../../fixtures/clients';
import { expectOAuthError } from '../../helpers/error-shape';
import { createPkcePair } from '../../helpers/pkce';

const { baseUrl } = wireConfig();

/** A code exchange by the seeded confidential client, for a code the server never issued. */
function exchangeUnknownCode(fields: Record<string, string>): Promise<Response> {
  return fetch(serverPath(baseUrl, '/oauth/token'), {
    method: 'POST',
    headers: {
      authorization: basicAuthorization(confidentialClient()),
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: randomBytes(32).toString('base64url'),
      code_verifier: createPkcePair().verifier,
      ...fields,
    }),
    redirect: 'manual',
  });
}

/**
 * Whether a token request needs `redirect_uri` depends on the code it
 * redeems (RFC 6749 §4.1.3; ADR-017 Decision 10, #627), so leaving it out is
 * not a malformed request: the endpoint reads the code, and a code it cannot
 * redeem is `invalid_grant`, with or without the parameter. Nothing is
 * created: the code is refused before anything is spent or issued.
 */
describe('RFC 6749 §4.1.3 — a code exchange answers by the code, not by the request’s shape', () => {
  it('answers an exchange without redirect_uri with 400 invalid_grant, not invalid_request (§4.1.3, §5.2)', async () => {
    const error = await expectOAuthError(await exchangeUnknownCode({}), {
      status: 400,
      error: 'invalid_grant',
    });

    expect(error).not.toHaveProperty('statusCode');
  });

  it('answers an exchange with an empty redirect_uri with 400 invalid_grant (§3.2, §5.2)', async () => {
    await expectOAuthError(await exchangeUnknownCode({ redirect_uri: '' }), {
      status: 400,
      error: 'invalid_grant',
    });
  });
});
