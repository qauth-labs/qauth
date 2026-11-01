import { beforeAll, describe, expect, it } from 'vitest';

import {
  type ClientAuthentication,
  consentedBrowser,
  exchangeCode,
  issueCode,
  readTokenResponse,
  type SignedInBrowser,
  tokenRequest,
} from '../../fixtures/authorization';
import {
  basicAuthorization,
  confidentialClient,
  SEEDED_CLIENT_SCOPE,
} from '../../fixtures/clients';
import { expectOAuthError } from '../../helpers/error-shape';
import { call } from '../../helpers/operations';

/** Revoke `token` as the seeded client. */
function revoke(
  token: string,
  fields: Record<string, string> = {},
  authentication: ClientAuthentication = 'client_secret_basic'
): Promise<Response> {
  const client = confidentialClient();
  return authentication === 'client_secret_basic'
    ? call('POST /oauth/revoke', {
        headers: { authorization: basicAuthorization(client) },
        form: { token, ...fields },
      })
    : call('POST /oauth/revoke', {
        form: { token, ...fields, client_id: client.id, client_secret: client.secret },
      });
}

/** RFC 7009 §2.2: 200, whatever was or was not revoked. */
async function expectRevoked(response: Response): Promise<void> {
  const text = await response.text();
  expect(response.status, text).toBe(200);
}

async function introspectionActive(token: string): Promise<unknown> {
  const response = await call('POST /oauth/introspect', {
    headers: { authorization: basicAuthorization(confidentialClient()) },
    form: { token },
  });
  const text = await response.text();
  expect(response.status, text).toBe(200);
  return (JSON.parse(text) as Record<string, unknown>)['active'];
}

describe('RFC 7009 §2 — token revocation answers 200', () => {
  it.each(['client_secret_basic', 'client_secret_post'] as const)(
    'answers 200 to a token it never issued, authenticated with %s (§2.1, §2.2)',
    async (authentication) => {
      await expectRevoked(await revoke('wire-suite-not-a-token', {}, authentication));
    }
  );

  it('answers 200 to an unknown token whatever its token_type_hint (§2.1, §2.2)', async () => {
    for (const hint of ['access_token', 'refresh_token']) {
      await expectRevoked(await revoke('wire-suite-not-a-token', { token_type_hint: hint }));
    }
  });

  it('revokes an access token: 200, then introspection reports it inactive (§2.1, §2.2; RFC 7662 §2.2)', async () => {
    const { access_token: token } = await readTokenResponse(
      await tokenRequest({ grant_type: 'client_credentials', scope: SEEDED_CLIENT_SCOPE })
    );
    expect(await introspectionActive(token)).toBe(true);

    await expectRevoked(await revoke(token, { token_type_hint: 'access_token' }));

    expect(await introspectionActive(token)).toBe(false);
  });

  describe('a user’s refresh token', () => {
    let session: SignedInBrowser;

    beforeAll(async () => {
      session = await consentedBrowser();
    });

    it('revokes a refresh token: 200, then the refresh grant refuses it with invalid_grant (§2.1, §2.2; RFC 6749 §5.2)', async () => {
      const tokens = await readTokenResponse(await exchangeCode(await issueCode(session)));
      expect(tokens.refresh_token).toBeTypeOf('string');

      await expectRevoked(await revoke(tokens.refresh_token as string));

      await expectOAuthError(
        await tokenRequest({
          grant_type: 'refresh_token',
          refresh_token: tokens.refresh_token as string,
        }),
        { status: 400, error: 'invalid_grant' }
      );
    });
  });
});
