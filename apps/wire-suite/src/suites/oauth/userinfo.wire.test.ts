import { decodeJwt } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import { wireConfig } from '../../config';
import {
  consentedBrowser,
  exchangeCode,
  issueCode,
  readTokenResponse,
  type SignedInBrowser,
  tokenRequest,
  type TokenResponse,
} from '../../fixtures/authorization';
import {
  basicAuthorization,
  confidentialClient,
  SEEDED_CLIENT_SCOPE,
} from '../../fixtures/clients';
import { expectOAuthError } from '../../helpers/error-shape';
import { call } from '../../helpers/operations';

const { mailUrl } = wireConfig();

/** Read a userinfo answer that must be a 200 JSON object. */
async function claimsOf(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  expect(response.status, text).toBe(200);
  expect(response.headers.get('content-type') ?? '').toMatch(/^application\/json\b/i);
  const body: unknown = JSON.parse(text);
  expect(body !== null && typeof body === 'object' && !Array.isArray(body)).toBe(true);
  return body as Record<string, unknown>;
}

/** A refusal at userinfo: the RFC 6750 §3 challenge and the error body. */
async function expectInvalidToken(response: Response): Promise<void> {
  expect(response.headers.get('www-authenticate') ?? '').toMatch(/^Bearer\b/);
  await expectOAuthError(response, { status: 401, error: 'invalid_token' });
}

describe('OIDC Core 1.0 §5.3 — the UserInfo endpoint', () => {
  let session: SignedInBrowser;
  let tokens: TokenResponse;
  let subject: string;

  beforeAll(async () => {
    session = await consentedBrowser();
    tokens = await readTokenResponse(await exchangeCode(await issueCode(session)));
    subject = decodeJwt(tokens.id_token as string).sub as string;
  });

  it('answers GET with a Bearer access token, and `sub` is unconditional: the ID token’s subject (§5.3.1, §5.3.2)', async () => {
    const claims = await claimsOf(
      await call('GET /oauth/userinfo', {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      })
    );

    expect(claims['sub']).toBe(subject);
  });

  it('answers POST with the Bearer header with the same claims as GET (§5.3.1; RFC 6750 §2.1)', async () => {
    const viaGet = await claimsOf(
      await call('GET /oauth/userinfo', {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      })
    );
    const viaPost = await claimsOf(
      await call('POST /oauth/userinfo', {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      })
    );

    expect(viaPost).toEqual(viaGet);
  });

  it('answers POST with the token as a form-encoded access_token parameter (§5.3.1; RFC 6750 §2.2)', async () => {
    const claims = await claimsOf(
      await call('POST /oauth/userinfo', { form: { access_token: tokens.access_token } })
    );

    expect(claims['sub']).toBe(subject);
  });

  it('releases the address only once verified, and never a claim as null (§5.3.2, §5.4)', async () => {
    const claims = await claimsOf(
      await call('GET /oauth/userinfo', {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      })
    );

    for (const [claim, value] of Object.entries(claims)) {
      expect(value, claim).not.toBeNull();
      expect(value, claim).not.toBe('');
    }
    if (mailUrl === undefined) {
      // The account was never verified: neither email claim is released.
      expect(claims).not.toHaveProperty('email');
      expect(claims).not.toHaveProperty('email_verified');
    } else {
      expect(claims['email']).toBe(session.credentials.email);
      expect(claims['email_verified']).toBe(true);
    }
  });

  it('refuses a client_credentials token, whose subject is no user, with 401 invalid_token (§5.3.3; RFC 6750 §3.1)', async () => {
    const machine = await readTokenResponse(
      await tokenRequest({ grant_type: 'client_credentials', scope: SEEDED_CLIENT_SCOPE })
    );

    await expectInvalidToken(
      await call('GET /oauth/userinfo', {
        headers: { authorization: `Bearer ${machine.access_token}` },
      })
    );
  });

  it('refuses an access token once it is revoked, on GET and on POST (§5.3.3; RFC 7009 §2.1)', async () => {
    const own = await readTokenResponse(await exchangeCode(await issueCode(session)));
    const revoked = await call('POST /oauth/revoke', {
      headers: { authorization: basicAuthorization(confidentialClient()) },
      form: { token: own.access_token, token_type_hint: 'access_token' },
    });
    expect(revoked.status).toBe(200);
    await revoked.body?.cancel();

    await expectInvalidToken(
      await call('GET /oauth/userinfo', {
        headers: { authorization: `Bearer ${own.access_token}` },
      })
    );
    await expectInvalidToken(
      await call('POST /oauth/userinfo', { form: { access_token: own.access_token } })
    );
  });
});
