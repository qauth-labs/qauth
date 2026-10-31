import { randomBytes } from 'node:crypto';

import { beforeAll, describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import {
  exchangeCode,
  issueCode,
  newBrowser,
  readTokenResponse,
  type SignedInBrowser,
  tokenRequest,
  type TokenResponse,
} from '../../fixtures/authorization';
import { confidentialClient } from '../../fixtures/clients';
import { expectOAuthError } from '../../helpers/error-shape';
import { getJsonObject } from '../../helpers/http';
import { remoteKeySet, verifyJwt } from '../../helpers/jwt';

const { baseUrl } = wireConfig();

function refresh(
  refreshToken: string,
  fields: Record<string, string> = {},
  authentication: 'client_secret_basic' | 'client_secret_post' = 'client_secret_basic'
): Promise<Response> {
  return tokenRequest(
    { grant_type: 'refresh_token', refresh_token: refreshToken, ...fields },
    authentication
  );
}

describe('RFC 6749 §6 — refreshing an access token, with rotation', () => {
  let session: SignedInBrowser;

  /** Tokens from a fresh code: a family of its own for each test. */
  async function freshTokens(): Promise<TokenResponse> {
    const tokens = await readTokenResponse(await exchangeCode(await issueCode(session)));
    expect(tokens.refresh_token, 'a remembered consent buys a refresh token').toBeTypeOf('string');
    return tokens;
  }

  beforeAll(async () => {
    session = await newBrowser();
  });

  it('answers a refresh with a new access token and a new refresh token in its place (§6; RFC 9700 §4.14.2)', async () => {
    const first = await freshTokens();

    const response = await refresh(first.refresh_token as string);
    expect(response.headers.get('cache-control') ?? '').toMatch(/no-store/i);
    const rotated = await readTokenResponse(response);

    expect(rotated.refresh_token).toBeTypeOf('string');
    expect(rotated.refresh_token).not.toBe(first.refresh_token);
    expect(rotated.access_token).not.toBe(first.access_token);
    expect(rotated.token_type.toLowerCase()).toBe('bearer');
    const { body: metadata } = await getJsonObject(
      serverPath(baseUrl, '/.well-known/openid-configuration')
    );
    const { payload } = await verifyJwt(
      rotated.access_token,
      remoteKeySet(metadata['jwks_uri'] as string),
      { issuer: baseUrl, typ: 'at+jwt' }
    );
    expect(payload['client_id']).toBe(confidentialClient().id);
    expect(String(payload['scope']).split(' ')).toEqual(
      expect.arrayContaining(String(first.scope).split(' '))
    );
  });

  it('accepts the refresh with client_secret_post as with client_secret_basic (§6; §2.3.1)', async () => {
    const first = await freshTokens();

    const rotated = await readTokenResponse(
      await refresh(first.refresh_token as string, {}, 'client_secret_post')
    );

    expect(rotated.refresh_token).toBeTypeOf('string');
  });

  it('refuses a rotated-out refresh token with invalid_grant and revokes its whole family (RFC 9700 §4.14.2; §5.2)', async () => {
    const first = await freshTokens();
    const rotated = await readTokenResponse(await refresh(first.refresh_token as string));

    await expectOAuthError(await refresh(first.refresh_token as string), {
      status: 400,
      error: 'invalid_grant',
    });

    // The replay ended the family: the token that replaced it is refused too.
    await expectOAuthError(await refresh(rotated.refresh_token as string), {
      status: 400,
      error: 'invalid_grant',
    });
  });

  it('refuses a scope the original grant did not include with invalid_scope (§6, §5.2)', async () => {
    const first = await freshTokens();

    await expectOAuthError(
      await refresh(first.refresh_token as string, { scope: 'openid wire:read' }),
      { status: 400, error: 'invalid_scope' }
    );
  });

  it('refuses a well-formed refresh token the server never issued with invalid_grant (§5.2)', async () => {
    // QAuth's refresh tokens are 64 hex characters; another shape is refused
    // by the request schema as invalid_request before any lookup.
    await expectOAuthError(await refresh(randomBytes(32).toString('hex')), {
      status: 400,
      error: 'invalid_grant',
    });
  });
});
