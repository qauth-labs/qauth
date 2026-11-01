import { randomBytes } from 'node:crypto';

import type { ProtectedHeaderParameters } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import {
  exchangeCode,
  issueCode,
  type IssuedCode,
  newBrowser,
  readTokenResponse,
  type SignedInBrowser,
  tokenRequest,
  type TokenResponse,
} from '../../fixtures/authorization';
import { basicAuthorization, confidentialClient } from '../../fixtures/clients';
import { expectOAuthError } from '../../helpers/error-shape';
import { getJsonObject } from '../../helpers/http';
import { remoteKeySet, verifyJwt } from '../../helpers/jwt';
import { call } from '../../helpers/operations';
import { createPkcePair } from '../../helpers/pkce';

const { baseUrl } = wireConfig();

/** A code exchange by the seeded confidential client, for a code the server never issued. */
function exchangeUnknownCode(fields: Record<string, string>): Promise<Response> {
  return call('POST /oauth/token', {
    headers: { authorization: basicAuthorization(confidentialClient()) },
    form: {
      grant_type: 'authorization_code',
      code: randomBytes(32).toString('base64url'),
      code_verifier: createPkcePair().verifier,
      ...fields,
    },
  });
}

/** The discovery document and the key set it names. */
async function discovery(): Promise<Record<string, unknown>> {
  const { body } = await getJsonObject(serverPath(baseUrl, '/.well-known/openid-configuration'));
  return body;
}

/** Introspect a token as the seeded client, returning the response members. */
async function introspect(token: string): Promise<Record<string, unknown>> {
  const response = await call('POST /oauth/introspect', {
    headers: { authorization: basicAuthorization(confidentialClient()) },
    form: { token },
  });
  const text = await response.text();
  expect(response.status, text).toBe(200);
  return JSON.parse(text) as Record<string, unknown>;
}

/** A refresh request for a refresh token, by the seeded client. */
function refresh(refreshToken: string): Promise<Response> {
  return tokenRequest({ grant_type: 'refresh_token', refresh_token: refreshToken });
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

/**
 * One account, signed in through `/ui/login` with a cookie jar, consenting on
 * `/ui/consent`, and one code exchanged for tokens: the flow a relying party
 * runs, checked as the relying party checks it.
 */
describe('OIDC Core 1.0 §3.1 — the authorization code flow end to end, with PKCE', () => {
  let issued: IssuedCode;
  let tokenHeaders: Headers;
  let tokens: TokenResponse;
  let metadata: Record<string, unknown>;

  beforeAll(async () => {
    const session = await newBrowser();
    issued = await issueCode(session);
    const response = await exchangeCode(issued);
    tokenHeaders = response.headers;
    tokens = await readTokenResponse(response);
    metadata = await discovery();
  });

  it('shows the sign-in page and the consent screen, then sends the code to the redirect URI (§3.1.2.5; RFC 6749 §4.1.2)', () => {
    expect(issued.response.pages).toEqual(['sign-in', 'consent']);
    expect(issued.response.params.get('state')).toBe(issued.request.state);
    expect(issued.response.params.get('iss')).toBe(baseUrl);
  });

  it('answers the token request with an id_token beside a Bearer access token, never cached (§3.1.3.3; RFC 6749 §5.1)', () => {
    expect(tokenHeaders.get('content-type') ?? '').toMatch(/^application\/json\b/i);
    expect(tokenHeaders.get('cache-control') ?? '').toMatch(/no-store/i);
    expect(tokens.token_type.toLowerCase()).toBe('bearer');
    expect(Number.isInteger(tokens.expires_in) && tokens.expires_in > 0).toBe(true);
    expect(tokens.id_token).toBeTypeOf('string');
    // The user remembered the decision, so the grant may outlive the access token.
    expect(tokens.refresh_token).toBeTypeOf('string');
    expect(String(tokens.scope).split(' ')).toEqual(expect.arrayContaining(['openid', 'profile']));
  });

  it('issues an ID token with all required claims, verified against the JWKS: iss, aud, nonce, exp (§2, §3.1.3.7)', async () => {
    const client = confidentialClient();
    const { header, payload } = await verifyJwt(
      tokens.id_token as string,
      remoteKeySet(metadata['jwks_uri'] as string),
      { issuer: baseUrl, audience: client.id }
    );
    const now = Math.floor(Date.now() / 1000);

    expect(payload.iss).toBe(baseUrl);
    expect([payload.aud].flat()).toContain(client.id);
    expect(payload['nonce']).toBe(issued.request.nonce);
    expect(payload.sub).toMatch(/\S/);
    expect((payload.sub as string).length).toBeLessThanOrEqual(255);
    expect(payload.exp).toBeGreaterThan(now);
    expect(payload.iat).toBeLessThanOrEqual(now + 5);
    expect(payload.exp as number).toBeGreaterThan(payload.iat as number);
    expectSignedWithAdvertisedKey(header, metadata);
  });

  it('asserts auth_time, the time the user signed in, no later than the token (§2)', async () => {
    const { payload } = await verifyJwt(
      tokens.id_token as string,
      remoteKeySet(metadata['jwks_uri'] as string),
      { issuer: baseUrl, audience: confidentialClient().id }
    );
    const now = Math.floor(Date.now() / 1000);

    expect(payload['auth_time']).toBeTypeOf('number');
    expect(payload['auth_time'] as number).toBeLessThanOrEqual(payload.iat as number);
    expect(payload['auth_time'] as number).toBeGreaterThan(now - 600);
  });

  it('issues an at+jwt access token for the client and the same user (RFC 9068 §2.1, §2.2)', async () => {
    const client = confidentialClient();
    const keys = remoteKeySet(metadata['jwks_uri'] as string);
    const { payload: idToken } = await verifyJwt(tokens.id_token as string, keys, {
      issuer: baseUrl,
      audience: client.id,
    });

    const { header, payload } = await verifyJwt(tokens.access_token, keys, {
      issuer: baseUrl,
      typ: 'at+jwt',
    });

    expect(payload.sub).toBe(idToken.sub);
    expect(payload['client_id']).toBe(client.id);
    expect([payload.aud].flat()).toContain(client.id);
    expect(String(payload['scope']).split(' ')).toEqual(
      expect.arrayContaining(['openid', 'profile'])
    );
    expect(payload.jti).toMatch(/\S/);
    expect(payload.exp as number).toBeGreaterThan(payload.iat as number);
    expectSignedWithAdvertisedKey(header, metadata);
  });
});

/** The token's `alg` is one discovery advertises, and its `kid` names a published key. */
function expectSignedWithAdvertisedKey(
  header: ProtectedHeaderParameters,
  metadata: Record<string, unknown>
): void {
  expect(metadata['id_token_signing_alg_values_supported']).toContain(header.alg);
  expect(header.kid).toBeTypeOf('string');
}

describe('RFC 7636 §4.6 — the token endpoint checks the verifier against the code’s challenge', () => {
  let session: SignedInBrowser;

  beforeAll(async () => {
    session = await newBrowser();
  });

  it('refuses a verifier that does not match with 400 invalid_grant, and the right one still redeems the code (§4.6; RFC 6749 §5.2)', async () => {
    const issued = await issueCode(session);

    await expectOAuthError(
      await exchangeCode(issued, { code_verifier: createPkcePair().verifier }),
      { status: 400, error: 'invalid_grant' }
    );

    await readTokenResponse(await exchangeCode(issued));
  });

  it('refuses an exchange without a code_verifier, issuing nothing (§4.5; RFC 6749 §5.2)', async () => {
    const issued = await issueCode(session);

    const response = await tokenRequest({
      grant_type: 'authorization_code',
      code: issued.code,
      redirect_uri: issued.request.redirectUri,
    });

    const error = await expectOAuthError(response, { status: 400 });
    expect(['invalid_request', 'invalid_grant']).toContain(error.error);
  });

  it('refuses a redirect_uri other than the one the code was issued for with 400 invalid_grant (RFC 6749 §4.1.3, §5.2)', async () => {
    const issued = await issueCode(session);

    await expectOAuthError(
      await exchangeCode(issued, { redirect_uri: 'http://127.0.0.1:9/wire-suite/elsewhere' }),
      { status: 400, error: 'invalid_grant' }
    );
  });
});

describe('OAuth 2.1 draft-16 §4.1.3 — a code returns tokens once', () => {
  let session: SignedInBrowser;

  beforeAll(async () => {
    session = await newBrowser();
  });

  it('denies a replayed code with invalid_grant, and revokes the refresh family and the access token it issued (§4.1.3; RFC 6749 §4.1.2; RFC 9700 §4.2.4)', async () => {
    const issued = await issueCode(session);
    const first = await readTokenResponse(await exchangeCode(issued));
    expect(first.refresh_token).toBeTypeOf('string');
    expect((await introspect(first.access_token))['active']).toBe(true);

    await expectOAuthError(await exchangeCode(issued), { status: 400, error: 'invalid_grant' });

    await expectOAuthError(await refresh(first.refresh_token as string), {
      status: 400,
      error: 'invalid_grant',
    });
    expect(await introspect(first.access_token)).toEqual({ active: false });
  });

  it('refuses a replay with a wrong verifier for that reason alone, and revokes nothing (§7.5.3)', async () => {
    const issued = await issueCode(session);
    const first = await readTokenResponse(await exchangeCode(issued));

    await expectOAuthError(
      await exchangeCode(issued, { code_verifier: createPkcePair().verifier }),
      { status: 400, error: 'invalid_grant' }
    );

    expect((await introspect(first.access_token))['active']).toBe(true);
    const rotated = await readTokenResponse(await refresh(first.refresh_token as string));
    expect(rotated.refresh_token).toBeTypeOf('string');
  });
});
