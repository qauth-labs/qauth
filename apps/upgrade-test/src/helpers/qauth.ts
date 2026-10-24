import { expect } from 'vitest';

import { serverPath } from '../config';
import { CookieJar, formBody, parseForms } from './browser';
import type { PkcePair } from './pkce';

/**
 * The HTTP calls the upgrade test makes, written against what every release
 * since the first baseline answers. Each call checks its own status and fails
 * with the method, the path and the body the server sent, so a CI log names
 * the request that broke.
 *
 * Where releases differ, the helper accepts each release's answer: registration
 * answers 201 with the new user in 0.1 and 202 with no body later, so the user
 * id comes from the login token's `sub`, never from the registration.
 */

/** A client the developer created through `POST /api/clients`. */
export interface CreatedClient {
  /** The row id, used in `/api/clients/:id` paths. */
  readonly id: string;
  /** The OAuth `client_id`. */
  readonly clientId: string;
  /** The plaintext secret, returned once at creation. */
  readonly clientSecret: string;
}

/** The answer of the token endpoint. */
export interface TokenSet {
  readonly accessToken: string;
  readonly refreshToken: string | undefined;
  readonly idToken: string | undefined;
  readonly scope: string | undefined;
}

/** A static API key, as `POST /api/clients/:id/api-keys` returned it. */
export interface CreatedApiKey {
  readonly id: string;
  readonly key: string;
  readonly prefix: string;
  readonly last4: string;
}

/** The first part of a body for a failure message; bodies can be whole HTML pages. */
function excerpt(text: string): string {
  return text.length > 600 ? `${text.slice(0, 600)}…` : text;
}

async function readJson(
  label: string,
  response: Response,
  expected: readonly number[]
): Promise<Record<string, unknown>> {
  const text = await response.text();
  expect(expected, `${label} answered ${response.status}: ${excerpt(text)}`).toContain(
    response.status
  );
  if (text === '') return {};
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(
      `${label} answered ${response.status} with a body that is not JSON: ${excerpt(text)}`
    );
  }
  expect(
    typeof body === 'object' && body !== null && !Array.isArray(body),
    `${label}: ${excerpt(text)}`
  ).toBe(true);
  return body as Record<string, unknown>;
}

function stringField(label: string, body: Record<string, unknown>, name: string): string {
  const value = body[name];
  expect(typeof value, `${label}: "${name}" in ${JSON.stringify(body)}`).toBe('string');
  return value as string;
}

function optionalString(body: Record<string, unknown>, name: string): string | undefined {
  const value = body[name];
  return typeof value === 'string' ? value : undefined;
}

/** The claims of a JWT, read without verifying it: the server is the judge of validity. */
export function jwtClaims(token: string): Record<string, unknown> {
  const parts = token.split('.');
  expect(parts.length, 'a JWT has three parts').toBe(3);
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>;
}

function basicAuthorization(clientId: string, clientSecret: string): string {
  // RFC 6749 §2.3.1: each part is form-urlencoded before it is joined.
  const encode = (value: string) => encodeURIComponent(value).replace(/%20/g, '+');
  return `Basic ${Buffer.from(`${encode(clientId)}:${encode(clientSecret)}`).toString('base64')}`;
}

/** `POST /auth/register`: a new password account. */
export async function register(baseUrl: string, email: string, password: string): Promise<void> {
  const response = await fetch(serverPath(baseUrl, '/auth/register'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  await readJson('POST /auth/register', response, [201, 202]);
}

/**
 * `POST /auth/verify`: confirm an address with the token from the
 * verification mail. The body carries the password too: required since 0.1.0,
 * and ignored by the releases before.
 */
export async function verifyEmail(baseUrl: string, token: string, password: string): Promise<void> {
  const response = await fetch(serverPath(baseUrl, '/auth/verify'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token, password }),
  });
  await readJson('POST /auth/verify', response, [200]);
}

/** `POST /auth/login`: the password sign-in that returns the developer's management token. */
export async function passwordLogin(
  baseUrl: string,
  email: string,
  password: string
): Promise<{ readonly accessToken: string; readonly userId: string }> {
  const response = await fetch(serverPath(baseUrl, '/auth/login'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const body = await readJson(`POST /auth/login as ${email}`, response, [200]);
  const accessToken = stringField('POST /auth/login', body, 'access_token');
  const sub = jwtClaims(accessToken)['sub'];
  expect(typeof sub, 'the login token carries the user id as sub').toBe('string');
  return { accessToken, userId: sub as string };
}

/** `POST /api/clients`: a confidential client owned by the signed-in developer. */
export async function createClient(
  baseUrl: string,
  managementToken: string,
  client: {
    readonly name: string;
    readonly redirectUri: string;
    readonly scopes: readonly string[];
  }
): Promise<CreatedClient> {
  const response = await fetch(serverPath(baseUrl, '/api/clients'), {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${managementToken}` },
    body: JSON.stringify({
      name: client.name,
      redirectUris: [client.redirectUri],
      scopes: client.scopes,
      grantTypes: ['authorization_code', 'refresh_token'],
      tokenEndpointAuthMethod: 'client_secret_basic',
    }),
  });
  const body = await readJson('POST /api/clients', response, [201]);
  return {
    id: stringField('POST /api/clients', body, 'id'),
    clientId: stringField('POST /api/clients', body, 'clientId'),
    clientSecret: stringField('POST /api/clients', body, 'clientSecret'),
  };
}

/** The `code` and `state` the authorization endpoint sent back to the client. */
export interface AuthorizationResult {
  readonly code: string;
  /** Whether the consent page was shown and allowed on the way. */
  readonly consented: boolean;
}

/**
 * The authorization code flow with PKCE (RFC 7636), driven through the hosted
 * pages as a browser would: follow each redirect, sign in on the page with a
 * password field, allow on the page with a `decision=allow` button, and stop at
 * the client's redirect URI.
 */
export async function authorizeInBrowser(options: {
  readonly baseUrl: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scope: string;
  readonly email: string;
  readonly password: string;
  readonly pkce: PkcePair;
  readonly state: string;
  readonly nonce: string;
}): Promise<AuthorizationResult> {
  const jar = new CookieJar();
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
    scope: options.scope,
    state: options.state,
    nonce: options.nonce,
    code_challenge: options.pkce.challenge,
    code_challenge_method: options.pkce.method,
  });
  let url = `${serverPath(options.baseUrl, '/oauth/authorize')}?${query}`;
  let method = 'GET';
  let body: URLSearchParams | undefined;
  let consented = false;
  const trail: string[] = [];

  for (let step = 0; step < 15; step++) {
    const label = `${method} ${new URL(url).pathname}`;
    trail.push(label);
    const response = await fetch(url, {
      method,
      redirect: 'manual',
      headers: {
        accept: 'text/html',
        ...(jar.header() ? { cookie: jar.header() } : {}),
        ...(body ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
      },
      body,
    });
    jar.storeFrom(response);

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      expect(location, `${label} redirected without a Location`).toBeTruthy();
      const next = new URL(location as string, url);
      if (next.href.startsWith(options.redirectUri)) {
        const error = next.searchParams.get('error');
        expect(
          error,
          `the server sent the client error=${error} (${next.searchParams.get('error_description')}) after ${trail.join(' → ')}`
        ).toBeNull();
        expect(next.searchParams.get('state'), 'the redirect returns the state').toBe(
          options.state
        );
        const code = next.searchParams.get('code');
        expect(code, `the redirect carries a code: ${next.href}`).toBeTruthy();
        return { code: code as string, consented };
      }
      url = next.href;
      method = 'GET';
      body = undefined;
      continue;
    }

    const text = await response.text();
    expect(response.status, `${label} after ${trail.join(' → ')}: ${excerpt(text)}`).toBe(200);
    const forms = parseForms(text).filter((form) => form.method === 'post');
    const login = forms.find((form) => form.inputs.some((input) => input.type === 'password'));
    const consent = forms.find((form) =>
      form.buttons.some((button) => button.name === 'decision' && button.value === 'allow')
    );
    if (login) {
      body = formBody(login, { email: options.email, password: options.password });
      url = new URL(login.action || url, url).href;
    } else if (consent) {
      body = formBody(consent, {}, { name: 'decision', value: 'allow' });
      url = new URL(consent.action || url, url).href;
      consented = true;
    } else {
      throw new Error(
        `${label} showed a page with neither a sign-in nor a consent form after ${trail.join(' → ')}: ${excerpt(text)}`
      );
    }
    method = 'POST';
  }
  throw new Error(`The authorization flow did not reach the client: ${trail.join(' → ')}`);
}

function tokenRequest(
  baseUrl: string,
  client: { readonly clientId: string; readonly clientSecret: string },
  parameters: Record<string, string>
): Promise<Response> {
  return fetch(serverPath(baseUrl, '/oauth/token'), {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: basicAuthorization(client.clientId, client.clientSecret),
    },
    body: new URLSearchParams(parameters),
  });
}

function tokenSet(label: string, body: Record<string, unknown>): TokenSet {
  return {
    accessToken: stringField(label, body, 'access_token'),
    refreshToken: optionalString(body, 'refresh_token'),
    idToken: optionalString(body, 'id_token'),
    scope: optionalString(body, 'scope'),
  };
}

/** Exchange an authorization code at the token endpoint (RFC 6749 §4.1.3, RFC 7636 §4.5). */
export async function exchangeCode(
  baseUrl: string,
  client: { readonly clientId: string; readonly clientSecret: string },
  code: string,
  redirectUri: string,
  verifier: string
): Promise<TokenSet> {
  const label = 'POST /oauth/token (authorization_code)';
  const response = await tokenRequest(baseUrl, client, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  });
  return tokenSet(label, await readJson(label, response, [200]));
}

/** Use a refresh token (RFC 6749 §6). */
export async function refresh(
  baseUrl: string,
  client: { readonly clientId: string; readonly clientSecret: string },
  refreshToken: string
): Promise<TokenSet> {
  const label = 'POST /oauth/token (refresh_token)';
  const response = await tokenRequest(baseUrl, client, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  });
  return tokenSet(label, await readJson(label, response, [200]));
}

/** The token endpoint's answer to a refresh token it must refuse: status and `error`. */
export async function refusedRefresh(
  baseUrl: string,
  client: { readonly clientId: string; readonly clientSecret: string },
  refreshToken: string
): Promise<{ readonly status: number; readonly error: unknown }> {
  const response = await tokenRequest(baseUrl, client, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  });
  const text = await response.text();
  let error: unknown;
  try {
    error = (JSON.parse(text) as Record<string, unknown>)['error'];
  } catch {
    error = undefined;
  }
  return { status: response.status, error };
}

/** Token introspection (RFC 7662 §2), authenticated as the client. */
export async function introspect(
  baseUrl: string,
  client: { readonly clientId: string; readonly clientSecret: string },
  token: string
): Promise<Record<string, unknown>> {
  const response = await fetch(serverPath(baseUrl, '/oauth/introspect'), {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: basicAuthorization(client.clientId, client.clientSecret),
    },
    body: new URLSearchParams({ token }),
  });
  return readJson('POST /oauth/introspect', response, [200]);
}

/**
 * The UserInfo endpoint with an access token (OIDC Core 1.0 §5.3). Its path is
 * read from discovery: releases serve it at `/oauth/userinfo`.
 */
export async function userinfo(
  baseUrl: string,
  accessToken: string
): Promise<Record<string, unknown>> {
  const discovery = await fetch(serverPath(baseUrl, '/.well-known/openid-configuration'));
  const metadata = await readJson('GET /.well-known/openid-configuration', discovery, [200]);
  const endpoint = stringField('discovery', metadata, 'userinfo_endpoint');
  const response = await fetch(endpoint, { headers: { authorization: `Bearer ${accessToken}` } });
  return readJson(`GET ${new URL(endpoint).pathname}`, response, [200]);
}

/** The signed-in user's consents, as `GET /api/consents` lists them. */
export async function listConsents(
  baseUrl: string,
  managementToken: string
): Promise<ReadonlyArray<{ readonly clientId: string; readonly scopes: readonly string[] }>> {
  const response = await fetch(serverPath(baseUrl, '/api/consents'), {
    headers: { authorization: `Bearer ${managementToken}` },
  });
  const body = await readJson('GET /api/consents', response, [200]);
  expect(Array.isArray(body['consents']), `GET /api/consents: ${JSON.stringify(body)}`).toBe(true);
  return body['consents'] as { clientId: string; scopes: string[] }[];
}

/** `POST /api/clients/:id/api-keys`: a static API key for a development client. */
export async function createApiKey(
  baseUrl: string,
  managementToken: string,
  clientRowId: string,
  name: string
): Promise<CreatedApiKey> {
  const label = `POST /api/clients/${clientRowId}/api-keys`;
  const response = await fetch(serverPath(baseUrl, `/api/clients/${clientRowId}/api-keys`), {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${managementToken}` },
    body: JSON.stringify({ name }),
  });
  const body = await readJson(label, response, [201]);
  return {
    id: stringField(label, body, 'id'),
    key: stringField(label, body, 'key'),
    prefix: stringField(label, body, 'prefix'),
    last4: stringField(label, body, 'last4'),
  };
}

/** The client's API keys, as `GET /api/clients/:id/api-keys` lists them (masked). */
export async function listApiKeys(
  baseUrl: string,
  managementToken: string,
  clientRowId: string
): Promise<ReadonlyArray<Record<string, unknown>>> {
  const label = `GET /api/clients/${clientRowId}/api-keys`;
  const response = await fetch(serverPath(baseUrl, `/api/clients/${clientRowId}/api-keys`), {
    headers: { authorization: `Bearer ${managementToken}` },
  });
  const body = await readJson(label, response, [200]);
  expect(Array.isArray(body['apiKeys']), `${label}: ${JSON.stringify(body)}`).toBe(true);
  return body['apiKeys'] as Record<string, unknown>[];
}
