import { randomBytes } from 'node:crypto';

import type { SeededClient } from '../config';
import { type AuthorizationResponse, Browser, type BrowserCredentials } from '../helpers/browser';
import { call, operationUrl } from '../helpers/operations';
import { createPkcePair, type PkcePair } from '../helpers/pkce';
import { basicAuthorization, confidentialClient } from './clients';
import { createSignInAccount } from './users';

/**
 * The authorization code flow of the seeded confidential client, driven as a
 * browser and a client would drive it: an authorization request with PKCE,
 * the sign-in page and the consent screen, then the token endpoint.
 */

/** The redirect URI `seed/clients.json` registers for the confidential client. Nothing listens on it. */
export const SEEDED_REDIRECT_URI = 'http://127.0.0.1:9/wire-suite/callback';

/** The scopes a user grants the seeded client in these flows. */
export const USER_SCOPES = 'openid profile email offline_access';

/** An opaque random value for `state` and `nonce`. */
export function randomValue(): string {
  return randomBytes(16).toString('base64url');
}

/** An authorization request (RFC 6749 §4.1.1, RFC 7636 §4.3, OIDC Core 1.0 §3.1.2.1). */
export interface AuthorizationRequest {
  /** The parameters sent, after overrides and omissions. */
  readonly params: URLSearchParams;
  readonly pkce: PkcePair;
  readonly state: string;
  readonly nonce: string;
  readonly redirectUri: string;
  /** `GET /oauth/authorize` with {@link params} as its query. */
  readonly url: URL;
}

/**
 * A complete authorization request for the seeded client. `overrides`
 * replaces parameters; a parameter set to `null` is left out.
 */
export function authorizationRequest(
  overrides: Record<string, string | null> = {},
  client: SeededClient = confidentialClient()
): AuthorizationRequest {
  const pkce = createPkcePair();
  const state = randomValue();
  const nonce = randomValue();
  const values: Record<string, string | null> = {
    response_type: 'code',
    client_id: client.id,
    redirect_uri: SEEDED_REDIRECT_URI,
    scope: USER_SCOPES,
    state,
    nonce,
    code_challenge: pkce.challenge,
    code_challenge_method: pkce.method,
    ...overrides,
  };
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(values)) {
    if (value !== null) params.set(name, value);
  }
  return {
    params,
    pkce,
    state: params.get('state') ?? state,
    nonce: params.get('nonce') ?? nonce,
    redirectUri: params.get('redirect_uri') ?? SEEDED_REDIRECT_URI,
    url: operationUrl('GET /oauth/authorize', params),
  };
}

/** A browser with a signed-in account. */
export interface SignedInBrowser {
  readonly browser: Browser;
  readonly credentials: BrowserCredentials;
}

/** A browser and an account the server has not seen yet. Nothing is sent. */
export async function newBrowser(): Promise<SignedInBrowser> {
  return { browser: new Browser(), credentials: await createSignInAccount() };
}

/** Send a browser through an authorization request, signing in and allowing when asked. */
export function authorizeAs(
  session: SignedInBrowser,
  request: AuthorizationRequest,
  options: { decision?: 'allow' | 'deny'; rememberConsent?: boolean } = {}
): Promise<AuthorizationResponse> {
  return session.browser.authorize(request.url, request.redirectUri, {
    credentials: session.credentials,
    ...options,
  });
}

/**
 * A browser whose account signed in and allowed the seeded client
 * {@link USER_SCOPES}, remembering the decision. Later authorization requests
 * for those scopes go straight back to the redirect URI with a code.
 */
export async function consentedBrowser(): Promise<SignedInBrowser> {
  const session = await newBrowser();
  const response = await authorizeAs(session, authorizationRequest());
  if (!response.params.get('code')) {
    throw new Error(`the first authorization returned no code: ${response.url.href}`);
  }
  return session;
}

/** An authorization code and the request it answers. */
export interface IssuedCode {
  readonly code: string;
  readonly request: AuthorizationRequest;
  readonly response: AuthorizationResponse;
}

/**
 * A fresh code for `session`, from a new request with its own PKCE pair.
 *
 * @throws when the redirect carries no `code`
 */
export async function issueCode(
  session: SignedInBrowser,
  overrides: Record<string, string | null> = {}
): Promise<IssuedCode> {
  const request = authorizationRequest(overrides);
  const response = await authorizeAs(session, request);
  const code = response.params.get('code');
  if (!code) throw new Error(`the authorization returned no code: ${response.url.href}`);
  return { code, request, response };
}

/** How a token-endpoint request authenticates the client (RFC 6749 §2.3.1). */
export type ClientAuthentication = 'client_secret_basic' | 'client_secret_post';

/**
 * POST a token request for the seeded confidential client.
 * `client_secret_basic` sends the `Authorization: Basic` header,
 * `client_secret_post` the `client_id` and `client_secret` body parameters.
 */
export function tokenRequest(
  fields: Record<string, string>,
  authentication: ClientAuthentication = 'client_secret_basic',
  client: SeededClient = confidentialClient()
): Promise<Response> {
  if (authentication === 'client_secret_post') {
    return call('POST /oauth/token', {
      form: { ...fields, client_id: client.id, client_secret: client.secret },
    });
  }
  return call('POST /oauth/token', {
    headers: { authorization: basicAuthorization(client) },
    form: fields,
  });
}

/** The authorization-code exchange for an issued code, with its verifier and redirect URI. */
export function exchangeCode(
  issued: IssuedCode,
  overrides: Record<string, string> = {}
): Promise<Response> {
  return tokenRequest({
    grant_type: 'authorization_code',
    code: issued.code,
    redirect_uri: issued.request.redirectUri,
    code_verifier: issued.request.pkce.verifier,
    ...overrides,
  });
}

/** A successful token response's members. */
export type TokenResponse = Record<string, unknown> & {
  readonly access_token: string;
  readonly token_type: string;
  readonly expires_in: number;
  readonly refresh_token?: string;
  readonly id_token?: string;
  readonly scope?: string;
};

/**
 * Read a token response that must be a success.
 *
 * @throws when the status is not 200 or the body is not a JSON object with an `access_token`
 */
export async function readTokenResponse(response: Response): Promise<TokenResponse> {
  const text = await response.text();
  if (response.status !== 200) {
    throw new Error(`the token endpoint answered ${response.status}: ${text.slice(0, 500)}`);
  }
  const body = JSON.parse(text) as Record<string, unknown>;
  if (typeof body['access_token'] !== 'string') {
    throw new Error(`the token response has no access_token: ${text.slice(0, 500)}`);
  }
  return body as TokenResponse;
}
