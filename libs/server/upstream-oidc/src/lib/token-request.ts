import { randomBytes } from 'node:crypto';

import type { AuthMethodContext, AuthMethodEgressResponse } from '@qauth-labs/server-federation';

import type { UpstreamOidcConfig } from './config';
import { invalidResponse, UpstreamOidcError } from './errors';
import type { UpstreamProviderMetadata } from './metadata';
import {
  jsonObjectBody,
  UPSTREAM_OIDC_CALL_CAPS,
  UPSTREAM_OIDC_PURPOSES,
  upstreamCall,
} from './upstream-call';

/**
 * The code exchange (OpenID Connect Core 1.0 §3.1.3) and the userinfo
 * request (§5.3), through the egress client.
 */

/** The `client_assertion_type` of a JWT client assertion (RFC 7523 §2.2). */
export const JWT_BEARER_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** How long a client assertion is valid, in seconds: it is used at once. */
export const CLIENT_ASSERTION_LIFETIME_SECONDS = 60;

/** The longest access token the client keeps, in characters. */
const MAX_ACCESS_TOKEN_LENGTH = 16 * 1024;

/** What the code exchange sends besides the client's credentials. */
export interface CodeExchange {
  readonly code: string;
  /** The `redirect_uri` the authorization request sent (RFC 6749 §4.1.3). */
  readonly redirectUri: string;
  /** The PKCE verifier (RFC 7636 §4.5). */
  readonly codeVerifier: string;
}

/** What the code exchange returns. */
export interface UpstreamTokens {
  readonly idToken: string;
  readonly accessToken: string;
}

/**
 * Value as `application/x-www-form-urlencoded` encodes it, the encoding
 * RFC 6749 §2.3.1 applies to the client id and secret before HTTP Basic.
 */
export function formEncode(value: string): string {
  return new URLSearchParams({ v: value }).toString().slice(2);
}

/**
 * The client's credentials for the token endpoint, by the configured method:
 * an `Authorization` header for `client_secret_basic`, form members for
 * `client_secret_post` and `private_key_jwt`.
 *
 * For `private_key_jwt` the signer role signs the assertion (ADR-019
 * Decision 9): `iss` and `sub` are the client id the realm's configuration
 * of the provider names, `aud` the provider's issuer identifier (the
 * assertion's sole audience, draft-ietf-oauth-rfc7523bis), with a fresh
 * `jti` and an `exp` {@link CLIENT_ASSERTION_LIFETIME_SECONDS} away. The
 * library sends the signed string and never sees the key.
 */
export async function clientCredentials(
  context: AuthMethodContext<UpstreamOidcConfig>,
  metadata: UpstreamProviderMetadata
): Promise<{ headers: Record<string, string>; form: [string, string][] }> {
  const { config } = context;
  const authentication = config.clientAuthentication;
  switch (authentication.method) {
    case 'client_secret_basic': {
      const pair = `${formEncode(config.clientId)}:${formEncode(authentication.clientSecret)}`;
      return {
        headers: { authorization: `Basic ${Buffer.from(pair, 'utf8').toString('base64')}` },
        form: [],
      };
    }
    case 'client_secret_post':
      return {
        headers: {},
        form: [
          ['client_id', config.clientId],
          ['client_secret', authentication.clientSecret],
        ],
      };
    case 'private_key_jwt': {
      const now = Math.floor(Date.now() / 1000);
      const assertion = await context.signer.signClientAssertion({
        audience: metadata.issuer,
        claims: {
          jti: randomBytes(16).toString('base64url'),
          iat: now,
          exp: now + CLIENT_ASSERTION_LIFETIME_SECONDS,
        },
        algorithm: authentication.signingAlgorithm,
      });
      return {
        headers: {},
        form: [
          ['client_id', config.clientId],
          ['client_assertion_type', JWT_BEARER_ASSERTION_TYPE],
          ['client_assertion', assertion],
        ],
      };
    }
  }
}

/**
 * Redeem an authorization code at the provider's token endpoint, with PKCE
 * and the configured client authentication.
 *
 * @throws UpstreamOidcError `provider_error` for an OAuth error answer,
 *   `upstream_unavailable` when the provider cannot be reached or answers
 *   `429` or `5xx`, `invalid_response` for anything else that fails a check
 */
export async function redeemCode(
  context: AuthMethodContext<UpstreamOidcConfig>,
  metadata: UpstreamProviderMetadata,
  exchange: CodeExchange
): Promise<UpstreamTokens> {
  const purpose = UPSTREAM_OIDC_PURPOSES.token;
  const credentials = await clientCredentials(context, metadata);
  const body = new URLSearchParams([
    ['grant_type', 'authorization_code'],
    ['code', exchange.code],
    ['redirect_uri', exchange.redirectUri],
    ['code_verifier', exchange.codeVerifier],
    ...credentials.form,
  ]).toString();
  const response = await upstreamCall(context.egress, {
    method: 'POST',
    url: metadata.tokenEndpoint,
    headers: {
      accept: 'application/json',
      'content-type': 'application/x-www-form-urlencoded',
      ...credentials.headers,
    },
    body,
    purpose,
    source: metadata.endpointSource,
    caps: UPSTREAM_OIDC_CALL_CAPS.token,
  });
  failedAnswer(response, purpose);
  const document = jsonObjectBody(response, purpose);
  const { token_type: tokenType, access_token: accessToken, id_token: idToken } = document;
  if (typeof tokenType !== 'string' || tokenType.toLowerCase() !== 'bearer') {
    throw invalidResponse(`${purpose}: the token type is not Bearer`);
  }
  if (
    typeof accessToken !== 'string' ||
    accessToken.length === 0 ||
    accessToken.length > MAX_ACCESS_TOKEN_LENGTH
  ) {
    throw invalidResponse(`${purpose}: no access token`);
  }
  if (typeof idToken !== 'string' || idToken.length === 0) {
    throw invalidResponse(`${purpose}: no ID token`);
  }
  return { idToken, accessToken };
}

/**
 * Read the userinfo endpoint with the access token (OpenID Connect Core 1.0
 * §5.3). Its `sub` must equal the ID token's (§5.3.4); a signed or
 * encrypted answer (`application/jwt`) is refused, since the config cannot
 * ask for one.
 *
 * @throws UpstreamOidcError as {@link redeemCode} does
 */
export async function readUserinfo(
  context: AuthMethodContext<UpstreamOidcConfig>,
  metadata: UpstreamProviderMetadata,
  accessToken: string,
  sub: string
): Promise<Record<string, unknown>> {
  const purpose = UPSTREAM_OIDC_PURPOSES.userinfo;
  if (metadata.userinfoEndpoint === undefined) {
    throw invalidResponse(`${purpose}: the provider names no userinfo endpoint`);
  }
  const response = await upstreamCall(context.egress, {
    method: 'GET',
    url: metadata.userinfoEndpoint,
    headers: { accept: 'application/json', authorization: `Bearer ${accessToken}` },
    purpose,
    source: metadata.endpointSource,
    caps: UPSTREAM_OIDC_CALL_CAPS.userinfo,
  });
  failedAnswer(response, purpose);
  const claims = jsonObjectBody(response, purpose);
  if (claims['sub'] !== sub) {
    throw invalidResponse(`${purpose}: the sub is not the ID token's`);
  }
  return claims;
}

/** An OAuth error code as it may be logged: printable ASCII, short. */
const LOGGABLE_ERROR_CODE = /^[\x20-\x21\x23-\x5b\x5d-\x7e]{1,64}$/;

/**
 * Throw for an answer that is not `200`: an OAuth error (`400`, `401`,
 * `403`) is the provider's, `429` and `5xx` mean it is unavailable, anything
 * else is a broken answer.
 */
function failedAnswer(response: AuthMethodEgressResponse, purpose: string): void {
  const { status } = response;
  if (status === 200) return;
  if (status === 429 || status >= 500) {
    throw new UpstreamOidcError(
      'upstream_unavailable',
      `${purpose}: the provider answered ${status}`
    );
  }
  if (status === 400 || status === 401 || status === 403) {
    let code = 'no error code';
    try {
      const error = jsonObjectBody(response, purpose)['error'];
      if (typeof error === 'string' && LOGGABLE_ERROR_CODE.test(error)) code = error;
    } catch {
      // Not JSON: the status alone is the provider's answer.
    }
    throw new UpstreamOidcError(
      'provider_error',
      `${purpose}: the provider answered ${status} (${code})`
    );
  }
  throw invalidResponse(`${purpose}: the provider answered ${status}`);
}
