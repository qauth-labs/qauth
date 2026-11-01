import { createHash, randomBytes } from 'node:crypto';

import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JSONWebKeySet,
  type JWK,
  jwtVerify,
  SignJWT,
} from 'jose';

/**
 * TEST SUPPORT — a fake OpenID Provider (#601), with no network of its own:
 * `answer()` takes a request as the egress client would send it and returns
 * the provider's answer, so a unit test plugs it into a fake egress client
 * and a flow test into a local HTTPS server.
 *
 * It does what a strict provider does: it registers clients with one
 * authentication method each, issues codes bound to the client, the
 * `redirect_uri`, the PKCE challenge and the `nonce`, redeems each code once
 * with the verifier and the client's credentials (a client assertion is
 * verified against the keys the test hands it), signs ID tokens with its own
 * key and serves discovery, its key set and userinfo.
 */

export type FakeClientAuthentication =
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'private_key_jwt';

/** A client registered at the fake provider. */
export interface FakeClient {
  readonly clientId: string;
  readonly method: FakeClientAuthentication;
  readonly clientSecret?: string;
  readonly redirectUris: readonly string[];
  /** For `private_key_jwt`: the key set the client's assertions verify under. */
  readonly assertionKeys?: () => Promise<{ readonly keys: readonly unknown[] }>;
  /**
   * For `private_key_jwt` under the contract test kit, whose signer hands back
   * a stand-in assertion: accept an assertion this says is good, unverified.
   */
  readonly trustAssertion?: (assertion: string) => boolean;
}

/** A request, as the egress client sends it. */
export interface FakeRequest {
  readonly method: string;
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string | Uint8Array;
}

/** An answer. */
export interface FakeAnswer {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: Uint8Array;
  readonly url: string;
}

/** A person signing in at the fake provider. */
export interface FakeSignIn {
  readonly sub: string;
  /** More ID token claims, such as `email`. */
  readonly claims?: Readonly<Record<string, unknown>>;
  /** Claims the userinfo endpoint answers besides `sub`. */
  readonly userinfo?: Readonly<Record<string, unknown>>;
}

export interface FakeProviderOptions {
  readonly issuer: string;
  /** The signing algorithm of the provider's key. Default `ES256`. */
  readonly algorithm?: 'ES256' | 'RS256' | 'EdDSA';
  /** Whether the authorization response carries `iss` (RFC 9207). Default `true`. */
  readonly issParameter?: boolean;
}

/** What a test may change about the next answers. */
export interface FakeProviderTampering {
  /** Members merged over the discovery document (`undefined` removes one). */
  discovery?: Record<string, unknown>;
  /** Claims merged over the next ID tokens (`undefined` removes one). */
  idTokenClaims?: Record<string, unknown>;
  /** Sign the next ID tokens with this instead of the provider's key. */
  idTokenSigner?: (claims: Record<string, unknown>) => Promise<string>;
  /** Answer the next token requests with this. */
  tokenAnswer?: () => FakeAnswer | Promise<FakeAnswer>;
}

export interface FakeProvider {
  readonly issuer: string;
  readonly discoveryUrl: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly userinfoEndpoint: string;
  /** The provider's public signing key, with `kid`, `alg` and `use`. */
  readonly publicJwk: JWK;
  /** Sign `claims` with the provider's own key. */
  sign(claims: Record<string, unknown>, header?: Record<string, unknown>): Promise<string>;
  register(client: FakeClient): void;
  /**
   * The person signs in for the authorization request `authorizationRequest`:
   * the response parameters the provider sends back (`code`, `state`, and
   * `iss` when it sends one), or an `error` when the request is not one the
   * provider accepts.
   */
  authorize(authorizationRequest: URL, person: FakeSignIn): Record<string, string>;
  /** The provider's answer to `request`. */
  answer(request: FakeRequest): Promise<FakeAnswer>;
  /** Every request answered, in order. */
  readonly requests: FakeRequest[];
  /** Every token request's form, in order. */
  readonly tokenRequests: URLSearchParams[];
  /** Every client assertion's verified claims, in order. */
  readonly assertions: Record<string, unknown>[];
  tamper: FakeProviderTampering;
}

interface IssuedCode {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly challenge: string;
  readonly nonce: string | undefined;
  readonly person: FakeSignIn;
  used: boolean;
}

const json = (status: number, value: unknown, url: string): FakeAnswer => ({
  status,
  headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  body: Buffer.from(JSON.stringify(value), 'utf8'),
  url,
});

/** `value` decoded from `application/x-www-form-urlencoded`. */
const formDecode = (value: string): string => decodeURIComponent(value.replace(/\+/g, ' '));

export async function createFakeProvider(options: FakeProviderOptions): Promise<FakeProvider> {
  const issuer = options.issuer;
  const base = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;
  const algorithm = options.algorithm ?? 'ES256';
  const { privateKey, publicKey } = await generateKeyPair(algorithm, { extractable: true });
  const kid = `fake-${randomBytes(4).toString('hex')}`;
  const publicJwk: JWK = { ...(await exportJWK(publicKey)), kid, alg: algorithm, use: 'sig' };
  const clients = new Map<string, FakeClient>();
  const codes = new Map<string, IssuedCode>();
  const accessTokens = new Map<string, FakeSignIn>();
  const seenAssertionIds = new Set<string>();
  const requests: FakeRequest[] = [];
  const tokenRequests: URLSearchParams[] = [];
  const assertions: Record<string, unknown>[] = [];

  const endpoints = {
    discoveryUrl: `${base}/.well-known/openid-configuration`,
    authorizationEndpoint: `${base}/authorize`,
    tokenEndpoint: `${base}/token`,
    jwksUri: `${base}/jwks`,
    userinfoEndpoint: `${base}/userinfo`,
  };

  const sign = (claims: Record<string, unknown>, header: Record<string, unknown> = {}) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: algorithm, kid, typ: 'JWT', ...header })
      .sign(privateKey);

  const provider: FakeProvider = {
    issuer,
    ...endpoints,
    publicJwk,
    sign,
    requests,
    tokenRequests,
    assertions,
    tamper: {},
    register(client) {
      clients.set(client.clientId, client);
    },
    authorize(request, person) {
      const parameter = (name: string) => request.searchParams.get(name) ?? undefined;
      const state = parameter('state') ?? '';
      const refuse = (error: string) => ({ error, state, ...issParameter() });
      const client = clients.get(parameter('client_id') ?? '');
      const redirectUri = parameter('redirect_uri');
      if (client === undefined || redirectUri === undefined) return refuse('unauthorized_client');
      if (!client.redirectUris.includes(redirectUri)) return refuse('invalid_request');
      if (parameter('response_type') !== 'code') return refuse('unsupported_response_type');
      if (
        parameter('code_challenge_method') !== 'S256' ||
        parameter('code_challenge') === undefined
      ) {
        return refuse('invalid_request');
      }
      if (!(parameter('scope') ?? '').split(' ').includes('openid')) return refuse('invalid_scope');
      const code = randomBytes(24).toString('base64url');
      codes.set(code, {
        clientId: client.clientId,
        redirectUri,
        challenge: parameter('code_challenge') as string,
        nonce: parameter('nonce'),
        person,
        used: false,
      });
      return { code, state, ...issParameter() };
    },
    async answer(request) {
      requests.push(request);
      const url = new URL(request.url);
      const path = `${url.origin}${url.pathname}`;
      if (request.method === 'GET' && path === endpoints.discoveryUrl) {
        const document: Record<string, unknown> = {
          issuer,
          authorization_endpoint: endpoints.authorizationEndpoint,
          token_endpoint: endpoints.tokenEndpoint,
          jwks_uri: endpoints.jwksUri,
          userinfo_endpoint: endpoints.userinfoEndpoint,
          response_types_supported: ['code'],
          response_modes_supported: ['query', 'form_post'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: [algorithm],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: [
            'client_secret_basic',
            'client_secret_post',
            'private_key_jwt',
          ],
          authorization_response_iss_parameter_supported: options.issParameter !== false,
          ...provider.tamper.discovery,
        };
        for (const [name, value] of Object.entries(document)) {
          if (value === undefined) delete document[name];
        }
        return json(200, document, request.url);
      }
      if (request.method === 'GET' && path === endpoints.jwksUri) {
        return {
          ...json(200, { keys: [publicJwk] } satisfies JSONWebKeySet, request.url),
          headers: { 'content-type': 'application/jwk-set+json' },
        };
      }
      if (request.method === 'POST' && path === endpoints.tokenEndpoint) {
        if (provider.tamper.tokenAnswer !== undefined) return provider.tamper.tokenAnswer();
        return tokenAnswer(request);
      }
      if (request.method === 'GET' && path === endpoints.userinfoEndpoint) {
        const authorization = header(request, 'authorization') ?? '';
        const person = accessTokens.get(authorization.replace(/^Bearer /, ''));
        if (person === undefined) return json(401, { error: 'invalid_token' }, request.url);
        return json(200, { ...person.userinfo, sub: person.sub }, request.url);
      }
      return json(404, { error: 'not_found' }, request.url);
    },
  };

  function issParameter(): Record<string, string> {
    return options.issParameter === false ? {} : { iss: issuer };
  }

  async function tokenAnswer(request: FakeRequest): Promise<FakeAnswer> {
    const body =
      typeof request.body === 'string'
        ? request.body
        : Buffer.from(request.body ?? new Uint8Array()).toString('utf8');
    const form = new URLSearchParams(body);
    tokenRequests.push(form);
    const fail = (status: number, error: string) => json(status, { error }, request.url);

    const client = await authenticatedClient(request, form);
    if (client === undefined) return fail(401, 'invalid_client');
    if (form.get('grant_type') !== 'authorization_code') return fail(400, 'unsupported_grant_type');
    const issued = codes.get(form.get('code') ?? '');
    if (issued === undefined || issued.used || issued.clientId !== client.clientId) {
      return fail(400, 'invalid_grant');
    }
    issued.used = true;
    if (form.get('redirect_uri') !== issued.redirectUri) return fail(400, 'invalid_grant');
    const verifier = form.get('code_verifier') ?? '';
    if (createHash('sha256').update(verifier, 'ascii').digest('base64url') !== issued.challenge) {
      return fail(400, 'invalid_grant');
    }
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      iss: issuer,
      sub: issued.person.sub,
      aud: client.clientId,
      iat: now,
      exp: now + 300,
      ...(issued.nonce === undefined ? {} : { nonce: issued.nonce }),
      ...issued.person.claims,
      ...provider.tamper.idTokenClaims,
    };
    for (const [name, value] of Object.entries(claims)) {
      if (value === undefined) delete claims[name];
    }
    const accessToken = randomBytes(24).toString('base64url');
    accessTokens.set(accessToken, issued.person);
    const idToken = await (provider.tamper.idTokenSigner ?? ((c) => sign(c)))(claims);
    return json(
      200,
      { token_type: 'Bearer', access_token: accessToken, expires_in: 300, id_token: idToken },
      request.url
    );
  }

  /** The client the token request authenticates as, by its registered method only. */
  async function authenticatedClient(
    request: FakeRequest,
    form: URLSearchParams
  ): Promise<FakeClient | undefined> {
    const authorization = header(request, 'authorization');
    if (authorization !== undefined) {
      const match = /^Basic ([A-Za-z0-9+/=]+)$/.exec(authorization);
      if (match === null) return undefined;
      const decoded = Buffer.from(match[1], 'base64').toString('utf8');
      const colon = decoded.indexOf(':');
      if (colon < 0) return undefined;
      const client = clients.get(formDecode(decoded.slice(0, colon)));
      return client?.method === 'client_secret_basic' &&
        client.clientSecret === formDecode(decoded.slice(colon + 1)) &&
        !form.has('client_secret') &&
        !form.has('client_assertion')
        ? client
        : undefined;
    }
    const assertion = form.get('client_assertion');
    if (assertion !== null) {
      if (
        form.get('client_assertion_type') !==
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      ) {
        return undefined;
      }
      const client = clients.get(form.get('client_id') ?? '');
      if (client?.method !== 'private_key_jwt') return undefined;
      if (client.trustAssertion !== undefined) {
        return client.trustAssertion(assertion) ? client : undefined;
      }
      if (client.assertionKeys === undefined) return undefined;
      try {
        const keys = createLocalJWKSet((await client.assertionKeys()) as JSONWebKeySet);
        const { payload } = await jwtVerify(assertion, keys, {
          issuer: client.clientId,
          subject: client.clientId,
          audience: issuer,
          requiredClaims: ['exp', 'jti'],
        });
        if (typeof payload.jti !== 'string' || seenAssertionIds.has(payload.jti)) return undefined;
        seenAssertionIds.add(payload.jti);
        assertions.push(payload as Record<string, unknown>);
        return client;
      } catch {
        return undefined;
      }
    }
    const client = clients.get(form.get('client_id') ?? '');
    return client?.method === 'client_secret_post' &&
      client.clientSecret === form.get('client_secret')
      ? client
      : undefined;
  }

  return provider;
}

function header(request: FakeRequest, name: string): string | undefined {
  for (const [key, value] of Object.entries(request.headers ?? {})) {
    if (key.toLowerCase() === name) return value;
  }
  return undefined;
}
