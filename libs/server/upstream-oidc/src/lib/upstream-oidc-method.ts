import { createHash, randomBytes } from 'node:crypto';

import {
  AUTH_METHOD_CONTRACT,
  type AuthMethod,
  type AuthMethodBounce,
  type AuthMethodCallbackRequest,
  type AuthMethodContext,
  type AuthMethodDisplay,
  type AuthMethodParameters,
  authMethodRoutePrefix,
  type AuthMethodRouteRequest,
  MAX_AUTH_METHOD_RAW_CLAIMS_BYTES,
  MAX_UPSTREAM_REDIRECT_LENGTH,
  UPSTREAM_STEP_URN,
  type UpstreamCallbackOutcome,
  type UpstreamStart,
  type UpstreamStartRequest,
  type UserAttribute,
  type VerifiedIdentity,
} from '@qauth-labs/server-federation';

import { claimAttributes } from './attributes';
import { type UpstreamOidcConfig, upstreamOidcConfigSchema } from './config';
import { invalidResponse, UpstreamOidcError } from './errors';
import { sameText, validateIdToken } from './id-token';
import { UpstreamJwksCache } from './jwks';
import {
  fetchDiscoveryDocument,
  resolveProviderMetadata,
  type UpstreamProviderMetadata,
} from './metadata';
import { readUserinfo, redeemCode } from './token-request';
import { TtlCache } from './ttl-cache';

/**
 * The generic upstream OpenID Connect client (#601): an AuthMethod (#599)
 * that signs a person in at an OpenID Provider with the authorization code
 * flow and PKCE, and hands the engine the provider's verified claims. It
 * makes no account decision: the upstream sign-in flow (#639) looks the
 * identity up and decides.
 *
 * One method per configured provider, each under its own `type`
 * (`oidc_<alias>`), so each provider has its own callback URL:
 * `/upstream/oidc_<alias>/callback` on the realm host.
 *
 * What it does, in order:
 *
 * 1. `start()`: reads the provider's metadata (discovery, or the endpoints
 *    set by hand), and sends the browser to the authorization endpoint with
 *    `response_type=code`, the client id, the provider's own `redirect_uri`,
 *    the scopes, a fresh `state` (also the binding the host checks), a fresh
 *    `nonce` and a PKCE S256 challenge. The transaction keeps `state`,
 *    `nonce`, the verifier, the provider's type and issuer and the
 *    `redirect_uri`.
 * 2. `GET /callback`: the host has matched `state` and handed over the
 *    transaction. The handler checks the transaction is this provider's (a
 *    response for another provider is refused), checks `iss` (RFC 9207),
 *    ends as `declined` on `access_denied`, redeems the code with the
 *    verifier and the configured client authentication, validates the ID
 *    token and, when configured, reads userinfo.
 * 3. `POST /callback`: a `form_post` response arrives cross-site without the
 *    `SameSite=Lax` flow cookie; the bounce sends the browser on to
 *    `GET /callback` on the same origin, which brings it.
 * 4. `verify()` turns a result of its own callback, once, into the identity:
 *    `externalSub` is the provider's `sub`, `rawClaims` the ID token's
 *    claims over the userinfo claims (the ID token's win), `iss` among
 *    them, so the flow can tie the subject to the issuer.
 *
 * EXPERIMENTAL, like the contract it implements.
 *
 * @experimental
 */

/** The implementation's `id`: every configured provider's method shares it. */
export const UPSTREAM_OIDC_METHOD_ID = 'oidc';

/**
 * A provider's `type`: `oidc_` and a lower-case alias of letters, digits and
 * `_`, at most 63 characters in all. It is the AuthMethod type, the
 * `user_credentials.provider_type` value and a segment of the callback URL,
 * so it holds no `:` or `/` and never equals an ID-JAG type
 * (`oidc_<issuer URL>`).
 */
export const UPSTREAM_OIDC_TYPE_PATTERN = /^oidc_[a-z0-9][a-z0-9_]{0,57}$/;

/** The callback route's path below the method's prefix. */
export const UPSTREAM_OIDC_CALLBACK_PATH = '/callback';

/**
 * The redirect URI an operator registers at the provider for a realm:
 * `<realm origin>/upstream/<type>/callback`. One per provider, so a response
 * meant for one provider cannot be replayed at another's callback.
 */
export function upstreamOidcRedirectUri(realmOrigin: string, type: string): string {
  const origin = new URL(realmOrigin);
  if (origin.origin !== realmOrigin) {
    throw new TypeError('realmOrigin must be a bare origin, such as https://auth.example.com');
  }
  if (!UPSTREAM_OIDC_TYPE_PATTERN.test(type)) {
    throw new TypeError('type must be oidc_ and a lower-case alias');
  }
  return `${origin.origin}${authMethodRoutePrefix(type)}${UPSTREAM_OIDC_CALLBACK_PATH}`;
}

/** What `start()` asks the engine to keep until the callback. */
export interface UpstreamOidcTransaction {
  /** The transaction's format. */
  readonly v: 1;
  /** The provider's `type`: a transaction answers only at its own callback. */
  readonly type: string;
  /** The issuer the request went to. */
  readonly issuer: string;
  /** The `redirect_uri` the authorization request sent. */
  readonly redirectUri: string;
  readonly state: string;
  readonly nonce: string;
  /** The PKCE verifier (RFC 7636 §4.1). */
  readonly codeVerifier: string;
}

/** Options of {@link createUpstreamOidcMethod}. */
export interface UpstreamOidcMethodOptions {
  /** `oidc_<alias>`: see {@link UPSTREAM_OIDC_TYPE_PATTERN}. */
  readonly type: string;
  /** What the sign-in page shows until an admin changes it. */
  readonly display: AuthMethodDisplay;
}

/** How long a discovery document is used before it is read again, in milliseconds. */
export const UPSTREAM_DISCOVERY_TTL_MS = 5 * 60 * 1000;

/** How many discovery documents one method keeps. */
const MAX_CACHED_DOCUMENTS = 256;

/** The authorization response parameters a `form_post` bounce carries on. */
const RESPONSE_PARAMETERS = ['code', 'state', 'iss', 'error', 'error_description', 'error_uri'];

/** A BCP 47 tag as `ui_locales` may carry it. */
const LOCALE_TAG = /^[A-Za-z0-9]{1,8}(?:-[A-Za-z0-9]{1,8}){0,7}$/;

/** The most `ui_locales` tags sent. */
const MAX_UI_LOCALES = 8;

/** The longest authorization code the callback accepts. */
const MAX_CODE_LENGTH = 4096;

/** A result of the callback: what `verify()` accepts, once. */
interface UpstreamOidcResult {
  readonly sub: string;
  readonly claims: Readonly<Record<string, unknown>>;
}

/**
 * Create the generic upstream OIDC method for one provider type.
 *
 * @throws TypeError when `type` is not `oidc_` and a lower-case alias
 * @experimental
 */
export function createUpstreamOidcMethod(
  options: UpstreamOidcMethodOptions
): AuthMethod<UpstreamOidcConfig, UpstreamOidcTransaction> {
  const { type, display } = options;
  if (typeof type !== 'string' || !UPSTREAM_OIDC_TYPE_PATTERN.test(type)) {
    throw new TypeError('type must be oidc_ and a lower-case alias, such as oidc_corp');
  }
  /** Results the callback produced and `verify()` has not taken yet. */
  const issued = new WeakSet<object>();
  const documents = new TtlCache<Record<string, unknown>>(
    UPSTREAM_DISCOVERY_TTL_MS,
    MAX_CACHED_DOCUMENTS
  );
  const keySets = new UpstreamJwksCache();

  /**
   * The provider's metadata for this realm's config. The discovery document
   * is kept per realm (by the callback URL, which names the realm's host)
   * and issuer: whether its fetch may use the allowlist depends on the realm.
   */
  const metadataFor = (
    context: AuthMethodContext<UpstreamOidcConfig>
  ): Promise<UpstreamProviderMetadata> => {
    const { config } = context;
    const scope = context.routeUrl(UPSTREAM_OIDC_CALLBACK_PATH);
    return resolveProviderMetadata(config, () =>
      documents.get(JSON.stringify([scope, config.issuer]), () =>
        fetchDiscoveryDocument(context.egress, config.issuer)
      )
    );
  };

  async function start(
    context: AuthMethodContext<UpstreamOidcConfig>,
    request: UpstreamStartRequest
  ): Promise<UpstreamStart<UpstreamOidcTransaction>> {
    const { config } = context;
    const metadata = await metadataFor(context);
    const redirectUri = context.routeUrl(UPSTREAM_OIDC_CALLBACK_PATH);
    const state = randomToken();
    const nonce = randomToken();
    const codeVerifier = randomToken();

    const url = new URL(metadata.authorizationEndpoint);
    const parameters: [string, string][] = [
      ['response_type', 'code'],
      ['client_id', config.clientId],
      ['redirect_uri', redirectUri],
      ['scope', config.scopes.join(' ')],
      ['state', state],
      ['nonce', nonce],
      ['code_challenge', s256(codeVerifier)],
      ['code_challenge_method', 'S256'],
    ];
    if (config.responseMode === 'form_post') parameters.push(['response_mode', 'form_post']);
    const locales = uiLocales(request.uiLocales);
    if (locales !== '') parameters.push(['ui_locales', locales]);
    // `set`: a parameter the endpoint's own query already names is replaced.
    for (const [name, value] of parameters) url.searchParams.set(name, value);
    if (url.href.length > MAX_UPSTREAM_REDIRECT_LENGTH) {
      throw invalidResponse(
        `the authorization request is longer than ${MAX_UPSTREAM_REDIRECT_LENGTH} characters`
      );
    }

    return {
      redirectTo: url.href,
      transaction: {
        v: 1,
        type,
        issuer: config.issuer,
        redirectUri,
        state,
        nonce,
        codeVerifier,
      },
      binding: state,
    };
  }

  async function callback(
    request: AuthMethodCallbackRequest<UpstreamOidcTransaction>,
    context: AuthMethodContext<UpstreamOidcConfig>
  ): Promise<UpstreamCallbackOutcome<UpstreamOidcResult>> {
    const { config } = context;
    const { query } = request;
    const transaction = ownTransaction(request.transaction, type, config, context);
    // The host compared `state` already; again here, at no cost.
    const state = single(query, 'state');
    if (state === undefined || !sameText(state, transaction.state)) {
      throw new UpstreamOidcError('transaction_mismatch', "the state is not the transaction's");
    }

    const metadata = await metadataFor(context);
    // RFC 9207 §2.4: a response that names another issuer is refused, and
    // so is one without `iss` from a provider that says it sends it.
    if (Object.hasOwn(query, 'iss')) {
      const iss = single(query, 'iss');
      if (iss === undefined || iss !== metadata.issuer) {
        throw invalidResponse('the response names another issuer (RFC 9207)');
      }
    } else if (metadata.issParameterSupported) {
      throw invalidResponse('the response carries no iss, which the provider says it sends');
    }

    if (Object.hasOwn(query, 'error')) {
      const error = single(query, 'error');
      if (error === 'access_denied') return { kind: 'declined' };
      throw new UpstreamOidcError('provider_error', 'the provider answered an error');
    }
    const code = single(query, 'code');
    if (code === undefined || code.length === 0 || code.length > MAX_CODE_LENGTH) {
      throw invalidResponse('the response carries no single code');
    }

    const tokens = await redeemCode(context, metadata, {
      code,
      redirectUri: transaction.redirectUri,
      codeVerifier: transaction.codeVerifier,
    });
    const scope = context.routeUrl(UPSTREAM_OIDC_CALLBACK_PATH);
    const idTokenClaims = await validateIdToken(
      tokens.idToken,
      {
        issuer: metadata.issuer,
        clientId: config.clientId,
        nonce: transaction.nonce,
        algorithms: metadata.idTokenSigningAlgorithms,
      },
      (algorithm, kid) =>
        keySets.candidates(
          context.egress,
          { scope, uri: metadata.jwksUri, source: metadata.endpointSource },
          algorithm,
          kid
        )
    );
    const sub = idTokenClaims['sub'] as string;
    const userinfo = config.fetchUserinfo
      ? await readUserinfo(context, metadata, tokens.accessToken, sub)
      : {};
    const claims = mergedClaims(idTokenClaims, userinfo);
    if (Buffer.byteLength(JSON.stringify(claims), 'utf8') > MAX_AUTH_METHOD_RAW_CLAIMS_BYTES) {
      throw invalidResponse('the claims are larger than an identity may carry');
    }
    const result: UpstreamOidcResult = Object.freeze({ sub, claims: Object.freeze(claims) });
    issued.add(result);
    return { kind: 'result', result };
  }

  const method: AuthMethod<UpstreamOidcConfig, UpstreamOidcTransaction> = {
    contract: AUTH_METHOD_CONTRACT,
    id: UPSTREAM_OIDC_METHOD_ID,
    type,
    display,
    configSchema: upstreamOidcConfigSchema,
    steps: Object.freeze([UPSTREAM_STEP_URN]),
    routes: Object.freeze([
      {
        kind: 'callback',
        method: 'GET',
        path: UPSTREAM_OIDC_CALLBACK_PATH,
        async handle(request, context) {
          try {
            return await callback(request, context);
          } catch (error) {
            if (!(error instanceof UpstreamOidcError)) throw error;
            context.log.warn(
              { provider: type, reason: error.reason, problem: error.message },
              'upstream OIDC callback refused'
            );
            return { kind: 'failed', reason: error.reason };
          }
        },
      },
      {
        kind: 'bounce',
        method: 'POST',
        path: UPSTREAM_OIDC_CALLBACK_PATH,
        async handle(request: AuthMethodRouteRequest): Promise<AuthMethodBounce> {
          // Only the response's own parameters, each a single value: the GET
          // callback refuses a missing or repeated one.
          const carried: Record<string, string> = {};
          for (const name of RESPONSE_PARAMETERS) {
            const value = single(request.form, name);
            if (value !== undefined) carried[name] = value;
          }
          return { to: UPSTREAM_OIDC_CALLBACK_PATH, query: carried };
        },
      },
    ]),
    start,
    async verify(input: unknown): Promise<VerifiedIdentity> {
      if (typeof input !== 'object' || input === null || !issued.has(input)) {
        throw new Error("not a result of this method's callback");
      }
      issued.delete(input);
      const { sub, claims } = input as UpstreamOidcResult;
      return { externalSub: sub, assuranceLevel: 'low', rawClaims: { ...claims } };
    },
    extractAttributes(identity: VerifiedIdentity): UserAttribute[] {
      return claimAttributes(type, identity);
    },
  };
  return Object.freeze(method);
}

/**
 * The transaction, when it is this provider's own for this realm's config;
 * otherwise a `transaction_mismatch`. A response for provider A that reaches
 * provider B's callback ends here: B holds no transaction of A's.
 */
function ownTransaction(
  value: unknown,
  type: string,
  config: UpstreamOidcConfig,
  context: AuthMethodContext<UpstreamOidcConfig>
): UpstreamOidcTransaction {
  const mismatch = (problem: string) => new UpstreamOidcError('transaction_mismatch', problem);
  if (typeof value !== 'object' || value === null) throw mismatch('no transaction');
  const transaction = value as Record<string, unknown>;
  if (transaction['v'] !== 1) throw mismatch('not a transaction of this client');
  if (transaction['type'] !== type) throw mismatch("another provider's transaction");
  if (transaction['issuer'] !== config.issuer) throw mismatch('a transaction for another issuer');
  if (transaction['redirectUri'] !== context.routeUrl(UPSTREAM_OIDC_CALLBACK_PATH)) {
    throw mismatch('a transaction for another callback');
  }
  for (const name of ['state', 'nonce', 'codeVerifier']) {
    if (typeof transaction[name] !== 'string') throw mismatch('an incomplete transaction');
  }
  return transaction as unknown as UpstreamOidcTransaction;
}

/**
 * Claims whose truth another claim of the same source vouches for: a value
 * and its `*_verified` flag (OpenID Connect Core 1.0 §5.1).
 */
const VERIFIED_CLAIM_PAIRS: readonly (readonly [value: string, flag: string])[] = [
  ['email', 'email_verified'],
  ['phone_number', 'phone_number_verified'],
];

/**
 * The identity's claims: the ID token's over the userinfo answer's. The ID
 * token's win: they are signed, and `iss`, `sub` and `aud` stay the checked
 * ones. A value and its `*_verified` flag are taken together, from the source
 * that holds the value: an ID token's unverified `email` never takes a
 * userinfo answer's `email_verified` for another address.
 */
function mergedClaims(
  idToken: Readonly<Record<string, unknown>>,
  userinfo: Readonly<Record<string, unknown>>
): Record<string, unknown> {
  const claims: Record<string, unknown> = { ...userinfo, ...idToken };
  for (const [value, flag] of VERIFIED_CLAIM_PAIRS) {
    const source = Object.hasOwn(idToken, value)
      ? idToken
      : Object.hasOwn(userinfo, value)
        ? userinfo
        : undefined;
    delete claims[flag];
    if (source !== undefined && Object.hasOwn(source, flag)) claims[flag] = source[flag];
  }
  return claims;
}

/** One parameter's single value; a missing or repeated one is `undefined`. */
function single(parameters: AuthMethodParameters, name: string): string | undefined {
  const value = Object.hasOwn(parameters, name) ? parameters[name] : undefined;
  return typeof value === 'string' ? value : undefined;
}

/** 32 random bytes, base64url: 43 characters, a state, nonce or PKCE verifier. */
function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

/** The S256 code challenge of a PKCE verifier (RFC 7636 §4.2). */
function s256(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/** `ui_locales`: the well-formed tags, at most {@link MAX_UI_LOCALES}, space-separated. */
function uiLocales(tags: readonly string[]): string {
  return tags
    .filter((tag) => typeof tag === 'string' && LOCALE_TAG.test(tag))
    .slice(0, MAX_UI_LOCALES)
    .join(' ');
}
