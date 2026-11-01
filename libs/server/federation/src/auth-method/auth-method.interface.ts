import type { z } from 'zod';

import type { CredentialProvider } from '../providers/credential-provider.interface';
import type {
  AUTH_METHOD_CONTRACT,
  AUTH_METHOD_ICON_MEDIA_TYPES,
  AuthMethodStepUrn,
  UpstreamFailureReason,
} from './contract';

/**
 * The AuthMethod contract (#599): a sign-in method that plugs into QAuth's
 * engine, such as an upstream OpenID Connect provider.
 *
 * EXPERIMENTAL. This is the plugin API of ADR-018 §4. It is public and
 * documented, but outside the 1.0 stability promise: it may change in a minor
 * release, and `contract` names the version a method is written against.
 *
 * ## What it adds to `CredentialProvider`
 *
 * `CredentialProvider` stays the verification half (ADR-003, as amended):
 * `type`, `verify()` and `extractAttributes()` keep their meaning. An
 * AuthMethod adds what a method needs beyond verification: a stable `id`, the
 * contract version, default display data, a config schema, the Interaction API
 * steps it contributes, the routes it mounts, and `start()`.
 *
 * ## The upstream step
 *
 * 1. The engine offers the upstream step and the person picks the method.
 * 2. The engine calls {@link AuthMethod.start}. The method returns where the
 *    browser goes, the transaction it needs back (`state`, `nonce`, a PKCE
 *    verifier) and the binding: the random value the authorization request
 *    carries to the provider and the callback carries back (`state`). The
 *    engine keeps the transaction and the binding server-side, bound to the
 *    interaction and its flow cookie; the transaction never reaches the
 *    browser.
 * 3. The provider sends the browser back to one of the method's callback
 *    routes, under `/upstream/<type>/`. The host compares the binding the
 *    callback carries (in the route's `bindingParameter`, `state` by default)
 *    with the pending transaction's, in constant time, before it takes the
 *    transaction: with no pending transaction (no flow cookie, another
 *    interaction, a replay) or a binding that is missing, repeated or
 *    another's, it answers `transaction_mismatch` itself, leaves the
 *    transaction pending, and the method never runs. Otherwise it takes the
 *    transaction (single use) and the route's handler gets it, checks the
 *    provider's answer and returns an outcome.
 * 4. The engine turns a `result` outcome into a `VerifiedIdentity` by calling
 *    `verify(result)`, checks it, and takes the attributes from
 *    `extractAttributes()`. Every attribute's `source` must equal `type`.
 *
 * `verify()` of an AuthMethod receives only what its own callback returned;
 * the engine calls it, once per result, and nothing else does. It still
 * rejects anything that is not such a result, a copy of a real result and a
 * result already used among them: the contract test kit checks that it does.
 *
 * ## What a method is handed (ADR-019 Decision 12)
 *
 * Plugin code is trusted code that runs in-process. The contract hands it only
 * what it needs, through {@link AuthMethodContext}: its config, the egress
 * client, the signer role and a logger. No database handle, no Redis handle,
 * no private key, no Fastify instance, no cookie and no request header.
 *
 * @typeParam TConfig - the parsed config, the output of `configSchema`
 * @typeParam TTransaction - what `start()` asks the engine to keep
 * @experimental
 */
export interface AuthMethod<TConfig = unknown, TTransaction = unknown> extends CredentialProvider {
  /**
   * The contract version the method is written against:
   * `qauth-auth-method/1-rc.0`. Its presence is what makes a registered
   * provider an AuthMethod.
   */
  readonly contract: typeof AUTH_METHOD_CONTRACT;
  /**
   * The stable name of the method's implementation, such as `oidc` or
   * `corp-sso`. Instances of one implementation (one per configured provider)
   * share it; `type` tells them apart.
   */
  readonly id: string;
  /** What the sign-in page shows for the method until an admin changes it. */
  readonly display: AuthMethodDisplay;
  /**
   * The schema of the method's config. The host parses the stored config with
   * it before it builds a context, so `context.config` is its output. A
   * secret member, such as a client secret, is marked with
   * `.meta({ writeOnly: true })`, so an admin API can keep it write-only.
   */
  readonly configSchema: z.ZodType<TConfig>;
  /** The Interaction API steps the method contributes, by versioned URN. */
  readonly steps: readonly AuthMethodStepUrn[];
  /** The routes the method mounts, below `/upstream/<type>`. */
  readonly routes: readonly AuthMethodRoute<TConfig, TTransaction>[];
  /**
   * Start an upstream transaction: where the browser goes, and what the
   * method needs back at its callback. Rejects when it cannot start, such as
   * when the provider's discovery document cannot be read.
   */
  start(
    request: UpstreamStartRequest,
    context: AuthMethodContext<TConfig>
  ): Promise<UpstreamStart<TTransaction>>;
}

/**
 * A method's default display data. An admin may override both per realm.
 *
 * @experimental
 */
export interface AuthMethodDisplay {
  /**
   * The provider's name, as the button says it: `Example Corp`. At most 64
   * characters, under the Interaction API's display rule.
   */
  readonly name: string;
  /** An icon for the button, or none. */
  readonly icon?: AuthMethodIcon;
}

/**
 * A default icon: a PNG image of at most 16 KiB. The host serves it from the
 * realm origin.
 *
 * @experimental
 */
export interface AuthMethodIcon {
  readonly mediaType: (typeof AUTH_METHOD_ICON_MEDIA_TYPES)[number];
  readonly bytes: Uint8Array;
}

/**
 * What a method is handed for one realm (ADR-019 Decision 12): its config,
 * the egress client, the signer role and a logger. Nothing else: no database
 * or cache handle, no key material.
 *
 * @experimental
 */
export interface AuthMethodContext<TConfig = unknown> {
  /** The method's config for this realm, parsed by its `configSchema`. Frozen. */
  readonly config: TConfig;
  /** Every outbound call goes through here (ADR-019 Decision 8). */
  readonly egress: AuthMethodEgress;
  /** Signatures without keys (ADR-019 Decision 9). */
  readonly signer: AuthMethodSigner;
  /** A logger. Never log a secret, a code or a token. */
  readonly log: AuthMethodLogger;
  /**
   * The absolute URL of one of the method's own routes on this realm's host,
   * such as the `redirect_uri` of an authorization request:
   * `routeUrl('/callback')` is `https://<realm host>/upstream/<type>/callback`.
   */
  routeUrl(path: string): string;
}

/**
 * The egress client as a method sees it. `createAuthMethodContext` builds it
 * over the host's client: it passes on only the members below and adds the
 * realm itself, so an allowlist entry of another realm never applies and a
 * method cannot lift the client's caps.
 *
 * @experimental
 */
export interface AuthMethodEgress {
  /**
   * Send one request. Resolves with the final response, whatever its status;
   * rejects when a check refuses the call (a private address, a redirect to
   * one, a cap) or the call fails.
   */
  request(request: AuthMethodEgressRequest): Promise<AuthMethodEgressResponse>;
}

/**
 * One outbound call of a method.
 *
 * @experimental
 */
export interface AuthMethodEgressRequest {
  readonly method: 'GET' | 'POST';
  /** An absolute `https` URL without credentials. */
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
  /** Not allowed with `GET`. */
  readonly body?: string | Uint8Array;
  /**
   * What the call is for, a fixed label: `upstream-discovery`,
   * `upstream-token`. Lower-case letters, digits and `_ . : -`, starting with
   * a letter, at most 64 characters.
   */
  readonly purpose: string;
  /**
   * Who set the destination: `operator` (the method's own code, installed
   * with the deployment), `admin` (the realm's config of the method) or
   * `remote_document` (a document the method fetched, such as a discovery
   * document). A method never sends to a destination a client or an end user
   * chose.
   */
  readonly source: 'operator' | 'admin' | 'remote_document';
}

/**
 * The final response of a call, after the redirects it followed.
 *
 * @experimental
 */
export interface AuthMethodEgressResponse {
  readonly status: number;
  /** Lower-case names. */
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
  /** The URL that answered. */
  readonly url: string;
}

/**
 * The signer role as a method sees it: signatures and public keys, never a
 * key. `createAuthMethodContext` binds the realm, the provider and the caller
 * role, and passes on only the members below, so a
 * method cannot sign for another provider or another realm.
 *
 * @experimental
 */
export interface AuthMethodSigner {
  /**
   * Sign a client assertion for `private_key_jwt` toward this method's
   * provider (RFC 7523): `iss` and `sub` are the client id the realm's config
   * names, `aud` is `audience`.
   */
  signClientAssertion(request: AuthMethodClientAssertionRequest): Promise<string>;
  /** The public keys of those assertions, for the provider to register or fetch. */
  getUpstreamJwks(): Promise<{ readonly keys: readonly Readonly<Record<string, unknown>>[] }>;
}

/**
 * Input of {@link AuthMethodSigner.signClientAssertion}.
 *
 * @experimental
 */
export interface AuthMethodClientAssertionRequest {
  /** The provider's issuer identifier, the assertion's sole `aud`. */
  readonly audience: string;
  /** The other claims, `exp` and `jti` among them, without `iss`, `sub` or `aud`. */
  readonly claims: Readonly<Record<string, unknown>>;
  /** The algorithm of the key registered with the provider. */
  readonly algorithm?: 'RS256' | 'ES256' | 'EdDSA';
}

/**
 * The part of a pino-style logger a method uses.
 *
 * @experimental
 */
export interface AuthMethodLogger {
  debug(fields: Record<string, unknown>, message: string): void;
  info(fields: Record<string, unknown>, message: string): void;
  warn(fields: Record<string, unknown>, message: string): void;
  error(fields: Record<string, unknown>, message: string): void;
}

/**
 * What the engine tells a method when it starts.
 *
 * @experimental
 */
export interface UpstreamStartRequest {
  /**
   * The person's preferred languages, BCP 47 tags, most preferred first, for
   * the provider's own pages (`ui_locales`). Empty when none is known.
   */
  readonly uiLocales: readonly string[];
}

/**
 * What a method answers when it starts.
 *
 * @experimental
 */
export interface UpstreamStart<TTransaction = unknown> {
  /**
   * Where the browser goes: the provider's authorization endpoint with the
   * request's parameters. An absolute `https` URL, no credentials, no
   * fragment, at most 8192 characters.
   */
  readonly redirectTo: string;
  /**
   * What the method needs back at its callback: `state`, `nonce`, a PKCE
   * verifier. An object of JSON data (objects, arrays, strings, finite
   * numbers, booleans, `null`), at most 4096 bytes as JSON. The engine keeps it server-side and
   * hands it, once, to the callback the same browser reaches.
   */
  readonly transaction: TTransaction;
  /**
   * The value that binds the callback to this start: fresh and random for
   * each start, sent to the provider in the authorization request (as
   * `state`, usually) so the provider sends it back. 22 to 512 base64url
   * characters (`AUTH_METHOD_BINDING_PATTERN`): 22 is the length of 128
   * random bits. The host compares it with what the callback carries before
   * it hands over the transaction.
   */
  readonly binding: string;
}

/**
 * What the host keeps for a started upstream step until its callback: the
 * `transaction` and `binding` that `startUpstreamStep` answered.
 *
 * @experimental
 */
export interface PendingUpstreamTransaction<TTransaction = unknown> {
  readonly binding: string;
  readonly transaction: TTransaction;
}

/**
 * A route a method mounts below `/upstream/<type>`, on the realm host.
 *
 * @experimental
 */
export type AuthMethodRoute<TConfig = unknown, TTransaction = unknown> =
  | AuthMethodCallbackRoute<TConfig, TTransaction>
  | AuthMethodBounceRoute;

/**
 * Members every route has.
 *
 * @experimental
 */
export interface AuthMethodRouteBase {
  readonly method: 'GET' | 'POST';
  /**
   * The path below the method's prefix: `/callback`. One to four segments of
   * lower-case letters, digits, `_` and `-`.
   */
  readonly path: string;
}

/**
 * The route the provider sends the browser back to. Its handler checks the
 * provider's answer against the pending transaction and hands an outcome to
 * the engine.
 *
 * @experimental
 */
export interface AuthMethodCallbackRoute<
  TConfig = unknown,
  TTransaction = unknown,
> extends AuthMethodRouteBase {
  readonly kind: 'callback';
  /**
   * The parameter the provider carries the binding back in: a query
   * parameter of a `GET` route, a form member of a `POST` one. Default
   * `state`. The host reads it, once and unrepeated, and compares it with
   * the pending transaction's binding before the handler runs.
   */
  readonly bindingParameter?: string;
  handle(
    request: AuthMethodCallbackRequest<TTransaction>,
    context: AuthMethodContext<TConfig>
  ): Promise<UpstreamCallbackOutcome>;
}

/**
 * A route that only sends the browser on to one of the method's own `GET`
 * routes, on the same origin: a provider's `form_post` arrives cross-site,
 * without the `SameSite=Lax` flow cookie, and the bounce makes the browser
 * bring it. It is handed no transaction and no context.
 *
 * @experimental
 */
export interface AuthMethodBounceRoute extends AuthMethodRouteBase {
  readonly kind: 'bounce';
  /**
   * Name where the browser goes. No context: anyone can send a cross-site
   * POST here, so a bounce holds no egress client, no signer and no config.
   */
  handle(request: AuthMethodRouteRequest): Promise<AuthMethodBounce>;
}

/**
 * Query and form parameters, by name. A repeated parameter is a list.
 *
 * @experimental
 */
export type AuthMethodParameters = Readonly<Record<string, string | readonly string[]>>;

/**
 * A request to one of a method's routes, as the method sees it: its
 * parameters, and no header and no cookie.
 *
 * @experimental
 */
export interface AuthMethodRouteRequest {
  readonly method: 'GET' | 'POST';
  readonly query: AuthMethodParameters;
  /** The form members of a `POST`; empty for a `GET`. */
  readonly form: AuthMethodParameters;
}

/**
 * A request to a callback route, with the transaction the engine kept.
 *
 * @experimental
 */
export interface AuthMethodCallbackRequest<TTransaction = unknown> extends AuthMethodRouteRequest {
  /**
   * The transaction `start()` returned for this method, which the request's
   * flow cookie names, taken: a second request never sees it again. Always
   * present, and always the one whose binding the request carries: without a
   * pending transaction, or with a binding that does not match, the host
   * answers `transaction_mismatch` and never calls the handler. A handler may
   * still compare `state` with the transaction itself; it costs nothing.
   */
  readonly transaction: TTransaction;
}

/**
 * Where a bounce route sends the browser: one of the method's own `GET`
 * routes, by its path, with the query to carry.
 *
 * @experimental
 */
export interface AuthMethodBounce {
  /** The path of one of the method's own `GET` routes: `/callback`. */
  readonly to: string;
  readonly query: Readonly<Record<string, string>>;
}

/**
 * What a callback hands the engine:
 *
 * - `result`: the provider's answer passed every check. The engine passes
 *   `result` to `verify()`.
 * - `declined`: the person cancelled or declined at the provider
 *   (`access_denied`). Nothing is sent to the client: the person has not
 *   refused the client's request, and may pick another method.
 * - `failed`: anything else, with its reason.
 *
 * @experimental
 */
export type UpstreamCallbackOutcome<TResult = unknown> =
  | { readonly kind: 'result'; readonly result: TResult }
  | { readonly kind: 'declined' }
  | { readonly kind: 'failed'; readonly reason: UpstreamFailureReason };
