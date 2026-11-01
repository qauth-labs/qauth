import type {
  AuthMethod,
  AuthMethodClientAssertionRequest,
  AuthMethodContext,
  AuthMethodEgressRequest,
  AuthMethodEgressResponse,
  AuthMethodLogger,
} from './auth-method.interface';
import { AUTH_METHOD_ROUTE_PATH_PATTERN, authMethodRoutePrefix } from './contract';
import { AuthMethodConfigError } from './errors';

/**
 * The egress client as the host has it: the shape of `EgressClient.request`
 * in `@qauth-labs/server-egress`, which takes the realm a destination belongs
 * to and per-call caps. The context's adapter sets the realm itself, and
 * passes one cap only: `maxRedirects: 0`, when the method asks to follow no
 * redirect. No other cap, so a method can tighten the client's redirect cap
 * and lift nothing.
 *
 * @experimental
 */
export interface AuthMethodHostEgress {
  request(request: {
    method: 'GET' | 'POST';
    url: string;
    headers?: Record<string, string>;
    body?: string | Uint8Array;
    purpose: string;
    source: 'operator' | 'admin' | 'remote_document';
    realm?: string;
    limits?: { maxRedirects: 0 };
  }): Promise<AuthMethodEgressResponse>;
}

/**
 * The signer as the host has it: the shape of the two `Signer` operations of
 * `@qauth-labs/server-keys` a method needs, each of which names its caller
 * role, the realm and the provider. The context's adapter fixes all three.
 *
 * @experimental
 */
export interface AuthMethodHostSigner {
  signClientAssertion(
    caller: string,
    request: {
      readonly realmId: string;
      readonly providerId: string;
      readonly audience: string;
      readonly claims: Readonly<Record<string, unknown>>;
      readonly algorithm?: 'RS256' | 'ES256' | 'EdDSA';
    }
  ): Promise<string>;
  getUpstreamJwks(
    caller: string,
    realmId: string,
    providerId: string
  ): Promise<{ readonly keys: readonly unknown[] }>;
}

/**
 * What a host passes to build a method's context for one realm.
 *
 * @experimental
 */
export interface AuthMethodContextParts {
  /** The realm's stored config of the method, before parsing. */
  readonly config: unknown;
  /**
   * The realm host's origin, as the browser reaches it:
   * `https://auth.example.com`. Route URLs are built on it.
   */
  readonly origin: string;
  /** The realm's name: the egress allowlist entries that name it apply. */
  readonly realmName: string;
  /** The realm's id, for the signer. */
  readonly realmId: string;
  /** The upstream provider, the scope of its client-assertion keys. */
  readonly providerId: string;
  /** The signer caller role the method's calls are made for, such as `api`. */
  readonly signerCaller: string;
  readonly egress: AuthMethodHostEgress;
  readonly signer: AuthMethodHostSigner;
  /** A logger, such as a pino child logger; only its four levels are used. */
  readonly log: AuthMethodLogger;
  /**
   * The method's secret members as the host decrypted them into `config`, by
   * path (`clientSecret`, `mtls.keyPassword`). The context keeps them out of
   * two places: its egress labels, so a secret that parses as a URL opens no
   * allowlisted destination; and its log lines, where a field named as a
   * secret path's last segment, and every occurrence of a secret's value in a
   * string or the message, is redacted.
   */
  readonly secrets?: ReadonlyMap<string, string>;
}

const EGRESS_METHODS: readonly string[] = ['GET', 'POST'];
const EGRESS_SOURCES: readonly string[] = ['operator', 'admin', 'remote_document'];
const EGRESS_REDIRECTS: readonly unknown[] = [undefined, 'follow', 'error'];
const ASSERTION_ALGORITHMS: readonly string[] = ['RS256', 'ES256', 'EdDSA'];

/**
 * The longest a client assertion signed through the context stays valid, in
 * seconds: its `exp` is lowered to at most this far past the moment it is
 * signed. Five minutes covers a token request and clock skew; an assertion
 * that outlives it is a replayable credential at the provider.
 *
 * @experimental
 */
export const MAX_AUTH_METHOD_CLIENT_ASSERTION_LIFETIME_SECONDS = 300;

/**
 * How far a client assertion's `iat` may lie in the future, in seconds, for
 * the clock skew between the method's idea of now and the host's.
 */
const ASSERTION_IAT_SKEW_SECONDS = 60;

/**
 * The fields a method's log line may not carry, at any depth, matched without
 * regard to case, `_` or `-` (`clientSecret` matches `client_secret`): the
 * value is replaced with `[Redacted]`. Codes, verifiers, client secrets and
 * assertions, tokens, nonces and passwords: what an upstream sign-in handles
 * and a log must never hold. The last segment of each of the method's own
 * secret paths joins them (`AuthMethodContextParts.secrets`), so does every
 * occurrence of a secret's value.
 *
 * @experimental
 */
export const AUTH_METHOD_LOG_REDACTED_FIELDS: readonly string[] = Object.freeze([
  'code',
  'code_verifier',
  'client_secret',
  'client_assertion',
  'refresh_token',
  'access_token',
  'id_token',
  'nonce',
  'password',
]);

/**
 * The key a method's log fields are nested under, so they never overwrite
 * the host's own fields of the line (`reqId`, `realm`, …).
 *
 * @experimental
 */
export const AUTH_METHOD_LOG_FIELDS_KEY = 'authMethod';

/** What a redacted log value is replaced with. */
const LOG_CENSOR = '[Redacted]';
/** How deep a method's log fields are copied; anything deeper is cut. */
const MAX_LOG_DEPTH = 8;

/**
 * Build the context a method is handed for one realm (ADR-019 Decision 12).
 *
 * The context holds exactly five members: the config, parsed by the method's
 * `configSchema`, copied and deep-frozen (it must be plain data: objects,
 * arrays and primitives, so a Map, Set, Date or other class instance is
 * refused, as none of them freezes); `egress`; `signer`; `log`; and
 * `routeUrl`. Each is an adapter that calls the host's object with the members
 * the contract names and nothing else:
 *
 * - `egress.request` passes `method` (`GET` or `POST`), `url`, `headers`,
 *   `body`, `purpose` and `source`, and adds this realm's name. One cap only,
 *   `maxRedirects: 0` when the method asks for `redirect: 'error'`; no other
 *   cap, no other realm, no other method. `source` is `operator` or `admin` (the
 *   labels the realm's egress allowlist applies to, for non-public
 *   addresses) only when the URL's origin is the origin of a URL among the
 *   plain members of the method's parsed config, never a secret one; any
 *   other call goes as `remote_document`, so a method cannot reach an
 *   allowlisted address its config does not name.
 * - `signer.signClientAssertion` passes `audience`, `claims` and `algorithm`,
 *   with this realm, this provider and the host's caller role. It sets `iat`
 *   when the claims carry none, and lowers `exp` to at most
 *   {@link MAX_AUTH_METHOD_CLIENT_ASSERTION_LIFETIME_SECONDS} from now.
 *   `signer.getUpstreamJwks` takes no argument and asks for this realm and
 *   provider.
 * - `log` calls the logger's four levels with a message and the method's
 *   fields nested under {@link AUTH_METHOD_LOG_FIELDS_KEY}, as a copy in which
 *   every field {@link AUTH_METHOD_LOG_REDACTED_FIELDS} names, or a secret
 *   path's last segment, is redacted at any depth, and every secret value is
 *   cut out of the message and of every string.
 * - `routeUrl` answers URLs only for the paths the method's own `routes`
 *   declare.
 *
 * So the host can hand over its whole egress client, signer and logger, and a
 * method still reaches no `validateDestination`, no `decrypt`, no `child`, no
 * database or cache handle and no key material.
 *
 * @throws AuthMethodConfigError when the config does not pass `configSchema`,
 *   or its parsed form is not plain data; the error names the failing
 *   members, never their values
 * @experimental
 */
export function createAuthMethodContext<TConfig>(
  method: AuthMethod<TConfig>,
  parts: AuthMethodContextParts
): AuthMethodContext<TConfig> {
  const type = method.type;
  const parsed = method.configSchema.safeParse(parts.config);
  if (!parsed.success) {
    throw new AuthMethodConfigError(
      type,
      parsed.error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.code}`)
    );
  }
  const notPlain = notPlainDataPath(parsed.data, [], 0);
  if (notPlain !== undefined) {
    throw new AuthMethodConfigError(type, [
      `${notPlain.join('.') || '(root)'}: not plain data (a Map, Set, Date or class instance does not freeze)`,
    ]);
  }
  let config: TConfig;
  try {
    // A copy, so freezing it leaves the caller's objects alone.
    config = structuredClone(parsed.data);
  } catch {
    throw new AuthMethodConfigError(type, ['(root): the parsed config is not plain data']);
  }

  const origin = new URL(parts.origin);
  if (origin.origin !== parts.origin) {
    throw new TypeError('origin must be a bare origin, such as https://auth.example.com');
  }
  const prefix = authMethodRoutePrefix(type);
  const routePaths = declaredRoutePaths(method.routes);
  const secrets = parts.secrets ?? new Map<string, string>();
  const secretValues = [...secrets.values()].filter((value) => value !== '');
  const configOrigins = urlOrigins(config, new Set(secrets.keys()), new Set(secretValues));
  const redaction: LogRedaction = {
    fields: new Set([
      ...AUTH_METHOD_LOG_REDACTED_FIELDS.map(fieldKey),
      ...[...secrets.keys()].map((path) => fieldKey(path.split('.').at(-1) ?? path)),
    ]),
    // The longest first, so no shorter value cuts a longer one apart.
    values: [...secretValues].sort((a, b) => b.length - a.length),
  };
  const { egress, signer, log, realmName, realmId, providerId, signerCaller } = parts;

  const logged = (fields: unknown): Record<string, unknown> => ({
    [AUTH_METHOD_LOG_FIELDS_KEY]: redactedCopy(fields, 0, new WeakSet(), redaction),
  });
  const message = (text: unknown): string => withoutSecrets(String(text), redaction);

  return Object.freeze({
    config: deepFreeze(config),
    egress: Object.freeze({
      request(request: AuthMethodEgressRequest): Promise<AuthMethodEgressResponse> {
        // Each member read once: what is checked is what is sent.
        const { method: verb, url, headers, body, purpose, source, redirect } = request;
        if (!EGRESS_METHODS.includes(verb)) {
          return Promise.reject(new TypeError('egress method must be GET or POST'));
        }
        if (!EGRESS_SOURCES.includes(source)) {
          return Promise.reject(
            new TypeError('egress source must be operator, admin or remote_document')
          );
        }
        if (!EGRESS_REDIRECTS.includes(redirect)) {
          return Promise.reject(new TypeError('egress redirect must be follow or error'));
        }
        return egress.request({
          method: verb,
          url,
          ...(headers === undefined ? {} : { headers: { ...headers } }),
          ...(body === undefined ? {} : { body }),
          purpose,
          source:
            source === 'remote_document' || configOrigins.has(originOf(url))
              ? source
              : 'remote_document',
          realm: realmName,
          // The one cap a method may set: zero redirects, the floor.
          ...(redirect === 'error' ? { limits: { maxRedirects: 0 as const } } : {}),
        });
      },
    }),
    signer: Object.freeze({
      signClientAssertion(request: AuthMethodClientAssertionRequest): Promise<string> {
        const { audience, claims, algorithm } = request;
        if (algorithm !== undefined && !ASSERTION_ALGORITHMS.includes(algorithm)) {
          return Promise.reject(new TypeError('algorithm must be RS256, ES256 or EdDSA'));
        }
        if (typeof claims !== 'object' || claims === null || Array.isArray(claims)) {
          return Promise.reject(new TypeError('claims must be an object'));
        }
        const now = Math.floor(Date.now() / 1000);
        const bounded: Record<string, unknown> = { ...claims };
        const { iat, exp } = bounded;
        if (iat === undefined) {
          bounded['iat'] = now;
        } else if (
          typeof iat !== 'number' ||
          !Number.isFinite(iat) ||
          iat > now + ASSERTION_IAT_SKEW_SECONDS
        ) {
          return Promise.reject(new TypeError('iat must be a time, in seconds, not in the future'));
        }
        // A missing or non-numeric exp goes on as it is: the signer refuses it.
        const latest = now + MAX_AUTH_METHOD_CLIENT_ASSERTION_LIFETIME_SECONDS;
        if (typeof exp === 'number' && exp > latest) bounded['exp'] = latest;
        return signer.signClientAssertion(signerCaller, {
          realmId,
          providerId,
          audience,
          claims: bounded,
          ...(algorithm === undefined ? {} : { algorithm }),
        });
      },
      async getUpstreamJwks() {
        const jwks = await signer.getUpstreamJwks(signerCaller, realmId, providerId);
        return { keys: jwks.keys as readonly Readonly<Record<string, unknown>>[] };
      },
    }),
    log: Object.freeze({
      debug: (fields: Record<string, unknown>, text: string) =>
        log.debug(logged(fields), message(text)),
      info: (fields: Record<string, unknown>, text: string) =>
        log.info(logged(fields), message(text)),
      warn: (fields: Record<string, unknown>, text: string) =>
        log.warn(logged(fields), message(text)),
      error: (fields: Record<string, unknown>, text: string) =>
        log.error(logged(fields), message(text)),
    }),
    routeUrl(path: string): string {
      if (
        typeof path !== 'string' ||
        !AUTH_METHOD_ROUTE_PATH_PATTERN.test(path) ||
        !routePaths.has(path)
      ) {
        throw new TypeError(
          "routeUrl takes the path of one of the method's own routes, such as /callback"
        );
      }
      return `${origin.origin}${prefix}${path}`;
    },
  });
}

/** The paths of a method's routes, read once by index. */
function declaredRoutePaths(routes: unknown): ReadonlySet<string> {
  const paths = new Set<string>();
  if (!Array.isArray(routes)) return paths;
  const length: unknown = routes.length;
  if (typeof length !== 'number' || !Number.isSafeInteger(length)) return paths;
  for (let index = 0; index < length; index += 1) {
    const route: unknown = routes[index];
    if (typeof route !== 'object' || route === null) continue;
    const path = (route as Record<string, unknown>)['path'];
    if (typeof path === 'string') paths.add(path);
  }
  return paths;
}

/**
 * The origins of every absolute URL among the strings of a (plain) config's
 * plain members: a member at one of `secretPaths`, and a string that is one
 * of `secretValues`, is skipped, so a secret that parses as a URL opens no
 * destination.
 */
function urlOrigins(
  config: unknown,
  secretPaths: ReadonlySet<string>,
  secretValues: ReadonlySet<string>
): ReadonlySet<string> {
  const origins = new Set<string>();
  const walk = (value: unknown, path: string, depth: number): void => {
    if (path !== '' && secretPaths.has(path)) return;
    if (typeof value === 'string') {
      if (secretValues.has(value)) return;
      const found = originOf(value);
      if (found !== '') origins.add(found);
      return;
    }
    if (typeof value !== 'object' || value === null || depth > 32) return;
    // A list's items have no member path; a secret is never inside one.
    const inList = Array.isArray(value);
    for (const [key, item] of Object.entries(value)) {
      walk(item, inList ? `${path}[]` : path === '' ? key : `${path}.${key}`, depth + 1);
    }
  };
  walk(config, '', 0);
  return origins;
}

/** The origin of an absolute http(s) URL, or `''`. */
function originOf(value: unknown): string {
  if (typeof value !== 'string') return '';
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return '';
  }
  return url.protocol === 'https:' || url.protocol === 'http:' ? url.origin : '';
}

/**
 * The path of the first member of `value` that is not plain data (an object
 * with the plain prototype or none, an array, or a primitive), or
 * `undefined` when there is none.
 */
function notPlainDataPath(
  value: unknown,
  path: readonly string[],
  depth: number
): readonly string[] | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  if (depth > 32) return path;
  if (!Array.isArray(value)) {
    const prototype = Object.getPrototypeOf(value) as unknown;
    if (prototype !== Object.prototype && prototype !== null) return path;
  }
  for (const [key, item] of Object.entries(value)) {
    const found = notPlainDataPath(item, [...path, key], depth + 1);
    if (found !== undefined) return found;
  }
  return undefined;
}

/** What a context's logger redacts: field names, by {@link fieldKey}, and secret values. */
interface LogRedaction {
  readonly fields: ReadonlySet<string>;
  readonly values: readonly string[];
}

/** A field name as redaction compares it: lower case, without `_` or `-`. */
function fieldKey(name: string): string {
  return name.toLowerCase().replace(/[_-]/g, '');
}

/** `text` with every occurrence of a secret value replaced by the censor. */
function withoutSecrets(text: string, redaction: LogRedaction): string {
  let result = text;
  for (const value of redaction.values) {
    if (result.includes(value)) result = result.split(value).join(LOG_CENSOR);
  }
  return result;
}

/**
 * A copy of a method's log fields with every field `redaction` names redacted,
 * at any depth, and every secret value cut out of every string. An Error is
 * copied as its name, message, stack, cause and own fields, as the host's
 * error serializer would write it; binary data as its size.
 */
function redactedCopy(
  value: unknown,
  depth: number,
  seen: WeakSet<object>,
  redaction: LogRedaction
): unknown {
  if (typeof value !== 'object' || value === null) {
    if (typeof value === 'string') return withoutSecrets(value, redaction);
    return typeof value === 'function' || typeof value === 'symbol'
      ? withoutSecrets(String(value), redaction)
      : value;
  }
  if (depth >= MAX_LOG_DEPTH) return '[Truncated]';
  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    return `[${value.byteLength} bytes]`;
  }
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) {
    const copy: unknown[] = [];
    const length = value.length;
    for (let index = 0; index < length; index += 1) {
      copy[index] = redactedCopy(value[index] as unknown, depth + 1, seen, redaction);
    }
    return copy;
  }
  // No prototype: a field named `__proto__` stays a field.
  const copy = Object.create(null) as Record<string, unknown>;
  if (value instanceof Error) {
    copy['type'] = redactedCopy(value.name, depth + 1, seen, redaction);
    copy['message'] = redactedCopy(value.message, depth + 1, seen, redaction);
    copy['stack'] = redactedCopy(value.stack, depth + 1, seen, redaction);
    if (value.cause !== undefined) {
      copy['cause'] = redactedCopy(value.cause, depth + 1, seen, redaction);
    }
  }
  for (const [key, item] of Object.entries(value)) {
    copy[key] = redaction.fields.has(fieldKey(key))
      ? LOG_CENSOR
      : redactedCopy(item, depth + 1, seen, redaction);
  }
  return copy;
}

/** Freeze `value` and everything it holds; `seen` stops at cycles. */
function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (typeof value !== 'object' || value === null || seen.has(value)) return value;
  seen.add(value);
  for (const item of Object.values(value)) deepFreeze(item, seen);
  Object.freeze(value);
  return value;
}
