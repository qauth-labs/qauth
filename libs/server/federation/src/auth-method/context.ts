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
 * to and per-call caps. The context's adapter never passes caps, and sets the
 * realm itself.
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
}

const EGRESS_METHODS: readonly string[] = ['GET', 'POST'];
const EGRESS_SOURCES: readonly string[] = ['operator', 'admin', 'remote_document'];
const ASSERTION_ALGORITHMS: readonly string[] = ['RS256', 'ES256', 'EdDSA'];

/**
 * Build the context a method is handed for one realm (ADR-019 Decision 12).
 *
 * The context holds exactly five members: the config, parsed by the method's
 * `configSchema`, copied and frozen; `egress`; `signer`; `log`; and
 * `routeUrl`. Each is an adapter that calls the host's object with the members
 * the contract names and nothing else:
 *
 * - `egress.request` passes `method` (`GET` or `POST`), `url`, `headers`,
 *   `body`, `purpose` and `source` (`operator`, `admin` or `remote_document`),
 *   and adds this realm's name. No caps, no other realm, no other method.
 * - `signer.signClientAssertion` passes `audience`, `claims` and `algorithm`,
 *   with this realm, this provider and the host's caller role;
 *   `signer.getUpstreamJwks` takes no argument and asks for this realm and
 *   provider.
 * - `log` calls the logger's four levels with a fields object and a message.
 *
 * So the host can hand over its whole egress client, signer and logger, and a
 * method still reaches no `validateDestination`, no `decrypt`, no `child`, no
 * database or cache handle and no key material.
 *
 * @throws AuthMethodConfigError when the config does not pass `configSchema`;
 *   the error names the failing members, never their values
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
  const { egress, signer, log, realmName, realmId, providerId, signerCaller } = parts;

  return Object.freeze({
    config: deepFreeze(config),
    egress: Object.freeze({
      request(request: AuthMethodEgressRequest): Promise<AuthMethodEgressResponse> {
        // Each member read once: what is checked is what is sent.
        const { method: verb, url, headers, body, purpose, source } = request;
        if (!EGRESS_METHODS.includes(verb)) {
          return Promise.reject(new TypeError('egress method must be GET or POST'));
        }
        if (!EGRESS_SOURCES.includes(source)) {
          return Promise.reject(
            new TypeError('egress source must be operator, admin or remote_document')
          );
        }
        return egress.request({
          method: verb,
          url,
          ...(headers === undefined ? {} : { headers: { ...headers } }),
          ...(body === undefined ? {} : { body }),
          purpose,
          source,
          realm: realmName,
        });
      },
    }),
    signer: Object.freeze({
      signClientAssertion(request: AuthMethodClientAssertionRequest): Promise<string> {
        const { audience, claims, algorithm } = request;
        if (algorithm !== undefined && !ASSERTION_ALGORITHMS.includes(algorithm)) {
          return Promise.reject(new TypeError('algorithm must be RS256, ES256 or EdDSA'));
        }
        return signer.signClientAssertion(signerCaller, {
          realmId,
          providerId,
          audience,
          claims,
          ...(algorithm === undefined ? {} : { algorithm }),
        });
      },
      async getUpstreamJwks() {
        const jwks = await signer.getUpstreamJwks(signerCaller, realmId, providerId);
        return { keys: jwks.keys as readonly Readonly<Record<string, unknown>>[] };
      },
    }),
    log: Object.freeze({
      debug: (fields: Record<string, unknown>, message: string) => log.debug(fields, message),
      info: (fields: Record<string, unknown>, message: string) => log.info(fields, message),
      warn: (fields: Record<string, unknown>, message: string) => log.warn(fields, message),
      error: (fields: Record<string, unknown>, message: string) => log.error(fields, message),
    }),
    routeUrl(path: string): string {
      if (typeof path !== 'string' || !AUTH_METHOD_ROUTE_PATH_PATTERN.test(path)) {
        throw new TypeError('routeUrl takes a route path, such as /callback');
      }
      return `${origin.origin}${prefix}${path}`;
    },
  });
}

/** Freeze `value` and everything it holds; `seen` stops at cycles. */
function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (typeof value !== 'object' || value === null || seen.has(value)) return value;
  seen.add(value);
  // A typed array with elements cannot be frozen; config is JSON-like anyway.
  if (ArrayBuffer.isView(value)) return value;
  for (const item of Object.values(value)) deepFreeze(item, seen);
  Object.freeze(value);
  return value;
}
