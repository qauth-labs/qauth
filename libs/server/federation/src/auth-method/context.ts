import type {
  AuthMethod,
  AuthMethodContext,
  AuthMethodEgress,
  AuthMethodLogger,
  AuthMethodSigner,
} from './auth-method.interface';
import { AUTH_METHOD_ROUTE_PATH_PATTERN, authMethodRoutePrefix } from './contract';
import { AuthMethodConfigError } from './errors';

/**
 * What a host passes to build a method's context for one realm. The host binds
 * the realm and the caller role into `egress` and `signer` before it passes
 * them (ADR-019 Decisions 8, 9 and 12).
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
  /** An object with the egress client's `request`; nothing else is copied. */
  readonly egress: AuthMethodEgress;
  /** An object with the signer's two calls; nothing else is copied. */
  readonly signer: AuthMethodSigner;
  /** A logger, such as a pino child logger; only its four levels are copied. */
  readonly log: AuthMethodLogger;
}

/**
 * Build the context a method is handed for one realm (ADR-019 Decision 12).
 *
 * The context holds exactly five members: the config, parsed by the method's
 * `configSchema` and frozen; `egress` with `request` only; `signer` with
 * `signClientAssertion` and `getUpstreamJwks` only; `log` with its four
 * levels; and `routeUrl`. Each function is copied bound to the object it came
 * from, so passing the whole egress client, the whole signer or a full logger
 * still hands the method nothing more: no `validateDestination`, no `decrypt`,
 * no `child`, no database or cache handle, no key material.
 *
 * @throws AuthMethodConfigError when the config does not pass `configSchema`;
 *   the error names the failing members, never their values
 * @experimental
 */
export function createAuthMethodContext<TConfig>(
  method: AuthMethod<TConfig>,
  parts: AuthMethodContextParts
): AuthMethodContext<TConfig> {
  const parsed = method.configSchema.safeParse(parts.config);
  if (!parsed.success) {
    throw new AuthMethodConfigError(
      method.type,
      parsed.error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.code}`)
    );
  }

  const origin = new URL(parts.origin);
  if (origin.origin !== parts.origin) {
    throw new TypeError('origin must be a bare origin, such as https://auth.example.com');
  }
  const prefix = authMethodRoutePrefix(method.type);

  const { egress, signer, log } = parts;
  return Object.freeze({
    config: deepFreeze(parsed.data),
    egress: Object.freeze({ request: egress.request.bind(egress) }),
    signer: Object.freeze({
      signClientAssertion: signer.signClientAssertion.bind(signer),
      getUpstreamJwks: signer.getUpstreamJwks.bind(signer),
    }),
    log: Object.freeze({
      debug: log.debug.bind(log),
      info: log.info.bind(log),
      warn: log.warn.bind(log),
      error: log.error.bind(log),
    }),
    routeUrl(path: string): string {
      if (!AUTH_METHOD_ROUTE_PATH_PATTERN.test(path)) {
        throw new TypeError('routeUrl takes a route path, such as /callback');
      }
      return `${origin.origin}${prefix}${path}`;
    },
  });
}

function deepFreeze<T>(value: T): T {
  // A typed array with elements cannot be frozen; config is JSON-like anyway.
  if (
    typeof value === 'object' &&
    value !== null &&
    !Object.isFrozen(value) &&
    !ArrayBuffer.isView(value)
  ) {
    Object.freeze(value);
    for (const item of Object.values(value)) deepFreeze(item);
  }
  return value;
}
