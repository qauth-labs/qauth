import { clientAddressKey, type ClientAddressSource } from './client-address';
import {
  ENVIRONMENT_PROFILES,
  parseEnvironment,
  type RateLimitTierConfig,
  resolveRateLimitMax,
} from './environment-policy';

/** The parts of a Fastify request {@link realmRateLimitKey} reads. */
export interface RealmRateLimitSource extends ClientAddressSource {
  /** The resolved realm (`request.realm`); `null` on a `none` route. */
  readonly realm?: { readonly id: string } | null;
}

/**
 * The bucket key of every rate limit of the app (issue #487): the id of the
 * realm the request resolved to, then the client address key
 * (`clientAddressKey`, an IPv6 client by its /64).
 *
 * With the realm in the key, one address has a bucket per realm. Two realms
 * are separate tenants on their own hosts, each with its own cap (see
 * {@link resolveRealmRateLimitMax}): one realm's traffic from a shared address
 * (a NAT, a proxy, a CI runner) must not use up another realm's limit. A
 * request with no realm, which only a `none` route such as `/health` serves,
 * keys by its address alone.
 *
 * Typed structurally so it can be passed straight to `keyGenerator`.
 */
export function realmRateLimitKey(request: RealmRateLimitSource): string {
  const address = clientAddressKey(request);
  return request.realm ? `${request.realm.id}:${address}` : address;
}

/**
 * Resolve the per-window request cap for a rate-limited route from its realm's
 * environment ceiling (ADR-008 §5, issue #209), for `max` of
 * `@fastify/rate-limit`: `max: (request) => resolveRealmRateLimitMax(request.realm, …)`.
 *
 * `@fastify/rate-limit` evaluates `max` BEFORE the route handler runs, so
 * before the specific client is authenticated, and a per-client policy is not
 * available here. The honest seam is the realm: a `production` realm forces
 * the strict cap regardless of any client, while a `development` / `staging`
 * realm ceiling permits the lenient cap (e.g. for load testing).
 *
 * The realm is the request's (`request.realm`, #487), whose row the realm
 * resolver read at most its cache time ago (30 seconds by default), so an
 * operator's ceiling change applies within that time and no request reads the
 * database for it.
 *
 * Fail-safe: no realm, or a ceiling that is unset or not an environment, gives
 * the strict cap, so a misconfiguration never relaxes the limit.
 */
export function resolveRealmRateLimitMax(
  realm: { readonly maxEnvironmentLaxity?: string | null } | null | undefined,
  config: RateLimitTierConfig
): number {
  if (!realm) return config.strictMax;
  const environment = parseEnvironment(realm.maxEnvironmentLaxity);
  return resolveRateLimitMax(ENVIRONMENT_PROFILES[environment].rateLimitTier, config);
}

/**
 * The bucket key of the admin listener's per-address ceiling (#511): the
 * client address key alone, as the listener has no host and so no realm
 * before the token guard runs. The ceiling counts every call to the
 * listener, a call without a token included.
 */
export function adminAddressRateLimitKey(request: ClientAddressSource): string {
  return `admin:address:${clientAddressKey(request)}`;
}

/** The parts of a Fastify request {@link adminSubjectRateLimitKey} reads. */
export interface AdminSubjectRateLimitSource {
  /** The claims of the token the admin token guard verified. */
  readonly jwtPayload?: { readonly iss?: string; readonly sub?: string };
}

/**
 * The bucket key of the admin listener's per-subject ceiling (#511): the
 * issuer and subject of the token the guard verified, so one account has one
 * bucket whatever address it calls from.
 *
 * @throws {Error} before the token guard, which sets the claims
 */
export function adminSubjectRateLimitKey(request: AdminSubjectRateLimitSource): string {
  const issuer = request.jwtPayload?.iss;
  const subject = request.jwtPayload?.sub;
  if (issuer === undefined || subject === undefined) {
    throw new Error('The per-subject ceiling runs after the admin token guard');
  }
  return `admin:subject:${issuer}:${subject}`;
}
