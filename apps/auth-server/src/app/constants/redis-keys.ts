import { createHash } from 'node:crypto';

/**
 * Hash a variable-length, externally-influenced key component into a fixed-size
 * hex digest.
 *
 * Used for the ID-JAG namespaces below, whose components are URLs and JWT `jti`
 * values: both can be long and can carry Redis-reserved characters, and an
 * unbounded key is a memory-amplification lever on a path an attacker can reach
 * with a forged assertion. Same technique `cimd.ts` applies to a CIMD
 * `client_id`. Not a security control — the digest is not a secret — purely a
 * key-shape bound.
 */
function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * Redis key generators for rate limiting and caching
 */
export const REDIS_KEYS = {
  /** Rate limit counter for resend verification requests per email */
  RESEND_RATE_LIMIT: (email: string) => `rate-limit:resend:${email}`,
  /** Last email sent timestamp for minimum interval check */
  LAST_EMAIL_SENT: (email: string) => `last-email-sent:${email}`,
  /** Sliding-window failed-login attempt counter, keyed per identifier (#115) */
  FAILED_LOGIN_ATTEMPTS: (identifier: string) => `failed-login:attempts:${identifier}`,
  /** Active failed-login lockout marker, keyed per identifier (#115) */
  FAILED_LOGIN_LOCKOUT: (identifier: string) => `failed-login:lockout:${identifier}`,
  /**
   * Access-token revocation denylist entry, keyed by the token's `jti`
   * (RFC 7009). Stored with a TTL equal to the token's remaining lifetime so
   * it self-evicts once the token would have expired.
   */
  REVOKED_ACCESS_TOKEN: (jti: string) => `revoked-access-token:${jti}`,
  /**
   * Detached ML-DSA-65 signature of a hybrid access token, keyed by the
   * token's `jti` (ADR-005 / #275, `PQC_TOKEN_DELIVERY='reference'`). The ~4.4
   * KB PQC component cannot ride in the bearer token, so it is parked here and
   * delivered via RFC 7662 introspection. Stored with the token's remaining
   * lifetime as TTL so it never outlives the credential it describes.
   */
  PQC_SIGNATURE: (jti: string) => `pqc-signature:${jti}`,
  /**
   * Single-use marker for an RFC 7523 §2.2 `private_key_jwt` client assertion
   * (#384), keyed by the presenting client and the assertion's `jti`.
   *
   * REPLAY PROTECTION, not a cache: the key is written with `SET NX` AFTER the
   * signature verifies, and a write that finds the key already present rejects
   * the request. Scoped by `clientId` so one client can never burn another
   * client's `jti` space.
   *
   * Both components are {@link digest}ed, so the key is fixed-length and free
   * of Redis-reserved characters regardless of what the (attacker-controlled)
   * `jti` contains. TTL is bounded by the assertion's own maximum permitted
   * lifetime plus the clock-skew leeway, so an entry never outlives the window
   * in which the assertion could be reused.
   */
  CLIENT_ASSERTION_JTI: (clientId: string, jti: string) =>
    `client-assertion:jti:${digest(clientId)}:${digest(jti)}`,
  /**
   * Cached JWK Set fetched from a client's registered `jwks_uri` (RFC 7591 §2),
   * keyed by the digest of the URL. Best-effort cache with a bounded TTL — a
   * miss simply re-fetches through the SSRF-guarded path.
   */
  CLIENT_JWKS: (jwksUri: string) => `client-jwks:${digest(jwksUri)}`,
  /**
   * Single-use marker for an inbound ID-JAG assertion (ADR-011 consume side),
   * keyed by the ASSERTING ISSUER and the assertion's `jti`.
   *
   * REPLAY PROTECTION, not a cache. Written with `SET NX` only AFTER the
   * signature, issuer, audience and temporal claims have all verified, so an
   * unauthenticated flood cannot fill the store. A write that finds the key
   * already present means the assertion was already redeemed and the request is
   * rejected — an ID-JAG is a single-use hand-off credential.
   *
   * Scoped by issuer so two trusted IdPs can never collide in `jti` space (and
   * so one can never burn the other's). TTL is bounded by
   * `ID_JAG_MAX_ASSERTION_LIFETIME + ID_JAG_CLOCK_SKEW_LEEWAY` — the longest
   * window in which a still-valid assertion could be replayed — which is what
   * keeps the store from growing without limit.
   */
  ID_JAG_JTI: (issuer: string, jti: string) => `id-jag:jti:${digest(issuer)}:${digest(jti)}`,
  /**
   * Cached OIDC discovery document of an ALLOWLISTED ID-JAG issuer (ADR-011),
   * keyed by the canonical issuer identifier. Only the two members key
   * resolution needs (`issuer`, `jwks_uri`) are stored. Best-effort with a
   * bounded TTL (`ID_JAG_JWKS_CACHE_TTL`) — a miss re-fetches through the
   * SSRF-guarded path.
   */
  ID_JAG_DISCOVERY: (issuer: string) => `id-jag:discovery:${digest(issuer)}`,
  /**
   * Cached JWK Set of an ALLOWLISTED ID-JAG issuer, fetched from the `jwks_uri`
   * that issuer's OWN discovery document names — never a URL taken from an
   * assertion. Same bounded TTL as the discovery entry; a `kid` miss forces ONE
   * bounded refresh rather than waiting the TTL out, so a key rotation is picked
   * up promptly without turning every verification into a network fetch.
   */
  ID_JAG_JWKS: (issuer: string) => `id-jag:jwks:${digest(issuer)}`,
} as const;
