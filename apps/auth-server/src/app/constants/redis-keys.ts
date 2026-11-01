import { createHash } from 'node:crypto';

/**
 * Hash a variable-length, externally-influenced key component into a fixed-size
 * hex digest.
 *
 * Used for the resend-verification and ID-JAG namespaces below, whose
 * components are email addresses, URLs and JWT `jti` values: all can be long
 * and can carry Redis-reserved characters, and an unbounded key is a
 * memory-amplification lever on a path an attacker can reach without an
 * account or with a forged assertion. Same technique `cimd.ts` applies to a CIMD
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
  /**
   * Per-address counter of verification-related mails, shared by
   * `POST /auth/resend-verification` and `POST /auth/register`.
   *
   * Both keys are written for EVERY request of either route, account or not,
   * before any lookup, so the address is {@link digest}ed: a key holding it
   * verbatim was an hour-long Redis entry as long as the caller's address.
   *
   * Keyed per realm (#489): an account is one realm's, so the same address in
   * two realms is two allowances, and mail asked for in one realm never holds
   * back another's. Counters written under the old, realm-less names are no
   * longer read and expire within their window.
   */
  RESEND_RATE_LIMIT: (realmId: string, email: string) =>
    `rate-limit:resend:${realmId}:${digest(email)}`,
  /**
   * Last email sent timestamp for minimum interval check, keyed per realm and
   * digested address, as above (#489)
   */
  LAST_EMAIL_SENT: (realmId: string, email: string) =>
    `last-email-sent:${realmId}:${digest(email)}`,
  /**
   * Sliding-window failed-login attempt counter, keyed per realm and identifier
   * (#115). An account is one realm's, so the same address in two realms is two
   * accounts with two counters, and a source address is counted per realm, as
   * the rate limits are (#487).
   */
  FAILED_LOGIN_ATTEMPTS: (realmId: string, identifier: string) =>
    `failed-login:attempts:${realmId}:${identifier}`,
  /** Active failed-login lockout marker, keyed per realm and identifier (#115, #487) */
  FAILED_LOGIN_LOCKOUT: (realmId: string, identifier: string) =>
    `failed-login:lockout:${realmId}:${identifier}`,
  /**
   * Access-token revocation denylist entry, keyed by the token's `jti`
   * (RFC 7009). Stored with a TTL equal to the token's remaining lifetime so
   * it self-evicts once the token would have expired.
   */
  REVOKED_ACCESS_TOKEN: (jti: string) => `revoked-access-token:${jti}`,
  /**
   * The access tokens issued by redeeming one authorization code (#627): a
   * hash of `jti` to `exp`, so a second redemption of the code can put them on
   * the {@link REDIS_KEYS.REVOKED_ACCESS_TOKEN} denylist (OAuth 2.1 §4.1.3).
   * Expires with the last token in it. The component is the code row's UUID.
   */
  CODE_ACCESS_TOKENS: (authorizationCodeId: string) => `code-access-tokens:${authorizationCodeId}`,
  /**
   * The access tokens issued in one refresh-token family, at the redemption
   * that started it and at every rotation (#627): a hash of `jti` to `exp`, so
   * a replay of the family's code or of one of its refresh tokens can put the
   * live ones on the denylist. Expires with the last token in it. The
   * component is the family's UUID.
   */
  REFRESH_FAMILY_ACCESS_TOKENS: (familyId: string) => `refresh-family-access-tokens:${familyId}`,
  /**
   * Set of the hosted browser session ids (`sid`) of one user, which the
   * previous release's `/auth/logout` reads to end every session the user
   * holds. This release's logout finds them in Postgres (#912) and only drops
   * the set; sign-in still writes it for nodes of the previous release during
   * a rolling upgrade. Expires with the latest-ending session in it. REMOVE IN
   * THE NEXT RELEASE.
   */
  USER_BROWSER_SESSIONS: (userId: string) => `user-browser-sessions:${userId}`,
  /**
   * A browser session's side record (#488): a hash of the per-session values
   * that are not the session and never reach Postgres. The consent screen's
   * CSRF token and the scopes and resources it bound, the consent API's CSRF
   * token, and the identifier the user signed in with. Expires with the
   * session's absolute end; losing it costs the user one more screen, never
   * a session.
   */
  BROWSER_SESSION_SIDE_RECORD: (realmId: string, sid: string) =>
    `browser-session-side:${realmId}:${sid}`,
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
   * lifetime plus twice the clock-skew leeway (once for a future `iat`, once
   * past `exp`), so an entry neither expires before nor outlives the window in
   * which the assertion could be reused.
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
   * `ID_JAG_MAX_ASSERTION_LIFETIME + 2 * ID_JAG_CLOCK_SKEW_LEEWAY` — the
   * longest window in which a still-valid assertion could be replayed — which
   * is what keeps the store from growing without limit.
   */
  ID_JAG_JTI: (issuer: string, jti: string) => `id-jag:jti:${digest(issuer)}:${digest(jti)}`,
  /**
   * Cached OIDC discovery document of an ALLOWLISTED ID-JAG issuer (ADR-011),
   * keyed by the canonical issuer identifier and the realm that fetched it:
   * the deployment egress allowlist may open the discovery URL for one realm
   * and not another (ADR-019 Decision 8), so one realm's document never
   * answers for another. Only the two members key resolution needs (`issuer`,
   * `jwks_uri`) are stored. Best-effort with a bounded TTL
   * (`ID_JAG_JWKS_CACHE_TTL`) — a miss re-fetches through the SSRF-guarded
   * path.
   */
  ID_JAG_DISCOVERY: (issuer: string, realm: string) =>
    `id-jag:discovery:${digest(issuer)}:${digest(realm)}`,
  /**
   * A realm's discovery fetch for an ID-JAG issuer that the egress address
   * check refused (#481): the issuer's discovery URL reaches a non-public
   * address no allowlist entry opens for the realm. Written for a short,
   * fixed time; while it exists the realm's requests fetch nothing, so they
   * stop resolving the name again. Per realm, since another realm's
   * allowlist entry may open the same address.
   */
  ID_JAG_FETCH_REFUSED: (issuer: string, realm: string) =>
    `id-jag:fetch-refused:${digest(issuer)}:${digest(realm)}`,
  /**
   * Cached JWK Set of an ALLOWLISTED ID-JAG issuer, fetched from the `jwks_uri`
   * that issuer's OWN discovery document names — never a URL taken from an
   * assertion. Same bounded TTL as the discovery entry; a `kid` miss forces a
   * refresh rather than waiting the TTL out, at most once per
   * {@link REDIS_KEYS.ID_JAG_KEY_REFRESH} cooldown, so a key rotation is picked
   * up promptly without turning every verification into a network fetch.
   */
  ID_JAG_JWKS: (issuer: string) => `id-jag:jwks:${digest(issuer)}`,
  /**
   * Per-issuer cooldown marker on the refresh a `kid` miss forces (#433).
   *
   * Claimed with `SET NX EX ID_JAG_JWKS_REFRESH_COOLDOWN` before the refresh
   * fetches anything: the request that claims it refreshes, and every other
   * `kid` miss for that issuer until it expires fails closed without a fetch.
   * The refresh runs before any signature check, so this marker — not the
   * token endpoint's rate limit — is what bounds the outbound traffic a client
   * can drive with random `kid` values.
   */
  ID_JAG_KEY_REFRESH: (issuer: string) => `id-jag:key-refresh:${digest(issuer)}`,
  /**
   * Negative cache entry for an ID-JAG issuer whose discovery document or JWK
   * Set could not be obtained (#433): transport error, timeout, non-200, a body
   * that fails validation. Written for `ID_JAG_JWKS_NEGATIVE_CACHE_TTL`; while
   * it exists no fetch is made for the issuer, so an outage costs one attempt
   * per window. Consulted only when a fetch would happen, so a key already in
   * the cache keeps verifying throughout.
   */
  ID_JAG_FETCH_FAILED: (issuer: string) => `id-jag:fetch-failed:${digest(issuer)}`,
  /**
   * A receiver's last verification request (SSF 1.0 §8.1.4.2, #410): set for
   * the stream's `min_verification_interval`, so a request sooner is answered
   * 429. Keyed by the receiver's client row, not the stream, so deleting the
   * stream and creating another does not reset it; a receiver has one stream
   * per realm. Both components are UUIDs.
   */
  SSF_VERIFICATION: (realmId: string, receiverClientId: string) =>
    `ssf:verification:${realmId}:${receiverClientId}`,
  /**
   * One interaction of the Interaction API (#592, ADR-019 Decision 6): the
   * record of one browser ceremony, as JSON. Keyed by the realm and the
   * SHA-256 (hex) of the interaction id: the id itself is never stored, so
   * reading Redis gives no id a browser could present. Expires a short grace
   * (`INTERACTION_SWEEP_GRACE_MS`) after the interaction's deadline, which the
   * server checks on every read, so the expiry sweep still finds the record it
   * audits: ten minutes after creation while nobody has answered it
   * (`INTERACTION_UNANSWERED_TTL_MS`), its absolute expiry from the first
   * processed answer on.
   */
  INTERACTION: (realmId: string, idHash: string) => `interaction:${realmId}:${idHash}`,
  /**
   * The turn of one interaction (#592): the revision of
   * {@link REDIS_KEYS.INTERACTION} that may be answered next, as a decimal
   * string. An answer, a cancel and a user switch take it with `GETDEL`
   * before they act, so of two concurrent requests only one acts; the answer
   * writes the next turn with the next state. Same components and deadline as
   * the record.
   */
  INTERACTION_TURN: (realmId: string, idHash: string) => `interaction-turn:${realmId}:${idHash}`,
  /**
   * Every live interaction, by its deadline (#592): a sorted set whose score
   * is the deadline in epoch milliseconds (the short one of an unanswered
   * interaction, moved to the absolute expiry by the first processed answer)
   * and whose member is
   * `<realmId>:<reference>:<id hash>` ({@link REDIS_KEYS.INTERACTION}'s
   * components and the interaction's audit reference). An interaction leaves
   * it when it finishes or is cancelled; the expiry sweep takes the rest once
   * they expire and audits each. One set for the deployment, so the sweep
   * needs no list of realms.
   */
  INTERACTION_EXPIRY_INDEX: () => 'interaction-expiry',
} as const;
