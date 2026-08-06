import { z } from 'zod';

/**
 * The development-only default for {@link SESSION_COOKIE_SECRET}.
 *
 * Exported so downstream apps (e.g. the auth-server) can reference the
 * SAME constant in a production-rejection `superRefine` rather than
 * hand-copying the literal — if this default ever changes, every guard
 * stays in sync automatically. Production deployments MUST set
 * `SESSION_COOKIE_SECRET` to a strong, unique secret; relying on this
 * default in production is insecure and the auth-server's env schema
 * actively rejects it when `NODE_ENV='production'`.
 */
export const DEV_SESSION_COOKIE_SECRET_DEFAULT =
  'dev-only-session-secret-change-me-1234567890abcdef';

/**
 * Authentication environment configuration schema
 * Auth-specific settings
 */
export const authEnvSchema = z.object({
  /**
   * Default realm name for new installations
   */
  DEFAULT_REALM_NAME: z.string().min(1).default('master'),

  /**
   * System OAuth client ID (defaults to "system")
   * Used for direct login operations (not OAuth flow)
   */
  SYSTEM_CLIENT_ID: z.string().optional().default('system'),

  /**
   * Require a verified email before password login succeeds.
   *
   * MVP posture is `false` (unverified-email login is allowed) to match
   * the PRD's "optional for MVP" stance. Operators who need a verified-email
   * guarantee — e.g. so the OIDC `email_verified` claim is always trustworthy —
   * flip this to `true`. The login route then throws `EmailNotVerifiedError`
   * before issuing tokens.
   *
   * This is a DECISION flag, not an auto-fix: do not default to `true`
   * without acknowledging the MVP tradeoff (existing unverified users would
   * be locked out).
   *
   * NB: uses the `z.enum(['true', 'false'])` pattern, NOT `z.coerce.boolean()`
   * — `coerce.boolean` treats ANY non-empty string as `true` (so `"false"` →
   * `true`), which would invert operator intent and silently lock out every
   * unverified user. The enum also rejects malformed values instead of
   * coercing them. Mirrors `SESSION_COOKIE_SECURE` / `SECURITY_HSTS_ENABLED`
   * below.
   */
  REQUIRE_EMAIL_VERIFIED: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),

  /**
   * Maximum registration attempts per window
   */
  REGISTRATION_RATE_LIMIT: z.coerce.number().int().min(1).default(3),

  /**
   * Registration rate limit window in seconds
   * Note: Converted to milliseconds in route handlers (value * 1000)
   */
  REGISTRATION_RATE_WINDOW: z.coerce.number().int().min(1).default(3600),

  /**
   * Maximum email verification attempts per window
   */
  VERIFICATION_RATE_LIMIT: z.coerce.number().int().min(1).default(10),

  /**
   * Email verification rate limit window in seconds (default: 900 = 15 minutes)
   * Note: Converted to milliseconds in route handlers (value * 1000)
   */
  VERIFICATION_RATE_WINDOW: z.coerce.number().int().min(1).default(900),

  /**
   * Maximum resend verification attempts per window (per-IP)
   */
  RESEND_VERIFICATION_RATE_LIMIT: z.coerce.number().int().min(1).default(100),

  /**
   * Resend verification rate limit window in seconds (default: 60 = 1 minute)
   * Note: Converted to milliseconds in route handlers (value * 1000)
   */
  RESEND_VERIFICATION_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum resend verification attempts per email address per window
   * Prevents inbox bombing attacks
   */
  RESEND_VERIFICATION_EMAIL_LIMIT: z.coerce.number().int().min(1).default(3),

  /**
   * Per-email resend verification rate limit window in seconds (default: 3600 = 1 hour)
   */
  RESEND_VERIFICATION_EMAIL_WINDOW: z.coerce.number().int().min(1).default(3600),

  /**
   * Minimum interval between resend requests to same email in seconds (default: 60)
   * Prevents rapid repeated requests
   */
  RESEND_VERIFICATION_MIN_INTERVAL: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum login attempts per window
   */
  LOGIN_RATE_LIMIT: z.coerce.number().int().min(1).default(5),

  /**
   * Login rate limit window in seconds (default: 900 = 15 minutes)
   * Note: Converted to milliseconds in route handlers (value * 1000)
   */
  LOGIN_RATE_WINDOW: z.coerce.number().int().min(1).default(900),

  /**
   * Maximum refresh token attempts per window
   */
  REFRESH_RATE_LIMIT: z.coerce.number().int().min(1).default(10),

  /**
   * Refresh token rate limit window in seconds (default: 60 = 1 minute)
   * Note: Converted to milliseconds in route handlers (value * 1000)
   */
  REFRESH_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum logout attempts per window
   */
  LOGOUT_RATE_LIMIT: z.coerce.number().int().min(1).default(20),

  /**
   * Logout rate limit window in seconds (default: 60 = 1 minute)
   * Note: Converted to milliseconds in route handlers (value * 1000)
   */
  LOGOUT_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum authorize attempts per window. This is the `strict` rate-limit tier
   * cap (ADR-008 §5, issue #197), applied to `production`-profile realms.
   */
  AUTHORIZE_RATE_LIMIT: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum authorize attempts per window for the `lenient` rate-limit tier
   * (ADR-008 §5, issue #197) — `development` / `staging` realms. Defaults
   * higher than the strict cap so local iteration and load testing are not
   * throttled. Selected per-request via `resolveRateLimitMax` only when the
   * realm's effective profile is non-production; an unset realm resolves to
   * `production` and therefore gets the strict cap (fail-safe).
   */
  AUTHORIZE_RATE_LIMIT_LENIENT: z.coerce.number().int().min(1).default(600),

  /**
   * Authorize rate limit window in seconds (default: 60 = 1 minute). Shared by
   * both tiers — environment moves the cap, not the window (ADR-008 §5).
   */
  AUTHORIZE_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum token exchange attempts per window. This is the `strict`
   * rate-limit tier cap (ADR-008 §5, issue #197), applied to `production`.
   */
  TOKEN_RATE_LIMIT: z.coerce.number().int().min(1).default(30),

  /**
   * Maximum token exchange attempts per window for the `lenient` tier
   * (ADR-008 §5, issue #197) — `development` / `staging` realms. See
   * AUTHORIZE_RATE_LIMIT_LENIENT for the selection rationale (fail-safe to
   * the strict cap for an unset/production realm).
   */
  TOKEN_RATE_LIMIT_LENIENT: z.coerce.number().int().min(1).default(300),

  /**
   * Token rate limit window in seconds (default: 60 = 1 minute). Shared by
   * both tiers.
   */
  TOKEN_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum token introspection attempts per window
   */
  INTROSPECT_RATE_LIMIT: z.coerce.number().int().min(1).default(30),

  /**
   * Introspect rate limit window in seconds (default: 60 = 1 minute)
   */
  INTROSPECT_RATE_WINDOW: z.coerce.number().int().min(1).default(60),
  /**
   * Maximum userinfo requests per window
   */
  USERINFO_RATE_LIMIT: z.coerce.number().int().min(1).default(60),
  /**
   * Userinfo rate limit window in seconds (default: 60 = 1 minute)
   */
  USERINFO_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * HMAC secret used to sign the `__Host-qauth_session` cookie (issue #150).
   * Minimum 32 characters. In production this MUST be set explicitly —
   * the default value is test-only and is rejected in NODE_ENV=production
   * by downstream consumers if needed.
   */
  SESSION_COOKIE_SECRET: z
    .string()
    .min(32, 'SESSION_COOKIE_SECRET must be at least 32 characters')
    .default(DEV_SESSION_COOKIE_SECRET_DEFAULT),

  /**
   * Browser session TTL in seconds (default 86400 = 24 hours, per issue #150).
   */
  SESSION_COOKIE_TTL: z.coerce
    .number()
    .int()
    .min(60)
    .default(24 * 60 * 60),

  /**
   * Whether to set the Secure attribute on the session cookie. Defaults true;
   * tests and local dev can set false to use plain HTTP. Production MUST
   * keep this true — the __Host- prefix will reject the cookie otherwise.
   */
  SESSION_COOKIE_SECURE: z
    .enum(['true', 'false'])
    .default('true')
    .transform((v) => v === 'true'),

  /**
   * Whether to emit the `Strict-Transport-Security` (HSTS) response header
   * (issue #113). Defaults true (strict-by-default, mirroring the
   * `SESSION_COOKIE_SECURE` pattern); local dev over plain HTTP can set false
   * so a browser does not pin the dev host to HTTPS for a year. Production
   * MUST keep this true. HSTS is only honoured by browsers over HTTPS, so
   * leaving it on is harmless behind a TLS-terminating reverse proxy.
   */
  SECURITY_HSTS_ENABLED: z
    .enum(['true', 'false'])
    .default('true')
    .transform((v) => v === 'true'),

  /**
   * `max-age` (seconds) for the HSTS header (issue #113). Defaults to one
   * year (31536000), the value required for HSTS preload-list inclusion.
   */
  SECURITY_HSTS_MAX_AGE: z.coerce
    .number()
    .int()
    .min(0)
    .default(365 * 24 * 60 * 60),

  /**
   * Window (in days) after dynamic registration during which the consent
   * screen shows the "Newly registered" phishing-defense badge. Zero
   * disables the badge.
   */
  DYNAMIC_CLIENT_BADGE_DAYS: z.coerce.number().int().min(0).default(30),

  /**
   * Maximum Dynamic Client Registration attempts per window per-IP
   * (RFC 7591). Matches /oauth/token's default (30) as a conservative
   * starting point — registration is higher-impact than a token exchange,
   * so this should never be looser than the token endpoint.
   */
  REGISTER_CLIENT_RATE_LIMIT: z.coerce.number().int().min(1).default(30),
  /**
   * Dynamic Client Registration rate limit window in seconds.
   */
  REGISTER_CLIENT_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum OID4VP `direct_post` response submissions per window per-IP
   * (`POST /oid4vp/response`, OID4VP 1.0 §8.1, issue #233).
   *
   * The endpoint is unauthenticated BY CONSTRUCTION — a wallet holds no client
   * credentials and there is nothing to authenticate it with — so an IP-scoped
   * cap is the only thing bounding how fast an anonymous caller can burn
   * candidate `state` values against it. Matches /oauth/token and
   * /oauth/register (30) rather than the far tighter login caps: a legitimate
   * wallet posts exactly once per presentation request, so the default already
   * sits well above real usage while keeping guessing bounded.
   */
  OID4VP_RESPONSE_RATE_LIMIT: z.coerce.number().int().min(1).default(30),
  /**
   * OID4VP `direct_post` response endpoint rate limit window in seconds.
   */
  OID4VP_RESPONSE_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * Comma-separated scopes allowed by default for dynamically registered
   * clients when a realm's `dynamic_registration_allowed_scopes` column is
   * empty. Used at /oauth/register time to seed the realm on first use.
   *
   * Intentionally tight: only OIDC core scopes. Admin / tenant-scoped
   * grants (e.g. `memory:admin`, `akinon:*`) MUST be added explicitly by
   * an operator and MUST NOT live in this default.
   */
  DEFAULT_DYNAMIC_REGISTRATION_SCOPES: z
    .string()
    .default('openid profile email offline_access')
    .transform((s) =>
      s
        .split(/[\s,]+/)
        .map((x) => x.trim())
        .filter((x) => x.length > 0)
    ),

  // ------------------------------------------------------------------
  // Client ID Metadata Documents (CIMD) — draft-ietf-oauth-client-id-
  // metadata-document-00 / MCP Authorization rev 2025-11-25. When a
  // `client_id` is an HTTPS URL, the AS fetches the metadata document on
  // demand instead of consulting a persisted registration record.
  // ------------------------------------------------------------------

  /**
   * Master switch for CIMD. When false, URL-formatted `client_id`s are
   * treated like any other (unknown) client_id and rejected with
   * `invalid_client`. Defaults to enabled per the MCP-first positioning
   * (ADR-007 §1) — CIMD is the recommended client-registration mechanism.
   */
  CIMD_ENABLED: z
    .enum(['true', 'false'])
    .default('true')
    .transform((v) => v === 'true'),

  /**
   * Domain trust policy applied to a CIMD `client_id` URL host after the
   * SSRF / structural checks pass (CIMD §6 leaves this to deployment
   * policy):
   *   - `accept-any-https` — any https URL whose document validates is
   *     accepted (most permissive; appropriate for open MCP servers).
   *   - `allowlist` — only hosts in `CIMD_TRUSTED_DOMAINS` are accepted.
   *     Any other host → `invalid_client`. Use for locked-down installs.
   */
  CIMD_TRUST_POLICY: z.enum(['accept-any-https', 'allowlist']).default('accept-any-https'),

  /**
   * Comma/space-separated host allowlist consulted when
   * `CIMD_TRUST_POLICY=allowlist`. A leading `*.` permits subdomains
   * (e.g. `*.example.com` matches `app.example.com` but not
   * `example.com`). Empty + allowlist policy means "trust nothing".
   */
  CIMD_TRUSTED_DOMAINS: z
    .string()
    .default('')
    .transform((s) =>
      s
        .split(/[\s,]+/)
        .map((x) => x.trim().toLowerCase())
        .filter((x) => x.length > 0)
    ),

  /**
   * Default TTL (seconds) for a cached CIMD document when the upstream
   * response carries no usable `Cache-Control: max-age` / `Expires`
   * header. Bounds how long a stale document can be served.
   */
  CIMD_CACHE_DEFAULT_TTL: z.coerce
    .number()
    .int()
    .min(0)
    .default(5 * 60),

  /**
   * Hard upper bound (seconds) on any cached CIMD document, regardless of
   * the upstream `max-age`. Prevents a misbehaving client document from
   * pinning a registration in cache indefinitely.
   */
  CIMD_CACHE_MAX_TTL: z.coerce
    .number()
    .int()
    .min(1)
    .default(60 * 60),

  /**
   * Maximum CIMD document size in bytes. Bounds memory + abuse surface
   * (CIMD documents are small JSON blobs).
   */
  CIMD_MAX_DOCUMENT_BYTES: z.coerce
    .number()
    .int()
    .min(256)
    .default(64 * 1024),

  /**
   * Per-fetch timeout (milliseconds) for retrieving a CIMD document.
   */
  CIMD_FETCH_TIMEOUT_MS: z.coerce.number().int().min(100).default(5000),

  /**
   * Allow CIMD fetches to non-public IP ranges (loopback, private,
   * link-local). MUST stay false in production — it disables the core
   * SSRF guard. Exists only so an integration/dev harness can point a
   * CIMD client_id at a localhost fixture server.
   */
  CIMD_ALLOW_PRIVATE_ADDRESSES: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),

  // ------------------------------------------------------------------
  // Identity Assertion Authorization Grant (ID-JAG) — the Enterprise-Managed
  // Agents (EMA) cross-domain grant, ADR-011. QAuth implements BOTH sides:
  //   - CONSUME: `urn:ietf:params:oauth:grant-type:jwt-bearer` at /oauth/token,
  //     validating an ID-JAG minted by a trusted enterprise IdP and issuing an
  //     access token audience-restricted to the assertion's `resource`.
  //   - MINT: RFC 8693 token exchange with
  //     `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`, with
  //     QAuth acting as the enterprise IdP for a third-party MCP server's AS.
  //
  // TRUST MODEL — operator config allowlist, and nothing else. Signing keys are
  // resolved by running OIDC discovery against an issuer that is ALREADY on
  // `ID_JAG_TRUSTED_ISSUERS`, then fetching that document's `jwks_uri`. Never
  // against an unlisted issuer, and never from any URL carried in the assertion
  // itself. Trust is never self-asserted by a client nor derived from assertion
  // content. Default-off + empty allowlist ⇒ the feature is inert until an
  // operator explicitly opts in, matching WALLET_FEDERATION_ENABLED and
  // `max_agent_mode`.
  // ------------------------------------------------------------------

  /**
   * Master switch for ID-JAG (both the consume and the mint side).
   * Defaults to FALSE — this is a cross-domain trust feature and must be an
   * explicit operator decision. When false the jwt-bearer grant is rejected
   * with `unsupported_grant_type` and a token-exchange request asking for an
   * ID-JAG is rejected with `invalid_request`; neither is advertised in
   * discovery metadata.
   */
  ID_JAG_ENABLED: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),

  /**
   * Comma/space-separated allowlist of trusted enterprise IdP **issuer
   * identifiers** (the exact `iss` string, e.g.
   * `https://idp.example.com`). An assertion whose `iss` is not byte-equal to
   * a listed value — after the same trailing-slash-only canonicalisation the
   * AS applies to its own issuer — is rejected without any network call.
   *
   * EMPTY BY DEFAULT, which means EVERY ID-JAG assertion is rejected. This is
   * the fail-closed posture, not an oversight: `ID_JAG_ENABLED=true` with an
   * empty allowlist still accepts nothing. Wildcards are deliberately NOT
   * supported — an issuer identifier is an exact-match trust anchor.
   */
  ID_JAG_TRUSTED_ISSUERS: z
    .string()
    .default('')
    .transform((s) =>
      s
        .split(/[\s,]+/)
        .map((x) => x.trim())
        .filter((x) => x.length > 0)
    ),

  /**
   * Per-fetch timeout (milliseconds) applied to BOTH outbound requests in the
   * key-resolution chain: the trusted issuer's OIDC discovery document and the
   * `jwks_uri` it names.
   */
  ID_JAG_FETCH_TIMEOUT_MS: z.coerce.number().int().min(100).default(5000),

  /**
   * TTL (seconds) for a cached trusted-issuer OIDC discovery document and its
   * JWK Set. Bounds how long a rotated-away key stays usable; a verification
   * failure on an unknown `kid` SHOULD force one bounded refresh rather than
   * waiting out the TTL. Default 5 minutes.
   */
  ID_JAG_JWKS_CACHE_TTL: z.coerce
    .number()
    .int()
    .min(0)
    .default(5 * 60),

  /**
   * Maximum size in bytes accepted for a fetched OIDC discovery document or
   * JWK Set. Bounds memory + abuse surface; both are small JSON blobs.
   */
  ID_JAG_MAX_DOCUMENT_BYTES: z.coerce
    .number()
    .int()
    .min(256)
    .default(64 * 1024),

  /**
   * Allow ID-JAG discovery / JWKS fetches to non-public IP ranges (loopback,
   * private, link-local). MUST stay false in production — it disables the core
   * SSRF guard. Exists only so an integration/dev harness can point a trusted
   * issuer at a localhost fixture server.
   */
  ID_JAG_ALLOW_PRIVATE_ADDRESSES: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),

  /**
   * Clock-skew leeway (seconds) applied when validating an inbound assertion's
   * `exp` / `nbf` / `iat`. Bounded hard at 300s: a larger window is a replay
   * window, and the assertion is a bearer credential for a cross-domain grant.
   * Default 60s.
   */
  ID_JAG_CLOCK_SKEW_LEEWAY: z.coerce.number().int().min(0).max(300).default(60),

  /**
   * Maximum accepted lifetime (seconds) of an INBOUND assertion, measured
   * `exp - iat`. An assertion whose window is longer is rejected outright.
   * This is what makes `jti` replay prevention bounded and affordable: the
   * replay cache only needs to retain a `jti` for this long (plus the skew
   * leeway), so it cannot grow without limit. Default 5 minutes, hard cap 1
   * hour.
   */
  ID_JAG_MAX_ASSERTION_LIFETIME: z.coerce
    .number()
    .int()
    .min(1)
    .max(60 * 60)
    .default(5 * 60),

  /**
   * Lifetime (seconds) of an ID-JAG that QAuth MINTS via token exchange. Kept
   * short — an ID-JAG is a single-use hand-off credential presented once to
   * the target resource's AS, not a session token. Default 5 minutes.
   */
  ID_JAG_ISSUED_LIFETIME: z.coerce
    .number()
    .int()
    .min(1)
    .max(60 * 60)
    .default(5 * 60),
});

/**
 * Auth environment configuration type
 */
export type AuthEnv = z.infer<typeof authEnvSchema>;
