/**
 * Security-related constants
 */

/** Authorization code TTL in milliseconds (5 minutes, OAuth 2.1) */
export const AUTHORIZATION_CODE_TTL_MS = 5 * 60 * 1000;

/**
 * Step-up authentication freshness window in milliseconds (ADR-007 §2, #185).
 *
 * When a request triggers a fresh-authentication step-up (`prompt=login` or a
 * dangerous scope), an authentication performed within this window is accepted
 * as "fresh". This both (a) prevents an infinite login→authorize→login redirect
 * loop after the user re-authenticates, and (b) bounds how long a single
 * re-authentication stays valid for issuing a dangerous/elevated grant.
 *
 * Tradeoff: a dangerous scope is satisfied by ANY authentication within this
 * window — including an unrelated login that happened ~110s earlier — so the
 * window is a deliberate usability relaxation of the dangerous-op gate, not a
 * guarantee of an immediate prompt. A relying party (e.g. `mcp-guard`) that
 * needs *exact* immediacy must send `max_age` (e.g. `max_age=0`), which is
 * enforced against its own value at OIDC second-granularity and is NOT widened
 * by this window. Two minutes balances usability against the "authenticate
 * shortly before the dangerous operation" intent.
 */
export const STEP_UP_FRESH_AUTH_WINDOW_MS = 2 * 60 * 1000;

/**
 * Minimum response time in milliseconds to prevent timing attacks
 * Used in authentication endpoints to prevent user enumeration
 */
export const MIN_RESPONSE_TIME_MS = {
  /** Login endpoint minimum response time (500ms) */
  LOGIN: 500,
  /** Resend verification endpoint minimum response time (200ms) */
  RESEND_VERIFICATION: 200,
  /** Refresh endpoint minimum response time (300ms) */
  REFRESH: 300,
  /** Token endpoint minimum response time (300ms) */
  TOKEN: 300,
  /** Introspect endpoint minimum response time (300ms) */
  INTROSPECT: 300,
  /** Userinfo endpoint minimum response time (300ms) */
  USERINFO: 300,
  /**
   * API-key authentication minimum response time (300ms, ADR-008 §6 / #97).
   * Pads the verify path so a present-but-wrong key, a revoked key, an unknown
   * prefix, and a now-forbidden client are indistinguishable by timing.
   */
  API_KEY_AUTH: 300,
} as const;

/**
 * Maximum length of the opaque, client-owned OAuth/OIDC params `state` and
 * `nonce`.
 *
 * RFC 6749 §4.1.1 and OIDC Core place NO length limit on these — they are
 * opaque and round-tripped to the client verbatim, and real clients pack
 * context into them. Cursor's MCP client base64url-encodes ~275 chars of
 * workspace context into `state`, and it varies at runtime (short from an
 * empty window, longer from a real project), so an over-tight cap fails
 * intermittently. Bound at 2048 — the same ceiling as the `resource` URI — as
 * a DoS guard, not a spec limit.
 *
 * This MUST be the single source for the bound: `state`/`nonce` appear both in
 * the `/oauth/authorize` query schema and in the `/ui/consent` form mirror,
 * and the two silently drifted once (query raised, body missed), which broke
 * the flow one step later. Reference this constant from every such schema.
 * See qauth-labs/qauth#316.
 */
export const OAUTH_OPAQUE_PARAM_MAX_LENGTH = 2048;

/**
 * Maximum length of the `scope` request parameter.
 *
 * RFC 6749 §3.3 places no limit on `scope` either, and the value is
 * round-tripped through the login/consent flow exactly like `state` and
 * `nonce`. It was the one such parameter left unbounded, which mattered once
 * the login bounce started parking the authorize URL server-side (#316
 * follow-up): `POST /oauth/authorize` accepts a body, so an unbounded `scope`
 * was an unauthenticated, pre-login write of arbitrary size into the Redis that
 * also holds live browser sessions. 2048 matches the ceiling this codebase
 * already applies to `scope` on the other OAuth schemas (token exchange, CIMD
 * client metadata) and is far above any real scope set.
 */
export const OAUTH_SCOPE_PARAM_MAX_LENGTH = 2048;

/**
 * Lifetime of a pending-authorization stash — the server-side record that lets
 * `/ui/login` carry a SHORT opaque handle instead of the whole authorize query
 * string. See `helpers/pending-authorization.ts` and qauth-labs/qauth#316.
 *
 * Longer than {@link AUTHORIZATION_CODE_TTL_MS} (5 min) because this window has
 * to cover an INTERACTIVE step — reading the login page, unlocking a password
 * manager, completing the form — whereas an authorization code is redeemed by a
 * machine within milliseconds. Ten minutes is the same order as the code TTL
 * (not the session TTL): the stash is auth-flow state, not user state, so it
 * must not linger. Expiry degrades to the "sign-in request expired" page at
 * `/ui/resume`, never to a silent redirect.
 */
export const PENDING_AUTHORIZATION_TTL_MS = 10 * 60 * 1000;

/**
 * Hard ceiling on the authorize URL a pending-authorization stash will hold.
 *
 * The stash is written BEFORE the end user authenticates, into the same Redis
 * that holds `session:` browser sessions and `rate:` counters, and it lives for
 * {@link PENDING_AUTHORIZATION_TTL_MS}. It must therefore never be an unbounded
 * write primitive for an unauthenticated caller. The per-parameter `max()`
 * bounds in `schemas/oauth.ts` are the primary control; this is the backstop
 * that survives one of them being dropped or a new parameter landing without
 * one.
 *
 * 16 KiB is well above any realistic request — the largest plausible one is a
 * 2048-char `state` plus a 2048-char `nonce` plus a handful of RFC 8707
 * `resource` URIs, ~8 KiB once percent-encoded — and a request larger than this
 * could not have arrived as a GET through a standard reverse proxy anyway
 * (nginx's default 8 KB request-line/header buffer), so rejecting it with a
 * crisp 400 is more honest than either a 500 or a `Location` header no proxy
 * will forward.
 *
 * Known tradeoff: a request at the ABSOLUTE schema maximum — ten `resource`
 * URIs of 2048 characters each, ~60 KiB percent-encoded — exceeds this and gets
 * a 400 on the unauthenticated login bounce (only there; an authenticated
 * request never touches the stash). No real client is shaped that way (resource
 * indicators are short service URLs; the 2048 is a bound, not a description),
 * and such a request is unserviceable through a browser login round-trip in any
 * case. Raise this constant rather than removing the check if that ever stops
 * being true.
 */
export const PENDING_AUTHORIZATION_MAX_URL_BYTES = 16 * 1024;

/**
 * Per-route body limit for `POST /oauth/authorize` (OIDC Core §3.1.2.1).
 *
 * The endpoint is unauthenticated and its body is a handful of short,
 * individually bounded form fields. Fastify's 1 MB default is simply the wrong
 * order of magnitude for it: it lets an unauthenticated caller push a megabyte
 * through body parsing and Zod on every request. 128 KiB is above the
 * theoretical schema maximum (~60 KiB, dominated by the RFC 8707 `resource`
 * array) so no valid request is refused, and an order of magnitude below the
 * default.
 */
export const AUTHORIZE_BODY_LIMIT_BYTES = 128 * 1024;

/**
 * Lifetime of a wallet-login flow record — the server-side state tying one
 * browser to one in-flight OID4VP presentation request (#239).
 *
 * Deliberately DERIVED from nothing: it is set to the same five minutes as
 * `DEFAULT_OID4VP_REQUEST_TTL_MS` in `@qauth-labs/server-federation`, plus a
 * grace window so the browser can still be told "this expired" instead of
 * "this never existed" for a short while after the presentation request itself
 * is dead. The authoritative expiry is the one stored on the flow record and
 * enforced on every read; this TTL only bounds how long the record survives in
 * Redis if nothing ever polls it again.
 */
export const WALLET_LOGIN_FLOW_TTL_MS = 6 * 60 * 1000;

/**
 * How often the wallet-login page asks the server whether the presentation has
 * arrived (#239).
 *
 * A wallet round-trip is a human action — unlock the phone, open the wallet,
 * approve the disclosure — so sub-second polling buys nothing and costs a
 * request per client per second. Three seconds keeps the perceived latency
 * under a wallet's own animation while capping a five-minute wait at ~100
 * requests, which is what {@link WALLET_LOGIN_STATUS_RATE_LIMIT} is sized for.
 */
export const WALLET_LOGIN_POLL_INTERVAL_MS = 3000;

/**
 * Per-IP cap on wallet-login status polls, over
 * {@link WALLET_LOGIN_STATUS_RATE_WINDOW_S}.
 *
 * The global default (`RATE_LIMIT_MAX`, 100/hour) is the wrong shape for a
 * polling endpoint: one legitimate five-minute wait would exhaust it and the
 * user would watch their own sign-in fail. This is the correction, not a
 * relaxation — it is still a hard cap, sized at roughly two concurrent flows
 * from one IP (each ~100 polls at {@link WALLET_LOGIN_POLL_INTERVAL_MS}), and
 * the endpoint it protects performs no credential work and reveals nothing
 * without an unguessable handle AND the matching browser-binder cookie.
 */
export const WALLET_LOGIN_STATUS_RATE_LIMIT = 200;

/** Window for {@link WALLET_LOGIN_STATUS_RATE_LIMIT}, in seconds. */
export const WALLET_LOGIN_STATUS_RATE_WINDOW_S = 300;

/**
 * Maximum length of the account identifier a user asserts on the wallet-login
 * form (ADR-009 §1).
 *
 * The value is written into an `external_sub` lookup, so it is bounded for the
 * same reason every other pre-authentication input in this codebase is: it
 * arrives from an unauthenticated caller and reaches Redis and the database.
 * 320 characters is the maximum length of an email address (RFC 3696 §3), which
 * is the identifier shape `PasswordProvider` already stores in that column.
 */
export const ASSERTED_IDENTIFIER_MAX_LENGTH = 320;
