import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import type { FastifyReply, FastifyRequest } from 'fastify';

import { env } from '../../config/env';

/**
 * Cookie name used to carry the browser session id (issue #150).
 *
 * The `__Host-` prefix binds the cookie to the current origin with strict
 * requirements enforced by browsers:
 *   - `Secure` attribute MUST be set
 *   - `Path=/` MUST be set
 *   - no `Domain` attribute
 * This gives us free CSRF-ish isolation across subdomains and prevents a
 * sibling origin from overwriting the session.
 */
export const SESSION_COOKIE_NAME = '__Host-qauth_session';

/**
 * Payload stored server-side in Redis keyed by session id. We never put the
 * userId in the cookie itself — the cookie only carries the session id +
 * HMAC. Binding the authenticated user to the cookie only via the Redis
 * lookup keeps revocation cheap (delete the key) and avoids leaking the
 * user id if the signing secret is ever compromised.
 */
export interface BrowserSessionData {
  userId: string;
  /**
   * Normalized address of the credential used to authenticate (#230:
   * `credential.externalSub`). Optional — future non-email credentials
   * (wallet, #231) have none; consumers fall back to `userId`. Pre-#230
   * Redis sessions carry the field and remain readable.
   */
  email?: string;
  sessionId: string;
  createdAt: number;
  /** Monotonic nonce for CSRF double-submit cookie (rotated on consent POST). */
  csrfToken?: string;
  /**
   * CSRF token for the cookie-authed JSON API (e.g. `DELETE /consents/:id`).
   * Distinct from {@link csrfToken} (which the consent screen burns after use)
   * so the two flows don't invalidate each other. Long-lived per session —
   * minted lazily by the GET that lists consents, validated via the
   * `X-CSRF-Token` header on state-changing JSON requests. The custom header
   * forces a CORS preflight, so naive cross-site CSRF is blocked even before
   * the token comparison runs.
   */
  apiCsrfToken?: string;
  /**
   * The exact scope set rendered on the most recent consent screen for a given
   * client, keyed by `client_id`. The consent POST handler grants ONLY these
   * scopes — the hidden `scope` form field is attacker-controllable, so the
   * granted set is bound to what the user actually saw, not to what is POSTed.
   */
  consentScopes?: Record<string, string[]>;
  [key: string]: unknown;
}

const SEPARATOR = '.';

function hmac(value: string): string {
  return createHmac('sha256', env.SESSION_COOKIE_SECRET).update(value).digest('base64url');
}

/**
 * Sign the given session id, returning a cookie value of the form
 * `<sessionId>.<hmac>`. Verification is timing-safe.
 */
export function signSessionId(sessionId: string): string {
  return `${sessionId}${SEPARATOR}${hmac(sessionId)}`;
}

/**
 * Verify a signed cookie value and return the session id if the signature
 * is valid, otherwise null. Never throws — callers treat null as "no
 * authenticated session".
 */
export function verifySignedSessionId(cookieValue: string | undefined | null): string | null {
  if (!cookieValue) return null;
  const idx = cookieValue.lastIndexOf(SEPARATOR);
  if (idx <= 0 || idx === cookieValue.length - 1) return null;

  const sessionId = cookieValue.slice(0, idx);
  const providedSig = cookieValue.slice(idx + 1);
  const expectedSig = hmac(sessionId);

  const providedBuf = Buffer.from(providedSig, 'base64url');
  const expectedBuf = Buffer.from(expectedSig, 'base64url');
  if (providedBuf.length !== expectedBuf.length) return null;
  if (!timingSafeEqual(providedBuf, expectedBuf)) return null;
  return sessionId;
}

/**
 * Parse the `Cookie` header and return the raw value of the given cookie
 * name, or undefined. Avoids adding @fastify/cookie just for read access.
 */
export function readCookie(request: FastifyRequest, name: string): string | undefined {
  const header = request.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const k = trimmed.slice(0, eq);
    if (k !== name) continue;
    return decodeURIComponent(trimmed.slice(eq + 1));
  }
  return undefined;
}

/**
 * Resolve whether the session cookie's `Secure` attribute is set.
 *
 * ADR-008 §5 (#197) T3 relaxation seam, CLIENT-SCOPED. Secure cookies are a T3
 * control. The session cookie is GLOBAL — it is minted at `/ui/login`, which
 * carries NO `client_id` (only a `return_to`) — so there is no client whose
 * environment could safely relax it there. We therefore DEFAULT TO STRICT:
 * `env.SESSION_COOKIE_SECURE` (true in production) governs the attribute, and a
 * caller may relax it ONLY by passing an explicit `secureOverride === false`
 * derived from a resolved `development`-profile policy on a surface that
 * unambiguously has a client in scope. No such caller exists today, so the
 * cookie stays strict everywhere — the deliberate fail-safe for a global
 * control. (Local plain-HTTP dev already relaxes it via `SESSION_COOKIE_SECURE`.)
 *
 * @param secureOverride When `false`, force-disable `Secure` (a deliberate
 *   client-scoped development relaxation). When omitted/`true`, the strict
 *   `env.SESSION_COOKIE_SECURE` default applies.
 */
function resolveCookieSecure(secureOverride?: boolean): boolean {
  if (secureOverride === false) return false;
  return env.SESSION_COOKIE_SECURE;
}

/**
 * Emit a Set-Cookie header for the signed session. Attributes match the
 * issue #150 spec: __Host-, Secure (configurable for local dev),
 * HttpOnly, SameSite=Lax, Path=/.
 *
 * @param secureOverride see {@link resolveCookieSecure} — a client-scoped
 *   development relaxation of the `Secure` attribute (defaults to strict).
 */
export function setSessionCookie(
  reply: FastifyReply,
  sessionId: string,
  secureOverride?: boolean
): void {
  const attrs = [
    `${SESSION_COOKIE_NAME}=${signSessionId(sessionId)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${env.SESSION_COOKIE_TTL}`,
  ];
  // __Host- prefix requires Secure. Tests may turn this off for in-process
  // assertions but production must have it set.
  if (resolveCookieSecure(secureOverride)) attrs.push('Secure');
  reply.header('Set-Cookie', attrs.join('; '));
}

/**
 * Clear the session cookie. Used on logout and when a session id fails to
 * resolve to a Redis entry (stale cookie).
 */
export function clearSessionCookie(reply: FastifyReply): void {
  const attrs = [`${SESSION_COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (env.SESSION_COOKIE_SECURE) attrs.push('Secure');
  reply.header('Set-Cookie', attrs.join('; '));
}

/**
 * Generate a CSRF token suitable for the consent form's hidden input. The
 * same value is also stored in the session payload; on POST the server
 * compares the two in a timing-safe way (double-submit cookie pattern).
 */
export function generateCsrfToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Timing-safe comparison of CSRF tokens. Returns false for any
 * length-mismatched or missing input without short-circuiting.
 */
export function csrfTokensEqual(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b) return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Cookie carrying the CSRF token for the PRE-authentication login form.
 *
 * The login page has no session yet, so the consent screen's session-bound
 * double-submit pattern cannot be reused. Instead we use a SIGNED double-submit
 * cookie: this `__Host-`-prefixed cookie holds the HMAC-signed CSRF token, and
 * the form's hidden field holds the same raw token. On POST the server verifies
 * the cookie signature (so an attacker who cannot read the victim's cookie
 * cannot forge a matching pair) and timing-compares the cookie token against
 * the submitted one. This defends against login CSRF (forced login into an
 * attacker-controlled account) without any server-side state.
 */
export const LOGIN_CSRF_COOKIE_NAME = '__Host-qauth_login_csrf';

/**
 * Emit the signed login-CSRF cookie. `Secure` follows the same global default
 * as the session cookie (`env.SESSION_COOKIE_SECURE`); `__Host-` requires it in
 * production. SameSite=Lax + HttpOnly mirror the session cookie. The value is
 * `<token>.<hmac>` using the same secret/scheme as the session id.
 */
export function setLoginCsrfCookie(reply: FastifyReply, token: string): void {
  const attrs = [
    `${LOGIN_CSRF_COOKIE_NAME}=${token}${SEPARATOR}${hmac(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${env.SESSION_COOKIE_TTL}`,
  ];
  if (env.SESSION_COOKIE_SECURE) attrs.push('Secure');
  reply.header('Set-Cookie', attrs.join('; '));
}

/**
 * Clear the login-CSRF cookie (burned after a successful login POST).
 */
export function clearLoginCsrfCookie(reply: FastifyReply): void {
  const attrs = [`${LOGIN_CSRF_COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (env.SESSION_COOKIE_SECURE) attrs.push('Secure');
  reply.header('Set-Cookie', attrs.join('; '));
}

/**
 * Cookie binding a wallet-login flow to the browser that started it (#239).
 *
 * The wallet-login handle in the URL is unguessable, but unguessable is not the
 * same as bound: a handle can be MAILED. Without this cookie an attacker could
 * start a wallet-login flow, present their own credential, and hand the victim
 * the resulting URL — the victim's browser would then finish the flow and be
 * signed in as the ATTACKER. That is login CSRF, the same attack the login-CSRF
 * cookie above defends the password form against, and the same defence applies:
 * the binder is minted into a `__Host-` cookie on the POST that CREATES the flow
 * and compared against the copy stored with the flow record on every read.
 *
 * This is the deliberate opposite of the pending-authorization stash's "NOT
 * bound to the browser" choice (see `helpers/pending-authorization.ts`). That
 * record confers no privilege — resuming it still requires authenticating. This
 * one ENDS in a session cookie, so it must be bound.
 *
 * ## One cookie, several flows
 *
 * The binder is per FLOW, not per browser: the cookie carries a bounded set of
 * `handle → binder` bindings rather than one value. A single value would be
 * overwritten by the next `POST /ui/wallet-login` from the same browser — a
 * second tab, or a re-submit while the first QR was still on screen — and
 * because a MISSING binder and a WRONG one are deliberately indistinguishable
 * from an expiry, the first flow would then report "expired" while its
 * presentation request was still live and its QR still scannable. Scanning it
 * at that point burns the single-use `state` for a flow no surface can read.
 *
 * The bindings share ONE cookie rather than getting a cookie name each, because
 * a per-flow name lets a browser accumulate cookies until it reaches its
 * per-domain cap and starts evicting — possibly the session cookie. The set is
 * capped at {@link WALLET_FLOW_COOKIE_MAX_BINDINGS}, soonest-to-expire dropped
 * first.
 */
export const WALLET_FLOW_COOKIE_NAME = '__Host-qauth_wallet_flow';

/**
 * How many concurrent wallet-login flows one browser may keep bound at once.
 *
 * Three covers what a person actually does (a second tab, an impatient
 * re-submit) and keeps the cookie a few hundred bytes. The cap is what makes
 * this cookie bounded rather than something a scripted caller can grow.
 */
export const WALLET_FLOW_COOKIE_MAX_BINDINGS = 3;

/** One flow's binder, as carried in the wallet-flow cookie. */
export interface WalletFlowBinding {
  /** Handle of the flow this binder belongs to. */
  handle: string;
  /** The CSPRNG binder value, also stored on the flow record. */
  binder: string;
  /** Absolute expiry (epoch ms) of the flow it binds. */
  expiresAt: number;
}

/**
 * Payload separators. Neither can occur in a base64url handle or binder, and
 * both are legal cookie-octets (RFC 6265 §4.1.1).
 */
const WALLET_FLOW_BINDING_SEPARATOR = '|';
const WALLET_FLOW_FIELD_SEPARATOR = ':';

/**
 * Drop expired bindings, then keep the {@link WALLET_FLOW_COOKIE_MAX_BINDINGS}
 * longest-lived. Every flow is minted with the same lifetime, so "longest-lived"
 * is "most recently started" — the eviction order a user expects.
 */
function pruneWalletFlowBindings(bindings: readonly WalletFlowBinding[]): WalletFlowBinding[] {
  const now = Date.now();
  return bindings
    .filter((binding) => binding.expiresAt > now)
    .sort((a, b) => a.expiresAt - b.expiresAt)
    .slice(-WALLET_FLOW_COOKIE_MAX_BINDINGS);
}

/**
 * Emit the signed wallet-flow binder cookie carrying `bindings`, or clear it
 * when none of them are still live. Attributes mirror the login-CSRF cookie;
 * `Max-Age` is the longest remaining flow lifetime rather than the session TTL,
 * so the cookie cannot outlive every flow it binds.
 */
export function setWalletFlowCookie(
  reply: FastifyReply,
  bindings: readonly WalletFlowBinding[]
): void {
  const live = pruneWalletFlowBindings(bindings);
  if (live.length === 0) {
    clearWalletFlowCookie(reply);
    return;
  }
  const payload = live
    .map((binding) =>
      [binding.handle, binding.binder, binding.expiresAt].join(WALLET_FLOW_FIELD_SEPARATOR)
    )
    .join(WALLET_FLOW_BINDING_SEPARATOR);
  // `live` is sorted soonest-first, so the last entry is the latest deadline.
  const maxAgeSeconds = Math.max(
    1,
    Math.ceil((live[live.length - 1].expiresAt - Date.now()) / 1000)
  );
  const attrs = [
    `${WALLET_FLOW_COOKIE_NAME}=${payload}${SEPARATOR}${hmac(payload)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (env.SESSION_COOKIE_SECURE) attrs.push('Secure');
  reply.header('Set-Cookie', attrs.join('; '));
}

/** Clear the wallet-flow binder cookie (burned when the last flow terminates). */
export function clearWalletFlowCookie(reply: FastifyReply): void {
  const attrs = [`${WALLET_FLOW_COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (env.SESSION_COOKIE_SECURE) attrs.push('Secure');
  reply.header('Set-Cookie', attrs.join('; '));
}

/**
 * Verify the signed wallet-flow cookie and return the bindings it carries. Same
 * `<value>.<hmac>` scheme + timing-safe verification as
 * {@link verifyLoginCsrfCookie}, applied to the whole payload — so a binding
 * cannot be added, edited or reordered without the signing secret.
 *
 * An absent, unsigned or tampered cookie yields an EMPTY list rather than a
 * throw: the caller reports "expired" for a handle it holds no binding for,
 * which is the answer every other unbindable state gets.
 */
export function readWalletFlowBindings(
  cookieValue: string | undefined | null
): WalletFlowBinding[] {
  const payload = verifySignedValue(cookieValue);
  if (payload === null) return [];
  const bindings: WalletFlowBinding[] = [];
  for (const entry of payload.split(WALLET_FLOW_BINDING_SEPARATOR)) {
    const [handle, binder, expiresAt] = entry.split(WALLET_FLOW_FIELD_SEPARATOR);
    if (!handle || !binder || !expiresAt) continue;
    const deadline = Number(expiresAt);
    if (!Number.isFinite(deadline)) continue;
    bindings.push({ handle, binder, expiresAt: deadline });
  }
  return pruneWalletFlowBindings(bindings);
}

/**
 * The binder this browser holds for `handle`, or null.
 *
 * The handle lookup is an ordinary comparison on purpose: the handle travels in
 * the URL and is not the secret. The BINDER this returns is the secret, and the
 * caller still compares it with {@link csrfTokensEqual}.
 */
export function findWalletFlowBinder(
  cookieValue: string | undefined | null,
  handle: string
): string | null {
  const match = readWalletFlowBindings(cookieValue).find((binding) => binding.handle === handle);
  return match ? match.binder : null;
}

/**
 * Burn ONE flow's binding, leaving any other flow this browser has in progress
 * bound. Clears the cookie outright when nothing else was in it.
 */
export function dropWalletFlowBinding(
  request: FastifyRequest,
  reply: FastifyReply,
  handle: string
): void {
  setWalletFlowCookie(
    reply,
    readWalletFlowBindings(readCookie(request, WALLET_FLOW_COOKIE_NAME)).filter(
      (binding) => binding.handle !== handle
    )
  );
}

/**
 * Verify the signed login-CSRF cookie value and return the embedded token if
 * the signature is valid, otherwise null. Same `<token>.<hmac>` scheme +
 * timing-safe verification as {@link verifySignedSessionId}.
 */
export function verifyLoginCsrfCookie(cookieValue: string | undefined | null): string | null {
  return verifySignedValue(cookieValue);
}

/**
 * Verify a `<value>.<hmac>` cookie and return the value, or null.
 *
 * The shared implementation behind {@link verifyLoginCsrfCookie} and
 * {@link readWalletFlowBindings}: both are pre-authentication, browser-bound
 * markers signed with the session secret, and neither may ever short-circuit its
 * comparison. Kept private so the two cookies stay separately NAMED — they have
 * different lifetimes and different clearing rules — while sharing one
 * timing-safe verification.
 */
function verifySignedValue(cookieValue: string | undefined | null): string | null {
  if (!cookieValue) return null;
  const idx = cookieValue.lastIndexOf(SEPARATOR);
  if (idx <= 0 || idx === cookieValue.length - 1) return null;

  const token = cookieValue.slice(0, idx);
  const providedSig = cookieValue.slice(idx + 1);
  const expectedSig = hmac(token);

  const providedBuf = Buffer.from(providedSig, 'base64url');
  const expectedBuf = Buffer.from(expectedSig, 'base64url');
  if (providedBuf.length !== expectedBuf.length) return null;
  if (!timingSafeEqual(providedBuf, expectedBuf)) return null;
  return token;
}
