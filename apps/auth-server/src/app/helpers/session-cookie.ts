import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import type { FastifyReply, FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import { type CookieKey, type CookieKeyHolder, cookieKeyRing } from './cookie-keys';
import { requestRealm } from './request-realm';

/**
 * The auth server's signed cookies (ADR-019 Decision 3 and Decision 9, issue
 * #493): the session cookie, the login-CSRF cookie and the wallet-flow cookie.
 *
 * ## Format
 *
 * Every signed cookie value is `<kid>.<payload>.<mac>`:
 *
 * - `kid` names the realm cookie key that signed it, so a rotation (#542)
 *   leaves the cookies the previous key signed verifiable for its retention;
 * - `payload` is the cookie's own content, which never holds a `.`;
 * - `mac` is the base64url HMAC-SHA256, under that key, of
 *   {@link COOKIE_MAC_LABEL}, the cookie's name, the realm id, the `kid` and
 *   the payload, NUL-separated.
 *
 * The keys are the realm's `cookie_hmac` keys, which the signer hands this
 * role (`getCookieSecrets`; see `cookie-keys.ts`). A new cookie is signed with
 * the realm's current key; one presented is verified with the key its `kid`
 * names, the current or the previous one, and the MAC is compared in constant
 * time. The cookie's name in the MAC keeps one cookie from passing for
 * another, and the realm id keeps a value from moving to another realm even
 * if two realms shared a key by mistake: each realm's host already holds its
 * own `__Host-` cookies, so this is the second wall.
 *
 * Every cookie here carries `Path=/`, `HttpOnly`, `SameSite=Lax`, no
 * `Domain` and, unless `SESSION_COOKIE_SECURE` is off for a plain-HTTP
 * development stack, `Secure`; the `__Host-` prefix makes a browser insist on
 * all but the first two.
 */

/**
 * Separates the parts of the MAC input. None of them can hold it: the realm id
 * is a UUID, a `kid` is matched against the realm's own keys, and a payload
 * comes from a cookie value.
 */
const MAC_SEPARATOR = '\u0000';

/** The format of the MAC input, first in it, so another use of the key cannot collide. */
export const COOKIE_MAC_LABEL = 'qauth-cookie/1-rc.0';

/** The characters of a `kid` the format carries: base64url, which every generated and imported cookie key uses. */
const KID_PATTERN = /^[A-Za-z0-9_-]{1,255}$/;

/** A base64url HMAC-SHA256: 32 bytes, 43 characters without padding. */
const MAC_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const SEPARATOR = '.';

function mac(key: CookieKey, cookieName: string, realmId: string, payload: string): Buffer {
  return createHmac('sha256', key.key)
    .update([COOKIE_MAC_LABEL, cookieName, realmId, key.kid, payload].join(MAC_SEPARATOR))
    .digest();
}

/**
 * Sign `payload` for the cookie `cookieName` of the realm, with the realm's
 * current cookie key.
 *
 * @throws the signer's error when the realm's cookie keys cannot be read
 * @throws Error when the payload holds a `.`, or the current key's `kid` is
 *   one the format cannot carry
 */
async function signCookieValue(
  fastify: CookieKeyHolder,
  cookieName: string,
  realmId: string,
  payload: string
): Promise<string> {
  if (payload.includes(SEPARATOR)) {
    throw new Error(`A ${cookieName} payload never holds "${SEPARATOR}"`);
  }
  const { current } = await cookieKeyRing(fastify).keys(realmId);
  if (!KID_PATTERN.test(current.kid)) {
    throw new Error("The realm's cookie key has a kid the cookie format cannot carry");
  }
  const signature = mac(current, cookieName, realmId, payload).toString('base64url');
  return [current.kid, payload, signature].join(SEPARATOR);
}

/**
 * Verify a `<kid>.<payload>.<mac>` value of the cookie `cookieName` for the
 * realm and return its payload, or `null`: absent, malformed, signed by a key
 * the realm does not hold (or no longer holds), signed for another realm or
 * another cookie, or tampered with. The MAC is compared in constant time.
 *
 * @throws the signer's error when the realm's cookie keys cannot be read: an
 *   unreachable signer is not an invalid cookie
 */
async function verifyCookieValue(
  fastify: CookieKeyHolder,
  cookieName: string,
  realmId: string,
  cookieValue: string | undefined | null
): Promise<string | null> {
  if (!cookieValue) return null;
  const parts = cookieValue.split(SEPARATOR);
  if (parts.length !== 3) return null;
  const [kid, payload, provided] = parts;
  if (!KID_PATTERN.test(kid) || payload.length === 0 || !MAC_PATTERN.test(provided)) return null;

  const key = await cookieKeyRing(fastify).find(realmId, kid);
  if (key === null) return null;
  const expected = mac(key, cookieName, realmId, payload);
  const presented = Buffer.from(provided, 'base64url');
  // The last of 43 characters carries two unused bits: only the canonical
  // spelling of a MAC is accepted, so a signed value has one form. This says
  // nothing about the key; the bytes are compared in constant time below.
  if (presented.toString('base64url') !== provided) return null;
  // Both are 32 bytes here: the pattern above fixes the presented length.
  if (presented.length !== expected.length) return null;
  return timingSafeEqual(presented, expected) ? payload : null;
}

/**
 * Cookie name used to carry the browser session (issue #150).
 *
 * The `__Host-` prefix binds the cookie to the current origin with strict
 * requirements enforced by browsers:
 *   - `Secure` attribute MUST be set
 *   - `Path=/` MUST be set
 *   - no `Domain` attribute
 * This gives us free CSRF-ish isolation across subdomains and prevents a
 * sibling origin from overwriting the session.
 *
 * The cookie carries only session ids, never the user id: the session itself
 * is the session service's (#488), looked up by `sid` in the request's realm,
 * so revoking it there ends the cookie too.
 */
export const SESSION_COOKIE_NAME = '__Host-qauth_session';

/**
 * The most sessions one session cookie may list. ADR-019 Decision 3 lets one
 * browser hold sessions of several accounts of a realm; the cookie lists them,
 * and this bounds what a value can hold.
 */
export const SESSION_COOKIE_MAX_SESSIONS = 8;

/** The longest session id a session cookie carries. */
const MAX_SESSION_ID_LENGTH = 128;

/** What a session cookie says: the sessions this browser holds in the realm, and the active one. */
export interface SessionCookieContents {
  /** Every session id the cookie lists, the active one among them. */
  readonly sessionIds: readonly string[];
  /** The session the browser acts as. */
  readonly activeSessionId: string;
}

/** The session a session cookie is set for: what the cookie names, and when it ends. */
export interface SessionCookieSession {
  readonly sid: string;
  /** The realm the session belongs to, which the cookie's MAC is bound to. */
  readonly realmId: string;
  /** The session's absolute end, in epoch ms: the cookie's `Max-Age` counts down to it. */
  readonly expiresAt: number;
}

/**
 * The session cookie's payload: `{ s: [sid], a: sid }` as base64url JSON, the
 * listed session ids and the active one.
 */
function encodeSessionPayload(contents: SessionCookieContents): string {
  return Buffer.from(
    JSON.stringify({ s: contents.sessionIds, a: contents.activeSessionId }),
    'utf8'
  ).toString('base64url');
}

/** The contents of a verified session payload, or `null` when it is not one this module writes. */
function decodeSessionPayload(payload: string): SessionCookieContents | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
  const { s, a, ...rest } = parsed as Record<string, unknown>;
  if (Object.keys(rest).length > 0) return null;
  if (!Array.isArray(s) || s.length === 0 || s.length > SESSION_COOKIE_MAX_SESSIONS) return null;
  if (!s.every(isSessionId) || new Set(s).size !== s.length) return null;
  if (typeof a !== 'string' || !s.includes(a)) return null;
  return Object.freeze({ sessionIds: Object.freeze([...s]), activeSessionId: a });
}

function isSessionId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_SESSION_ID_LENGTH;
}

/**
 * Verify a session cookie value for the realm and return what it lists, or
 * `null` when it does not verify (see {@link verifyCookieValue}).
 *
 * @throws the signer's error when the realm's cookie keys cannot be read
 */
export async function readSessionCookie(
  fastify: CookieKeyHolder,
  realmId: string,
  cookieValue: string | undefined | null
): Promise<SessionCookieContents | null> {
  const payload = await verifyCookieValue(fastify, SESSION_COOKIE_NAME, realmId, cookieValue);
  return payload === null ? null : decodeSessionPayload(payload);
}

/**
 * Verify a session cookie value for the realm and return the active session
 * id, or `null`. Never `null` for a signer it cannot reach: that throws.
 */
export async function verifySessionCookie(
  fastify: CookieKeyHolder,
  realmId: string,
  cookieValue: string | undefined | null
): Promise<string | null> {
  return (await readSessionCookie(fastify, realmId, cookieValue))?.activeSessionId ?? null;
}

/**
 * The signed value of a session cookie that names `session` alone, signed
 * with the current cookie key of the session's realm.
 */
export function signSessionCookie(
  fastify: CookieKeyHolder,
  session: Pick<SessionCookieSession, 'sid' | 'realmId'>
): Promise<string> {
  return signCookieValue(
    fastify,
    SESSION_COOKIE_NAME,
    session.realmId,
    encodeSessionPayload({ sessionIds: [session.sid], activeSessionId: session.sid })
  );
}

/**
 * Strip what a browser strips around a cookie-pair — SP and HTAB (RFC 6265
 * §5.2) — and nothing else.
 *
 * NOT `String.prototype.trim()`: that also removes U+00A0, which is how Node's
 * latin-1 header decoding delivers the byte 0xA0. A browser keeps that byte as
 * part of the name, so `<A0>__Host-x` does not START with `__Host-` there and a
 * sibling host may set it with `Domain=`. Trimming it would read that cookie as
 * the `__Host-` one and void the isolation every cookie in this file relies on.
 *
 * A loop rather than a regex: the header is caller-controlled, and `[ \t]+$`
 * backtracks quadratically on a long inner run of spaces.
 */
function stripCookieWhitespace(pair: string): string {
  let start = 0;
  let end = pair.length;
  while (start < end && (pair[start] === ' ' || pair[start] === '\t')) start += 1;
  while (end > start && (pair[end - 1] === ' ' || pair[end - 1] === '\t')) end -= 1;
  return pair.slice(start, end);
}

/**
 * Parse the `Cookie` header and return the raw value of the given cookie
 * name, or undefined. Avoids adding @fastify/cookie just for read access.
 */
export function readCookie(request: FastifyRequest, name: string): string | undefined {
  const header = request.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const trimmed = stripCookieWhitespace(part);
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

/** The attributes every cookie of this module carries, `Max-Age` and `Secure` aside. */
function cookieHeader(name: string, value: string, maxAgeSeconds: number, secure: boolean): string {
  const attrs = [
    `${name}=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}

/**
 * The seconds left until `expiresAt` (epoch ms), rounded down so the cookie
 * never outlives what it names: `0`, which deletes the cookie, once it is
 * past.
 */
function secondsUntil(expiresAt: number): number {
  return Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
}

/**
 * The `Set-Cookie` header for the signed session cookie of `session`:
 * `__Host-`, `Path=/`, `HttpOnly`, `SameSite=Lax`, no `Domain`, `Secure`
 * unless turned off for local development, and a `Max-Age` of the time left
 * until the session's absolute end, so the cookie lasts as long as the
 * session it names.
 *
 * Computed before the reply is touched, so a caller that must set it together
 * with other state can read the realm's key first and fail before anything is
 * written.
 *
 * @param secureOverride see {@link resolveCookieSecure} — a client-scoped
 *   development relaxation of the `Secure` attribute (defaults to strict).
 * @throws the signer's error when the realm's cookie keys cannot be read
 */
export async function sessionCookieHeader(
  fastify: CookieKeyHolder,
  session: SessionCookieSession,
  secureOverride?: boolean
): Promise<string> {
  return cookieHeader(
    SESSION_COOKIE_NAME,
    await signSessionCookie(fastify, session),
    secondsUntil(session.expiresAt),
    resolveCookieSecure(secureOverride)
  );
}

/**
 * Set the signed session cookie for `session` ({@link sessionCookieHeader}).
 *
 * @throws the signer's error when the realm's cookie keys cannot be read
 */
export async function setSessionCookie(
  fastify: CookieKeyHolder,
  reply: FastifyReply,
  session: SessionCookieSession,
  secureOverride?: boolean
): Promise<void> {
  reply.header('Set-Cookie', await sessionCookieHeader(fastify, session, secureOverride));
}

/**
 * Clear the session cookie. Used on logout, and when a cookie does not verify
 * or names no live session (a stale cookie).
 */
export function clearSessionCookie(reply: FastifyReply): void {
  reply.header('Set-Cookie', cookieHeader(SESSION_COOKIE_NAME, '', 0, env.SESSION_COOKIE_SECURE));
}

/**
 * Generate a CSRF token suitable for the consent form's hidden input. The
 * same value is also stored in the session's side record; on POST the server
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
 * Emit the signed login-CSRF cookie for the realm. `Secure` follows the same
 * global default as the session cookie (`env.SESSION_COOKIE_SECURE`);
 * `__Host-` requires it in production. SameSite=Lax + HttpOnly mirror the
 * session cookie. The value is `<kid>.<token>.<mac>`, signed with the realm's
 * cookie key as the session cookie is.
 *
 * @throws the signer's error when the realm's cookie keys cannot be read
 */
export async function setLoginCsrfCookie(
  fastify: CookieKeyHolder,
  reply: FastifyReply,
  realmId: string,
  token: string
): Promise<void> {
  const value = await signCookieValue(fastify, LOGIN_CSRF_COOKIE_NAME, realmId, token);
  reply.header(
    'Set-Cookie',
    cookieHeader(LOGIN_CSRF_COOKIE_NAME, value, env.SESSION_COOKIE_TTL, env.SESSION_COOKIE_SECURE)
  );
}

/**
 * Clear the login-CSRF cookie (burned after a successful login POST).
 */
export function clearLoginCsrfCookie(reply: FastifyReply): void {
  reply.header(
    'Set-Cookie',
    cookieHeader(LOGIN_CSRF_COOKIE_NAME, '', 0, env.SESSION_COOKIE_SECURE)
  );
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
 * Emit the signed wallet-flow binder cookie of the realm carrying `bindings`,
 * or clear it when none of them are still live. Attributes mirror the
 * login-CSRF cookie; `Max-Age` is the longest remaining flow lifetime rather
 * than the session TTL, so the cookie cannot outlive every flow it binds.
 *
 * @throws the signer's error when the realm's cookie keys cannot be read
 */
export async function setWalletFlowCookie(
  fastify: CookieKeyHolder,
  reply: FastifyReply,
  realmId: string,
  bindings: readonly WalletFlowBinding[]
): Promise<void> {
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
  const value = await signCookieValue(fastify, WALLET_FLOW_COOKIE_NAME, realmId, payload);
  reply.header(
    'Set-Cookie',
    cookieHeader(WALLET_FLOW_COOKIE_NAME, value, maxAgeSeconds, env.SESSION_COOKIE_SECURE)
  );
}

/** Clear the wallet-flow binder cookie (burned when the last flow terminates). */
export function clearWalletFlowCookie(reply: FastifyReply): void {
  reply.header(
    'Set-Cookie',
    cookieHeader(WALLET_FLOW_COOKIE_NAME, '', 0, env.SESSION_COOKIE_SECURE)
  );
}

/**
 * Verify the signed wallet-flow cookie for the realm and return the bindings
 * it carries. Same `<kid>.<payload>.<mac>` scheme and timing-safe verification
 * as {@link verifyLoginCsrfCookie}, applied to the whole payload — so a
 * binding cannot be added, edited or reordered without the realm's cookie key.
 *
 * An absent, unsigned or tampered cookie yields an EMPTY list rather than a
 * throw: the caller reports "expired" for a handle it holds no binding for,
 * which is the answer every other unbindable state gets.
 *
 * @throws the signer's error when the realm's cookie keys cannot be read
 */
export async function readWalletFlowBindings(
  fastify: CookieKeyHolder,
  realmId: string,
  cookieValue: string | undefined | null
): Promise<WalletFlowBinding[]> {
  const payload = await verifyCookieValue(fastify, WALLET_FLOW_COOKIE_NAME, realmId, cookieValue);
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
export async function findWalletFlowBinder(
  fastify: CookieKeyHolder,
  realmId: string,
  cookieValue: string | undefined | null,
  handle: string
): Promise<string | null> {
  const match = (await readWalletFlowBindings(fastify, realmId, cookieValue)).find(
    (binding) => binding.handle === handle
  );
  return match ? match.binder : null;
}

/**
 * Burn ONE flow's binding, leaving any other flow this browser has in progress
 * bound. Clears the cookie outright when nothing else was in it. The cookie is
 * the request's realm's.
 *
 * @throws the signer's error when the realm's cookie keys cannot be read
 */
export async function dropWalletFlowBinding(
  fastify: CookieKeyHolder,
  request: FastifyRequest,
  reply: FastifyReply,
  handle: string
): Promise<void> {
  const realmId = requestRealm(request).id;
  const bindings = await readWalletFlowBindings(
    fastify,
    realmId,
    readCookie(request, WALLET_FLOW_COOKIE_NAME)
  );
  await setWalletFlowCookie(
    fastify,
    reply,
    realmId,
    bindings.filter((binding) => binding.handle !== handle)
  );
}

/**
 * Verify the signed login-CSRF cookie value for the realm and return the
 * embedded token if the signature is valid, otherwise null. Same
 * `<kid>.<payload>.<mac>` scheme and timing-safe verification as the session
 * cookie ({@link readSessionCookie}).
 *
 * @throws the signer's error when the realm's cookie keys cannot be read
 */
export function verifyLoginCsrfCookie(
  fastify: CookieKeyHolder,
  realmId: string,
  cookieValue: string | undefined | null
): Promise<string | null> {
  return verifyCookieValue(fastify, LOGIN_CSRF_COOKIE_NAME, realmId, cookieValue);
}
