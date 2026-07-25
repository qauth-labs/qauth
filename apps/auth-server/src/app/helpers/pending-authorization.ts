import { randomBytes } from 'node:crypto';

import { BadRequestError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply } from 'fastify';

import { PENDING_AUTHORIZATION_MAX_URL_BYTES, PENDING_AUTHORIZATION_TTL_MS } from '../constants';

/**
 * Pending-authorization stash (qauth-labs/qauth#316 follow-up).
 *
 * ## The problem
 *
 * Every surface that bounces an unauthenticated end user to the login page used
 * to nest the ENTIRE authorize query string inside `return_to`:
 *
 *     /ui/login?return_to=%2Foauth%2Fauthorize%3Fresponse_type%3Dcode%26...
 *
 * The re-encoding is CORRECT — `requestUrlWithParams` is already a
 * percent-encoded URL, so nesting it as a query-parameter value requires
 * encoding `%` to `%25` for the receiver to decode back to the identical
 * string. The defect is SIZE, not encoding. #316 raised the `state`/`nonce` cap
 * from 255 to `OAUTH_OPAQUE_PARAM_MAX_LENGTH` (2048), which makes a legal
 * client with a raw-JSON `state` reachable: each `{`, `"`, `:`, `,` costs three
 * bytes in the authorize query and five once nested, so the `Location` header
 * measured ~10.4 KB. That is past nginx's default
 * `large_client_header_buffers 4 8k` and typical ALB/CDN request-line limits,
 * so the browser gets a 414/400 instead of the login page — on the
 * unauthenticated first-visit path, invisible in local dev (no proxy).
 * (`OAUTH_OPAQUE_PARAM_MAX_LENGTH` is the shared 2048 bound in
 * `constants/security.ts`.)
 *
 * ## The fix
 *
 * Park the pending authorize URL server-side in the existing Redis session
 * store under a CSPRNG handle, and send the browser a compact relative path:
 *
 *     /ui/login?return_to=%2Fui%2Fresume%2F<handle>
 *
 * `/ui/resume/<handle>` starts with a single `/` and never `//`, so
 * `isSafeReturnTo` in `routes/ui/login.ts` accepts it as-is — the
 * open-redirector defence is not relaxed anywhere for this change, it is simply
 * given a much shorter value. (It was TIGHTENED while this landed: it now also
 * rejects `/\host`, the backslash spelling of a protocol-relative URL.) After a
 * successful sign-in, `/ui/resume/:handle` swaps the handle back for the
 * authorize URL and redirects there.
 *
 * ## Security properties
 *
 * - **Not an open redirector.** The resume target is never reconstructed from
 *   user input and is never a client-supplied absolute URL. It is read back
 *   from Redis and re-checked by {@link normalizeInternalAuthorizeUrl} before use,
 *   so the only reachable destination is this server's own
 *   `/oauth/authorize?…`, which then re-validates `client_id` and
 *   `redirect_uri` exactly as it does on a first visit.
 * - **Never a 500.** The stash is the FIRST Redis dependency on the
 *   pre-authentication path (`resolveBrowserSession` does no Redis I/O when the
 *   cookie is absent), so a failed write must not turn a 302-to-login into an
 *   opaque 500 at the authorization endpoint. A write failure degrades to the
 *   pre-#316 inline `return_to`, which is correct for every request small
 *   enough to fit a proxy's header buffer — i.e. all of them but the
 *   pathological `state` this helper exists for. Symmetrically, a failed read
 *   in {@link consumePendingAuthorization} degrades to the "expired" page.
 * - **Bounded.** {@link PENDING_AUTHORIZATION_MAX_URL_BYTES} caps what an
 *   unauthenticated caller can write, so the stash can never become an
 *   unbounded pre-auth write primitive against the Redis that also holds live
 *   browser sessions — including if a future schema change drops a `max()`.
 * - **Unguessable.** 32 CSPRNG bytes (`node:crypto`, never `Math.random`),
 *   base64url-encoded to 43 URL-safe characters — the same entropy the
 *   authorization codes and CSRF tokens in this codebase use.
 * - **Single-use.** {@link consumePendingAuthorization} deletes the record as it
 *   reads it, so a login URL captured from history or a screen share cannot be
 *   replayed.
 * - **NOT bound to the browser.** Deliberate, on two grounds. (1) A binding
 *   would have to survive `/ui/login`'s session-fixation defence, which mints a
 *   BRAND-NEW session id on every successful sign-in — so a stash bound to the
 *   pre-login session id would be unresolvable exactly on the step-up path that
 *   needs it most, and binding to a second dedicated cookie means setting a
 *   cookie on an unauthenticated redirect that some browsers/proxies will drop,
 *   turning a size bug into an availability bug. (2) The stash holds no secret
 *   and confers no privilege: it contains only the authorize parameters the
 *   client itself put in a URL, and resuming it still requires the resumer to
 *   authenticate as themselves and pass the consent screen, after which the code
 *   goes to the client's REGISTERED redirect_uri. An attacker holding a handle
 *   can do nothing they could not do by composing an `/oauth/authorize` URL by
 *   hand. Unguessability plus single-use plus a 10-minute TTL is therefore the
 *   proportionate control; browser binding would buy no distinct defence.
 */

/**
 * Redis key namespace for the stash. `sessionUtils` prefixes every key with
 * `session:`, so entries land at `session:pending-authz:<handle>` — a namespace
 * a browser session id (a UUID) can never collide with.
 */
const PENDING_AUTHORIZATION_KEY_PREFIX = 'pending-authz:';

/** CSPRNG bytes per handle; 32 bytes → 43 base64url characters. */
const HANDLE_BYTES = 32;

/** Exactly what `randomBytes(32).toString('base64url')` produces. */
const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/**
 * Path the login round-trip returns to. Relative and single-slash-prefixed by
 * construction so `isSafeReturnTo` accepts it without any relaxation.
 */
export const RESUME_PATH_PREFIX = '/ui/resume/';

/** The only destination a resumed handle is ever allowed to point at. */
const AUTHORIZE_PATH = '/oauth/authorize';

/** Shape stored in Redis. Kept minimal — this is auth-flow state, not user state. */
interface PendingAuthorization {
  /** Server-minted authorize URL: path + query, relative to this origin. */
  authorizeUrl: string;
  /** Mint time (epoch ms), for diagnostics; expiry is enforced by the Redis TTL. */
  createdAt: number;
  [key: string]: unknown;
}

/** Cheap shape guard so a junk path segment never reaches Redis. */
export function isPendingAuthorizationHandle(value: unknown): value is string {
  return typeof value === 'string' && HANDLE_PATTERN.test(value);
}

/**
 * Normalize a candidate to the canonical relative `/oauth/authorize[?…]` form,
 * or return `null` when it is not one.
 *
 * Applied on the way IN (so nothing else can be stashed) and again on the way
 * OUT (so a tampered or corrupted Redis value cannot turn the resume route into
 * an open redirector).
 *
 * Two subtleties, both load-bearing:
 *
 * 1. **Trailing slash.** `main.ts` starts Fastify with
 *    `routerOptions.ignoreTrailingSlash: true`, so `GET /oauth/authorize/?…`
 *    routes to the authorize handler with `request.url` returned VERBATIM —
 *    trailing slash and all. A byte-exact comparison against `/oauth/authorize`
 *    therefore rejected a request the router had deliberately accepted, turning
 *    the unauthenticated entry point of the whole OAuth flow into a 500. We
 *    normalize the path instead of rejecting it, and stash the normalized form
 *    so the resume redirect lands on the canonical path.
 *
 * 2. **No `new URL()` parse.** The obvious implementation — parse against a
 *    placeholder origin and compare `pathname` — is unsafe here: the WHATWG URL
 *    parser folds `\` into `/` for special schemes, so
 *    `new URL('/\\evil.example/x', 'http://placeholder')` yields host
 *    `evil.example`. Splitting the string ourselves and requiring the path to
 *    equal {@link AUTHORIZE_PATH} after trailing-slash trimming is strictly
 *    tighter: `//evil.example`, `/\evil.example`, `/oauth/authorize/../x` and
 *    any absolute URL all fail the equality check.
 */
export function normalizeInternalAuthorizeUrl(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  if (!value.startsWith('/')) return null;
  // Protocol-relative (`//host`) and its backslash twin (`/\host`), which a
  // browser resolves to the same thing. Mirrors — and slightly exceeds —
  // `isSafeReturnTo`'s guard in routes/ui/login.ts.
  if (value.startsWith('//') || value.startsWith('/\\')) return null;
  const queryStart = value.indexOf('?');
  const path = queryStart < 0 ? value : value.slice(0, queryStart);
  const search = queryStart < 0 ? '' : value.slice(queryStart);
  // `ignoreTrailingSlash: true` accepts `/oauth/authorize/`; canonicalise it.
  const normalizedPath = path.length > 1 ? path.replace(/\/+$/, '') : path;
  if (normalizedPath !== AUTHORIZE_PATH) return null;
  return `${normalizedPath}${search}`;
}

/**
 * Store `authorizeUrl` under a fresh handle and return the handle.
 *
 * @throws {Error} when the URL is not an internal authorize URL — a
 *   programming error, and one that must never silently become a redirect
 *   target.
 * @throws {BadRequestError} when the URL exceeds
 *   {@link PENDING_AUTHORIZATION_MAX_URL_BYTES}. A 400 rather than a throw
 *   because it is caller-driven, not a bug: the request is too large to be
 *   served through the login round-trip at all (a proxy would reject the
 *   equivalent inline redirect too), so a crisp `invalid_request` beats both a
 *   500 and an unbounded unauthenticated Redis write.
 */
export async function stashPendingAuthorization(
  fastify: FastifyInstance,
  authorizeUrl: string
): Promise<string> {
  const normalized = normalizeInternalAuthorizeUrl(authorizeUrl);
  if (normalized === null) {
    throw new Error('pending authorization must be a relative /oauth/authorize URL');
  }
  assertPendingAuthorizationSize(normalized);
  const handle = randomBytes(HANDLE_BYTES).toString('base64url');
  await fastify.sessionUtils.setSession<PendingAuthorization>(
    `${PENDING_AUTHORIZATION_KEY_PREFIX}${handle}`,
    { authorizeUrl: normalized, createdAt: Date.now() },
    Math.floor(PENDING_AUTHORIZATION_TTL_MS / 1000)
  );
  return handle;
}

/**
 * Reject an authorize URL too large to park.
 *
 * The primary bound is at the edge — every round-tripped parameter has a
 * `max()` in `schemas/oauth.ts` and the `/ui/consent` form mirror. This is the
 * backstop for the case those bounds drift or a new parameter lands without
 * one, because the consequence here is specific and nasty: the stash is written
 * BEFORE the user authenticates, into the SAME Redis that holds live browser
 * sessions and the rate-limit counters, and it is retained for
 * `PENDING_AUTHORIZATION_TTL_MS`. An unbounded write there is an
 * unauthenticated memory-pressure primitive against session storage, not merely
 * against this feature.
 */
function assertPendingAuthorizationSize(authorizeUrl: string): void {
  if (Buffer.byteLength(authorizeUrl, 'utf8') > PENDING_AUTHORIZATION_MAX_URL_BYTES) {
    throw new BadRequestError('invalid_request: authorization request is too large');
  }
}

/**
 * Read and BURN a handle, returning the authorize URL it stood for, or `null`
 * when the handle is malformed, unknown, expired, or already used.
 *
 * The delete is issued unconditionally and before the value is inspected, so a
 * record is consumed even if it fails validation — a poisoned entry cannot be
 * probed repeatedly. Read-then-delete is not atomic (`sessionUtils` exposes no
 * `GETDEL`), so two genuinely simultaneous requests could both observe the
 * record; the worst outcome is one duplicate resume of the user's own pending
 * request, which is why single-use is a replay-window control here rather than a
 * hard mutual exclusion.
 *
 * A Redis failure is treated as a miss rather than propagated: `/ui/resume`
 * documents that it never 500s, and an unreachable store is operationally
 * indistinguishable from an expired handle for the user standing in front of it.
 */
export async function consumePendingAuthorization(
  fastify: FastifyInstance,
  handle: unknown
): Promise<string | null> {
  if (!isPendingAuthorizationHandle(handle)) return null;
  const key = `${PENDING_AUTHORIZATION_KEY_PREFIX}${handle}`;
  let record: PendingAuthorization | null;
  try {
    record = await fastify.sessionUtils.getSession<PendingAuthorization>(key);
    await fastify.sessionUtils.deleteSession(key);
  } catch (error) {
    fastify.log.warn(
      { err: error },
      'pending authorization store unavailable; treating as expired'
    );
    return null;
  }
  if (!record) return null;
  // Re-validate on read: never redirect to anything but our own authorize path.
  const normalized = normalizeInternalAuthorizeUrl(record.authorizeUrl);
  if (normalized === null) {
    fastify.log.warn({ key }, 'pending authorization held a non-authorize URL; refusing to resume');
    return null;
  }
  return normalized;
}

/**
 * The ONE way every call site bounces a user to the login page.
 *
 * Centralised on purpose: #316 was a "fixed one site, missed the others" bug,
 * and there are five surfaces that redirect to `/ui/login` (two in
 * `/oauth/authorize`, three in `/ui/consent`). Routing them all through this
 * helper makes it impossible for one of them to keep nesting the full query
 * string. `encodeURIComponent` is retained because `return_to` is still a nested
 * query-parameter value — it is now applied to a ~60-character path instead of a
 * multi-kilobyte URL.
 *
 * Degrades, never 500s. If the stash write fails (Redis failover, connection
 * reset) we fall back to the pre-#316 inline `return_to`. That is the SAME
 * value this code has always produced and it is correct for every request whose
 * parameters fit a proxy's header buffer; only the pathological multi-kilobyte
 * `state` that motivated the stash would still be too large, and for that case a
 * too-long redirect is strictly better than an opaque 500 at the authorization
 * endpoint during a Redis blip. The fallback target is the SAME normalized,
 * validated internal path we would have stashed, so it cannot be an open
 * redirect.
 */
export async function redirectToLoginWithPendingAuthorization(
  fastify: FastifyInstance,
  reply: FastifyReply,
  authorizeUrl: string
): Promise<FastifyReply> {
  const normalized = normalizeInternalAuthorizeUrl(authorizeUrl);
  if (normalized === null) {
    throw new Error('pending authorization must be a relative /oauth/authorize URL');
  }
  // Deliberately OUTSIDE the try/catch below: an oversized request is a 400 for
  // the caller, not a condition to silently degrade around.
  assertPendingAuthorizationSize(normalized);

  let returnTo = normalized;
  try {
    returnTo = `${RESUME_PATH_PREFIX}${await stashPendingAuthorization(fastify, normalized)}`;
  } catch (error) {
    fastify.log.warn(
      { err: error },
      'pending authorization store unavailable; falling back to an inline return_to'
    );
  }
  return reply.redirect(`/ui/login?return_to=${encodeURIComponent(returnTo)}`, 302);
}
