---
title: Hosted UI
description: The server-rendered login, consent, and resume screens an integrator's users see during authorization_code + PKCE.
sidebar:
  order: 3
lastVerified: '2026-07-27'
---

`authorization_code` + PKCE ([OAuth 2.1 Flow, step 2](/integrate/oauth-flow/#2-redirect-the-user-to-oauth-authorize))
sends the browser to QAuth itself for a stretch. Three server-rendered pages
handle that stretch — `/ui/login`, `/ui/consent`, and `/ui/resume/{handle}` — and
every integrator meets all three, even one that never renders its own login UI.

## `/ui/login`

`GET /ui/login?return_to=<path>&error=<message>` renders an email/password
form. `return_to` must be a relative, same-origin path — `isSafeReturnTo`
(`apps/auth-server/src/app/routes/ui/login.ts:38`) rejects absolute URLs,
`//host` protocol-relative values, and the `/\host` backslash variant a
browser also resolves as protocol-relative, falling back to `/` on anything
that fails. The page carries a signed, double-submit login-CSRF token in both
a hidden form field and a cookie.

`POST /ui/login` verifies the CSRF pair, then the credentials. On success it
mints a **fresh** session id (session-fixation defence — a pre-login session
id is never reused), sets it as `__Host-qauth_session`, and redirects to
`return_to`. On failure it re-renders the form with a `401` (bad credentials)
or `403` (CSRF mismatch) and a fresh CSRF token.

## `/ui/consent`

`GET /ui/consent` takes the same query parameters as
[`/oauth/authorize`](/integrate/api-reference/#oauth-2-1) and renders the scope
consent screen. It requires a valid `__Host-qauth_session` cookie; without one
it redirects to `/ui/login` (via the pending-authorization mechanism below,
not a raw inline redirect). `POST /ui/consent` submits the decision
(`allow` / `deny`, CSRF-protected) and, on `allow`, issues the authorization
code and redirects to the client's `redirect_uri` exactly as a first visit
would.

## `/ui/resume/{handle}`

`GET /ui/resume/{handle}` is where a login round-trip lands after a
successful sign-in. It exchanges a single-use handle for the pending
`/oauth/authorize` URL and redirects there — see below for what the handle
is and why it exists. Resuming re-validates `client_id`, `redirect_uri`,
scope, PKCE, and step-up **from scratch**, exactly as on a first visit
(`apps/auth-server/src/app/routes/ui/resume.ts:124`); a resumed handle grants
nothing a fresh authorize request would not.

---

## Pending authorization: why the login bounce carries a handle, not a URL

Before qauth-labs/qauth#319, every surface that bounced an unauthenticated
user to `/ui/login` nested the **entire** authorize query string inside
`return_to` — `/ui/login?return_to=%2Foauth%2Fauthorize%3F...`. Once `state`
and `nonce` could legally reach 2048 characters each
(`OAUTH_OPAQUE_PARAM_MAX_LENGTH`,
`apps/auth-server/src/app/constants/security.ts:71`), that `Location` header
could exceed ~10 KB — past a typical reverse proxy's default header-buffer
limit, so the browser got a `414`/`400` instead of the login page, on the
_unauthenticated first-visit path_, and invisibly so in local dev (no proxy
in front).

#319 fixed this by parking the authorize URL server-side instead of nesting
it in the redirect:

- An unauthenticated `GET /oauth/authorize` no longer nests the query. It
  stashes the normalized authorize URL in Redis under a fresh,
  **43-character CSPRNG handle** (`randomBytes(32).toString('base64url')`,
  `apps/auth-server/src/app/helpers/pending-authorization.ts:97`) and
  redirects to `/ui/login?return_to=%2Fui%2Fresume%2F<handle>` — a ~60-byte
  path regardless of how large `state`, `nonce`, or `resource` are. The same
  stash-then-redirect helper
  (`redirectToLoginWithPendingAuthorization`,
  `apps/auth-server/src/app/helpers/pending-authorization.ts:283`) backs all
  five login-bounce call sites: two in
  `apps/auth-server/src/app/routes/oauth/authorize.ts` (lines 334 and 554)
  and three in `apps/auth-server/src/app/routes/ui/consent.ts` (lines 369,
  559, and 763) — #319 closed #316 specifically because an earlier fix had
  patched only one of these sites and missed the rest.

- **Single-use.** `consumePendingAuthorization`
  (`apps/auth-server/src/app/helpers/pending-authorization.ts:235`) deletes
  the Redis record as it reads it, before even validating its contents. A
  login URL saved from browser history or a screen recording therefore
  cannot be replayed — the second `GET /ui/resume/{handle}` for the same
  handle gets the "expired" page, not a second redirect.

- **Expires after 10 minutes.**
  `PENDING_AUTHORIZATION_TTL_MS`
  (`apps/auth-server/src/app/constants/security.ts:101`) bounds the stash to
  10 minutes — long enough to cover an interactive login (reading the page,
  a password manager, typing credentials) but short because this is
  auth-flow state, not user session state. An expired, unknown, or
  already-used handle all render the **same** "this sign-in request has
  expired" page (`expiredPage`,
  `apps/auth-server/src/app/routes/ui/resume.ts:40`) with a plain `400` and
  no redirect — the three cases are made indistinguishable on purpose, so a
  handle can't be probed to learn which ones ever existed.

- **A `state` over 16 KB is rejected outright.**
  `PENDING_AUTHORIZATION_MAX_URL_BYTES`
  (`apps/auth-server/src/app/constants/security.ts:131`) caps the authorize
  URL the stash will accept. This is a backstop behind the per-parameter
  2048-character bounds already enforced at the edge, not the primary
  control — but because the stash is written **before** the caller
  authenticates, an unbounded write there would be a pre-auth memory-pressure
  primitive against the same Redis that holds live browser sessions and
  rate-limit counters. Exceeding it returns `400 invalid_request:
authorization request is too large`
  (`apps/auth-server/src/app/helpers/pending-authorization.ts:213`)
  rather than either a `500` or a `Location` header no proxy would forward.

### Redis is now on the pre-authentication path

Before #319, an unauthenticated visit to `/oauth/authorize` touched no Redis
at all (`resolveBrowserSession` only reads Redis when a session cookie is
present). The pending-authorization stash changes that: **writing** the
handle is now the first Redis dependency an unauthenticated caller can
trigger. QAuth degrades rather than fails when that write cannot complete —
if Redis is unreachable, `redirectToLoginWithPendingAuthorization` catches
the failure and falls back to the pre-#319 inline `return_to`
(`apps/auth-server/src/app/helpers/pending-authorization.ts:296`). That
inline fallback is correct for every request small enough to survive a
proxy's header buffer — only the pathological multi-kilobyte `state` that
motivated the stash would still be too large during a Redis outage, and for
that one case an oversized redirect is judged better than an opaque `500` at
the authorization endpoint. Symmetrically, a **read** failure in
`consumePendingAuthorization` is treated as a miss and renders the same
"expired" page a genuinely-expired handle would
(`apps/auth-server/src/app/helpers/pending-authorization.ts:245`) — an
unreachable Redis is, from the user's side of `/ui/resume/{handle}`,
indistinguishable from a handle that timed out.

### Not an open redirector

The handle is never resolved from anything the client controls at resume
time — it comes back out of Redis and is re-validated
(`normalizeInternalAuthorizeUrl`,
`apps/auth-server/src/app/helpers/pending-authorization.ts:153`) to be
this server's own `/oauth/authorize` path before use, both on the way in and
the way out. The only reachable destination is a fresh visit to
`/oauth/authorize`, which then re-checks `client_id` and `redirect_uri`
exactly as it would on a first request.

---

## See also

- [OAuth 2.1 Flow](/integrate/oauth-flow/) — the `authorization_code` + PKCE
  walkthrough these screens sit inside.
- [API Reference → Hosted UI](/integrate/api-reference/#hosted-ui) — the wire
  contract (methods, parameters, status codes) for these three routes.
