---
title: Hosted UI
description: The server-rendered login, consent, and resume screens an integrator's users see during authorization_code + PKCE.
sidebar:
  order: 3
lastVerified: '2026-10-31'
---

`authorization_code` + PKCE ([OAuth 2.1 Flow, step 2](/integrate/oauth-flow/#2-redirect-the-user-to-oauthauthorize))
sends the browser to QAuth itself for a stretch. Three server-rendered pages
handle that stretch — `/ui/login`, `/ui/consent`, and `/ui/resume/{handle}` — and
every integrator meets all three, even one that never renders its own login UI.

## `/ui/login`

`GET /ui/login?return_to=<path>` renders an email/password
form. `return_to` must be a relative, same-origin path — `isSafeReturnTo`
(`apps/auth-server/src/app/helpers/return-to.ts:50`) rejects absolute URLs,
`//host` protocol-relative values, and the `/\host` backslash variant a
browser also resolves as protocol-relative, falling back to `/` on anything
that fails. The page carries a signed, double-submit login-CSRF token in both
a hidden form field and a cookie.

`POST /ui/login` verifies the CSRF pair, then the credentials. On success it
mints a **fresh** session id (session-fixation defence — a pre-login session
id is never reused), sets it as `__Host-qauth_session`, and redirects to
`return_to`. On failure it re-renders the form, and the two failure modes
handle the CSRF token differently: a `403` (CSRF pair missing or mismatched,
`apps/auth-server/src/app/routes/ui/login.ts:304`) mints and sets a **fresh**
token so a legitimate retry can succeed; a `401` (bad credentials,
`apps/auth-server/src/app/routes/ui/login.ts:339`) **reuses** the existing
cookie's token unchanged, since that cookie is still valid — only the
credentials were wrong. An account whose address is not verified yet gets that
same `401` page while `REQUIRE_VERIFIED_ACCOUNT` is on (the default), so the
page cannot be used to tell a just-registered free address from a registered
one; its message mentions confirming the address for that reason.

The session is stored in Postgres, with Redis as a cache in front of it, in
the realm of the host the browser signed in on: the cookie names no session at
another realm's host. The cookie lasts `SESSION_COOKIE_TTL` from sign-in and is
not extended by use. The session behind it can end sooner, when the realm sets
`sso_max_lifespan` or `sso_idle_timeout`.
[`POST /auth/logout`](/integrate/api-reference/#post-authlogout) ends every
hosted session of the user, so the next `/oauth/authorize` shows this page
again.

## `/ui/consent`

`GET /ui/consent` takes the same query parameters as
[`/oauth/authorize`](/integrate/api-reference/#oauth-21) and renders the scope
consent screen. It requires a valid `__Host-qauth_session` cookie; without one
it redirects to `/ui/login` (via the pending-authorization mechanism below,
not a raw inline redirect). `POST /ui/consent` submits the decision
(`allow` / `deny`, CSRF-protected) and, on `allow`, issues the authorization
code and redirects to the client's `redirect_uri` exactly as a first visit
would. The **Remember this decision** checkbox (ticked by default) stores the
consent, which lets later requests for the same scopes skip the screen and lists
the client under `/consents`. Unticked, the approval is one-time: nothing is
stored, and `/oauth/token` returns no `refresh_token` for that code.

The screen names the client by what the server verified about it, never by the
name the client gives itself
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/)
Decision 6):

- A client whose `client_id` is a Client ID Metadata Document URL is shown by
  that URL's host, in its ASCII (`xn--`) form, with the registrable domain in
  bold. A host under a shared-hosting suffix (the private section of the Public
  Suffix List) is flagged. The host is all the screen shows, and all the server
  verified: with the default `CIMD_TRUST_POLICY=accept-any-https`, a document
  anyone can publish on a host that serves anyone's files appears under that
  host. A deployment that accepts third-party agents should use the
  `allowlist` policy
  ([CIMD](/operate/docker/#what-the-consent-screen-shows-for-a-cimd-client)).
- A client the operator provisioned is shown by the domain the operator set on
  it: `verified_domain` in the `db:seed-oauth-clients` manifest.
- Any other client, a dynamically registered or developer-portal one included,
  is shown as an unverified app, with the host that receives the code.

A redirect to a loopback address is shown as "this device", with a warning. The
name the client declared comes after all of this, labelled as declared, cut to
64 characters and stripped of control and bidirectional characters. No logo or
link the client supplied is shown.

Since the screen always says where the code goes, registration refuses a
redirect URI it could not show: a host that is not a DNS name of valid labels
(an underscore, an empty label), an IPv6 address other than loopback, or a
private-use scheme longer than 64 characters.

### An AI agent client

For an agent client (one with `is_agent`, see
[Agent Authorization](/integrate/agent-authorization/#1-agent-client-type-is_agent)),
the screen adds two lines after the "Signed in as" line. They are QAuth's own
text, never anything the client declared:

- **"This app is an AI agent."** The name the client declared stays in its
  own line, labelled as declared.
- **How long the agent may keep working.** In a realm without
  `sso_max_lifespan`: "It may keep working until you revoke it." In a realm
  that sets one: "It may keep working until you revoke it, or until &lt;the
  limit&gt; after you signed in, whichever comes first." The limit is written
  as an exact duration that names every unit it holds: `3600` is "1 hour",
  `5400` "1 hour and 30 minutes".

The second line is the end of the agent's refresh-token family. Without a
limit each refresh moves the family's end forward, until the user revokes the
consent under `/consents`. With one, the family ends no later than its start
plus the limit and the end of the browser session behind the code, and that
session ends the limit after the sign-in
([Refresh Token](/integrate/oauth-flow/#refresh-token-rotation)). Three things
the line leaves to this page:

- **The family needs a stored consent.** The code exchange issues a refresh
  token only under one: the approval with **Remember this decision** ticked,
  or a consent the user remembered on an earlier visit, which unticking the
  box later does not remove (revoke it under `/consents`). With neither, no
  refresh token is issued and the agent stops when its access token expires.
- **An access token outlives both ends.** Revoking the consent and the
  family's end stop refreshes; an access token already issued works until it
  expires, `ACCESS_TOKEN_LIFESPAN` (15 minutes by default) or, for a
  `development` client, `DEV_ACCESS_TOKEN_LIFESPAN`.
- **The limit is the one the page read.** The page states the realm's limit
  as it is when the page renders. A limit the operator changes later applies
  to the family as the Refresh Token section describes, not as the page said.
  A browser session keeps the end it was given at sign-in, so after a realm
  raises `sso_max_lifespan`, a family started from a session signed in before
  the change ends at the earlier of its start plus the new limit and that
  session's own end, which the old limit set.

A stored consent never skips the screen for an agent client (ADR-015
Decision 11): every authorization request from an agent shows it, and
`prompt=none` from an agent answers `consent_required` with no code.

The decision is taken for the page the user saw. A client whose `is_agent`
changes between the page and the decision (a Client ID Metadata Document can
change it) gets nothing from that decision: the browser goes back to
`/oauth/authorize`, which shows the page the client needs now.

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
  `apps/auth-server/src/app/helpers/pending-authorization.ts:191`) and
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
  (`apps/auth-server/src/app/helpers/pending-authorization.ts:215`)
  rather than either a `500` or a `Location` header no proxy would forward.

### What the stash adds to the pre-authentication path

Redis was already on that path before #319, and not marginally: the
Redis-backed `@fastify/rate-limit` plugin is registered app-wide
(`apps/auth-server/src/app/app.ts:260`) ahead of both route sweeps (lines 294
and 301), against the same `fastify.redis` client
(`apps/auth-server/src/app/plugins/rate-limit.ts:28`); `RATE_LIMIT_ENABLED`
defaults to `true` (`libs/server/config/src/lib/schemas/rate-limit.ts:12-15`);
and the `onRequest` hook it attaches to each of those routes `INCR`s a per-IP
counter on **every** request, authenticated or not (`PEXPIRE` on the first
request of a window, `PTTL` on the rest) — which is why the size cap above talks
about "the same Redis that holds live browser sessions and rate-limit
counters". What the pending-authorization stash adds is narrower and worth
naming precisely: it is
the first **caller-influenced write** an unauthenticated visitor can trigger,
which is the reason `PENDING_AUTHORIZATION_MAX_URL_BYTES` exists at all.

The stash itself degrades rather than fails. If the write cannot complete,
`redirectToLoginWithPendingAuthorization` catches the failure and falls back
to the pre-#319 inline `return_to`
(`apps/auth-server/src/app/helpers/pending-authorization.ts:299`). That
inline fallback is correct for every request small enough to survive a
proxy's header buffer — only the pathological multi-kilobyte `state` that
motivated the stash would still be too large, and for that one case an
oversized redirect is judged better than an opaque `500` at the
authorization endpoint. Symmetrically, a **read** failure in
`consumePendingAuthorization` is treated as a miss and renders the same
"expired" page a genuinely-expired handle would
(`apps/auth-server/src/app/helpers/pending-authorization.ts:245`) — an
unreachable Redis is, from the user's side of `/ui/resume/{handle}`,
indistinguishable from a handle that timed out.

Do not read those fallbacks as "a Redis outage is invisible here", though.
`@fastify/rate-limit`'s `skipOnError` is left at its default of `false`, so
when the store is unreachable the rate-limiter rethrows from its `onRequest`
hook — before the route handler, and therefore before either fallback can
run. The fallbacks cover a stash operation that fails on its own; they do not
cover an instance-wide Redis outage, which fails the request at the
rate-limit hook instead.

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
