---
title: Hosted UI
description: The server-rendered login, consent, and resume screens an integrator's users see during authorization_code + PKCE.
sidebar:
  order: 3
lastVerified: '2026-11-07'
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
`apps/auth-server/src/app/routes/ui/login.ts:312`) mints and sets a **fresh**
token so a legitimate retry can succeed; a `401` (bad credentials,
`apps/auth-server/src/app/routes/ui/login.ts:347`) **reuses** the existing
cookie's token unchanged, since that cookie is still valid — only the
credentials were wrong. An account whose address is not verified yet gets that
same `401` page while the realm requires verified accounts
(`accounts.requireVerifiedAccount`, the default), so the page cannot be used to tell a just-registered free address from a registered
one; its message mentions confirming the address for that reason.

The session is stored in Postgres, with Redis as a cache in front of it, in
the realm of the host the browser signed in on: the cookie names no session at
another realm's host. The cookie lasts until the session's absolute end:
`SESSION_COOKIE_TTL` from sign-in, or the realm's `sso_max_lifespan` when it
sets one, and is not extended by use. The session behind it can end sooner,
when the realm sets `sso_idle_timeout`.
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
  verified: with the default `accept-any-https` trust policy, a document
  anyone can publish on a host that serves anyone's files appears under that
  host. A deployment that accepts third-party agents should give each realm
  the `allowlist` trust policy
  ([CIMD](/operate/docker/#what-the-consent-screen-shows-for-a-cimd-client)).
- A client the operator provisioned is shown by the domain the operator set on
  it: `verified_domain` in the `db:seed-oauth-clients` manifest, or
  `db:set-client-verified-domain` for a client that exists already.
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
consent under `/consents`, except for a browser-based agent (a public client
with an `https` redirect URI), whose family ends when its first refresh token
expires. With one, the family ends no later than its start
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
  expires, after the realm's access token lifetime
  (`tokens.accessTokenLifespanSeconds`, 15 minutes by default) or, for a
  `development` client, its `tokens.developmentAccessTokenLifespanSeconds`.
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

### A first-party client

An operator can mark a client as first party: the seed manifest's
`first_party_profile` ([Docker](/operate/docker/)), which no registration path
can set
([ADR-017](/reference/records/adr/017-first-party-login/) Decisions 2
and 9). For such a client the operator's decision stands in for the user's
consent, an administrative consent:

- `/oauth/authorize` issues a code without this screen when none of the
  requested scopes is dangerous (`write:*`, `agent:admin`, `agent:exec`) and
  the request does not carry `prompt=consent`. Under `prompt=none` it issues
  the code too, for a `web_redirect` client.
- The waiver stores nothing for the user. Unless the user once remembered a
  consent for the client on this screen, the client is not listed under
  `/consents`, and `/oauth/token` returns no `refresh_token` for such a code,
  as for an approval with **Remember this decision** unticked. A remembered
  consent that covers the code's scopes, at each resource indicator the code
  is bound to, still yields one.
- Every such code is recorded as a
  [`consent.administrative`](/reference/events/#consentadministrative-v1-rc0)
  event: the profile it rests on, the scopes and resource indicators it
  covered, and the endpoint.
- A dangerous scope or `prompt=consent` shows this screen, as for any client,
  even when a stored consent covers the request. Under `prompt=none` such a
  request answers `login_required` when a fresh sign-in is due (a dangerous
  scope on a sign-in more than two minutes old), else `consent_required`.
- A client whose profile is `native_backend`, the backend of a native app, has
  every request treated as `prompt=login`, whatever the request says: a
  browser that already holds a session meets the login page unless its sign-in
  is less than two minutes old, and `prompt=none` answers `login_required`
  however recent the sign-in. A `POST /ui/consent` for such a client asks for
  the same fresh sign-in. So a native app's browser leg completes only on a
  sign-in of the last two minutes, the window `prompt=login` gives every
  client, never on an older session. Its own `prompt=consent` still shows this
  screen.

A client whose profile does not hold, because its row breaks one of the
profile's rules or its policy does not parse, is treated as a client without
one.

## Upstream providers on the login page

When the login page was opened for an authorization request, it lists the
realm's upstream identity providers, each as a plain link that works without
JavaScript: "Sign in with <name>", in the realm's order, a hidden provider left
out (#639). `GET /ui/upstream/{type}?return_to=<the same return_to>` sends the
browser back to that authorization request with
[`qauth_upstream=<type>`](/integrate/oauth-flow/#routing-to-an-upstream-provider),
reading a parked request (`/ui/resume/{handle}`) without spending it. The
authorization endpoint starts an interaction for the request and sends the
browser to `GET /ui/upstream/{type}/start?interaction=<id>`, which starts the
provider and answers a waiting page: it goes on to the provider at once, with a
link for a browser that does not follow the refresh and a way back.

The provider sends the browser back to `/upstream/{type}/callback` on the realm
host. Only the browser that started may complete the sign-in, once; the account
is found by the provider's subject under its issuer, never by email, and a new
one is created only when the realm allows sign-up (`ALLOW_SIGN_UP`). On success
the browser goes back to the authorization request under its new session. A
cancel or an error at the provider shows a page with a way back to the first
step; every other failure shows one error page with the request's trace id.
Nothing of either reaches the client. These pages show no further step, so an
account that needs one is refused here: an account the provider's verified
switch left unverified, whose address the Interaction API's ceremony page
(`INTERACTION_UI_ENABLED`) verifies with an emailed code, whatever
`REQUIRE_VERIFIED_ACCOUNT` says. With that switch off, these pages create no
account at all, and neither does the ceremony page for a provider that gives no
email: such an account could never sign in. An account that holds a passkey is
refused in both, since a passkey outranks an upstream sign-in and no passkey
step is served yet (#651).

### Linking an upstream account to an existing one

With the Interaction API on, an identity no account holds does not create an
account at once (#670). The interaction asks first, at its `upstream_link`
step, which `GET /ui/upstream-link/{interactionId}` shows as a page: "I
already have an account", or "Create a new account" when the realm allows
sign-up. The page names the provider and nothing else: no address, no account
and no hint, and QAuth never looks an account up by an email address.

"I already have an account" goes on to a sign-in to that account in the same
interaction, with its own factors and its MFA policy: the password or the
passkey, then the second factor the account or the realm asks for. No upstream
provider and no password reset is offered during it. Once that sign-in
completes, the identity joins the account it proved, the owner gets an email
notice, and the security log records the link; the authorization request goes
on as after any sign-in. An identity another account took meanwhile, or an
account that already has an identity of that provider, is refused: the browser
goes to `GET /ui/upstream-link-refused`, which says why, and nothing reaches
the client.

A signed-in account links a provider through an authorization request with
[`qauth_link=<type>`](/integrate/oauth-flow/#linking-an-upstream-account): the
provider first, then the same fresh sign-in. The pages of the Interaction API
off (`INTERACTION_UI_ENABLED`) offer no link, and create the account at once as
before.

## `/ui/resume/{handle}`

`GET /ui/resume/{handle}` is where a login round-trip lands after a
successful sign-in. It exchanges a single-use handle for the pending
`/oauth/authorize` URL and redirects there — see below for what the handle
is and why it exists. Resuming re-validates `client_id`, `redirect_uri`,
scope, PKCE, and step-up **from scratch**, exactly as on a first visit
(`apps/auth-server/src/app/routes/ui/resume.ts:124`); a resumed handle grants
nothing a fresh authorize request would not.

---

## The recovery-code pages

A recovery code stands in for a lost second factor after the password (#649;
ADR-017 Decision 8). Redemption, and showing a new set, happen only on the
hosted pages: the sign-in engine never offers either step to the first-party
login endpoint, which answers `redirect_to_web` instead. Two server-rendered
pages serve them for an interaction of the Interaction API, until the
design-system screens of #650 replace them:

- `GET /ui/recovery-code/{interactionId}`: "Use a recovery code", one field,
  with "That code did not work" after a refused one (the same for a wrong
  code, a used one and one of another set).
- `GET /ui/recovery-codes/{interactionId}`: "Save your recovery codes", the
  ten codes of a new set and a confirmation that they are saved. The codes
  are shown only to the browser whose flow cookie binds the interaction, and
  never to a page another site opened (`403`).

Both forms post to the Interaction API's answer endpoint
(`/interaction/v1-rc.0/{interactionId}/answer`) with the step, its CSRF value
and the answer, and work without JavaScript. An interaction at another step is
sent to its ceremony page (`303`); one that ended gets a page saying so
(`410`). Neither page puts a code in a URL, and both are sent with
`Cache-Control: no-store`.

A code is `xxxx-xxxx-xxxx-xxxx`, typed with any case, spaces and dashes. Each
works once, adds no `amr` value and never meets an MFA policy. Wrong codes are
counted on the account, whatever the transaction or the address: from five,
each attempt waits longer, up to 15 minutes, after a bot challenge. A code
used, a set regenerated and a run of 100 wrong codes (at most once a day) each
mail the account a notice that no realm can switch off.

---

## The passkey pages

A passkey is the strongest factor an account can bind (#651; ADR-017
Decisions 4 and 10). While passkey sign-in is on, the sign-in engine offers
it first: with no `login_hint`, the first step asks for a passkey and offers
the password and the identifier beside it; with one, it asks for the password
and offers the passkey. A login completes only after the account's strongest
bound factor, so after a right password an account that holds a passkey is
asked for it. On these pages `/oauth/authorize` starts a sign-in with no
`login_hint` at that first step, and one with a hint at the identifier step,
which the hint fills in. After a password sign-in, the engine may offer to add
one. Two server-rendered pages run the ceremonies for an interaction of the
Interaction API, until the design-system screens of #652 replace them:

- `GET /ui/passkey/{interactionId}`: "Sign in with a passkey", for the
  `webauthn_get` step, current or offered beside the password. Its options
  name no account. After a refused answer it says "That passkey did not
  work", the same whatever was wrong. "Sign in another way" links back to the
  interaction's ceremony page, for the password or the identifier.
- `GET /ui/passkey-enrolment/{interactionId}`: "Add a passkey", for the
  `webauthn_create` step, with "Not now" beside it. The options carry the
  account's name, so the page is shown only to the browser whose flow cookie
  binds the interaction, and never to a page another site opened (`403`).

Each page runs the browser's ceremony (`navigator.credentials.get()` or
`.create()`, so it needs JavaScript) and posts the credential's JSON as
`webauthn_response` to the Interaction API's answer endpoint with the step and
its CSRF value. The server refuses an assertion whose authenticator did not
verify the user. An interaction at another step is sent to its ceremony page
(`303`); one that ended gets a page saying so (`410`). Both are sent with
`Cache-Control: no-store`.

## The authenticator app's pages

An authenticator app (TOTP: RFC 6238 with SHA-1, six digits and a 30-second
step, one step of tolerance either way) is a second factor an account binds
(#653; ADR-017 Decisions 7 and 8, ADR-020 §3). After the first factor, an
account that holds one is asked for its code; under an MFA policy, an account
with no second factor is asked to set one up before the sign-in completes,
and is sent no code. Password then code gives `amr` `["pwd","otp","mfa"]`.
Two server-rendered pages serve the steps for an interaction of the
Interaction API, until the design-system screens of #654 replace them:

- `GET /ui/totp/{interactionId}`: "Enter the code from your authenticator
  app", for the `totp` step. After a refused answer it says "That code did not
  work", the same for a wrong code, a used one and a late one. When the step
  offers a recovery code in its place, "Use a recovery code instead" opens its
  form.
- `GET /ui/totp-setup/{interactionId}`: "Set up an authenticator app", for the
  `totp_setup` step: the new secret as a QR code of its `otpauth://` URI and
  as text, and the field for the first code. The secret is bound only once
  that code is valid, and that code stands for the sign-in's `totp` step. The
  secret is personal data, so the page is shown only to the browser whose
  flow cookie binds the interaction, and never to a page another site opened
  (`403`). The interaction record does not keep it: each read opens the
  sign-in's sealed copy again. An account whose address is not proved cannot bind one, and the
  first second factor of a password-only account also needs a code mailed to
  its address, unless the sign-in proved the mailbox already. The first
  binding issues a set of recovery codes.

Both work without JavaScript and post to the Interaction API's answer endpoint
with the step and its CSRF value. An interaction at another step is sent to
its ceremony page (`303`); one that ended gets a page saying so (`410`). Both
are sent with `Cache-Control: no-store`.

Wrong codes count per account, across transactions, clients and IP
addresses, and no successful password clears them: after the fifth in a row,
each attempt waits longer (up to 15 minutes), and an attempt that comes early
gets `429` without being checked. A wrong code after a right password mails
the account a notice, at most once a day. At 100 in a row, and only while
these pages are on and the account keeps an unused recovery code or another
usable second factor, the authenticator app is turned off and the account is
told. The next sign-in takes a recovery code in its place, then asks to set
up the app again before it completes. No realm can switch these notices off.

## The account pages

`/ui/account` is the signed-in person's own account (#844; ADR-017 Decision 8,
ADR-020 §3): their sign-in methods and their sessions, server-rendered in the
style of the pages above until the design-system account console replaces
them. The pages exist while the hosted pages do (`INTERACTION_UI_ENABLED`); with
the switch off, every path answers `404`. They are reached with the realm's
browser session: a browser with none is sent through a sign-in on the hosted
pages and comes back.

| Page or form                                                                    | What it does                                                                                                                                                   | Replaced by |
| ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `GET /ui/account`                                                               | The overview: the password, the passkeys, the authenticator app, the recovery codes, the linked upstream accounts and the live sessions, each with its actions | #685        |
| `GET` and `POST /ui/account/password`                                           | Change the password, with the current one, under the realm's password policy and breach list                                                                   | #685        |
| `POST /ui/account/passkeys/add`, `…/{passkeyId}/rename`, `…/{passkeyId}/remove` | Add a passkey through the enrolment step of the sign-in, rename one, remove one                                                                                | #686        |
| `POST /ui/account/totp/setup`, `/ui/account/totp/remove`                        | Set up an authenticator app through the set-up step of the sign-in, turn it off                                                                                | #687        |
| `POST /ui/account/recovery-codes/regenerate`, `…/confirm`                       | A new set of recovery codes, shown once; every code of the old set stops working                                                                               | #687        |
| `POST /ui/account/sessions/{sessionId}/end`, `/ui/account/sessions/end-all`     | Sign one session out, or sign out everywhere                                                                                                                   | #688        |
| `POST /ui/account/linked-accounts/link`, `…/{linkedAccountId}/unlink`           | Link an upstream account by signing in to it, unlink one                                                                                                       | —           |
| `POST /ui/account/reauthenticate`                                               | "Confirm it's you": a fresh sign-in, then back to the page                                                                                                     | —           |

Every action is a plain form that works without JavaScript, and every post is
checked in the same order before anything is read or changed: it comes from the
realm's origin (`Sec-Fetch-Site: same-origin`, or the realm's `Origin` when the
browser sends no fetch metadata), it carries the browser session, and it
carries the session's CSRF value. A post that fails the first or the last is
refused with `403` and recorded as `request.csrf_rejected`.

A change asks for the fresh authentication the account API asks of the same
operation (#663): a sign-in from the last five minutes with the account's
strongest bound factor, a passkey, else the authenticator app, else the
password. Removing a passkey or the app also takes a sign-in that used a
recovery code in place of the lost one; renaming a passkey and ending sessions
ask for none. A change refused for want of one answers `403` with "Confirm it's
you", which starts that sign-in and comes back. Adding a passkey, setting up an
app and linking an account are such a sign-in themselves, followed by the
binding step, with its own rules: a password-only account proves its mailbox
with a mailed code before its first second factor, and the first one issues a
recovery code set. A link attaches only the identity the provider proved to
the account the same interaction signed in to; nothing is matched by an email
address.

The pages keep an account usable. A removal that would leave no way to sign
in (an authenticator app is a second factor, never a way in on its own, and a
credential the failure ladder or a passkey rebind turned off counts as none) is
refused with `409`, and so is one that would leave no second factor where the
realm's MFA policy requires one. A new password ends the account's other
sessions and revokes every refresh token; this browser stays signed in. Ending a
session, one or all, tells every relying party it signed in to with a
back-channel logout URI. Each change is recorded as a user event:
`user.password_changed`, `user.credential_added`, `user.credential_removed`,
`user.passkey_renamed`, `user.recovery_codes_regenerated`,
`user.upstream_linked`, `user.upstream_unlinked` and `user.signed_out`. A
changed password, a removed passkey or authenticator app, a new recovery code
set and a linked or unlinked account mail the owner. No page puts a secret or a code in a URL, and every page is
sent with `Cache-Control: no-store`.

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
(`apps/auth-server/src/app/app.ts:931`) ahead of both route sweeps (lines 294
and 301), against the same `fastify.redis` client
(`apps/auth-server/src/app/plugins/rate-limit.ts:28`); `RATE_LIMIT_ENABLED`
defaults to `true` (`libs/server/config/src/lib/schemas/rate-limit.ts:41-44`);
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
  contract (methods, parameters, status codes) for these routes.
