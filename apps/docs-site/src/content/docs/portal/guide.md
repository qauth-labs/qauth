---
title: Portal guide
description: The developer portal's session model, required environment variables, and every flow it implements, each traced to its route and server action.
sidebar:
  order: 1
lastVerified: '2026-07-27'
---

`apps/developer-portal` (Nx project `developer-portal`) is a TanStack Start + React 19
application. It is where a developer registers an account, verifies their email, logs in, and
manages the OAuth clients they use against the auth-server. This page describes what is in the
tree today; there is no prior prose on this app to lean on, so every claim below is traced to a
file.

## The session model

The portal owns its own session — it does not reuse the auth-server's hosted-UI session cookie
(see [the consents page](#the-consents-page-and-a-cookie-mismatch) below for the one flow where
that distinction matters). The session lives in an `HttpOnly`, signed, `__Host-` prefixed cookie,
and the property worth understanding before extending this app is that **tokens never reach the
browser**: every call to the auth-server is made from a TanStack Start server function, running
on the server, and the browser only ever holds the signed cookie.

- **Cookie name**: `__Host-qauth_portal_session`
  (`apps/developer-portal/src/server/session-cookie.ts:5`).
- **Payload**: `{ accessToken, refreshToken, expiresAt }`
  (`apps/developer-portal/src/server/session-cookie.ts:7`, the `PortalSessionPayload` interface).
- **Signing**: HMAC-SHA256 over the base64url-encoded payload, compared with `timingSafeEqual`
  on verification — `createHmac('sha256', secret).update(value).digest('base64url')`
  (`apps/developer-portal/src/server/session-cookie.ts:25`) and the constant-time comparison at
  `apps/developer-portal/src/server/session-cookie.ts:45`. The signature is not encryption: the
  payload is base64url, not encrypted, so it is unreadable-by-accident but not confidential
  against anyone who can read the cookie value directly (nobody but the browser and the portal's
  own server should be able to).
- **Cookie attributes**: `Path=/`, `HttpOnly`, `Secure`, `SameSite=Lax`, and
  `Max-Age=<PORTAL_SESSION_TTL>`, set in `setSessionCookieHeader`
  (`apps/developer-portal/src/server/session-cookie.ts:61`, the `Max-Age` line itself is
  `apps/developer-portal/src/server/session-cookie.ts:69`).
  `Secure` is always emitted regardless of environment — the code comment at
  `apps/developer-portal/src/server/session-cookie.ts:56` notes that the `__Host-` prefix
  requires it per RFC 6265bis §4.1.3.2, and browsers reject the `Set-Cookie` header outright
  without it, even on `localhost`. Developing over plain HTTP therefore requires looping back
  through `localhost` (which browsers treat as a secure context) or a TLS-terminating proxy.
- **TTL**: `PORTAL_SESSION_TTL`, an environment variable defaulting to `900` seconds
  (`apps/developer-portal/src/server/config.ts:3`) — this is the cookie's `Max-Age`, i.e. how
  long the browser keeps the cookie at all.

That TTL is a separate number from the `expiresAt` field inside the payload. `expiresAt` is
computed at login as `Date.now() + result.data.expires_in * 1000`
(`apps/developer-portal/src/server/actions/login.server.ts:16`) — the auth-server's own access
token lifetime, not `PORTAL_SESSION_TTL`. Every server function that needs the current user reads
the cookie and separately checks `Date.now() >= session.expiresAt`
(e.g. `apps/developer-portal/src/server/actions/current-user.server.ts:14`) before trusting the
access token inside it, so a cookie that outlives the token it carries is still treated as
expired.

The payload also carries a `refreshToken`, but nothing in the portal currently reads it back out
to refresh an expired access token. The comment directly above that expiry check says so:

> Refresh-token rotation lives in Phase 2.x; for now an expired session bounces the user to
> `/login`.
> — `apps/developer-portal/src/server/actions/current-user.server.ts:12`

So today, once `expiresAt` passes, the developer is signed out and has to log in again — the
stored `refreshToken` is inert.

**Login** (`apps/developer-portal/src/server/actions/login.server.ts`) calls
`authServerClient.login` (`apps/developer-portal/src/server/actions/login.server.ts:13`), a JSON
`fetch` to the auth-server's `/auth/login`, and on success sets the session cookie via
`setSessionCookieHeader` (`apps/developer-portal/src/server/actions/login.server.ts:20`).
**Logout** (`apps/developer-portal/src/server/actions/logout.server.ts`) reads the current
session, calls the auth-server's `/auth/logout` with the access token
(`apps/developer-portal/src/server/actions/logout.server.ts:11`), and always clears the cookie
(`apps/developer-portal/src/server/actions/logout.server.ts:14`) — even if the upstream call
fails, the developer's browser stops holding a session.

Every route under `_authed` (`apps/developer-portal/src/routes/_authed.tsx`) gates on this same
cookie: `beforeLoad` calls `currentUserFn` and redirects to `/login` when it returns `null`
(`apps/developer-portal/src/routes/_authed.tsx:9`).

## Environment variables

Three environment variables are required or configurable server-side
(`apps/developer-portal/src/server/config.ts`):

| Variable                | Required | Default | What it does                                                                                                            |
| ----------------------- | -------- | ------- | ----------------------------------------------------------------------------------------------------------------------- |
| `AUTH_SERVER_URL`       | Yes      | —       | Base URL of the auth-server the portal's server functions call. Read at `apps/developer-portal/src/server/config.ts:1`. |
| `PORTAL_SESSION_SECRET` | Yes      | —       | HMAC-SHA256 key used to sign and verify the session cookie. Read at `apps/developer-portal/src/server/config.ts:2`.     |
| `PORTAL_SESSION_TTL`    | No       | `900`   | Session cookie `Max-Age` in seconds. Parsed at `apps/developer-portal/src/server/config.ts:3`.                          |

`AUTH_SERVER_URL` and `PORTAL_SESSION_SECRET` are enforced at startup: `config.ts` throws if
either is missing, but only when running server-side (`import.meta.env.SSR`,
`apps/developer-portal/src/server/config.ts:9`) — the comment there explains why: this
module can be pulled into a client bundle chunk via the server actions, where `process.env` is
always empty, so the check is scoped to avoid a false failure in the browser.

## Flows

### Register → verify → login → logout

- **Register** (`/register`, `apps/developer-portal/src/routes/register.tsx`) submits email and
  password through `registerFn` → `registerHandler`
  (`apps/developer-portal/src/server/actions/register.ts:5`), which calls the auth-server's
  `/auth/register`. On success the page shows a "check your inbox" screen with a resend option;
  it does not log the developer in.
- **Verify** (`/verify?token=...`, `apps/developer-portal/src/routes/verify.tsx`) validates the
  token shape client-side (64 hex characters, `apps/developer-portal/src/routes/verify.tsx:9`)
  before calling `verifyFn` (`apps/developer-portal/src/server/actions/verify.ts:13`), which
  hits the auth-server's `/auth/verify`.
- **Login** (`/login`, `apps/developer-portal/src/routes/login.tsx`) — see the session model
  above. On failure the page always shows the same generic "Invalid email or password" message
  regardless of the underlying error code, an explicit anti-enumeration choice
  (`apps/developer-portal/src/routes/login.tsx:39`). The page also has a "Forgot password?
  Coming soon." line (`apps/developer-portal/src/routes/login.tsx:72`) — there is no
  password-reset endpoint anywhere in `apps/auth-server`, so that line is accurate as written,
  not a stale claim.
- **Logout** is a button in the authed layout's header
  (`apps/developer-portal/src/routes/_authed.tsx:35`) that calls `logoutFn` and navigates
  to `/login`.

### OAuth client management

All of `/clients` sits under the `_authed` layout.

- **List** (`/clients`, `apps/developer-portal/src/routes/_authed/clients.index.tsx`) calls
  `listClientsFn` on mount and renders one card per client.
- **Create** (`/clients/new`, `apps/developer-portal/src/routes/_authed/clients.new.tsx`) submits
  a form to `createClientFn`; on success it shows the one-time secret reveal (below) before
  routing to the new client's detail page.
- **Detail** (`/clients/$clientId`,
  `apps/developer-portal/src/routes/_authed/clients.$clientId.tsx`) loads one client via
  `getClientFn` and is also where edit, delete, secret regeneration, and API-key management all
  live.
- **Edit** is the same detail page in an editing state, submitting to `updateClientFn`
  (`apps/developer-portal/src/routes/_authed/clients.$clientId.tsx:72`, the `handleSave`
  function).
- **Delete** is a confirmation modal calling `deleteClientFn`
  (`apps/developer-portal/src/routes/_authed/clients.$clientId.tsx:99`, the `handleDelete`
  function); the modal's own copy says the deletion "cannot be undone."

Every client-management server function (`apps/developer-portal/src/server/actions/clients.server.ts`)
follows the same shape: read the access token out of the signed session cookie
(`apps/developer-portal/src/server/actions/clients.server.ts:20`), return an `UNAUTHENTICATED`
result if it's missing or expired, and
otherwise proxy the call to the auth-server with `Authorization: Bearer <token>`. The access
token is attached server-side on every request; the browser never sees it.

### The one-time secret reveal and regeneration

A confidential client's secret is shown exactly once — at creation
(`apps/developer-portal/src/routes/_authed/clients.new.tsx:83`, the `SecretReveal` render) or
after a regeneration (`apps/developer-portal/src/routes/_authed/clients.$clientId.tsx:324`) —
through the shared
`SecretReveal` component (`apps/developer-portal/src/components/secret-reveal.tsx`). Its own
doc comment states the mechanism plainly:

> Renders inside a non-dismissible modal so the developer cannot lose the secret by clicking the
> backdrop. The secret is passed in as a prop and never written to any store — when the parent
> removes this component the value is gone.
> — `apps/developer-portal/src/components/secret-reveal.tsx:21`

There is no "view secret again" affordance anywhere in the client-detail page: once the reveal
modal closes, the detail view only ever shows "Hidden. Secrets are shown only once, at creation
or regeneration." (`apps/developer-portal/src/routes/_authed/clients.$clientId.tsx:202`). A public
client (`tokenEndpointAuthMethod === 'none'`) has no secret to show at all
(`apps/developer-portal/src/routes/_authed/clients.$clientId.tsx:201`).
**Regenerating** a secret (behind a confirmation modal warning that existing integrations break
immediately) invalidates the old one and re-triggers the same one-time reveal.

The absence of a "view again" button is a UI convenience, not the guarantee. "Never retrievable"
is enforced two levels below it, and neither is client-side:

- **At the type level**, the portal's own client for `/api/clients` distinguishes the two shapes.
  `OAuthClient` (`apps/developer-portal/src/server/auth-server-client.ts:71`) — what every list
  and get call returns — has no `clientSecret` field at all; the comment above it says why:
  "deliberately absent here — it only exists on {@link ClientWithSecret}"
  (`apps/developer-portal/src/server/auth-server-client.ts:62`). `ClientWithSecret`
  (`apps/developer-portal/src/server/auth-server-client.ts:141`) is a distinct type, returned
  **only** by the create and regenerate calls
  (`apps/developer-portal/src/server/auth-server-client.ts:137`). There is no portal API call
  that can ask for a client and get a secret back outside those two responses — the type the
  other calls return cannot carry one.
- **On the auth-server**, where the actual guarantee is enforced: `POST /api/clients` generates
  the secret, hashes it with Argon2id, and keeps the plaintext only in a local variable
  (`generateClientSecret`, `apps/auth-server/src/app/routes/clients/index.ts:269`). Only
  `clientSecretHash` is passed to the repository's `create` call
  (`apps/auth-server/src/app/routes/clients/index.ts:439`); the plaintext is spread into the
  HTTP response once (`apps/auth-server/src/app/routes/clients/index.ts:480`) and then goes out
  of scope. Regeneration is the same shape: only the new `hash` is persisted
  (`apps/auth-server/src/app/routes/clients/index.ts:673`), and the plaintext is returned once
  (`apps/auth-server/src/app/routes/clients/index.ts:694`). No code path — in the portal or the
  auth-server — reads a plaintext secret back out of storage, because no plaintext secret is
  ever stored.

So a portal contributor who "improves" `SecretReveal` to add a persistence layer would not
weaken this guarantee — they'd just be caching a value the auth-server never lets them fetch
again. The enforcement that matters lives in the response shapes and the database column, not in
this component.

### API keys

Static developer API keys let a client authenticate without the full OAuth flow, and — per
ADR-008 — they are environment-gated: only a client whose effective environment resolves to
`development` may mint one (see
[Environment-Aware Authorization](/operate/environment-authorization/#static-developer-api-keys)
for the resolver). This shipped as issues #97 (backend) and #98 (portal UI), and the code is in
the tree today: `apps/developer-portal/src/components/api-keys-section.tsx`.

The management UI is **not** a standalone page — it is a section embedded in the client-detail
page, rendered under the client's own fields
(`apps/developer-portal/src/routes/_authed/clients.$clientId.tsx:222`). Its own doc comment
describes the gate:

> Environment gating: the create form renders ONLY when `client.staticApiKeysAllowed` is true (a
> `development` client). For a `staging`/`production` client the form is replaced with guidance
> to use the OAuth `client_credentials` grant. As defense-in-depth, a `403` from the mint endpoint
> is still handled gracefully (it surfaces the same guidance), so the UI stays correct even if the
> gate flag is stale.
> — `apps/developer-portal/src/components/api-keys-section.tsx:30`

A newly created key's plaintext is shown once, in the same non-dismissible-modal pattern as the
client secret (`apps/developer-portal/src/components/api-keys-section.tsx:263`); the list
view afterwards only ever shows the masked `prefix…last4` form. Revoking a key
(`apps/developer-portal/src/components/api-keys-section.tsx:99`, the `handleRevoke` function) is
an idempotent soft-delete — a revoked key is still listed, marked "Revoked," and cannot
authenticate again.

### The consents page

`/consents` (`apps/developer-portal/src/routes/consents.tsx`) lists the OAuth clients a developer
has granted access to and lets them revoke a grant. Its own doc comment explains the intent:

> A user lands here from account settings, sees the apps they have authorized, and can take back
> any grant. Revoking a row forces a fresh consent prompt the next time the app tries
> `/oauth/authorize`.
> — `apps/developer-portal/src/routes/consents.tsx:9`

#### The consents page and a cookie mismatch

Unlike every other authenticated page in this app, `/consents` does not go through a TanStack
Start server function. It calls `fetch()` directly from the browser against the auth-server, with
`credentials: 'include'` (`apps/developer-portal/src/routes/consents.tsx:45` for the list
call, `apps/developer-portal/src/routes/consents.tsx:70` for revoke), reading `AUTH_SERVER_URL`
from the client-exposed `VITE_AUTH_SERVER_URL`
(`apps/developer-portal/src/routes/consents.tsx:32`) rather than the server-only
`AUTH_SERVER_URL` this page documents above. That is the opposite of the "server functions are
the only callers of auth-server endpoints" property described at the top of this page — on this
one page, the browser talks to the auth-server directly.

The component's own comment says why it expects that to work: `credentials: 'include'` "so the
browser sends the `__Host-qauth_session` cookie to the auth-server even on cross-origin
deployments" (`apps/developer-portal/src/routes/consents.tsx:14`). `__Host-qauth_session` is
real — it is the auth-server's own session cookie, set by `POST /ui/login`
(`apps/auth-server/src/app/routes/ui/login.ts:218`, and see
[Hosted UI](/integrate/hosted-ui/#uilogin)). But the developer portal's own login flow never
visits `/ui/login`. It calls the JSON API `POST /auth/login` from a server function (see
[the session model](#the-session-model) above) and stores the result in
`__Host-qauth_portal_session` — a different cookie, on the same origin as this app, not the
auth-server's origin. A developer who signs in through this portal's own `/login` page has never
had a `__Host-qauth_session` cookie set for the auth-server's origin, so a browser visiting
`/consents` after that login has nothing to send: the auth-server answers `401`, and the page
shows "Please sign in to manage authorized applications" — the signed-out message — to a
developer who is, by every other page in this app, signed in.

The portal never sending a developer through `/ui/login` is not the only blocker, and fixing just
that would not make this page work. Two more hold independently, even for a browser that somehow
already carries `__Host-qauth_session`:

- **`SameSite=Lax`.** The auth-server's session cookie is set with `SameSite=Lax`
  (`apps/auth-server/src/app/helpers/session-cookie.ts:153`). `Lax` cookies are not attached to
  cross-site `fetch()` subresource requests — only to top-level navigations — regardless of
  `credentials: 'include'`. A `fetch()` from the portal's origin to the auth-server's origin is
  exactly the request shape `Lax` withholds the cookie from.
- **CORS is fail-closed in production.** `cors` is registered with
  `origin: corsOrigins.length > 0 ? corsOrigins : env.NODE_ENV === 'production' ? false : '*'`
  (`apps/auth-server/src/app/app.ts:255`) — `false` unless an operator sets `CORS_ORIGIN`. The
  comment immediately above it (`apps/auth-server/src/app/app.ts:238`) says the assumption
  behind the default is that "the JSON API is called by the same-origin developer portal." This
  page's direct browser `fetch()` is the one call site that isn't.

And the shipped topology is cross-origin to begin with: [Docker](/operate/docker/#developer-portal)
documents `auth-server` and `developer-portal` as separate Compose services on different ports.
A same-origin deployment where all three of these happened to line up — same origin, so no CORS
or `SameSite` boundary to cross, _and_ a browser that had separately visited `/ui/login` — is not
impossible, but it is not the topology this repository's own docs describe, and it does not
describe how a developer reaches `/consents` through this portal's own login flow. Treat
`/consents` as not working from this portal as shipped, rather than working under an unstated
deployment assumption.

## See also

- [Known gaps](/portal/known-gaps/) — the dashboard's stale API-keys card and `/consents` being
  unlinked.
- [Environment-Aware Authorization](/operate/environment-authorization/) — the ADR-008 policy
  that gates static API keys.
- [Hosted UI](/integrate/hosted-ui/) — `/ui/login`, `/ui/consent`, and the `__Host-qauth_session`
  cookie the consents page (above) depends on.
- [Docker](/operate/docker/#developer-portal) — how the portal is deployed and where
  `AUTH_SERVER_URL` / `VITE_AUTH_SERVER_URL` point in that setup.
