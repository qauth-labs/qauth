---
title: API Reference
description: Hand-written reference for every path in QAuth's committed OpenAPI spec.
sidebar:
  order: 4
lastVerified: '2026-11-02'
---

Hand-written reference for QAuth's HTTP endpoints. The **authoritative, always-current**
contract is the interactive OpenAPI / Swagger UI served at /docs on any running
instance — this page is a stable, linkable companion. The same contract is also
published as a static file: [`openapi.json`](https://docs.qauth.dev/openapi.json).

For step-by-step flows with copy-paste `curl`, see the [OAuth 2.1 Flow](/integrate/oauth-flow/)
guide; for working client code, see [Code Examples](/integrate/code-examples/); for the
login/consent/resume screens an end user sees, see [Hosted UI](/integrate/hosted-ui/).

**Conventions**

- Base URL / issuer: `http://localhost:3000` (your `JWT_ISSUER`).
- First-party auth, client-management, and hosted-UI bodies are **JSON**
  (`application/json`) with **camelCase** fields. OAuth wire endpoints (the OAuth 2.1
  section below) use **`application/x-www-form-urlencoded`** with **snake_case** per the RFCs.
- Access tokens are **EdDSA (Ed25519)** JWTs; verify against
  `GET /.well-known/jwks.json`.
- Path parameters are written in OpenAPI's `{param}` style below (matching
  `openapi.json`), not the `:param` style the Fastify route files use internally.

## Error model

QAuth answers an error in one of two formats (ADR-019 Decision 7). Branch on the machine-readable
member and the HTTP status, never on the wording, which may change.

**Problem documents.** Every route that is not an OAuth protocol endpoint (first-party auth,
client management, consents, the hosted UI, the well-known documents and any path no route serves)
answers with an RFC 9457 problem details document, sent as `application/problem+json`:

```json
{
  "type": "https://docs.qauth.dev/reference/problem-types/#validation-error",
  "title": "Validation error",
  "status": 400,
  "detail": "The request is not valid.",
  "instance": "/auth/login",
  "code": "validation_error",
  "trace_id": "7d1c2e9a-5b8f-4f3e-9c6a-1e2d3f4a5b6c",
  "errors": [{ "pointer": "/email", "message": "Invalid email address" }]
}
```

- `code` is the stable, machine-readable name of the error. The list of codes, with each one's
  `type`, status and title, is on [Problem types](/reference/problem-types/).
- `trace_id` is the id the server logged the request under, the `X-Request-Id` the response also
  carries (the header `REQUEST_ID_HEADER` names), on every answer, the 404 of a path no route
  serves and a request the server could not read included. Quote it when you report a failure.
- `errors` names each field a validation failure rejected: `pointer` is an RFC 6901 JSON Pointer
  into the body or the parameters, and `message` says what is wrong with it. The validator's own
  issue objects also carry the schema path, the rule keyword and a parameter bag, and those
  describe how QAuth is built rather than what it accepts, so they are not returned. At most 20
  entries are returned. An array longer than its limit is one entry for the array as a whole; its
  elements are not checked. A weak password's feedback arrives as entries whose pointer names the
  password field.
- A 5xx carries no `detail`. A 401 or 403 from a route that takes a bearer token also carries a
  `WWW-Authenticate` challenge (RFC 6750 §3): `error="invalid_token"` for a token that was
  presented and refused (`invalid_access_token`, `access_token_expired`), and no error code for a
  request that presented none (`unauthorized`).

**OAuth error bodies.** The OAuth protocol endpoints answer with the body their specification
defines, `application/json` with only `error` and, where there is something to say,
`error_description`: the authorization, token, introspection, revocation, dynamic registration and
userinfo endpoints and the wallet-facing OID4VP endpoints.

```json
{ "error": "invalid_client", "error_description": "CIMD document is not valid JSON" }
```

`error` is the registered code (RFC 6749 §5.2, RFC 7591 §3.2.2, RFC 6750 §3.1); the codes are
listed in [OAuth 2.1 Flow → Errors](/integrate/oauth-flow/#errors). `error_description` is omitted
where describing the failure would be an enumeration oracle: client authentication failures answer
with the bare `invalid_client`. The `Retry-After` and `WWW-Authenticate` headers are sent as before.

| Status | Meaning                                                                                             |
| ------ | --------------------------------------------------------------------------------------------------- |
| `400`  | Malformed request / validation error                                                                |
| `401`  | Missing, malformed, or invalid bearer token / session                                               |
| `403`  | Authenticated but not permitted (e.g. insufficient scope)                                           |
| `404`  | Resource not found                                                                                  |
| `409`  | Conflict (e.g. a resource that must be unique)                                                      |
| `429`  | Rate limited                                                                                        |
| `503`  | Too busy to check a client secret now; `Retry-After` says when to retry (`temporarily_unavailable`) |

---

## System

Unauthenticated operational endpoints.

### `GET /`

Root endpoint. Returns a fixed greeting to verify the server is running.

**`200 OK`**: `{ "message": "Hello API" }`

### `GET /health`

Liveness probe. Answers on any host, checks no dependency, and names the
service roles the process runs.

**`200 OK`**:

```json
{
  "status": "ok",
  "timestamp": "2026-07-27T00:00:00.000Z",
  "roles": ["web", "api", "admin", "signer", "delivery"]
}
```

### `GET /ready`

Readiness probe. Answers on any host and runs the checks the process's roles
need: `database` on every role, `redis` on `web`, `api` and `admin`, `kek` on
`signer` and `outbox` on `delivery`.

**`200 OK`** (every check passed):

```json
{
  "status": "ok",
  "roles": ["api"],
  "checks": { "database": { "status": "ok" }, "redis": { "status": "ok" } }
}
```

**`503 Service Unavailable`**: a problem document with the code
`service_unavailable`, whose `detail` names the failed checks and whose
extension members `roles` and `checks` carry what the `200` answer carries,
each failed check as `{ "status": "fail", "reason": "error" }` or
`"reason": "timeout"`.

Both are rate-limited per client address. The Prometheus metrics are not on
this port: they are served on the internal listener (see
[Observability](/operate/observability/#who-can-read-the-metrics)).

---

## First-party authentication

Email/password endpoints for **end users of your own application**. Third-party
/ MCP clients use the [OAuth endpoints](#oauth-21) instead.

### `POST /auth/register`

Register a password account. The answer is the same for every address, whether
it was free or already has an account, so it reveals neither. What happens next
arrives by email (the `mock` provider delivers nothing):

- A free address gets an unverified account and a verification link.
- An address that already has a verified account gets no new account. Its owner
  gets a notice that someone tried to register it, with no link in it.
- An address whose account is still unverified gets its verification link
  again. The link verifies only with the password chosen when the account was
  first registered (see [`POST /auth/verify`](#post-authverify)).

A mail to an existing account counts toward the same per-address caps as
[`POST /auth/resend-verification`](#post-authresend-verification), and every
registration claims the minimum interval there, so a resend right after a
registration answers `429` for any address. A new account's verification mail is
always sent.

**Request** (`application/json`)

| Field      | Type           | Required | Notes                                        |
| ---------- | -------------- | -------- | -------------------------------------------- |
| `email`    | string (email) | yes      | At most 254 characters (RFC 5321).           |
| `password` | string         | yes      | The realm's password policy applies (below). |
| `realmId`  | string (uuid)  | no       | Must be the realm of the request's host.     |

**`202 Accepted`** (`Cache-Control: no-store`)

```json
{ "message": "Registration received. Check your inbox for an email with the next step." }
```

The body carries no user id: anything that differed between a new account and an
existing one would answer the question this endpoint must not. Show a "check your
inbox" screen, never "account created" or "address taken". While the realm
requires verified accounts (`accounts.requireVerifiedAccount`, the default), the
account can sign in only after
its owner has verified it; until then [`POST /auth/login`](#post-authlogin)
answers it with the same `401` as a wrong password.

The account is created in the realm of the host the request names. A `realmId`
in the body picks no other realm: any value but that realm's id is refused.

The password must meet the realm's password policy (ADR-017 Decision 8): at
least `password.minLength` characters (15 by default), counted after Unicode
NFC normalisation; at most 256 UTF-16 code units as typed; not, as a whole and
ignoring case, a common word or password, the address, its local part or
domain, or the service's or realm's name; and a zxcvbn score of at least
`password.minScore` (2 by default). No mix of character types is required.
Mark the fields for password managers: `autocomplete="username"` on the
address and `autocomplete="new-password"` on the password.

Errors: `400` (validation, a password over 256 UTF-16 code units among it, or
a `realmId` that is not the host's realm), `422` (`weak_password`, whose
`reasons` list why the password was refused: `too_short`, `blocklisted`,
`too_weak`; `errors` carries a message for each, whose pointer names the
password field), `429` (rate limited). None of them depends on
whether the address is registered. Before 2026-10-19 this endpoint answered `201`
with the new user and `409` for a registered address (breaking change, listed in
`CHANGELOG.md`).

### `POST /auth/login`

Authenticate with email/password and receive tokens directly (first-party).

**Request** (`application/json`): `{ "email": "...", "password": "..." }`. The
address is at most 254 characters.

**`200 OK`**

```json
{
  "access_token": "eyJ…",
  "refresh_token": "a1b2…(64 hex)",
  "expires_in": 900,
  "token_type": "Bearer"
}
```

The access token is issued to the system client, its `aud` is the developer
API's audience, `urn:qauth:aud:developer:v1-rc.0` (#524), and its `scope` is
`qauth:developer:read qauth:developer:write` (#933): it reaches the
[Developer API](#developer-api-developer-family-v1-rc0), the deprecated
`/api/clients/` and `/api/consents/`, userinfo and `POST /auth/logout`. A token
minted before #524, whose `aud` was the system client's id, is refused there, so
its developer signs in again (see
[API conventions](/reference/api-conventions/#issuing-a-family-audience)). It
is not a sign-in at `GET /oauth/authorize`, which takes only the browser session.

Errors: `400` (validation), `401` (invalid credentials), `429` (rate limited,
locked out, or inside the account's wait on the
[per-account failure ladder](/operate/observability/#per-account-failure-ladder);
with `Retry-After`), `503` (the failure ladder's store is unavailable; nothing
was checked; `Retry-After: 5`).
The `401` is the same for an unknown address, a wrong password, a disabled
account and, while the realm requires verified accounts
(`accounts.requireVerifiedAccount`, the default), an account whose
address is not verified yet: registering an address and then logging in must not
tell a free address from a registered one.
Renew the access token with the [`refresh_token` grant](/integrate/oauth-flow/#refresh-token-rotation)
at `POST /oauth/token` — there is no separate refresh endpoint.

### `POST /auth/logout`

Sign the user out everywhere. Ends the user's hosted browser sessions (from
`/ui/login` or wallet login, so `/oauth/authorize` shows the login page again),
revokes every refresh token the user holds, at every client, invalidates the
user's unredeemed authorization codes, and denylists the access token the
request was made with. Access tokens already
issued to other clients are not reached: they stay valid until they expire (see
[what revocation reaches](/integrate/oauth-flow/#what-revocation-reaches)).

**Headers**: `Authorization: Bearer <access_token>` (required). Only the access
token from [`POST /auth/login`](#post-authlogin) is accepted, expired or not. A
token issued to any other client or audience is refused.

**`200 OK`**: `{ "success": true, "message": "Successfully logged out" }`

Errors: `401` (missing/invalid bearer, or a token whose user no longer exists).

### `POST /auth/verify`

Confirm an email address with the token from the verification email and the
account's password. The token proves control of the mailbox. The password proves
the person who registered. Both are required, so someone who registered with
another person's address cannot get it verified by that person clicking a link.
This is a POST, so no fetch or prefetch of the emailed link can verify an address
by itself. The emailed link opens [`GET /auth/verify`](#get-authverify), a page
that asks for the password; the developer portal's verification page calls this
route the same way.

**Body**: `{ "token": "<64-char hex string>", "password": "<the account's password>" }`

**`200 OK`**: `{ "message": "...", "email": "dev@example.com" }`

Errors: `400` (malformed token, or an unknown, expired or used token: one
answer for all of them), `401` `INVALID_CREDENTIALS` (wrong password; the token
is not consumed, so the request can be retried), `409` (the address is already
verified), `429` (rate limited, or the account is locked out: wrong passwords
here count toward the same failed-login lockout and per-account failure ladder
as `POST /auth/login`, and the `429` carries `Retry-After`), `503` (the failure
ladder's store is unavailable; the password was not checked; `Retry-After: 5`).

### `GET /auth/verify`

The page the verification email links to: `<issuer>/auth/verify?token=<64-char hex>`,
where `<issuer>` is the issuer of the account's realm. The link verifies only at
a host of that realm. The GET does not look the token up, so at another realm's
host it still renders the form (`200`); submitting it there answers `400`, as for
an unknown token, because `POST /ui/verify` looks the token up in the realm the
request's host names.
A mail client opens the link with GET, so this page is what a person sees. It
holds the token in a hidden field and asks for the account's password; opening
it verifies nothing and reads nothing from the database, so a mail gateway's
link scanner or a browser prefetch cannot verify an address. The form posts to
`POST /ui/verify` (below), which verifies through the same code as
[`POST /auth/verify`](#post-authverify).

**Query**: `token` — the 64-character hex token. A missing or malformed token
gets a `400` page that says the link is incomplete, with no form.

**`200 OK`**: `text/html` page with the form. It sets the signed
`__Host-qauth_login_csrf` cookie the form's double-submit CSRF check needs, the
same cookie as [`/ui/login`](/integrate/hosted-ui/#uilogin).

Every answer carries `Cache-Control: no-store` and `Referrer-Policy: no-referrer`,
and the request log censors the `token` value. A `browser` route: it answers on
the realm's primary host only (`421` on an endpoint host).

**`POST /ui/verify`** (`application/x-www-form-urlencoded`: `token`, `password`,
`csrf_token`) answers a page with the status `POST /auth/verify` answers for the
same outcome:

| Status | Outcome                                                                                        |
| ------ | ---------------------------------------------------------------------------------------------- |
| `200`  | Verified. The account can sign in.                                                             |
| `400`  | Unknown, expired or used token (one page for all), or a malformed body.                        |
| `401`  | Wrong password. The form stays; nothing is consumed.                                           |
| `403`  | CSRF pair missing or mismatched. The form comes back with a fresh token.                       |
| `409`  | The address is already verified.                                                               |
| `429`  | Rate limited, or locked out by the failed-login lockout or the failure ladder (`Retry-After`). |
| `503`  | The failure ladder's store is unavailable; nothing was checked (`Retry-After`).                |

It has the rate limit of `POST /auth/verify`, and wrong passwords count toward
the same failed-login lockout and failure ladder. This page is interim: the email-code step (#638)
and the hosted account verification UI (#644) replace link verification.

### `POST /auth/resend-verification`

Re-send the verification email. Rate-limited per address (min-interval +
per-window caps). [`POST /auth/register`](#post-authregister) counts toward the
same caps.

**Request** (`application/json`): `{ "email": "dev@example.com" }`

**`200 OK`**: `{ "message": "..." }` — returned even for unknown addresses
(no account enumeration). Errors: `400` (not an address, or longer than 254
characters), `429` (too soon / over limit).

### `POST /auth/link/wallet`

Start linking a wallet credential to the **signed-in** account (issue #238,
[ADR-004](/reference/records/adr/004-wallet-agnostic-federation/) /
[ADR-009](/reference/records/adr/009-wallet-account-resolution/) §5). Registered
only when `WALLET_FEDERATION_ENABLED` is on; otherwise the path does not exist
(`404`).

Requires a valid `__Host-qauth_session` cookie **and** an `X-CSRF-Token` header
matching the per-session token returned by `GET /consents/`.

**Request** (`application/json`, optional): `{ "device": "this" }`. Linking is
**same-device only** ([ADR-013](/reference/records/adr/013-same-device-return-leg/),
amended 2026-11-07): the wallet must be on the device the browser runs on.
Render `invocation_uri` as a deep link; the link completes on the browser's
return leg at `GET /ui/wallet-login/return`, never by polling. `this`, an empty
body, or no body at all are the same request. `"device": "other"`, the
cross-device mode this endpoint accepted before, is refused with `400`
`validation_error`, whose `errors` entry points at the `device` member, as is
any other value. The
generated OpenAPI document marks this request body as required — the
generator's default for any declared body schema — but a `POST` with no body at
all is accepted.

**`200 OK`**: `{ "handle": "...", "invocation_uri": "openid4vp://...", "expires_at": 1730000000000 }`
— render `invocation_uri` as a deep link ("Open my wallet"); it is opaque.
Errors: `401` (no session), `400` (`invalid_csrf_token`, or a `device` other
than `this`: `validation_error`), `404` (no usable `VerifierProfile`), `500`.

### `GET /auth/link/wallet/{handle}`

Poll a linking flow, and complete it once the wallet has responded. Requires the
session cookie and the browser-binder cookie minted by the `POST` above; the
session must be the **same user** that started the flow.

**`200 OK`**: `{ "status": "pending" | "linked" | "conflict" | "expired" | "rejected", "message"?: "..." }`

On `linked`, a second `user_credentials` row (`provider_type='wallet'`) now
exists under the same `users.id`, keyed on the identifier the account already
owned — so a later wallet sign-in returns tokens with the identical `sub`. This
poll never completes a link: it answers `pending` after the wallet has
responded, `linked` **once** after the return leg has completed it in the same
browser, and `rejected` if the redirect has not landed within 180 s or landed
in a different browser (#405). A cross-device link flow started before the
2026-11-07 change is answered `rejected`, and nothing is linked.
`conflict` is the one specific outcome (the credential belongs to another
account) and is only reachable under the `issuer-scoped-claim` strategy; every
other failure renders one uniform refusal. See
[Wallet sign-in](/integrate/wallet-login/#account-linking-238).

### `GET /auth/pass`

The page a mailed pass link opens: `<issuer>/auth/pass?pass=<43-char base64url>`,
where `<issuer>` is the issuer of the account's realm. The send-ceiling notice
and the password-disabled notice carry it. The pass is single use, bound to the
address it was mailed to and valid 24 hours. It takes one reset or registration
start on the hosted pages past every per-address send cap; the code that start
mails is still required.

Opening the link does not spend the pass: it starts an interaction in this
browser, with a flow cookie of its own, that holds the pass's hash, and answers
`303` to the interaction's ceremony page, whose path names the interaction id
and nothing else. Only the start the interaction carries spends the pass, so a
mail gateway's link scanner or a browser prefetch spends nothing. A reset starts at the `password_reset` step, a
registration at the `identifier` step. Until the hosted reset and registration
are built, the interaction can be read but not answered.

**Query**: `pass` — the mailed pass. A missing, malformed, unknown, used or
expired pass, or one of another realm, gets one `400` HTML page and no
interaction. Every answer carries `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`, and the request log censors the `pass` value.

---

## OAuth 2.1

Full request/response detail and a worked end-to-end walkthrough live in the
[OAuth 2.1 Flow](/integrate/oauth-flow/) guide. Contract summary:

| Endpoint                                                                           | Method    | Body type    | Purpose                                                                                                                                            |
| ---------------------------------------------------------------------------------- | --------- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`/oauth/authorize`](/integrate/oauth-flow/#2-redirect-the-user-to-oauthauthorize) | GET, POST | query / form | Start `authorization_code` + PKCE. POST mirrors GET with form-encoded params (OIDC Core §3.1.2.1) — browser-navigated either way, not an API call. |
| [`/oauth/token`](/integrate/oauth-flow/#3-exchange-the-code-for-tokens)            | POST      | form         | `authorization_code` / `refresh_token` / `client_credentials` / `token-exchange` (RFC 8693)                                                        |
| [`/oauth/introspect`](/integrate/oauth-flow/#token-introspection-rfc-7662)         | POST      | form         | Token introspection (RFC 7662) — confidential clients only                                                                                         |
| [`/oauth/userinfo`](/integrate/oauth-flow/#userinfo-oidc)                          | GET, POST | —            | OIDC UserInfo (Bearer header, or POST with a form-encoded `access_token`, RFC 6750 §2.2)                                                           |
| [`/oauth/register`](/integrate/oauth-flow/#dynamic-client-registration-rfc-7591)   | POST      | JSON         | Dynamic Client Registration (RFC 7591, open mode)                                                                                                  |
| `/oauth/revoke`                                                                    | POST      | form         | Token revocation (RFC 7009)                                                                                                                        |
| [`/oauth/end-session`](/integrate/oauth-flow/#rp-initiated-logout)                 | GET, POST | query / form | RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0) — browser-navigated, not an API call                                                  |

Key contract facts:

- `response_type` is `code` only; `code_challenge_method` is `S256` only (PKCE required).
- Tokens carry `iss`, `aud` (RFC 8707 resource binding), `exp`, `iat`, and `scope`.
- `client_credentials` tokens set `sub = client_id` and issue **no** refresh token.
- Scopes are **deny-by-default** (client allowlist; DCR clients capped to the
  realm's allowlist, which `DEFAULT_DYNAMIC_REGISTRATION_SCOPES` seeds). The
  `qauth:` scope namespace is QAuth's own, the admin API's scopes among them: no
  realm allowlist holds one, so dynamic registration drops one, a CIMD
  document's is ignored, and discovery does not list them
  ([admin permissions](/reference/admin-permissions/)).
- The `urn:ietf:params:oauth:grant-type:token-exchange` grant (RFC 8693, ADR-007 §2)
  lets an **agent** client delegate on behalf of a user: `sub` stays the user and
  an `act` claim names the agent (nested for chained delegation). Agent-only and
  default-deny; scope/audience are preserved or narrowed, never widened. See the
  [Token Exchange](/integrate/oauth-flow/#token-exchange--agent-on-behalf-of-delegation-rfc-8693)
  section and the [Agent Authorization guide](/integrate/agent-authorization/).
- DPoP (RFC 9449), when the operator sets `DPOP_ENABLED=true`: a token request
  that carries a `DPoP` proof gets an access token bound to the proof's key
  (`cnf.jkt` in the token, `token_type: "DPoP"` in the response), whatever the
  grant. Send `dpop_jkt` on the authorization request to bind the code to the
  key too. A public client's refresh token is bound to the key and needs a
  proof under it on every refresh; a confidential client's is not. A client the
  operator marked `dpop_bound_access_tokens` in the seed manifest must send a
  proof on every token request, or gets `400 invalid_dpop_proof`. Discovery
  then lists the accepted proof algorithms in `dpop_signing_alg_values_supported`.
  A resource server built on `@qauth-labs/resource-guard` refuses a bound token,
  because the SDK verifies no DPoP proof yet; a client that calls one sends no
  proof, so its tokens stay unbound. Three kinds of token are always bound, so
  they cannot be used at such a resource server until the SDK verifies DPoP
  proofs: the tokens of a client marked `dpop_bound_access_tokens`, a token
  exchanged from a DPoP-bound subject token, and an access token issued for a
  `cnf`-bound ID-JAG.
- Dynamic Client Registration (`POST /oauth/register`) accepts the optional
  QAuth extension field `is_agent` (boolean, default `false`) marking the client
  as an AI agent; it is echoed back in the response. The flag is self-asserted
  and untrusted — see [Agent Authorization](/integrate/agent-authorization/#1-agent-client-type-is_agent).

### Token response (`POST /oauth/token`, `200 OK`)

```json
{
  "access_token": "eyJ…",
  "refresh_token": "a1b2…", // omitted for client_credentials, token-exchange, and a code no stored consent covers (its scopes at each resource)
  "id_token": "eyJ…", // authorization_code grant only, when `openid` was granted
  "expires_in": 900,
  "token_type": "Bearer",
  "scope": "openid profile email", // present when scopes granted
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token" // token-exchange only (RFC 8693 §2.2.1)
}
```

`id_token` is a separate, client-audienced (`aud` = your `client_id`) EdDSA JWT
asserting the sign-in event: `sub`, `nonce` (when sent), `auth_time` (when a
sign-in backs the code), `amr` (when that sign-in recorded its methods), `sid`
(the browser session, when one backs the code), `name` (only under the
`profile` scope, and only when set on the user), and `email` /
`email_verified` (only under the `email` scope, same trust-ordered resolution
as the [UserInfo response](#userinfo-response-getpost-oauthuserinfo-200-ok)
below). The ID token and UserInfo release the same profile and email claims
for the same grant. Only the `authorization_code` grant issues one;
`refresh_token` does not reissue it. See
[ID token claims](/integrate/oauth-flow/#id-token-claims-oidc) for the full
list.

### Introspection response (`POST /oauth/introspect`, `200 OK`)

```json
{
  "active": true,
  "sub": "...",
  "client_id": "...",
  "scope": "mcp:read",
  "aud": "http://localhost:8088",
  "iss": "http://localhost:3000",
  "exp": 1750000000,
  "iat": 1749999100,
  "token_type": "Bearer"
}
```

An inactive/expired/unknown/wrong-audience token returns `{ "active": false }`,
and so does a user's token once that user is disabled or deleted. A DPoP-bound
token is reported with `"token_type": "DPoP"` and `"cnf": { "jkt": "…" }`, the
thumbprint of its key (RFC 9449 §6.2): the resource server checks the request's
DPoP proof against it. `@qauth-labs/resource-guard` checks no DPoP proof yet, so
it refuses such a token with `401 invalid_token`.

### UserInfo response (`GET|POST /oauth/userinfo`, `200 OK`)

```json
{ "sub": "...", "email": "dev@example.com", "email_verified": true }
```

`email`/`email_verified` are conditional: released only under the `email`
scope and only when a **verified** email attribute exists (ADR-002 trust
order `wallet > oidc_* > self_reported`). Otherwise both keys are **absent**
(never `null`). When present, `email_verified` is always `true`. The `POST`
form accepts the access token either as a Bearer header or as a form-encoded
`access_token` field (RFC 6750 §2.2). A token whose user has been disabled
since it was issued gets `401`. So does a token that is not addressed to
UserInfo: its `aud` must contain the token's own `client_id` (the default when
the grant named no `resource`) or the `userinfo_endpoint` URL from discovery.
See [UserInfo](/integrate/oauth-flow/#userinfo-oidc).

A DPoP-bound token is accepted only as `Authorization: DPoP <token>` with a
`DPoP` proof for the request whose `ath` is the token's hash (RFC 9449 §7.1).
Sent as a Bearer token, in the header or the form body, it gets `401`
(RFC 9449 §7.2).

### `POST /oauth/revoke`

RFC 7009 token revocation. Confidential client authentication required
(`client_secret_basic` / `client_secret_post`, the same as introspection).

**Request** (form-urlencoded): `token` (required), `token_type_hint`
(`access_token` | `refresh_token`, optional/advisory), plus client credentials
if not sent via HTTP Basic.

**`200 OK`**, empty body — **always**, per RFC 7009 §2.2. A refresh token
revokes its whole rotation family; an access token is denylisted by `jti` for
its remaining lifetime. A token the caller doesn't own, or an unknown/invalid
token, is a silent no-op (not an error), so the endpoint cannot be used to
probe whether a token exists. The only non-`200` outcomes are a client
authentication failure (`invalid_client`) and `503` with `Retry-After` when the
server is too busy to check the client secret (`temporarily_unavailable`; RFC
7009 §2.2.1: the token still exists, retry after the delay).

### `GET|POST /oauth/end-session`

OpenID Connect RP-Initiated Logout 1.0. A browser route: the app sends the
browser here. **Parameters** (query, or form-encoded body): `id_token_hint`,
`client_id`, `post_logout_redirect_uri`, `state`, `ui_locales` and
`logout_hint`, each optional and given at most once.

- A valid `id_token_hint` (expired accepted) that names the account of the
  browser session and, by its `sid`, that session ends it: **`303`** to the
  registered `post_logout_redirect_uri` with `state`, or **`200`** with a
  signed-out page, and the session cookie cleared.
- Any other signed-in browser gets the `logout_confirm` step: **`200`** with a
  form, or **`303`** to the ceremony page when `INTERACTION_UI_ENABLED` is on.
  Nothing ends until the person answers.
- A browser with no session: **`303`** to the registered URI, or **`200`**.
- A client the operator did not set up (open dynamic registration, CIMD, the
  developer API) gets no automatic redirect in either case: **`200`** with the
  signed-out page, which links to the registered URI with `state`.
- **`400`** HTML information page, never a redirect: `client_id` is not the
  hint's audience, a `post_logout_redirect_uri` comes with no client named, or
  the client does not register it exactly, or the client is disabled.
- A `POST` without the session cookie (the cookie is `SameSite=Lax`, so a
  cross-site form post leaves it out): **`303`** to the same endpoint as a
  `GET` with the same parameters.
- **`400`** `validation_error` for a repeated or over-long parameter; **`429`**
  over the authorization endpoint's rate limit.

No refresh token is revoked. `GET /oauth/end-session/status` takes no
parameter and says whether this browser is still signed in.

---

## Discovery

Unauthenticated and cacheable. The discovery documents carry
`Cache-Control: public, max-age=3600`; the JWKS carries `public, max-age=300`,
so an HTTP cache keeps a key set for at most five minutes. A JWKS client
library keeps its own cache: set it to five minutes at most
([Caching the JWKS](/integrate/oauth-flow/#caching-the-jwks)).

| Endpoint                                      | Returns                                                    |
| --------------------------------------------- | ---------------------------------------------------------- |
| `GET /.well-known/oauth-authorization-server` | OAuth 2.0 AS metadata (RFC 8414)                           |
| `GET /.well-known/openid-configuration`       | OIDC Discovery 1.0 (superset of the above)                 |
| `GET /.well-known/jwks.json`                  | JWKS — the realm's published token signing keys (RFC 7517) |

All three are the documents of the realm the request's host names
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/),
Decision 1):

- `issuer` is the realm's issuer, and every endpoint URL, `jwks_uri` included,
  is built on it.
- The JWKS lists the realm's published keys, each under its own `kid`: its
  active keys, a next key from its publication, before it signs, and a retired
  key while it stays published (after a rotation, until its retention ends).
  No other realm's key is in it.
- `id_token_signing_alg_values_supported` follows the realm's active keys:
  `["RS256","EdDSA"]` when it has an active RS256 key, else `["EdDSA"]`.
- `client_id_metadata_document_supported` follows the realm's CIMD policy
  (`registration.cimd.enabled`,
  [#534](https://github.com/qauth-labs/qauth/issues/534)): a realm that has
  CIMD off omits it.
- The settings that add the other members belong to the deployment, and every
  realm advertises them alike: `DPOP_ENABLED`, and `ID_JAG_ENABLED` once
  `ID_JAG_TRUSTED_ISSUERS` names an issuer.

Every node that serves these documents (a process holding the `api` role, see
[Service roles](/operate/service-roles/)) answers the same bytes for the same
realm, whether or not it holds the signer, given the same settings. After a key
changes, a node may serve its previous key list for up to a minute, its key
refresh interval. A host that names no realm gets `421` for all three, with no
fallback to the default realm.

An endpoint host (`DEFAULT_REALM_ENDPOINT_HOSTS`) gets its realm's documents
unchanged: `issuer` and every URL name the realm's issuer, never the endpoint
host, and no document lists endpoint hosts. RFC 8414 §3.3 and OpenID Connect
Discovery §4.3 ask a client to check that `issuer` is the issuer whose
well-known URL it fetched, which an endpoint host's URL is not. A server-side
caller that reaches QAuth through an endpoint host must therefore configure the
realm's issuer explicitly, check `issuer` and the tokens' `iss` against it, and
use the endpoint host only as the address it connects to. A client library that
takes the expected issuer from the URL it fetched refuses these documents.

Prefer discovering endpoint URLs from these documents over hard-coding paths.
The AS metadata advertises `resource_indicators_supported: true`,
`authorization_response_iss_parameter_supported: true` (RFC 9207 — `/oauth/authorize`
returns `iss` on both success and error redirects, so the flag is not
configurable), and, when the realm's CIMD policy is on,
`client_id_metadata_document_supported: true` (CIMD).

### Passkey association files

Experimental. Two more well-known files tell Apple and Android
platforms which native apps share the realm host's passkeys and passwords. They
are served only while the passkey RP ID is the realm host (`WEBAUTHN_RP_ID`
unset or equal to it), and only for a platform the operator listed apps for;
otherwise the path answers `404`. Both carry `Content-Type: application/json`
and `Cache-Control: public, max-age=3600`.

| Endpoint                                      | Returns                                                                                       |
| --------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `GET /.well-known/apple-app-site-association` | `webcredentials.apps` from `WEBAUTHN_APPLE_APP_IDS`                                           |
| `GET /.well-known/assetlinks.json`            | One `delegate_permission/common.get_login_creds` statement per app in `WEBAUTHN_ANDROID_APPS` |

### Shared Signals Framework transmitter

Experimental, off by default. With `SSF_TRANSMITTER_ENABLED=true`, a realm whose
`ssf_transmitter_enabled` is on is an
[OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
transmitter: receivers create a stream and QAuth pushes Security Event Tokens
(RFC 8417) to it (RFC 8935). With the switch off none of these routes exists;
for a realm whose own switch is off they answer the `404` of a route that does
not exist, before the request is validated.
[SSF transmitter](/operate/ssf-transmitter/) covers setting one up.

| Endpoint                               | Purpose                                                                     |
| -------------------------------------- | --------------------------------------------------------------------------- |
| `GET /.well-known/ssf-configuration`   | Transmitter metadata (SSF 1.0 §7). Unauthenticated.                         |
| `GET /ssf/jwks.json`                   | The keys that verify the realm's SETs (its `jwks_uri`). Unauthenticated.    |
| `POST /ssf/stream`                     | Create the receiver's stream: `201`, or `409` when it has one in the realm. |
| `GET /ssf/stream`                      | Read it with `?stream_id=`, or list the receiver's streams without.         |
| `PATCH /ssf/stream`, `PUT /ssf/stream` | Update or replace the receiver-supplied members.                            |
| `DELETE /ssf/stream`                   | Delete it with `?stream_id=`: `204`.                                        |
| `GET /ssf/status`, `POST /ssf/status`  | Read or set `enabled`, `paused` or `disabled`, with `delivery_status`.      |
| `POST /ssf/subjects/add`               | Add an RFC 9493 subject: `200`; `403` for an unrelated user.                |
| `POST /ssf/subjects/remove`            | Remove one: `204`.                                                          |
| `POST /ssf/verify`                     | Ask for a verification event: `204`; `429` within 10 seconds of the last.   |

The SET keys are published only at `/ssf/jwks.json`, never in the realm JWKS at
`/.well-known/jwks.json`, so a resource server that skips the `typ` check cannot
take a SET for an access token. Every stream management route takes the
receiver's own access token (`client_credentials`) carrying the `ssf:stream`
scope, with the realm's issuer in `aud` and no other realm's issuer. The client must still hold `ssf:stream`. A receiver reaches only
its own stream; another `stream_id`, or a stream deleted meanwhile, answers
`404`. The verification interval is per receiver. A paused stream holds its
events without spending attempts and sends them within 30 seconds of being
enabled. In `delivery_status`, an endpoint refused or not reached reads
`destination_unreachable`. Delivery is push only. `default_subjects` is `NONE`:
a stream receives events only about the subjects its receiver added, and its
verification events. `events_supported` lists the CAEP, RISC and QAuth-defined
events QAuth's security events are sent as; [SSF events](/reference/ssf-events/)
gives the mapping. A receiver may add a user only when the user holds an active
consent for the receiver's client or a live refresh token it was issued, or a live
refresh token whose audience names the receiver as a resource server; the subject
ends once that relation has ended and the events about the user have reached the
stream (see [SSF transmitter](/operate/ssf-transmitter/#register-a-receiver)).

Errors are problem documents (see [Error model](#error-model)): SSF 1.0 gives
stream management statuses but defines no error body, so these routes are not
OAuth protocol endpoints. `400` is `validation_error` for a body or query the
schema refuses and `bad_request` for a request the protocol refuses, with the
reason in `detail` (`endpoint_url is refused`, a transmitter-supplied member that
does not match, poll delivery); `401` is `unauthorized` for a request with no
token, with a bare `WWW-Authenticate: Bearer` challenge, and `invalid_access_token`
or `access_token_expired` for a token that was refused, with
`error="invalid_token"` in the challenge; `403` is
`forbidden` with `error="insufficient_scope", scope="ssf:stream"` in the
challenge for a token without the scope, and `forbidden` with a bare challenge
for a user the receiver may not add, an unknown user id included; `404` is `not_found`, for a stream the receiver does not have and, as
for any path no route serves, for a realm that does not run the transmitter;
`409` is `conflict`; and `429` is `too_many_requests` with `Retry-After`.

### Interaction API

`GET /interaction/v1-rc.0/openapi.json` returns the OpenAPI 3.1 document of the Interaction API,
the API sign-in pages use to reach the engine, with `Cache-Control: public, max-age=3600`. It is
the same document the docs site publishes; the [Interaction API](/reference/interaction-api/) page
describes its operations, steps and versioning rules.

| Endpoint                                        | Method | Purpose                                                                                          |
| ----------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------ |
| `/interaction/v1-rc.0/{interactionId}`          | GET    | Read the current step and its CSRF value. The interaction id alone is enough; no personal data.  |
| `/interaction/v1-rc.0/{interactionId}/personal` | GET    | Read the current step's personal data. Needs the flow cookie; refused from another origin.       |
| `/interaction/v1-rc.0/{interactionId}/answer`   | POST   | Answer the current step, as JSON or as a plain HTML form post. A form post gets `303 See Other`. |
| `/interaction/v1-rc.0/{interactionId}/cancel`   | POST   | Cancel the interaction: the client gets `access_denied`.                                         |

An answer and a cancel need the realm origin (`Sec-Fetch-Site: same-origin`, or an `Origin` of the
realm), the flow cookie and the CSRF value of the step read, checked in that order; the sign-in
engine runs only once all three pass. A request from another origin and a wrong CSRF value get one
generic `403` `forbidden`, audited as `request.csrf_rejected` with `form: interaction`. A CSRF value
answers its step view once: a processed answer, a refused one included, gives the step a new value,
while an answer refused before it is processed (a `400`, a `429`, a `503`) leaves it as it was. A
body is JSON or `application/x-www-form-urlencoded` (else `415`), at most 16 KiB, or 64 KiB for an
answer to `webauthn_create` (else `413`); a form field may not be repeated (`400` `invalid_answer`).
A form post gets `303` to the ceremony app's page of the interaction (under the realm's
sign-in pages), or to the final redirect; a JSON answer gets the next step or the redirect as JSON. The redirect is
taken from the interaction and the realm, never from the request. When a sign-in finishes, its
authorization request goes on (#628): it is checked and decided again for the new session, and the
client gets its code, or the next interaction starts; a cancel checks the request again before the
client gets `error=access_denied`. Every answer is `Cache-Control: no-store`, sends no CORS header, and every
error is a problem document without `detail` or `instance`; a throttled sign-in is `429` with
`Retry-After`. Rate limits count per address and route: an answer that carries a credential (a
password, a one-time or recovery code, a passkey response, a device's user code) counts against the
sign-in form's limit (`LOGIN_RATE_LIMIT` per `LOGIN_RATE_WINDOW`), as one sign-in form post does;
any other answer and the cancel count against the authorization endpoint's (`AUTHORIZE_RATE_LIMIT`
per `AUTHORIZE_RATE_WINDOW`), as do the personal read and the step read. The ceremony app's server
reads the step for every browser, so a step read from one of its addresses that the operator lists
in `CEREMONY_APP_PEERS` counts per interaction instead, under `CEREMONY_APP_PEER_RATE_LIMIT` reads
a minute. With the list empty, as by default, every person signing in through that server shares
its one address bucket.

---

## Hosted UI

Server-rendered, cookie-authenticated pages back the browser leg of
`authorization_code` — see [Hosted UI](/integrate/hosted-ui/) for the full
behaviour, including the pending-authorization mechanics behind the login
bounce.

| Endpoint                                | Method    | Purpose                                                                             |
| --------------------------------------- | --------- | ----------------------------------------------------------------------------------- |
| `/ui/login`                             | GET, POST | Session-cookie login page and form submission                                       |
| `/ui/consent`                           | GET, POST | OAuth consent screen and decision submission                                        |
| `/ui/resume/{handle}`                   | GET       | Resume a pending authorization after login (single-use, 10-minute TTL)              |
| `/ui/verify`                            | POST      | The form of the emailed verification link ([`GET /auth/verify`](#get-authverify))   |
| `/ui/upstream/{type}`                   | GET       | A provider button of the login page: back to the request with `qauth_upstream`      |
| `/ui/upstream/{type}/start`             | GET       | Start the routed upstream provider, then the waiting page that sends the browser on |
| `/ui/upstream-link/{interactionId}`     | GET       | "I already have an account" or a new one: the `upstream_link` step's form (#670)    |
| `/ui/upstream-link-refused`             | GET       | The page of a refused upstream link: why, and nothing sent to the client (#670)     |
| `/ui/recovery-code/{interactionId}`     | GET       | "Use a recovery code": the `recovery_code` step's form (#649)                       |
| `/ui/recovery-codes/{interactionId}`    | GET       | "Save your recovery codes": a new set, shown once, and its confirmation (#649)      |
| `/ui/passkey/{interactionId}`           | GET       | "Sign in with a passkey": the `webauthn_get` step's ceremony (#651)                 |
| `/ui/passkey-enrolment/{interactionId}` | GET       | "Add a passkey": the `webauthn_create` step's ceremony, or "Not now" (#651)         |
| `/ui/totp/{interactionId}`              | GET       | "Enter the code from your authenticator app": the `totp` step's form (#653)         |
| `/ui/totp-setup/{interactionId}`        | GET       | "Set up an authenticator app": the secret as a QR code and text, and a first code   |

The account pages below are registered **only** while the hosted pages are on
(`INTERACTION_UI_ENABLED`); with the switch off every path 404s. They are
experimental: the design-system account console replaces them. See
[Hosted UI → The account pages](/integrate/hosted-ui/#the-account-pages) for
the checks every form post meets (#844).

| Endpoint                                               | Method    | Purpose                                                                                 |
| ------------------------------------------------------ | --------- | --------------------------------------------------------------------------------------- |
| `/ui/account`                                          | GET       | The overview of the browser session's account; a browser with no session signs in first |
| `/ui/account/password`                                 | GET, POST | Change the password, with the current one, under the realm's password policy            |
| `/ui/account/reauthenticate`                           | POST      | "Confirm it's you": a fresh sign-in, then back to the page                              |
| `/ui/account/passkeys/add`                             | POST      | Add a passkey: a fresh sign-in, then the `webauthn_create` step                         |
| `/ui/account/passkeys/{passkeyId}/rename`              | POST      | Rename a passkey                                                                        |
| `/ui/account/passkeys/{passkeyId}/remove`              | POST      | Remove a passkey                                                                        |
| `/ui/account/totp/setup`                               | POST      | Set up an authenticator app: a fresh sign-in, then the `totp_setup` step                |
| `/ui/account/totp/remove`                              | POST      | Turn the authenticator app off                                                          |
| `/ui/account/recovery-codes/regenerate`                | POST      | A new set of recovery codes, shown once                                                 |
| `/ui/account/recovery-codes/confirm`                   | POST      | Confirm the new set is saved                                                            |
| `/ui/account/sessions/{sessionId}/end`                 | POST      | Sign one session out                                                                    |
| `/ui/account/sessions/end-all`                         | POST      | Sign out everywhere                                                                     |
| `/ui/account/linked-accounts/link`                     | POST      | Link an upstream account by signing in to it                                            |
| `/ui/account/linked-accounts/{linkedAccountId}/unlink` | POST      | Unlink an upstream account                                                              |

The wallet-login screens below are registered **only** when
`WALLET_FEDERATION_ENABLED` is on; with the flag off (the default) every path
404s. See [Wallet sign-in](/integrate/wallet-login/) for the flow they implement.

| Endpoint                           | Method    | Purpose                                                                                                                                                                                                                                             |
| ---------------------------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/ui/wallet-login`                 | GET, POST | GET renders the ADR-009 identifier form; POST starts the sign-in. The form field `device` (`this` \| `other`, absent ⇒ `other`) says where the wallet is: `this` renders the deep link, `other` the QR code (#405).                                 |
| `/ui/wallet-login/{handle}`        | GET       | The waiting screen for a pending presentation.                                                                                                                                                                                                      |
| `/ui/wallet-login/{handle}/status` | GET       | Poll the presentation's outcome. Completes a cross-device sign-in once the presentation lands; a same-device one only once its return leg has, and rejects it if the redirect never arrives.                                                        |
| `/ui/wallet-login/return`          | GET       | The same-device return leg: `?response_code=` carries the single-use Response Code the wallet received from `POST /oid4vp/response`. Spent first, then bound to the browser that started the flow; every refusal renders one identical page (#405). |
| `/ui/wallet-link`                  | GET, POST | GET renders the confirmation screen; POST starts the link (issue #238) for a wallet on this device. Linking is same-device only: the form field `device` accepts only `this` (absent means the same), `other` answers `400` `validation_error`.     |
| `/ui/wallet-link/{handle}`         | GET       | The waiting/outcome screen for a pending link.                                                                                                                                                                                                      |

---

## Developer API (`developer` family, v1-rc.0)

A developer's OAuth clients, their static API keys, and the developer's own consents (#524). The
paths follow the [API conventions](/reference/api-conventions/): JSON members in `camelCase`, except
registered OAuth client metadata, which keeps its RFC 7591 name (`client_id`, `client_name`,
`redirect_uris`, `grant_types`, `response_types`, `token_endpoint_auth_method`, `client_secret`);
times as RFC 3339 strings; lists as `{ "items": [...], "nextCursor": ... }` with `limit` (1 to 200,
default 50) and `cursor`; an `ETag` on every read of a client, and `If-Match` on its update; errors as
problem documents.

**Authentication.** `Authorization: Bearer <access_token>` (or `DPoP` while DPoP is on), where the
token's only audience is `urn:qauth:aud:developer:v1-rc.0`, it carries no `act` claim, and its subject
is an enabled user of the realm. A token for another family, or with no family audience, is refused with
`401` `invalid_access_token`, before the request is validated.

**Scopes.** A list or a read needs `qauth:developer:read`; a create, update, delete, secret
regeneration, API key mint or revocation, and consent revocation needs `qauth:developer:write`
(#933). The two are independent. A token without the scope an operation needs is refused with `403`
`forbidden` and `WWW-Authenticate: Bearer realm="OAuth", error="insufficient_scope", scope="…"`,
before the request is validated. The token [`POST /auth/login`](#post-authlogin) mints for the
developer portal carries both. Another client gets them only when an operator lists the developer
audience in its `audience` and the scopes in its `scopes`
([API conventions](/reference/api-conventions/#issuing-a-family-audience)).

**Ownership.** Every route reads only the caller's own clients. A client that does not exist, that
another developer owns, or that belongs to another realm is `404` `not_found`, never `403`.

### `GET /developer/v1-rc.0/clients`

List the caller's clients, newest first.

**Query**: `limit`, `cursor`.

**`200 OK`**

```json
{
  "items": [
    {
      "id": "0b9f7d4e-5c1a-4f7e-9d2b-3a6c8e1f0a42",
      "client_id": "3f1c…",
      "client_name": "My App",
      "description": null,
      "redirect_uris": ["https://app.example.com/cb"],
      "scopes": ["openid"],
      "grant_types": ["authorization_code", "refresh_token"],
      "response_types": ["code"],
      "token_endpoint_auth_method": "client_secret_basic",
      "enabled": true,
      "suspended": false,
      "requirePkce": true,
      "environment": "production",
      "staticApiKeysAllowed": false,
      "createdAt": "2026-10-31T09:30:00.000Z",
      "updatedAt": "2026-10-31T09:30:00.000Z",
      "lastUsedAt": null
    }
  ],
  "nextCursor": null
}
```

`scopes` is a list, as the client stores it. `environment`, `staticApiKeysAllowed` and `suspended`
are read-only. Errors: `400` (`validation_error` for a `limit` above 200, `invalid_cursor` for a cursor
this list did not issue), `401`, `403`.

### `POST /developer/v1-rc.0/clients`

Create a client. The body is a closed object: `client_name` (required), `description`,
`redirect_uris`, `scopes`, `grant_types`, `response_types`, `token_endpoint_auth_method`. Left out,
they take the defaults of dynamic registration: `authorization_code` and `refresh_token`, the `code`
response type, and a public client (`none`, PKCE).

**`201 Created`**, with `ETag` and `Location`: the client, and `client_secret` for a confidential
client, in this answer only. Errors: `400` (`validation_error`, `invalid_redirect_uri`,
`invalid_client_metadata` for a scope the realm does not allow), `401`, `403` (the scope, or the per-developer
client limit), `429`.

### `GET /developer/v1-rc.0/clients/{clientId}`

One client, with its `ETag`. `{clientId}` is the client's `id`, not its `client_id`. The `ETag` covers
every member but `lastUsedAt`, which changes whenever the client is used and no update writes.
Errors: `400`, `401`, `403`, `404`.

### `PATCH /developer/v1-rc.0/clients/{clientId}`

Change a client with a JSON Merge Patch (RFC 7396), sent as `application/merge-patch+json`, naming
the version it changes in `If-Match`. Members: `client_name`, `description`, `redirect_uris`,
`scopes`, `grant_types`, `response_types`, `token_endpoint_auth_method`, `enabled`. A member left out
keeps its value; a list is replaced whole; `null` gives a member the value a create gives it when it
is left out (`description` none, the lists empty, the grant and response types and the auth method
their defaults, `enabled` true). `enabled` does not lift an operator's suspension.

The merged client must pass the rules a create checks, and a refusal answers as there: `400`
`invalid_redirect_uri` (a user-facing grant left without a redirect URI) or `invalid_client_metadata`
(grant and response types that do not fit, a scope the realm does not allow).

**`200 OK`**: the client and its new `ETag`. Errors: `400` (`validation_error`, also for a member the
patch may not name, such as `client_id`; the create rules above), `401`, `403`, `404`, `412` (`precondition_failed`: the client
changed since that `ETag`; read it again), `415` (a body that is not a merge patch), `422`
(`unprocessable_content`: `client_name` set to `null`), `428` (`precondition_required`: no
`If-Match`).

### `DELETE /developer/v1-rc.0/clients/{clientId}`

Delete a client. **`204 No Content`**. Errors: `400`, `401`, `403`, `404`.

### `POST /developer/v1-rc.0/clients/{clientId}/regenerate-secret`

Issue a new `client_secret` for a confidential client; the old one stops working at once.
**`200 OK`**: the client and `client_secret`, in this answer only. Errors: `400` (a public client has
no secret), `401`, `403`, `404`, `429`.

### `GET /developer/v1-rc.0/clients/{clientId}/api-keys`

A client's static API keys, newest first, masked (`prefix`, `last4`), revoked ones included
(`revokedAt` set). `clientId` in each key is the client's `id`. **Query**: `limit`, `cursor`.
**`200 OK`**: `{ "items": [...], "nextCursor": ... }`. Errors: `400`, `401`, `403`, `404`.

### `POST /developer/v1-rc.0/clients/{clientId}/api-keys`

Mint a key: `{ "name": "ci" }`. Only while the client's effective environment is `development`
(ADR-008 §6). **`201 Created`**: the key's fields and the plaintext `key`, in this answer only.
Errors: `400`, `401`, `403` (the scope, or not a development client: use `client_credentials`), `404`, `429`.

### `DELETE /developer/v1-rc.0/clients/{clientId}/api-keys/{keyId}`

Revoke a key, idempotently: **`200 OK`** with the key, `revokedAt` set. Errors: `400`, `401`, `403`, `404`.

### `GET /developer/v1-rc.0/consents`

The caller's own active consents, as a user, by when each was first given, newest first (a new grant
to the same client keeps its place, so a page never skips one). It serves the developer portal until the
account console takes them over.

**`200 OK`**

```json
{
  "items": [
    {
      "id": "0b9f7d4e-5c1a-4f7e-9d2b-3a6c8e1f0a42",
      "client_id": "https://agent.example.com/client.json",
      "client_name": "My Agent",
      "scopes": ["openid"],
      "grantedAt": "2026-10-31T09:30:00.000Z"
    }
  ],
  "nextCursor": null
}
```

Errors: `400`, `401`, `403`.

### `DELETE /developer/v1-rc.0/consents/{consentId}`

Revoke one of the caller's consents, with the refresh tokens and the unredeemed authorization codes
the caller holds for that client. **`204 No Content`**. Errors: `400`, `401`, `403`, `404` (a consent of
another user is the same `404` as one that does not exist).

---

## Account API (`account` family, v1-rc.0)

An end user's own account (#524), for the account console's backend. A token whose only audience
is `urn:qauth:aud:account:v1-rc.0`, sent as a Bearer or DPoP token; a token for the developer API is
refused here with `401`, and the reverse. A read needs `qauth:account:read` and a change
`qauth:account:write` (#933), or `403` `forbidden` with the `insufficient_scope` challenge. The
conventions are those of the developer API above.

### `GET /account/v1-rc.0/consents`

The user's active consents, in the order and representation of
`GET /developer/v1-rc.0/consents`. Errors: `400`, `401`, `403`.

### `DELETE /account/v1-rc.0/consents/{consentId}`

Revoke one of the user's consents, as `DELETE /developer/v1-rc.0/consents/{consentId}` does.
**`204 No Content`**. Errors: `400`, `401`, `403`, `404`.

### `GET /account/v1-rc.0/linked-accounts`

The upstream accounts linked to the user (#670), newest first, a page at a time: each with its
`id`, its `provider` type, the provider's `providerName` while the realm has it on, and
`createdAt`. Never the identity's subject at the provider. Linking one is no operation here: it is
an authorization request with
[`qauth_link`](/integrate/oauth-flow/#linking-an-upstream-account), which asks the person to sign
in again. Errors: `400`, `401`, `403`.

### `DELETE /account/v1-rc.0/linked-accounts/{linkedAccountId}`

Unlink one of the user's upstream accounts: the account no longer signs in through that provider,
and the owner gets an email notice. Needs a fresh sign-in with the account's strongest factor and
refuses an act-chain token, as every change to the ways into the account does. The account's last
way to sign in is `409` `last_credential`; one of another user is the same `404` as one that does
not exist. **`204 No Content`**. Errors: `400`, `401`, `403`, `404`, `409`.

---

## Consents (`/consents/`)

:::caution[Deprecated]
Deprecated since #524: every answer carries the `Deprecation` header (RFC 9745), and the operations
are `deprecated` in `openapi.json`. Use [`GET /account/v1-rc.0/consents`](#get-accountv1-rc0consents).
The path keeps working until the release-candidate cleanup removes it
([Deprecations](/reference/api-conventions/#deprecations)).
:::

Lets a signed-in user manage their own OAuth consent grants from the auth-server's
**hosted UI**. **Cookie-authed** (`__Host-qauth_session`), so it carries a CSRF
token.

If you are calling from a separate origin — the developer portal, or your own
front end — use [`/api/consents/`](#consents-api-apiconsents) below instead. That
cookie is set only by `POST /ui/login` and is `SameSite=Lax`, so it will not be
attached to a cross-site `fetch()` whatever `credentials: 'include'` says.

### `GET /consents/`

List the signed-in user's active consents. The response also carries a
per-session CSRF token that **must** be echoed back as `X-CSRF-Token` on
`DELETE /consents/{id}`.

**`200 OK`**

```json
{
  "consents": [
    {
      "id": "...",
      "clientId": "...",
      "clientName": "My App",
      "scopes": ["openid"],
      "grantedAt": 1750000000000
    }
  ],
  "csrfToken": "..."
}
```

Errors: `401` `unauthorized` (no or invalid session), a problem document like every other error
here. The credential is a cookie, so the answer carries no `WWW-Authenticate` challenge.

### `DELETE /consents/{id}`

Revoke one consent owned by the signed-in user. The refresh tokens and the
unredeemed authorization codes the user holds for that client are revoked with
it. Access tokens already issued stay valid until they expire.

**Headers**: `X-CSRF-Token: <csrfToken from GET /consents/>` (required).

**`204 No Content`**. Errors: `400` (`invalid_csrf_token` — missing or
mismatched `X-CSRF-Token`; the first outcome you'll hit if the header isn't
wired up yet), `401` (`unauthorized` — no or invalid session), `404`
(`not_found` — consent does not exist or is not owned by the caller).

---

## Consents API (`/api/consents/`)

:::caution[Deprecated]
Deprecated since #524, with the same `Deprecation` header. Use
[`GET /developer/v1-rc.0/consents`](#get-developerv1-rc0consents) (the developer portal does) or
the account API. The shapes below stay as they are until the path is removed.
:::

The same consent management, **Bearer-authed** — the credential the developer
portal and any other API client actually holds. Same auth model as
[`/api/clients/`](#client-management-apiclients): `Authorization: Bearer
<access_token>`, scoped strictly to the token subject, with `qauth:developer:read`
to list and `qauth:developer:write` to revoke (#933).

**No CSRF token.** A Bearer token is not ambient authority a cross-site page can
make the browser attach, so there is nothing for one to add. The cookie-authed
`/consents/` above needs one precisely because its credential is ambient.

Ownership and auditing are shared with `/consents/`, so the two surfaces cannot
diverge on who may revoke what.

### `GET /api/consents/`

List the authenticated user's active consents.

**Headers**: `Authorization: Bearer <access_token>` (required).

**`200 OK`**

```json
{
  "consents": [
    {
      "id": "...",
      "clientId": "...",
      "clientName": "My App",
      "scopes": ["openid"],
      "grantedAt": 1750000000000
    }
  ]
}
```

No `csrfToken` field — see above. Errors: `401` (missing/invalid bearer).

### `DELETE /api/consents/{id}`

Revoke one consent owned by the authenticated user, with the same effect as
[`DELETE /consents/{id}`](#delete-consentsid).

**`204 No Content`**. Errors: `401` (missing/invalid bearer), `404` (consent
does not exist **or** is not owned by the caller — deliberately the same
outcome, so the API never reveals that another user's consent id exists).

---

## Client management (`/api/clients/`)

:::caution[Deprecated]
Deprecated since #524, with the same `Deprecation` header: use the
[Developer API](#developer-api-developer-family-v1-rc0), which serves the same clients and API keys
in the API conventions' representation. These routes accept only the developer portal's token, whose
audience is `urn:qauth:aud:developer:v1-rc.0` since #524. The shapes below stay as they are until
the paths are removed. Each route needs the developer scope of the operation it aliases (#933):
`qauth:developer:read` for a `GET`, `qauth:developer:write` for any other method, or `403`
`forbidden` with the `insufficient_scope` challenge. The portal's token carries both.
:::

Developer-portal API for managing a developer's own OAuth clients. **JSON**,
**camelCase**, and authenticated with a developer **`Authorization: Bearer`**
access token (from [`POST /auth/login`](#post-authlogin)). Results are scoped to
the token subject's `developer_id`; the client secret is **never** returned.

:::note[Dynamically registered clients and ownership]
A client registered **anonymously** through [`POST /oauth/register`](/integrate/oauth-flow/#dynamic-client-registration-rfc-7591)
or materialised from a CIMD document has no developer to attribute to, so its
`developer_id` is `NULL` and it will **not** appear here for anyone. That is
deliberate: inventing an owner would hand an anonymous caller's client to
whoever the server guessed. Manage such a client out of band, or register it
with attribution instead.

**To get a manageable client from dynamic registration, send your developer
access token with the registration request** (#374):

```bash
curl -s -X POST https://auth.example.com/oauth/register \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{ "client_name": "My App", "redirect_uris": ["https://app.example.com/cb"] }'
```

The client is then owned by that token's subject and behaves like any client
created through `POST /api/clients/`, including the per-developer limit on the
number of clients (`MAX_CLIENTS_PER_DEVELOPER`, `403` once reached). The token
needs `qauth:developer:write`, as `POST /api/clients/` does (#933), or the
registration answers `403` `access_denied`. A token
that does not verify is rejected
rather than silently ignored — otherwise you would get an unowned client while
believing you owned it, which is the failure this note exists to prevent.
:::

### `GET /api/clients/`

List the authenticated developer's OAuth clients.

**Headers**: `Authorization: Bearer <access_token>` (required).

**`200 OK`**

```json
{
  "clients": [
    {
      "id": "0190f7…",
      "clientId": "0190f7a0-…-uuid",
      "name": "My App",
      "description": null,
      "redirectUris": ["http://localhost:5173/callback"],
      "scopes": ["openid", "profile"],
      "grantTypes": ["authorization_code", "refresh_token"],
      "responseTypes": ["code"],
      "tokenEndpointAuthMethod": "none",
      "enabled": true,
      "suspended": false,
      "requirePkce": true,
      "createdAt": 1750000000000,
      "updatedAt": 1750000000000,
      "lastUsedAt": null
    }
  ]
}
```

A developer with no clients gets `{ "clients": [] }`. Errors: `401` (missing/invalid bearer).

`enabled` is the owner's switch. `suspended` is read-only: `true` when the
operator has suspended the client, which is then refused wherever a disabled
client is (`unauthorized_client` at `/oauth/authorize`, `invalid_client` at the
token, introspection and revocation endpoints), whatever `enabled` says. Only
the operator lifts a suspension.

> **Ownership & 404 semantics.** Every per-client route is scoped to the token
> subject's `developer_id`. A client that exists but is owned by another
> developer is reported as **`404 Not Found`** (not `403`) so the API never
> confirms the existence of clients the caller does not own.

### `POST /api/clients/`

Create an OAuth client owned by the authenticated developer. The server
generates the `clientId` (UUID) and, for confidential clients, a 32-byte
`clientSecret`. **The plaintext `clientSecret` is returned in this response
only** — only its argon2id hash is stored, so it is unrecoverable afterwards.

**Headers**: `Authorization: Bearer <access_token>` (required).

**Body** (all besides `name` optional):

| Field                     | Type     | Default                                  | Notes                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | -------- | ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`                    | string   | —                                        | Required, 1–255 chars.                                                                                                                                                                                                                                                                                                       |
| `description`             | string   | `null`                                   |                                                                                                                                                                                                                                                                                                                              |
| `redirectUris`            | string[] | `[]`                                     | At most 20. Each validated (OAuth 2.1 §10.3 — `https`, loopback `http`, an RFC 8252 private-use scheme such as `com.example.app:`, or a scheme without a period listed in `REDIRECT_URI_CUSTOM_SCHEMES`; any other scheme is refused). **Required (≥1) for user-involving grants** (`authorization_code` / `refresh_token`). |
| `scopes`                  | string[] | `[]`                                     | At most 100. Capped to the realm's allowed-scopes policy (same allowlist as dynamic registration); a scope outside it is rejected.                                                                                                                                                                                           |
| `grantTypes`              | string[] | `["authorization_code","refresh_token"]` | At most 8. `authorization_code` / `refresh_token` / `client_credentials`.                                                                                                                                                                                                                                                    |
| `responseTypes`           | string[] | `["code"]`                               | At most 4. OAuth 2.1 only supports `code`.                                                                                                                                                                                                                                                                                   |
| `tokenEndpointAuthMethod` | string   | `"none"`                                 | `none` (public) / `client_secret_post` / `client_secret_basic` / `private_key_jwt`.                                                                                                                                                                                                                                          |

**Rate limit**: per-IP, shared budget with `POST /oauth/register`
(`REGISTER_CLIENT_RATE_LIMIT` / `REGISTER_CLIENT_RATE_WINDOW`) — create runs an
argon2id hash on every call, so the cap is mandatory (`429` on exceed).

**`201 Created`** (`Cache-Control: no-store`)

```json
{
  "id": "0190f7…",
  "clientId": "0190f7a0-…-uuid",
  "name": "My App",
  "description": null,
  "redirectUris": ["https://app.example.com/cb"],
  "scopes": ["openid"],
  "grantTypes": ["authorization_code", "refresh_token"],
  "responseTypes": ["code"],
  "tokenEndpointAuthMethod": "client_secret_post",
  "enabled": true,
  "suspended": false,
  "requirePkce": true,
  "createdAt": 1750000000000,
  "updatedAt": 1750000000000,
  "lastUsedAt": null,
  "clientSecret": "a1b2c3…(64 hex chars, shown once)"
}
```

Public clients (`tokenEndpointAuthMethod: "none"`) get **no** `clientSecret`.
A repeated scope is stored once. A client created here is not
operator-provisioned: an authorization error that `/oauth/authorize` would send
before the user sees any QAuth page (for example `login_required` for
`prompt=none`) is shown on an issuer page with a link to the redirect URI, not
redirected automatically (see [Errors](/integrate/oauth-flow/#errors)). A developer may own at most
`MAX_CLIENTS_PER_DEVELOPER` clients (default 100), counting the ones registered
with attribution through `POST /oauth/register`.
Errors: `400` (invalid `redirectUri`, inconsistent grant/response types, missing
`redirectUris` for a user-involving grant, or a scope outside the realm policy),
`401` (missing/invalid bearer, or a non-user token), `403` (the developer already
owns `MAX_CLIENTS_PER_DEVELOPER` clients), `429` (rate limited).

### `GET /api/clients/{id}`

Get one of the developer's clients. Safe fields only — never the secret.

**`200 OK`** — the same shape as a `GET /api/clients/` list item.
Errors: `401`; `404` (not found or not owned).

### `PATCH /api/clients/{id}`

Partially update a client. Any subset of: `name`, `description`,
`redirectUris`, `scopes`, `grantTypes`, `responseTypes`,
`tokenEndpointAuthMethod`, `enabled`, with the same limits as on create. `clientId`, the secret, and
`developerId` are **immutable** here (unknown/immutable keys are ignored). The
_effective_ configuration (request value or persisted value) is re-validated:
grant/response-type consistency, a redirect URI for user-involving grants, and
the realm scope cap when `scopes` is changed.

`enabled` is the owner's switch and may be set either way. It does not lift an
operator's suspension: `suspended` cannot be written here, and a suspended
client stays refused after `"enabled": true` until the operator lifts it.

**`200 OK`** — the updated client (safe fields, no secret).
Errors: `400` (validation / inconsistent config / disallowed scope / missing
redirect for a user-involving grant), `401`, `404`.

### `DELETE /api/clients/{id}`

Delete a client. After deletion the client can no longer authenticate at the
token endpoint and cannot start new authorization flows. Note: already-issued
**access tokens are stateless JWTs** and remain valid until they expire;
short access-token lifetimes bound this window.

**`204 No Content`**. Errors: `401`; `404` (not found or not owned).

### `POST /api/clients/{id}/regenerate-secret`

Issue a new `clientSecret`. The previous secret is invalidated immediately;
**the new plaintext secret is returned in this response only.**

**`200 OK`** (`Cache-Control: no-store`) — the client (safe fields) plus a
`clientSecret` string. Errors: `400` (public client — no secret to rotate),
`401`, `404`, `429` (rate limited — argon2id, same per-IP budget as create).

Clients may also be obtained outside this API: via **CIMD**, the mechanism
MCP Authorization 2026-07-28 says to prefer; via
[Dynamic Client Registration](/integrate/oauth-flow/#dynamic-client-registration-rfc-7591)
(`POST /oauth/register`), which that revision deprecates but QAuth still
supports; or via the `seed-oauth-clients` script.

---

## API keys (`/api/clients/{clientId}/api-keys`)

Static, long-lived developer API keys scoped to one of the developer's own
OAuth clients — an alternative to `client_credentials` for **development-only**
use. Same Bearer developer authentication and ownership/404 rules as client
management, above.

> **Environment-gated (ADR-008 §6).** Minting a key is permitted only while the
> client resolves to a **development** environment; a staging/production (or
> unset-environment) client is refused with `403`. Use the OAuth
> `client_credentials` grant instead for anything beyond local development.

### `POST /api/clients/{clientId}/api-keys`

Mint a static API key for the client.

**Request** (`application/json`): `{ "name": "..." }` (1–255 chars).

**`201 Created`**

```json
{
  "id": "...",
  "clientId": "...",
  "name": "local dev",
  "prefix": "...",
  "last4": "...",
  "createdAt": 1750000000000,
  "lastUsedAt": null,
  "revokedAt": null,
  "key": "...(plaintext, shown once)"
}
```

Errors: `400`, `401`, `403` (client not in a development environment), `404`.

### `GET /api/clients/{clientId}/api-keys`

List the client's API keys — masked fields only (`prefix` + `last4`, never the
key or its hash). Includes revoked keys (`revokedAt` set).

**`200 OK`**: `{ "apiKeys": [ { "id": "...", "clientId": "...", "name": "...", "prefix": "...", "last4": "...", "createdAt": 0, "lastUsedAt": null, "revokedAt": null } ] }`

Errors: `401`, `404`.

### `DELETE /api/clients/{clientId}/api-keys/{keyId}`

Revoke one API key. Idempotent soft-delete — the row is retained with
`revokedAt` set, and a revoked key never authenticates again.

**`200 OK`** — the revoked key (masked fields, `revokedAt` set).
Errors: `401`, `404` (client or key not found / not owned).

---

## Wallet federation transport (`/oid4vp/request/{handle}`, `/oid4vp/response`)

**Flag-gated, off by default.** `POST /oid4vp/response` is registered only when
`WALLET_FEDERATION_ENABLED=true` **and** a `VerifierProfile` is configured for
the deployment; both default off, and with either missing the route does not
exist (404) or fails closed. See the [Status page](/reference/status/) for
where wallet federation stands overall.

**Even when enabled, this endpoint is transport only.** It is the OID4VP 1.0
`direct_post` Response Endpoint: it structurally parses and correlates a
wallet's Authorization Response (`vp_token` + `state`, or `error` + `state`)
against a single-use presentation request. **It performs no signature,
credential, or issuer validation, and authenticates no user.**

**Request** (form-urlencoded): `state` (required), `vp_token`, `error`,
`error_description`.

**`200 OK`** — a transport-level acknowledgement: a JSON object, sent
`Cache-Control: no-store` (OID4VP 1.0 §8.2). For a **cross-device** request
the object is empty, `{}`, and the wallet is not required to do anything
further. For a request the user started as **same-device**, and for every account-link
request (linking is same-device only), it is
`{ "redirect_uri": "https://<issuer>/ui/wallet-login/return?response_code=<43 base64url chars>" }`
— an absolute URI under the issuer carrying a fresh, single-use Response Code,
which the wallet MUST redirect the user agent to (HAIP 1.0 §5.1); it is returned
on the accepted path and on a wallet-reported error alike. Either way the
acknowledgement confirms only that the response was well-formed and correlated.
It does **not** assert that any credential was verified or any user
authenticated — whoever follows the `redirect_uri` must also hold the browser
binder of the flow the code names, and the return route decides that, not this
body. Cross-device (QR) flows are unchanged by #405.

### `GET /oid4vp/request/{handle}`

**Flag-gated on the same variable, and registered only alongside the endpoint
above.** This is the JAR Request Object Endpoint (RFC 9101 §5.2.2, HAIP 1.0
§5.1): under a `VerifierProfile` that mandates signed Authorization Requests,
the wallet invocation URI carries a `request_uri` pointing here instead of the
request parameters inline, and the wallet fetches the signed request object from
it (#377).

**`200 OK`** — the compact JWS, served as `application/oauth-authz-req+jwt` with
`Cache-Control: no-store`. Its `x5c` header carries the Verifier's leaf
certificate and any intermediates, with the trust anchor excluded; `client_id`
is the base64url SHA-256 of that leaf.

**It consumes nothing and writes nothing.** The request `state` is not redeemed
here — a wallet may legitimately retry the fetch — so single use stays enforced
where it belongs, at `POST /oid4vp/response`. An unknown, expired or malformed
handle all produce the **same** bare `404`, so the endpoint is not an oracle for
which requests exist.

---

## See also

- [OAuth 2.1 Flow](/integrate/oauth-flow/) — worked flows with `curl`.
- [Hosted UI](/integrate/hosted-ui/) — the login, consent, and resume screens.
- [Agent Authorization](/integrate/agent-authorization/) — the agent-native layer
  (`is_agent`, Token Exchange, scope modes, step-up, audit).
- [Code Examples](/integrate/code-examples/) — runnable Node/TS and browser clients.
- [MCP Quickstart](/integrate/mcp-quickstart/) — protect an MCP server end-to-end.
- [`@qauth-labs/resource-guard`](https://github.com/qauth-labs/qauth/blob/main/libs/sdk/resource-guard/README.md) — the
  resource-server SDK that validates the tokens these endpoints issue.
