# Threat Model — QAuth Authorization Server

This document is for anyone reviewing QAuth for vulnerabilities, by hand or
with automated tools. It states what QAuth promises, where untrusted input
enters, what matters most, and how we rate severity. How to report is in
[`SECURITY.md`](../../SECURITY.md).

It describes the code on `main`. Where it and the code disagree, the code is
the fact and this document is the bug.

## What QAuth is

QAuth is an OAuth 2.1 and OpenID Connect authorization server, written in
TypeScript on Fastify, with PostgreSQL and Redis behind it. It issues access
tokens, refresh tokens and ID tokens. It renders its own login and consent
pages. It serves MCP servers and AI agents as clients, and it can delegate
on behalf of a user with RFC 8693 token exchange.

The parts that matter:

- `apps/auth-server` — the server: every route, the hosted pages, all policy.
- `apps/developer-portal` — a separate web app where developers manage their
  clients. It talks to the auth-server's management API.
- `libs/fastify/plugins/mcp-guard` — a library a resource server uses to
  validate QAuth tokens.

## Deployment assumptions

- TLS is terminated by a reverse proxy in front of the auth-server.
- `TRUST_PROXY` names that proxy and the developer portal by address, never
  a range clients can connect from. With it unset, no forwarded header is
  trusted, and every caller shares the proxy's address. The portal's own
  `PORTAL_TRUST_PROXY` names the proxy in front of the portal, by address.
  Each named proxy appends the address it accepted the connection from to
  `X-Forwarded-For`.
- PostgreSQL and Redis are private to the deployment and trusted.
- The operator's environment and configuration are trusted.
- One deployment has one issuer (`JWT_ISSUER`) and serves one default realm.
- Signing keys come from the operator's environment and stay on the server.

An attacker who already controls the database, Redis, the host or the
operator's configuration is out of scope.

## Where untrusted input enters

Every HTTP route takes untrusted input. The routes live in
`apps/auth-server/src/app/routes/`:

| Area                 | Routes                                                                                                                                                                                      |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Discovery            | `GET /.well-known/oauth-authorization-server`, `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`                                                                        |
| OAuth / OIDC         | `GET`/`POST /oauth/authorize`, `POST /oauth/token`, `POST /oauth/introspect`, `POST /oauth/revoke`, `POST /oauth/register`, `GET`/`POST /oauth/userinfo`                                    |
| Hosted pages         | `GET`/`POST /ui/login`, `GET`/`POST /ui/consent`, `GET /ui/resume/:handle`, `/ui/wallet-login` and its `/:handle`, `/:handle/status` and `/return` routes, `/ui/wallet-link` and `/:handle` |
| Wallet response leg  | `GET /oid4vp/request/:handle`, `POST /oid4vp/response`                                                                                                                                      |
| JSON account API     | `POST /auth/register`, `/auth/login`, `/auth/logout`, `/auth/verify`, `/auth/resend-verification`, `/auth/link/wallet` and `/auth/link/wallet/:handle`                                      |
| Management API       | `/api/clients` (list, create, read, update, delete, regenerate secret), `/api/clients/:clientId/api-keys`, `/api/consents`                                                                  |
| Browser consent list | `GET /consents`, `DELETE /consents/:id`                                                                                                                                                     |
| Operations           | `GET /health`, `GET /metrics`, `GET /`                                                                                                                                                      |

`POST /oauth/token` carries the most logic. It serves `authorization_code`,
`refresh_token`, `client_credentials`, RFC 8693 token exchange, and the
RFC 7523 `jwt-bearer` grant for ID-JAG assertions.

Other untrusted input:

- **Documents QAuth fetches from URLs a client or credential names.** Client ID
  Metadata Documents, a client's `jwks_uri` for `private_key_jwt` and ID-JAG
  issuer keys go through `apps/auth-server/src/app/helpers/ssrf-safe-fetch.ts`.
  Token Status Lists named by a wallet credential are fetched by
  `libs/server/federation/src/status/`, only under an operator allowlist of
  URI prefixes.
- **Wallet presentations.** SD-JWT VCs, key-binding JWTs, key attestations and
  `x5c` chains, posted to `/oid4vp/response`.
- **Tokens and assertions.** Bearer access tokens on every protected route,
  refresh tokens, client assertions, ID-JAG assertions and subject or actor
  tokens in a token exchange.
- **Cookies and form fields** on the hosted pages, including the CSRF pairs.
- **Dynamic Client Registration bodies.**

## Default-off surfaces are in scope when enabled

Some surfaces are off by default. Review them as if the operator turned them
on, and name the switch in the report.

| Switch                                      | Default | Surface                                                                    |
| ------------------------------------------- | ------- | -------------------------------------------------------------------------- |
| `WALLET_FEDERATION_ENABLED`                 | `false` | Wallet sign-in over OID4VP 1.0: `/ui/wallet-*`, `/oid4vp/*`, account links |
| `HYBRID_SIGNING_ENABLED`                    | `false` | ML-DSA-65 + Ed25519 hybrid signing (`SIGNING_ALGORITHM_MODE`)              |
| `ID_JAG_ENABLED` + `ID_JAG_TRUSTED_ISSUERS` | `false` | Enterprise-managed authorization: consuming and minting ID-JAG             |
| `CIMD_ENABLED`                              | `true`  | Client ID Metadata Documents. On by default                                |

## What matters most and least

Most:

- `apps/auth-server/src/app/routes/` and `apps/auth-server/src/app/helpers/`.
- `libs/server/jwt`, `libs/server/password`, `libs/server/pkce`.
- `libs/server/federation` — OID4VP, SD-JWT VC, trust, status lists, `x509`.
- `libs/core/crypto` and `libs/core/crypto-native` — the signing backends.
- `libs/fastify/plugins/` — including `mcp-guard`, which resource servers use
  to accept QAuth tokens.
- Session and token handling in `apps/developer-portal/src/server/`.

Out of scope:

- `apps/docs-site` — a static documentation site.
- `scripts/`, `.claude/`, the CI configuration and other repository tooling.
- Test fixtures and test helpers.

## What QAuth promises

A break of any of these is a finding:

- PKCE with `S256` is required on every authorization code flow.
- A redirect URI must match a registered one exactly. The one exception is
  the port of a loopback redirect URI (RFC 8252).
- A token is bound to its audience (RFC 8707). A token issued for one audience
  is never accepted for another. See [ADR-006](../adr/006-oauth-grants-and-audience.md).
- A refresh token is single-use. Reusing one revokes its whole family.
- An authorization code is issued only with the user's consent, or when an
  active consent already covers the requested scopes.
- Token exchange preserves or narrows scope and audience. It never widens
  them, and the `act` claim records every delegation step.
- Revoking a consent, a token, or a user's access stops new tokens being
  minted from it.
- A disabled user gets no tokens.
- Data in one realm never reaches another.
- Secrets are hashed with Argon2id and compared in constant time.
- Login and registration do not reveal whether an account exists.
- Every cookie-authenticated state change is CSRF-protected.
- Authorization responses carry `iss` (RFC 9207).
- A URL a client or credential names never makes QAuth reach a private or
  loopback address, or follow a redirect, unless the operator allowed it.
- The management API accepts only the developer portal's own tokens. See
  [ADR-012](../adr/012-dynamic-client-ownership.md) for who owns a
  dynamically registered client.

## How we rate severity

Ratings follow the advisories already published in this repository.

- **Critical** — a bypass of authentication or consent; minting or accepting a
  token across clients, audiences, users or realms; exposure of a signing key;
  remote code execution. Examples:
  [GHSA-46p8-vmjm-2jpq](https://github.com/qauth-labs/qauth/security/advisories/GHSA-46p8-vmjm-2jpq)
  (`prompt=none` issued a code without consent) and
  [GHSA-c863-7xrr-ww9v](https://github.com/qauth-labs/qauth/security/advisories/GHSA-c863-7xrr-ww9v)
  (the management API accepted a token issued for any audience).
- **High** — an unauthenticated request that takes the server down, or account
  takeover that needs the victim to act. Example:
  [GHSA-m9gc-789c-9xwc](https://github.com/qauth-labs/qauth/security/advisories/GHSA-m9gc-789c-9xwc)
  (an unbounded password blocked the event loop).
- **Medium** — a control that should end or limit access does not, or not
  promptly: revocation, a disabled user, lockout, rate limiting. Also races
  with a narrow window, open redirects, and trust decisions that depend on a
  documented but non-default configuration. Examples:
  [GHSA-6fcx-34r3-24v4](https://github.com/qauth-labs/qauth/security/advisories/GHSA-6fcx-34r3-24v4)
  (token exchange kept minting after consent revocation),
  [GHSA-c2gj-r6hx-292c](https://github.com/qauth-labs/qauth/security/advisories/GHSA-c2gj-r6hx-292c)
  (refresh rotation was check-then-act),
  [GHSA-54c2-vvpr-33mf](https://github.com/qauth-labs/qauth/security/advisories/GHSA-54c2-vvpr-33mf)
  (a disabled user still got tokens) and
  [GHSA-7vg7-x4w7-7m8c](https://github.com/qauth-labs/qauth/security/advisories/GHSA-7vg7-x4w7-7m8c)
  (an open redirect in `return_to`).
- **Low** — a hardening gap with no demonstrated impact.

A finding in a default-off surface is rated as if the switch were on. Name the
switch in the report.

## How to exercise it

- Build: `pnpm install --frozen-lockfile`, then
  `pnpm exec nx run-many -t build`.
- Unit tests: `pnpm exec nx run-many -t test`. Integration tests
  (`test-integration`) need a Docker daemon, because they use testcontainers.
- A self-contained review image: `tools/security-review/Dockerfile`. It holds
  the built workspace, PostgreSQL 18 and Redis, so it works with no network.
  Inside it, `tools/security-review/start-stack.sh` starts the database and
  Redis, runs the migrations and starts the auth-server on
  `http://localhost:3000`. Export a switch from the table above before running
  the script to turn that surface on.

## How a report and a patch should look

- A reproducer: a failing `vitest` test next to the code it exercises, or a
  `curl` script against the local stack.
- The rule that breaks, from the list above, or the ADR that states it. The
  ADRs live in `docs/adr/`.
- A patch, if you have one: the smallest change that restores the rule, with a
  regression test that fails before it and passes after.

## Things to leave alone

- `WalletProvider.verify()` throws on every call. That is deliberate and
  fail-closed. Wallet sign-in does not use it.
- Keys, secrets and tokens inside test fixtures are dummies, not leaks.
- Open Dynamic Client Registration is the documented policy. Registering a
  client is not a finding. A registered client that gets a token without the
  user's consent is.
- Deprecated surfaces are still in scope. Dynamic Client Registration and
  `POST /auth/login` are both reviewed like any other route.
