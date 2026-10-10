# ADR-019: Deployment Topology, Trust Boundaries and Key Custody

**Status:** Proposed — records the maintainer's decisions of 2026-10-08, 2026-10-09 and 2026-10-10; it becomes Accepted when the maintainer has read this text.  
**Date:** 2026-10-09  
**Authors:** QAuth Team

> Nothing below is implemented. This record fixes six things:
>
> - where a realm lives on the wire;
> - who owns the browser session;
> - how sign-in screens reach the engine;
> - who may administer what;
> - how roles split across machines;
> - where keys live.
>
> For production, it supersedes the environment-variable key model of
> [ADR-001](./001-jwt-key-management.md). See Decision 9.
>
> **Amended 2026-10-09** with the effects of the maintainer's 2026-10-09 answers to ADR-014 to
> ADR-017. Those records hold the reasons.
>
> - Decision 3: a realm's `ssoMaxLifespan` also caps refresh families, and "sign out everywhere"
>   is defined.
> - Decision 7: the Authority Tree's realm-admin powers map onto the permission catalog.
>
> **Amended 2026-10-10** with the maintainer's answers on the UI scope, given on 2026-10-09 and
> 2026-10-10. ADR-020 (proposed in a separate PR) records the screens.
>
> - Decision 3: one browser may hold several accounts' sessions for a realm.
> - Decision 5: the UI list, the theme tier and the federation section of the admin console.
> - Decision 7: a two-admin approval rule for security operations.
> - Decision 8: event delivery through a transactional outbox and a delivery role.
> - Decision 9: two more key purposes.
> - New Decisions 10 to 12: where settings live, the paired sandbox realm, and plugins.

## Context

QAuth's 1.0 is aimed at self-hosting developers. Its stability promise is a wire-level promise. An
independent external security audit covers it before 1.0.

A promise of that kind needs a written topology first. Some parts of the topology cannot change
after 1.0 without breaking deployed clients, passkeys or federation partners:

- the host a realm's issuer lives on;
- the host a passkey is bound to;
- the origin that owns the browser session;
- the API a sign-in screen uses to reach the engine.

Two browser rules shape most of the answers below.

- A `__Host-` cookie must carry `Path=/` and no `Domain` attribute. It belongs to a whole host,
  never to a path.
- A WebAuthn relying-party ID (RP ID) is the page's host or a parent domain of it. A passkey works
  only under the RP ID it was registered for.

So two realms on one host would share one session cookie and one RP ID.

### What exists today and what this record changes

| Area                      | Today                                                                                                                                                                           | This record                                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Realm, host, issuer       | One issuer per deployment, from `JWT_ISSUER`. Requests resolve to the default realm through `getOrCreateDefaultRealm`, named by `DEFAULT_REALM_NAME`.                           | One host and one issuer per realm (Decision 1).                                                                                  |
| Custom domains            | MVP-PRD defers them to Phase 6+.                                                                                                                                                | In 1.0 (Decision 1).                                                                                                             |
| Passkeys                  | No passkey sign-in.                                                                                                                                                             | RP ID is the realm's exact host, locked after the first enrolment (Decision 2).                                                  |
| Browser session           | `__Host-qauth_session`, HMAC-signed with `SESSION_COOKIE_SECRET`. Session data lives only in Redis. The auth server does not use the `sessions` table.                          | Lives only on the realm's auth host. Postgres is the source of truth and Redis a cache (Decision 3).                             |
| Developer portal session  | The `__Host-qauth_portal_session` cookie carries the access and refresh tokens, HMAC-signed with `PORTAL_SESSION_SECRET`.                                                       | Tokens move server-side. The cookie carries only a session id (Decision 3).                                                      |
| Logout                    | No end-session endpoint. `POST /auth/logout` revokes the user's refresh tokens.                                                                                                 | RP-initiated logout and OIDC Back-Channel Logout 1.0. No front-channel logout (Decision 4).                                      |
| Sign-in screens           | The auth server renders `/ui/login`, `/ui/consent`, `/ui/resume/{handle}`, `/ui/wallet-login` and `/ui/wallet-link` itself.                                                     | A separate reference ceremony app on the public Interaction API (Decisions 5 and 6).                                             |
| Resuming an authorization | A Redis pending-authorization stash, picked up by `/ui/resume/{handle}` after sign-in.                                                                                          | Replaced by the Interaction API (Decision 6).                                                                                    |
| Management API            | `/api/clients`, with its API-key routes, and `/api/consents` accept only the portal's system-client token (`assertManagementToken`). `roles` and `user_roles` are not enforced. | Three API families, one audience per token. Admin access by scope and role, DPoP-bound, passkey-gated (Decision 7).              |
| Scale-out                 | Every auth-server instance serves every route and reads every key.                                                                                                              | Roles of one codebase over one transactional store (Decision 8).                                                                 |
| Keys                      | Read from environment variables or files on every instance. Retired keys are not wired at the app layer.                                                                        | Per realm and per purpose, envelope-encrypted in Postgres, held by a signer role, rotated every 90 days by default (Decision 9). |
| Settings                  | Most policies are environment keys: `ACCESS_TOKEN_LIFESPAN`, `REFRESH_TOKEN_LIFESPAN`, `REQUIRE_VERIFIED_ACCOUNT`, `PASSWORD_MIN_SCORE`, `EMAIL_FROM_*`, `SMTP_*` and `CIMD_*`. | Deployment switches stay in the environment. Realm policies live on the realm row (Decision 10).                                 |
| Sandbox                   | None.                                                                                                                                                                           | A paired sandbox realm with its own host, issuer and keys (Decision 11).                                                         |
| Plugins                   | `CredentialProvider` implementations compiled into the auth server.                                                                                                             | Operator-installed, in-process plugins on the AuthMethod contract (Decision 12).                                                 |

Today's key and secret variables include:

- `JWT_PRIVATE_KEY`, `JWT_RS256_PRIVATE_KEY` and `JWT_MLDSA_PRIVATE_KEY`;
- `OID4VP_VERIFIER_SIGNING_KEY` and `OID4VP_RESPONSE_KEY_SECRET`;
- `SESSION_COOKIE_SECRET` and `PORTAL_SESSION_SECRET`.

The JWT plugin can already publish retired keys under their own `kid`. The app layer does not pass
them, so a rotation still forces users to sign in again. ADR-001's status note records this gap.

## Decision

### 1. Realm, host and issuer

- Each realm has its own host and its own issuer.
- The host is a subdomain or any hostname the operator configures. Custom domains are part of 1.0.
- A single-realm simple mode uses the deployment's host as the default realm's issuer.
- QAuth needs a dedicated host. It never runs under a path of a shared host.
  - `__Host-` cookies need `Path=/`.
  - WebAuthn RP IDs are host-scoped.
- Path-based realms are rejected. For example, Keycloak uses the `/realms/{name}` form. Realms on
  one host would share the session cookie and the RP ID.
- A realm's issuer host is permanent. Changing it breaks issued tokens, registered clients, enrolled
  passkeys and federation identity.

### 2. Passkey RP ID

- The RP ID is the realm's exact host by default.
- A parent domain is allowed only by explicit operator opt-in, with a warning.
- The RP ID is locked after the first passkey enrolment in that realm.

A parent-domain RP ID lets every host under that domain request assertions for the realm's
passkeys. A changed RP ID orphans every passkey already enrolled.

### 3. Session ownership and storage

Ownership:

- The browser session lives only on the realm's auth host.
- Its cookie is a `__Host-` cookie with no `Domain` attribute.
- There is no SSO across realms. A realm trusts another only through upstream OIDC or OpenID
  Federation.
- Every other UI keeps its own BFF session, with its tokens stored server-side.
- The admin console is a client of a separate operator realm.
- The developer portal follows the same rule. Its tokens move server-side, and its cookie carries
  only a session id. This lands with ADR-017 F0.

Storage:

- Postgres is the source of truth for sessions.
- Redis is a cache in front of it.
- Last-seen updates are throttled.

Today browser sessions live only in Redis. The `sessions` table exists in the schema, but the auth
server does not use it.

Lifetime and sign-out everywhere, decided 2026-10-09 (maintainer):

- When a realm sets `ssoMaxLifespan`, that limit also caps the realm's refresh-token families.
  Today the `realms` table has the column, but no code reads it.
- "Sign out everywhere" revokes the user's session rows in Postgres and clears them from the
  cache. It also sends back-channel logout (Decision 4).

Several accounts on one browser, decided 2026-10-10 (maintainer). This widens the 2026-10-08 rule
of a single browser session on the auth host:

- One browser may hold sessions for several accounts of the same realm.
- `prompt=select_account` shows a chooser. With `prompt=none`, more than one account session and no
  hint naming one, the answer is `account_selection_required` (OpenID Connect Core 1.0 §3.1.2.6).
- Each account session keeps its own `sid`, its own back-channel logout and its own sign-out. A user
  can sign out of one account or of all accounts on the browser.
- The ownership rules above still hold: the sessions live only on the realm's auth host, under
  `__Host-` cookies with no `Domain` attribute. How the cookies are laid out is an implementation
  detail inside that rule.
- There is still no SSO across realms.

### 4. Logout

- 1.0 ships RP-initiated logout, as ADR-017 F0 describes.
- 1.0 ships OIDC Back-Channel Logout 1.0.
- There is no front-channel logout.
- Authority Trees survive sign-out, as ADR-014 parked decision 1 records. A tree ends by explicit
  revocation or by expiry.

### 5. User interfaces are separate, replaceable clients

Headless means the core has no UI of its own. Every UI is a separate, replaceable client of public
APIs:

- the reference ceremony app;
- the admin console, with its federation section;
- the developer portal;
- the account console, which holds the Authority Tree screens.

The account console is the "portal" that ADR-014 names for agent owners. That follows from the
API families of Decision 7: an agent belongs to a human account, and its owner acts through the
account API.

The federation section is part of the admin console, not a separate app. It opens when the console
connects to a federation-operator deployment's admin API. That deployment's signer role signs; the
console holds no keys. Decided 2026-10-10 (maintainer).

The reference ceremony app covers these ceremonies:

- login and consent;
- Authority Tree approval;
- registration and password reset;
- passkey enrolment;
- wallet sign-in;
- device-code entry for the RFC 8628 device authorization grant;
- the account chooser for several accounts on one browser (Decision 3).

How it is deployed:

- It is deployed separately from the auth server.
- It is served on the realm origin under `/ui/*`, through reverse-proxy path routing.
- The proxy strips QAuth's cookies from requests to `/ui/*`.
- It uses only the public Interaction API. It has no private shortcut into the engine.
- Today's server-rendered pages move into it: `/ui/login`, `/ui/consent`, `/ui/resume`,
  `/ui/wallet-login` and `/ui/wallet-link`.
- The pending-authorization mechanism behind `/ui/resume/{handle}` does not move. The Interaction
  API replaces it (Decision 6).

Customisation comes in three tiers:

1. Theme: brand settings in the admin console. They cover the logo, colours, a font from a safe
   list, per-locale strings, links and dark mode. There are no uploaded templates and no custom CSS
   or JavaScript. Decided 2026-10-10 (maintainer).
2. Fork the reference app.
3. Build your own UI on the API.

A component library builds on `libs/ui`.

Every ceremony page meets one baseline:

- WCAG 2.2 AA.
- A strict CSP, with no third-party scripts.
- `frame-ancestors 'none'`.
- Password, the email-code step and TOTP work without JavaScript. Their forms post directly to the
  auth server.
- Passkeys need JavaScript.

### 6. The Interaction API

**Name.** "Interaction API" is QAuth's name. It is not a spec term. Its neighbours are:

- "End-User interaction" and the `interaction_required` error in OpenID Connect Core 1.0;
- GNAP (RFC 9635);
- the "interactions" of a widely used open-source Node.js OpenID Provider library, for example
  `oidc-provider`.

**Model.** The API is browser-facing and same-origin.

- A cookie and a CSRF token protect it.
- Credentials go straight from the browser to the engine.
- The UI server holds no privileged key.

**One grammar, two transports, one engine.**

- The Interaction API shares its step grammar with FiPA. ADR-017 Decision 3 defines that grammar.
- The Interaction API is the transport for browser ceremonies.
- The FiPA endpoint is the transport for first-party native apps.
- One engine sits behind both. It is the engine of ADR-017 F1.
- Web front-ends use the redirect flow. This answers ADR-017 parked question 1.

**Display rules.**

- The API returns typed data from the auth server's own records only. It never returns HTML.
- Client-supplied names are untrusted. So the screen shows the verified domain: the CIMD URL host,
  or the federation entity id and its trust marks.
- For an Authority Tree approval, the passkey challenge is bound to the hash of the canonical
  request.

**Contract.**

- The path is versioned: `/interaction/v1`.
- It is published as OpenAPI, plus JSON Schema for the steps.
- It is inside the 1.0 stability promise.

**What it replaces.** The Interaction API replaces today's internal pending-authorization stash and
`/ui/resume/{handle}`.

### 7. API families and admin authorization

There are three API families. Each token carries one audience.

| Family    | Caller    | Today                                                            |
| --------- | --------- | ---------------------------------------------------------------- |
| admin     | Operator  | No admin API.                                                    |
| account   | End user  | Cookie-authenticated `GET /consents` and `DELETE /consents/:id`. |
| developer | Developer | `/api/clients`, its API-key routes, and `/api/consents`.         |

**Who administers what.**

- Operator-realm admins manage any realm, by grant.
- Realm-local admins manage only their own realm. Their token's `iss` must be that realm's issuer.
- Realm-local admins never manage the operator realm.

**Permissions.**

- Scopes are coarse and independent: `admin:read`, `admin:write` and `admin:security`.
- Scopes are intersected with roles.
- Roles are built from a permission catalog. Custom roles are allowed.

**Authority Tree powers.** ADR-014 gives a realm admin three powers. They map onto the permission
catalog. This answers ADR-015 parked question 10. Decided 2026-10-09 (maintainer).

- Revoke-by-agent needs `admin:security`, with a fresh passkey approval for each operation.
- Disabling a transmitter needs the same.
- The view the agent's public profile withholds needs `admin:read`.

**Credentials.**

- Admin tokens are DPoP-bound and short-lived.
- Admin sign-in needs a passkey.
- A security operation needs a fresh passkey approval bound to that operation. It uses the
  mechanism of ADR-014 §14.
- Security operations include key rotation, realm deletion and ownership transfer.

**Two-admin approval**, decided 2026-10-10 (maintainer).

- The admin console recommends a second admin's approval for every `admin:security` operation.
- A realm chooses the operations where it is mandatory. Deleting a user's passkey or TOTP is the
  first example.
- The second admin approves with their own fresh passkey. Nobody approves their own request.
- A realm with one admin sees a warning. If a mandatory rule leaves no second admin, the break-glass
  CLI below is the way out.
- Both approvals land in the admin events.

**Automation.**

- Service accounts live in the operator realm.
- They use `client_credentials` with `private_key_jwt`.
- CI exchanges its workload OIDC token through RFC 8693 token exchange.
- There are no static admin keys.

**Acting for a user.**

- There is no classic impersonation.
- An admin acting for a user gets an act-chain token.
- That action is visible in the audit log and on the user's account page.

**Operations.**

- The admin API runs on a separate internal listener.
- Bootstrap and break-glass go through a CLI.
- Every admin action lands in an immutable audit log.
- An admin-events API reads that log.

Today the management API accepts only the portal's system-client token, checked by
`assertManagementToken`. The `roles` and `user_roles` tables exist, but nothing enforces them.

### 8. Distributed roles over one transactional store

- A distributed deployment runs the same codebase, split by role.
- All roles share one transactional store.
- Security-critical state is never split across databases. That covers:
  - refresh-token rotation;
  - single-use codes;
  - consent revocation;
  - the Authority Tree ledger and its cascades.
- Internal traffic uses mTLS or workload identity.
- Each realm has one issuer, with consistent discovery on every node.
- Trusted proxy hops are configured explicitly.
- Every node checks a configuration digest at boot.

Where endpoints sit:

- Browser-session endpoints sit on the realm host. They are authorize, the ceremony UI, end-session
  and approval.
- API endpoints may sit elsewhere. They are token, introspection, revocation, JWKS and admin.
- RFC 8414 metadata allows endpoints on other hosts.

How revocation reaches resource servers:

- short token lifetimes;
- introspection for high-risk calls;
- OpenID Shared Signals Framework (SSF) streams with CAEP events, which 1.0 ships as one of the
  event routes below.

**Event delivery**, decided 2026-10-10 (maintainer). ADR-018 §3 lists the four routes.

- Each event is written to a transactional outbox in Postgres, in the same transaction as the change
  it records. No event is lost when a node fails.
- A delivery role reads the outbox and sends signed webhooks and SSF streams. It runs in-process in
  a single deployment, like the signer.
- Delivery is at least once. Every event carries a stable id, so a receiver drops duplicates.
- The cursor-based event API reads the same store.
- The delivery role holds no private keys. The signer role signs Security Event Tokens and webhook
  payloads (Decision 9).
- OpenTelemetry export is telemetry each role emits. The event API and webhooks are the channels
  that guarantee delivery.

### 9. Key custody

**Storage.**

- Keys are kept per realm and per purpose.
- They are stored envelope-encrypted in Postgres.
- The key-encryption key (KEK) comes from a pluggable provider.
- The default provider reads the KEK from an environment variable or a file.
- Optional packages add adapters, for example for a cloud key management service, a secrets vault
  or an HSM through PKCS#11.
- The local backend stays the default. EdDSA and ML-DSA support varies across KMS products.

**One key per purpose.**

- access-token and ID-token signing;
- Security Event Token (SET) and logout-token signing;
- the federation entity key;
- the trust-anchor key;
- OID4VP verifier request signing;
- OID4VP response encryption;
- data-at-rest encryption;
- the cookie HMAC;
- webhook payload signing, per subscription. Added 2026-10-10;
- client-assertion keys QAuth uses as a relying party toward an upstream provider, for example the
  `private_key_jwt` key the My Number plugin needs. Added 2026-10-10.

**Who holds keys.**

- A signer role holds the private keys.
- In a single deployment, the signer runs in-process.
- In a distributed deployment, other roles call the signer over mTLS.
- The trust-anchor key lives in a separate federation-operator deployment. It may be kept offline.
- The admin, UI and interaction roles hold no private keys.
- Only the browser-facing role holds the cookie HMAC secret.

**Rotation.**

- Rotation is automatic and overlapping.
- The next signing key is pre-published in JWKS before it signs.
- The old key stays published for verification.
- The default period is 90 days. The operator can change it.
- A manual rotation needs `admin:security` plus a passkey approval.
- This record closes the retired-key wiring gap that ADR-001's status note records.

**Relation to ADR-001.** This record supersedes ADR-001's environment-variable key model for
production. Today every instance reads its keys from environment variables or files.

### 10. Settings: deployment switches and realm policies

Decided 2026-10-10 (maintainer).

- **Deployment-wide switches stay in the environment.** Examples are `WALLET_FEDERATION_ENABLED`,
  `AUTHORITY_TREE_ENABLED`, the signing mode and experimental features. The console shows them read
  only.
- **Realm policies live in Postgres, on the realm row.** They change through the admin API and the
  admin console. They include sign-up, the verified-account requirement, password and MFA policy,
  session and token lifetimes, brand settings, upstream providers and the email sender.
- **The environment only seeds a new realm's defaults.** Changing an environment key later does not
  change an existing realm.
- The admin API's realm representation and the declarative realm file of ADR-018 §5 carry these
  policies.

ADR-008's posture already lives in the database: `realms.max_environment_laxity` and
`oauth_clients.environment`. The admin console edits both. Tightening is free. Loosening needs
`admin:security` with a fresh passkey, and a second admin where the realm requires one (Decision 7).

### 11. Paired sandbox realm

Decided 2026-10-10 (maintainer).

- A live realm can have a paired sandbox realm. It is a realm in its own right.
- It has its own host, issuer, keys and passkey RP ID, under Decisions 1, 2 and 9.
- Its ADR-008 ceiling is `staging`, so the developer portal's flow test console works there.
- It shares no users with the live realm. Its upstream providers use test accounts.
- Configuration moves from sandbox to live through the realm file's diff (ADR-018 §5). Secret values
  are never copied, so live secrets are set on the live realm.
- The admin console and the developer portal switch between sandbox and live with one control.

A production resource server rejects a sandbox token because the issuer differs. No extra check is
needed in the resource server. That is why a sandbox flag inside the live issuer was rejected:
every resource server would have to check that claim, and one that forgot would accept sandbox
tokens.

### 12. Plugins

Decided 2026-10-10 (maintainer).

- Plugins implement the AuthMethod contract. Examples are the Google, Microsoft, Apple, GitHub and
  My Number provider plugins of ADR-018 §3.
- A plugin is trusted code. The operator installs it with the deployment, and it runs in-process.
- The admin console can enable, configure and disable an installed plugin. It never uploads or edits
  plugin code. For the same reason there are no script mappers.
- A plugin holds no private keys. It asks the signer role, like every other component (Decision 9).
- The plugin API is experimental in 1.0 (ADR-018 §4).

## Consequences

### Positive

- One realm maps to one host and one issuer. Cookies, passkeys and tokens cannot cross realms by
  sharing a host.
- Custom domains in 1.0 let an operator put each issuer under its own name.
- A UI can be replaced without touching the engine.
- One engine and one step grammar serve both browser ceremonies and first-party native apps.
- The ceremony app's server holds no privileged key, so a compromise there yields no signing key.
- Admin access is passkey-gated, DPoP-bound and audited. No static admin key exists to leak.
- A key rotation no longer forces users to sign in again.
- Security-critical state stays in one transactional store when a deployment scales out.
- The Interaction API is versioned and published, so a custom UI has a stable target.
- A sandbox token can never pass a production resource server, because the issuer differs.
- Events survive node failures, because the outbox shares the transaction of the change.

### Negative

- The operator provisions DNS and TLS for every realm host. Automatic TLS (ACME) and DNS
  verification come later, with a hosted service.
- An issuer host chosen badly cannot be fixed later. The choice is permanent.
- There is no SSO across realms. A person with accounts in two realms signs in to each, unless the
  realms federate.
- A path-routing reverse proxy becomes a deployment requirement. Its cookie stripping for `/ui/*`
  must be configured correctly.
- Sessions in Postgres add writes on sign-in and throttled writes on activity.
- Envelope encryption, a signer role and automatic rotation are new code inside the audit's scope.
- Passkeys need JavaScript. Only password and TOTP work without it.
- Rebuilding today's server-rendered pages as a separate app is a large migration.
- Several accounts on one browser make session handling, sign-out and `prompt=none` more complex.
- A sandbox realm doubles the host, DNS and TLS work for every realm that uses one.
- Moving realm policies from environment keys to the realm row needs a one-time migration of today's
  values.

### Neutral

- The single-realm simple mode keeps a one-host deployment simple.
- KMS, vault and HSM adapters are optional packages. The default needs no external service.
- The FiPA authorization challenge endpoint stays experimental in 1.0 until FiPA is an RFC. The
  engine behind it is stable, because the hosted pages use it.
- Web front-ends keep the standard redirect flow.

## Answers to the open questions (2026-10-09)

The maintainer answered these on 2026-10-09. Each answer is a decision of this record.

- **Breadth of administration.** SAML, LDAP, Kerberos and UMA are not in 1.0. ADR-018 says when
  SAML and LDAP come.
- **Support window.** ADR-018 sets it: a deprecation waits at least 12 months, and removal happens
  only in a new major release. So `/interaction/v1` stays served for at least 12 months after a
  successor ships, and until the next major release.
- **Session write throttle.** By default a session's last-seen time is written at most once a
  minute. The operator can change the interval.
- **Retired-key lifetime.** The next key is published in the JWKS 7 days before it starts signing.
  A retired key stays published for 14 days after rotation, and never for less than the longest
  lifetime of a token it signed. These defaults cover relying parties' JWKS caches.
- **Existing issuers.** On upgrade, a deployment's current `JWT_ISSUER` becomes the issuer of its
  default realm, in single-realm mode. Keys from environment variables are imported once into the
  encrypted store at first boot. Existing clients and tokens keep working.
- **ADR-013's return leg.** The endpoint the wallet returns to stays on the auth server, under the
  Interaction API path `/interaction/v1/`. The Response Code binding and the signed `__Host-` binder
  cookie stay as they are. The ceremony app shares the realm origin, so the cookie keeps working.
  The ceremony app reads the flow's status only through the Interaction API.

## Open questions

None. The UI screen list was answered on 2026-10-09 and 2026-10-10; ADR-020 records it.

## Related

- [ADR-001: JWT Key Management Strategy](./001-jwt-key-management.md) — superseded for production
  by Decision 9.
- [ADR-005: Post-Quantum Cryptography — Hybrid Signing Roadmap](./005-pqc-hybrid-signing.md) — the
  ML-DSA key and the #248 checklist.
- [ADR-007: MCP-First Positioning](./007-mcp-first-positioning.md) — CIMD, whose URL host the
  consent screen shows.
- [ADR-008: Environment-Aware Authorization Posture](./008-environment-aware-authorization.md)
- [ADR-011: Enterprise-Managed Authorization](./011-enterprise-managed-authorization.md) —
  `private_key_jwt`.
- [ADR-012: Ownership of Dynamically Registered Clients](./012-dynamic-client-ownership.md) — the
  developer API family.
- [ADR-013: Same-Device Return Leg](./013-same-device-return-leg.md) — `/ui/wallet-login/return`
  and the `__Host-qauth_wallet_flow` binder cookie.
- [ADR-014: Authority Tree](./014-agent-authority-tree.md) — §14 remote approval; parked decision 1
  on sign-out.
- ADR-015 and ADR-016, proposed in PR #420 — the rest of the Authority Tree records.
- ADR-017: First-Party Login, proposed in PR #417 — F0, F1, Decision 3 and parked question 1.
- [ADR-018: QAuth 1.0 — Scope, Stability Promise and Release Path](./018-1-0-scope-and-stability.md)
  — the 1.0 scope and the stability promise this topology serves.
- ADR-020, proposed in a separate PR — UI surfaces and UX acceptance criteria.
- [Hosted UI guide](https://docs.qauth.dev/integrate/hosted-ui/) — today's server-rendered pages.
- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)
- [RFC 8628: OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
- [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 9635: Grant Negotiation and Authorization Protocol (GNAP)](https://www.rfc-editor.org/rfc/rfc9635)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
- [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
- [Standard Webhooks](https://www.standardwebhooks.com/)
- [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
