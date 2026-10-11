# ADR-019: Deployment Topology, Trust Boundaries and Key Custody

**Status:** Accepted 2026-10-11 — records the maintainer's decisions of 2026-10-08, 2026-10-09 and 2026-10-10.  
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
> 2026-10-10. ADR-020 records the screens.
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
  Only operator-realm admins assign a realm's host. Hosts are unique across all realms, sandbox
  twins included, and a wildcard host is refused.
- A single-realm simple mode uses the deployment's configured host as the default realm's issuer.
  That is the host of the configured issuer, never the host a request names.
- QAuth needs a dedicated host. It never runs under a path of a shared host.
  - `__Host-` cookies need `Path=/`.
  - WebAuthn RP IDs are host-scoped.
- Path-based realms are rejected. For example, Keycloak uses the `/realms/{name}` form. Realms on
  one host would share the session cookie and the RP ID.
- A realm's issuer host is permanent. Changing it breaks issued tokens, registered clients, enrolled
  passkeys and federation identity.

How a request finds its realm:

- A request belongs to the realm whose configured host, or one of whose configured endpoint hosts
  (Decision 8), equals the request's authority. The match is exact and case-insensitive, on the
  port-less ASCII form of the host. The authority is the `Host` header (`:authority` in HTTP/2). A
  forwarded host counts only when the hop that sent it is listed in `TRUST_PROXY` (Decision 8).
- Endpoint hosts are assigned and kept unique like realm hosts, and a server-to-server caller
  addresses the realm by one of them. An internal host name is configured the same way. For
  example, the developer portal's server reaches the auth server at `AUTH_SERVER_URL`
  (`http://auth-server:3000` in the Compose file); the operator configures that name as an endpoint
  host of the realm, and those calls keep working. An endpoint host answers no browser-session
  endpoint of Decision 8 (authorize, the ceremony UI, end-session and approval); a request for one
  there gets 421.
- The internal admin listener is not routed by host: it takes the realm from the request, within
  the caller's grant (Decision 7).
- A request that matches no realm host or endpoint host is refused with `421 Misdirected Request`.
  It gets no realm context: no cookie, no discovery and no fallback to the default realm. Simple
  mode refuses every host but its configured host and endpoint hosts in the same way. Only the
  health endpoints, which carry no realm data, answer on any host.
- No URL is built from the request. The issuer, the discovery and JWKS URLs, every endpoint URL,
  the links in mail, redirect targets, `verification_uri`, the WebAuthn origin and RP ID checks,
  and cookie attributes all come from the realm row.
- Every lookup by a user, client, session, consent or refresh-family id also takes the resolved
  realm id. A session, cookie or token that belongs to another realm is rejected.

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
- The proxy routes `/ui/*` on the normalised path, and the auth server answers no `/ui/*` path
  itself. A request that a path variant routes the wrong way fails instead of reaching the other
  side.
- The reference ceremony app refuses a request that carries a QAuth cookie, so a proxy that does
  not strip them fails at once.

The ceremony app is part of the realm's trusted computing base, whether it is the reference app or
a replacement. It shares the realm origin, so it sees every credential typed into it, and script it
runs can act as the signed-in user on that origin. Replacing it is a security decision of the
operator, like installing a plugin (Decision 12).

A ceremony page trusts nothing navigational from its URL that the server has not bound to the
interaction. It reads one opaque interaction id from the URL. The client, the redirect target and
everything else it shows come from the Interaction API. There is no `return_to`, redirect or client
parameter.

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
  auth server, with the step's CSRF value (Decision 6).
- Passkeys need JavaScript.

The proxy enforces the header part of the baseline. On every `/ui/*` response it sets the CSP
(scripts from the realm origin only, no third-party script), `frame-ancestors 'none'`,
`Referrer-Policy: no-referrer` and `Cache-Control: no-store`, replacing whatever the app sent. A
replacement app cannot loosen them. QAuth's reference proxy configuration does this. The reference
ceremony app runs under that policy with no inline script; the stack spike of ADR-020 §6 checks it.

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

**Flow binding and CSRF.** The proxy strips QAuth's cookies from `/ui/*`, so the ceremony app can
neither see nor mint a session-bound value. The engine supplies it.

- The authorization endpoint creates the interaction. It sets a `__Host-` flow cookie (`HttpOnly`,
  `Secure`, `SameSite=Lax`) bound to it, and redirects to `/ui/*` with an opaque interaction id.
- The id alone cannot answer a step. With it, the ceremony app's server reads the current step: its
  typed display data and a CSRF value for that step. That read returns no personal data. Personal
  data, such as the account chooser's list, reaches the page only through a call that carries the
  flow cookie.
- Every answer, whether an Interaction API call or a no-JS form post, carries the flow cookie and
  the step's CSRF value, and comes from the realm origin. The engine checks all three. The ceremony
  app embeds the CSRF value; it cannot mint one.
- A CSRF value is valid for one step and is never put in a URL.
- A flow is usable only in the browser that started it. The session id is rotated at
  authentication.
- A link QAuth mails points at the auth server, not at `/ui/*`. Opening it starts an interaction in
  that browser, with its own flow cookie, as the authorization endpoint does.

**One grammar, two transports, one engine.**

- The Interaction API shares its step grammar with FiPA. ADR-017 Decision 3 defines that grammar.
- The Interaction API is the transport for browser ceremonies.
- The FiPA endpoint is the transport for first-party native apps.
- One engine sits behind both. It is the engine of ADR-017 F1. Its abuse controls apply to both
  transports whatever `FIRST_PARTY_LOGIN_ENABLED` says (ADR-017 Decision 7).
- Web front-ends use the redirect flow. This answers ADR-017 parked question 1.

**Display rules.**

- The API returns typed data from the auth server's own records only. It never returns HTML.
- Client-supplied names are untrusted. So the screen shows the verified domain: the CIMD URL host,
  or the federation entity id and its trust marks.
- For an Authority Tree approval, the passkey challenge is bound to the hash of the canonical
  request.

The verified domain, per client class:

- **CIMD client:** the host of the client ID URL, shown in its ASCII (punycode) form. The
  registrable domain is highlighted. A host under a shared-hosting suffix, from the private section
  of the Public Suffix List, is flagged.
- **Federation client:** the entity id and its validated trust marks.
- **Client an admin registered:** the domain the admin set on it.
- **Dynamically registered or developer-portal client:** none. The screen says the app is
  unverified and shows the host that receives the code. A loopback redirect is shown as "this
  device", with a warning. The client-supplied name appears only below that, marked as declared by
  the app.

A client-supplied name, logo or link is data. It is length-capped, stripped of control and
bidirectional characters, and never shown above or instead of the verified domain. No logo is
loaded from a client-supplied URL at render time. A logo appears only when an admin uploaded it, or
when the server fetched it through the egress client (Decision 8) and re-encoded it. It is served
from the realm origin. An unverified client shows no logo.

The same rule holds on every screen that names a client: consent, device-code entry, the approval
page and the account console's applications list.

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
- Security operations include key rotation, realm deletion and ownership transfer. The next
  paragraph defines them by effect.

**Security operations, defined by effect.** An admin API operation needs `admin:security` because of
what it does, not because of the screen it sits on. The developer API's changes to a client or
resource the caller owns (ADR-012) and the account API's changes to the caller's own account keep
their own rules. An admin API operation is a security operation when it:

- changes which credentials, links or addresses can authenticate or recover an account: a set-up or
  reset link the admin copies; an account's identifier or contact address; removing a passkey, TOTP
  or recovery codes; an upstream provider, trusted issuer or AuthMethod plugin and its mappers;
  unlinking an upstream or wallet account, and linking an enterprise ID-JAG subject to a user
  (an admin never links any other upstream or wallet account: those are linked only when the user
  signs in to the existing account, ADR-020 §3. The ID-JAG link is the one exception, because the
  operator already chose to trust that issuer; [ADR-011](./011-enterprise-managed-authorization.md)
  gate 14); the realm's mail transport and sender;
  loosening the allowed sign-in methods or the MFA, password or brute-force policy;
- changes what a token asserts or who receives it: mappers, the scope catalog, roles and groups and
  their assignment to accounts, resource-server and audience registration, an agent type's
  `is_agent`, `max_agent_mode`, `spawn_allowlist`, `registered_rights` and grants (ADR-014 §1, §5),
  the verified domain an admin sets on a client (Decision 6), and a client's redirect URIs,
  authentication method or first-party trust, including its first-party policy and switching PKCE
  or DPoP off for it (ADR-017 Decision 2);
- issues a token or session for someone other than the caller, such as an act-chain token (below);
- changes who administers: granting or removing an admin role, creating an admin or a service
  account, and the two-admin configuration below;
- imports a realm file, or promotes a sandbox configuration into a live realm, whose diff holds any
  change listed here (Decision 11);
- acts as a federation operator: entity configuration, subordinates, metadata policy, trust marks,
  explicit registration and federation keys;
- is named as one elsewhere in this record: the Authority Tree powers above, key operations
  (Decision 9), loosening the environment posture (Decision 10) and revoking sessions or
  refresh-token families in bulk (ADR-020 §3).

`admin:write` covers the rest: display data, and operational changes with none of these effects. A
permission that performs a security operation exists only under `admin:security`, so no custom
role reaches one through `admin:write`. Sending a set-up or reset link to the contact address
already on the account is not a security operation. The link reaches only the person a
self-service reset reaches, and it does no more than ADR-017 Decision 8's reset could. Apart from
the copy operation, which returns its link once to the admin who performs it, no event, log,
webhook payload, admin view or API response carries a set-up or reset link, code or token.

Brand strings and links are not security settings: they are display data under `admin:write` on
the ceremony pages. Mail takes the brand's logo, colours and strings but no brand link (ADR-020
fork C). Brand settings never form or replace a mail's link, code or pass, which the server builds
from the realm row (Decision 1).

A service account has no passkey. It can file a security operation, for example a realm-file import
from CI, but the operation runs only after a human admin approves it with a fresh passkey. That
approval stands in for the requester's own; where the realm requires a second admin, a second,
different human admin approves too.

**Two-admin approval**, decided 2026-10-10 (maintainer).

- The admin console recommends a second admin's approval for every `admin:security` operation.
- A realm chooses the operations where it is mandatory. Deleting a user's passkey or TOTP is the
  first example.
- The second admin approves with their own fresh passkey. Nobody approves their own request.
- A realm with one admin sees a warning. If a mandatory rule leaves no second admin, the break-glass
  CLI below is the way out. For anything but an emergency key retirement, it enrols a new admin, who
  can approve only 7 days later (below); until then the operation fails closed.
- Both approvals land in the admin events.

How the rule protects itself:

- Once any operation is mandatory, these are themselves mandatory two-admin operations: changing
  the mandatory set, creating an admin, granting or removing `admin:security`, and changing an
  admin's credentials, identifier or contact address through the admin API. One admin alone can
  only tighten the mandatory set, by adding an operation. An admin's change to its own credentials,
  identifier or contact address through the account API needs no second admin: it follows the
  account API's own rules (ADR-017 Decision 8, ADR-020 §3), and that admin cannot approve for the
  next 7 days (below).
- The approver is a different account that held `admin:security` in the target realm before the
  request was made. In the 7 days before the request it was not created or granted a role, and its
  credentials, identifier and contact address did not change, whoever made the change. The
  automatic password disable of ADR-017 Decision 7 is not such a change. It approves
  with a passkey credential that is not registered to the requester's account. The admin event
  records both credential ids.
- An approval is single use and expires within minutes. Its passkey challenge is bound to the hash
  of the canonical operation: the target, the parameters, the realm, the requester and a nonce.
- The approver sees the operation rendered from the stored request. Text the requester adds, such
  as a reason, is shown as quoted text and never as the operation.
- If a mandatory rule cannot be met, the operation fails closed.
- The rule binds accounts, not people. One person who set up two admin accounts before any
  operation was mandatory can still satisfy it, so the admin events show who created each approver.
  Whoever holds the host and the KEK stands outside the rule through the break-glass CLI, whose
  every use is recorded and announced (below).

**Automation.**

- Service accounts live in the operator realm.
- They use `client_credentials` with `private_key_jwt`.
- CI exchanges its workload OIDC token through RFC 8693 token exchange.
- There are no static admin keys.

**Acting for a user.**

- There is no classic impersonation.
- An admin acting for a user gets an act-chain token.
- That action is visible in the audit log and on the user's account page.
- Acting for a user is a security operation. An act-chain token never counts as the user's fresh
  authentication. The account API refuses it on every route that changes a credential, an
  identifier, the contact address or a linked account, and on account deletion.

**Operations.**

- The admin API runs on a separate internal listener. The listener trusts no caller for its network
  position: every call carries a DPoP-bound admin token and is authorized as above.
- Bootstrap and break-glass go through a CLI.
  - The break-glass CLI runs only on a host that holds the database credentials and the KEK. It is
    not reachable over the network.
  - It can create a one-time admin enrolment and retire a key in an emergency (Decision 9). It never
    sets a password and never imports a key.
  - Each use records the operating-system user in the audit log and sends a critical security event
    on every event route.
- Every admin action lands in an immutable audit log. The roles that write it hold only `INSERT` on
  it. Each row carries the hash of the row before it, so a changed or removed row breaks the chain.
  Only the retention job deletes, oldest rows first, and only after the event routes have offered
  them.
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
- API endpoints may sit elsewhere. They are token, introspection, revocation, JWKS and admin. Off
  the realm host, the admin API answers on its internal listener (Decision 7), and every other API
  endpoint a server-side caller uses answers on the realm's endpoint hosts (Decision 1): the first
  four, userinfo, the account and developer APIs, and the legacy `/auth/*` routes until ADR-017
  removes them (Decision 12).
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

**Outbound calls.** Every outbound call that configuration or user input causes goes through one
SSRF-safe egress client. That covers webhooks, SSF push, back-channel logout, upstream discovery,
JWKS, token and userinfo calls, federation statements, CIMD and client `jwks_uri` fetches,
bot-challenge verification, breach-list lookups and logo fetches. Plugins use the same client
(Decision 12). The client:

- serves every HTTP method, not only `GET`;
- uses `https` only, with no credentials in the URL;
- resolves the name once per request, checks every address and connects only to a checked address;
- never connects to a private, loopback, link-local or otherwise non-public address, unless a
  deployment-level allowlist names that host or range and the destination was set by the operator
  or an admin, for a realm that the allowlist entry names. Realm admins cannot edit that list, and a
  destination that a client, an end user or a remote document supplies never uses it;
- re-checks a redirect target by the same rules before it follows it;
- caps the time and the size of every response.

A destination is checked when it is registered and again at every delivery. That holds for a
`backchannel_logout_uri`, a webhook or SSF endpoint, and the owner-registered webhook of ADR-014
decision 16. Every URL an upstream's discovery or federation document names passes the same check,
and the document's `issuer` must equal the configured one. Neither those URLs nor a
`backchannel_logout_uri` that a client registers ever use the allowlist, so neither reaches a
private or loopback address, even for a development client. An operator whose upstream provider
sits on a private address sets the provider's endpoints in its configuration instead of taking them
from discovery. A back-channel logout endpoint on a private address is set on the client by an
admin, not by the client's own registration.

The delivery role does not share network reach with the signer or the internal admin listener. In
a distributed deployment it runs with egress rules that block the cloud metadata address, Redis,
the signer, the admin listener and every database access beyond its outbox credentials. In a single
deployment, where it runs in-process, the egress client is its only way out, and the admin listener
trusts no caller for its network position (Decision 7).

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
  `private_key_jwt` key the My Number plugin needs. Added 2026-10-10;
- the upstream app identity keys a credential adapter mints from (ADR-014 §13), set in
  configuration or uploaded by the agent's owner, and the per-realm keys, one per purpose, that wrap
  an uploaded key and the pass-through token (ADR-016 §4). An uploaded key is stored only in that
  wrapped form and stays QAuth-side; no route returns it. Added 2026-10-10.

**Who holds keys.**

- A signer role holds the private keys.
- In a single deployment, the signer runs in-process.
- In a distributed deployment, other roles call the signer over mTLS.
- The trust-anchor key lives in a separate federation-operator deployment. It may be kept offline.
- The admin, UI and interaction roles hold no private keys.
- Only the browser-facing role holds the cookie HMAC secret.

How that separation is enforced:

- The KEK is provisioned only to the signer role. In a distributed deployment, only signer nodes
  receive it.
- Each role connects to Postgres as its own database user, with only the grants it needs. Only the
  signer's user can read the key table. A role that needs a symmetric secret, such as the
  browser-facing role's cookie HMAC, receives it from the signer.
- In a single deployment every role runs in one process, which is one trust domain. The separation
  protects keys once the roles run on separate nodes.

**Rotation.**

- Rotation is automatic and overlapping.
- The next signing key is pre-published in JWKS before it signs.
- The old key stays published for verification.
- The default period is 90 days. The operator can change it.
- A manual rotation needs `admin:security` plus a passkey approval.
- This record closes the retired-key wiring gap that ADR-001's status note records.
- Both keys of a hybrid pair rotate together, under the same overlap.
- The cookie HMAC and the data-at-rest key rotate the same way: the new key signs or encrypts, and
  the old one only verifies or decrypts until it is retired.
- Rotating the KEK re-wraps every stored key. It is a security operation.

**Emergency retirement.** A key that may be compromised is retired as soon as its retirement is
approved, as below. This is not a rotation, and the overlap above does not apply.

- It needs `admin:security`, a fresh passkey and the second admin where the realm requires one for
  key operations or bulk revocation; the other admins are notified. When no second admin can
  approve in time, the break-glass CLI does it (Decision 7).
- The key leaves the JWKS at once, and a new key starts signing.
- Its `kid` goes on a denylist that every verifier inside the auth server checks, whatever a JWKS
  cache holds, among them the token, introspection, userinfo, revocation and end-session endpoints.
  Introspection answers `active: false` for a token the key signed.
- Every session and refresh-token family issued under the key is revoked, with back-channel logout.
- A critical admin event and a security event naming the `kid` go out on every event route.
  `@qauth-labs/resource-guard` drops the key when that event reaches it, or at its next JWKS fetch.
- Both keys of a hybrid pair retire together.

**Relying parties' JWKS caches.** QAuth serves its JWKS with a cache lifetime of at most 5 minutes.
Its docs and SDKs state one rule for relying parties and resource servers: cache the JWKS for at
most 5 minutes, refetch it on an unknown `kid` at most once a minute, and drop a key the JWKS no
longer lists. `@qauth-labs/resource-guard` follows that rule by default.

**Relation to ADR-001.** This record supersedes ADR-001's environment-variable key model for
production. Today every instance reads its keys from environment variables or files.

### 10. Settings: deployment switches and realm policies

Decided 2026-10-10 (maintainer).

- **Deployment-wide switches stay in the environment.** Examples are `WALLET_FEDERATION_ENABLED`,
  `AUTHORITY_TREE_ENABLED`, the signing mode and experimental features. The console shows them read
  only.
- **Realm policies live in Postgres, on the realm row.** They change through the admin API and the
  admin console. They include sign-up, the verified-account requirement, password and MFA policy,
  session and token lifetimes, brand settings, upstream providers and the email sender. A change
  that Decision 7 counts as a security operation, such as the email sender, an upstream provider or
  a looser password or MFA policy, needs `admin:security` and a fresh passkey.
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

How a realm file reaches a live realm:

- Importing a realm file is not a privilege of its own. Each change in the diff is authorized as
  the single operation it equals, and the diff marks each change as tightening, loosening or
  neutral.
- The strictest change gates the import. If any change is a security operation (Decision 7), the
  import needs `admin:security`, a fresh passkey bound to the whole diff, and the second admin
  wherever the realm requires one for any change in it.
- A promotion from the sandbox is an import into the live realm.
- Fields that describe the sandbox's environment are not promoted unless they are selected one by
  one in the diff: `max_environment_laxity`, each client's environment, `http` and loopback redirect
  URIs, upstream endpoints and test accounts, webhook and SSF destinations, trust lists and plugin
  configuration.

The twin shares the deployment's database, KEK and signer role with the live realm. Its keys are
its own; its trust domain is the deployment's.

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
- A plugin makes its outbound calls through the egress client (Decision 8).
- Enabling or configuring a plugin that signs users in is a security operation (Decision 7).
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
- Security operations are defined by effect, so `admin:write` alone cannot change who can sign in
  to an account or what its tokens assert.
- A compromised key is retired as soon as its retirement is approved, without waiting out the
  rotation overlap.
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
  and the baseline headers it sets must be configured correctly.
- The ceremony app shares the realm origin, so it is part of the realm's trusted computing base. A
  compromised or careless replacement sees every credential typed into it and can act as the
  signed-in user.
- Every security operation costs a passkey approval, and some cost a second admin. Routine changes
  such as group membership become security operations.
- An admin that changes its own credentials, identifier or contact address, or that the break-glass
  CLI enrols, cannot approve for 7 days. Where no other admin can approve, a mandatory operation
  other than an emergency key retirement waits that long.
- An upstream provider on a private address cannot be set up through discovery. Its endpoints are
  set one by one in its configuration.
- In a single deployment every role shares one process, so the key separation of Decision 9 holds
  only once the roles run on separate nodes.
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
  lifetime of a token it signed. These defaults cover relying parties' JWKS caches. They apply to
  scheduled and manual rotation; an emergency retirement (Decision 9) unpublishes a key at once.
- **Existing issuers.** On upgrade, a deployment's current `JWT_ISSUER` becomes the issuer of its
  default realm, in single-realm mode. Keys from environment variables are imported once into the
  encrypted store at first boot. Existing clients and tokens keep working. After the import, the
  server warns at every boot while any imported key variable is still set, and the upgrade guide
  tells operators to remove them. The guide also has them configure every internal host name a
  server-side caller already uses, such as the developer portal's `AUTH_SERVER_URL`, as an endpoint
  host (Decision 1).
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
- ADR-015 and ADR-016 — the rest of the Authority Tree records.
- ADR-017: First-Party Login — F0, F1, Decision 3 and parked question 1.
- [ADR-018: QAuth 1.0 — Scope, Stability Promise and Release Path](./018-1-0-scope-and-stability.md)
  — the 1.0 scope and the stability promise this topology serves.
- ADR-020 — UI surfaces and UX acceptance criteria.
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
