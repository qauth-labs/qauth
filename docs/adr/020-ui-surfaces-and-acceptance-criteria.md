# ADR-020: 1.0 UI Surfaces and Acceptance Criteria

**Status:** Proposed — records the maintainer's decisions of 2026-10-09 and 2026-10-10; it is approved together with the other 1.0 records.  
**Date:** 2026-10-10  
**Authors:** QAuth Team

> Nothing below is built. This record answers the open question of
> [ADR-018](./018-1-0-scope-and-stability.md): which screens 1.0 ships. It names the UI surfaces,
> records seven design choices, lists what each surface contains and sets the bar a screen must
> meet before it counts as done. [ADR-019](./019-deployment-topology-and-trust-boundaries.md)
> Decision 5 already fixes how the UIs are deployed; this record does not restate it.
>
> Some decisions here change ADR-018's scope or ADR-019's topology: the device authorization
> grant, account selection, event delivery, the plugin API and the paired sandbox realm. Those
> records carry the changes. This one names them so the UI scope reads whole.

## Context

### What exists today (checked 2026-10-10)

- The auth server renders five HTML pages itself: `/ui/login`, `/ui/consent`, `/ui/resume`,
  `/ui/wallet-login` and `/ui/wallet-link`.
- The developer portal (`apps/developer-portal`) is built on TanStack Start, React and Tailwind. It
  has sign-in, sign-up, verification, a dashboard, client management with API keys, and a consents
  page.
- `libs/ui` holds five primitives: Button, Card, Input, Label and FormField.
- There is no admin console and no account console. Most realm policy lives in environment
  variables, as if there were one realm.

### The bar

The 1.0 goal is at least the breadth of an established open-source identity server, with good
UX. Keycloak is the reference for breadth: its admin console, account console, login theme pages
and email templates. The reference release is Keycloak 26.8.0 of 1 October 2026
([release notes](https://www.keycloak.org/2026/10/keycloak-2680-released)). Its 26.7 and 26.8
releases also moved into QAuth's area: an experimental OID4VP verifier, the receiving side of
ID-JAG, and token-exchange delegation for agents in preview
([26.7.0](https://www.keycloak.org/2026/07/keycloak-2670-released)). QAuth's own surfaces, such
as the Authority Tree, OpenID Federation and PQC keys, have no Keycloak counterpart.

The maintainer went through the comparison in two passes. The seven forks (A to G below) were
answered on 2026-10-09. Every remaining proposal was reviewed one by one on 2026-10-10. The full
table is the [Appendix](#appendix-inventory).

## Decision

### 1. Five surfaces

No surface holds a private key. Each is a separate, replaceable client of public APIs, as ADR-019
Decision 5 requires.

| Surface          | API                                                       | Session                                                                 | Runs                                                 |
| ---------------- | --------------------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------- |
| Ceremony app     | Interaction API (`/interaction/v1`)                       | None of its own; the realm's `__Host-` session cookie, same origin      | On the realm host under `/ui/*`, deployed separately |
| Account console  | account API                                               | BFF, tokens server-side                                                 | Any host                                             |
| Admin console    | admin API (`admin:read`, `admin:write`, `admin:security`) | BFF, a client of the operator realm, DPoP-bound tokens, passkey step-up | Any host                                             |
| Developer portal | developer API                                             | BFF, signs in through `/oauth/authorize` (ADR-017 F0)                   | Any host                                             |
| Emails           | Rendered by the auth server                               | —                                                                       | —                                                    |

Placement rules that follow from earlier decisions:

- The ceremony app is the reference implementation. An operator may replace it with any app built
  on the Interaction API.
- The CIBA approval page of ADR-014 §14 is a ceremony-app page, because approval happens only on
  QAuth's origin.
- "The portal" in ADR-014 means the account console. An agent's owner is a human account, and the
  owner's actions belong to the account API. ADR-019 Decision 5's "Authority Tree dashboard" is a
  section of the account console.
- The consents page moves from the developer portal to the account console. Consents belong to the
  user, not to a client's developer.
- The OpenID Federation operator screens are a section of the admin console, not a separate app.
  The section opens when the console connects to a federation-operator deployment's admin API.
  That deployment's signer role signs; the console never sees the trust-anchor key.

### 2. Seven forks (decided 2026-10-09)

**A. Where settings live.** Settings are split.

- Deployment-wide switches stay in environment variables. Examples: `WALLET_FEDERATION_ENABLED`,
  `AUTHORITY_TREE_ENABLED`, the signing mode, `HYBRID_SIGNING_ENABLED` and experimental features.
- Realm policy lives in Postgres on the realm row. The admin console and the admin API change it.
  Examples: sign-up, the verified-account requirement (`REQUIRE_VERIFIED_ACCOUNT`), password and
  MFA policy, session and token lifetimes, branding, identity providers, the email sender,
  brute-force thresholds, the self-registration policy and event retention.
- Environment variables only seed a new realm's defaults.

**B. Sign-in flows.** 1.0 has a policy screen, not a flow editor.

- Per realm and per client: the allowed methods (password, passkey, wallet, upstream), MFA (off,
  optional, required, required for admins), passkey first, and step-up rules.
- The step grammar of ADR-017 Decision 3 stays fixed, so the stability promise stays narrow.
- New methods arrive through the AuthMethod contract.
- A Keycloak-style flow editor comes in 1.x.

**C. Appearance.** Brand settings only.

- Logo, colours, a font from a safe list, per-locale strings, links and dark mode.
- No uploaded templates, custom CSS or custom JavaScript. Each would weaken the strict CSP and open
  a surface outside the promise. Email templates are fixed too; their logo, colours and strings come
  from the brand settings.
- Full control means replacing the ceremony app, the second and third tiers of ADR-019 Decision 5.

**D. Roles, groups and organizations.**

- Realm roles and client roles. No composite roles.
- Flat groups: members, attributes, roles and default groups. Groups carry roles. Both reach tokens
  as claims.
- Group hierarchy and organizations (domains, members, invitations, per-organization identity
  providers) come in 1.x. Realms already isolate tenants.

**E. User profile and claim mapping.** Two separate systems, as in Keycloak.

- A user profile schema: fields, types, validators, required fields, and who may edit each field
  (the user or an admin). It drives sign-up, profile completion, the account console and the admin
  console's user screens.
- A mapper system with Keycloak's breadth of types: attribute to claim, role or group to claim,
  audience, constant values. Identity-provider mappers use the same language in the other
  direction, from an upstream claim to an attribute.
- No script mappers. A script mapper runs administrator-written code inside the process that signs
  tokens. Custom logic is written as a plugin (§4).
- No mapper output is ever used to match accounts.

**F. Languages.** 1.0 ships in English only.

- The translation infrastructure and per-locale string overrides ship in 1.0. The community adds
  languages.
- The language picker appears once a deployment has more than one language.

**G. Configuration as code.** In 1.0.

- A declarative realm file that leaves out secret values.
- Export and import through the admin API and the CLI. A dry run shows the diff before anything is
  applied.
- The admin console has "Export" and "Review diff and import".
- Today's seed manifest becomes a subset of this file.
- The file format is inside the 1.0 stability promise.

### 3. Per-surface decisions (reviewed 2026-10-10)

**Ceremony app**

- Sign-in asks for the identifier first. An unknown account gets the same next step as a known one,
  so the page does not reveal whether an account exists.
- "Try another way" lists the user's other methods. The strongest method is the default.
- `prompt=select_account` is in 1.0: several accounts can stay signed in in one browser. This
  widens the session model, which ADR-019 records.
- The OAuth 2.0 device authorization grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628))
  is in 1.0, with a code-entry page. Against device-code phishing, the page shows the client's
  verified domain. ADR-018 records the scope change.
- A forced password update comes when an admin asks for it or when the password appears on a
  breach list. The list's source, a local list or a k-anonymity lookup, is a realm setting. There
  is no periodic expiry.
- First sign-in through an upstream never merges accounts automatically. Email is only an attribute
  by default. An account is linked only when the user signs in to the existing account.
- Error, info and expired pages share one design. Each says what happened and what to do, and
  shows a trace id. None reveals detail an attacker could use.
- Sign-in with an X.509 client certificate and versioned terms acceptance come in 1.x. In 1.0 the
  sign-up page only links to the terms.

**Account console**

- The user changes identifiers and the contact address after fresh authentication. A new address is
  verified by code, and the old one is notified. A realm can block username changes.
- A security log shows the last 90 days: sign-ins, new devices and security changes. A "this
  wasn't me" button ends that session and asks for new credentials.
- A user can delete the account immediately, after fresh authentication and a typed confirmation.
  A realm can turn self-deletion off; then only an admin deletes.
- "Download my data" comes in 1.x. In 1.0 the admin API has a user export endpoint.

**Admin console**

- Environment posture ([ADR-008](./008-environment-aware-authorization.md)) is edited in the
  console. It lives in the database: the realm ceiling `max_environment_laxity` and each client's
  `environment`. Tightening is free. Loosening needs `admin:security`, a fresh passkey and, where
  the realm requires it, a second admin. Each change lands in the admin events with its diff.
- Security headers are fixed. The console shows them read-only.
- Brute-force thresholds are set per realm, with an increasing delay. There is no permanent
  lockout, because that would let an attacker lock anyone out. A floor keeps the thresholds safe.
- There is no client-policy engine. PAR, JAR, DPoP and algorithm requirements are client settings.
- There is no workflow engine. Automation is built outside QAuth on the event delivery of §4.
- A type-first wizard adds an app. It asks what is being built: a web app with a backend, a
  single-page app, a mobile or desktop app, an MCP server, an agent, or a machine client. The
  client type, authentication method, redirect form and DPoP follow. The developer portal uses the
  same wizard.
- Clients get the device grant capability in 1.0. General CIBA, for any client, comes in 1.x on the
  same approval infrastructure. mTLS client authentication (RFC 8705) comes in 1.x.
- A client secret rotates with an overlap: at most two secrets are active, and use of the old one
  is visible.
- A client's token lifetimes can only be shorter than the realm's.
- The client screen lists the client's sessions and refresh-token families, with single and bulk
  revocation. Bulk revocation needs `admin:security` and a passkey.
- A self-registration screen holds the dynamic-registration switch, the scope ceiling and the CIMD
  allow and deny lists, on the realm row.
- A scope catalog per realm holds each scope's per-locale consent text, a sensitivity flag and the
  clients it is open to. System scopes such as `openid`, `profile` and `agent:*` cannot be deleted
  and keep their meaning. There are no parameterized scopes; fine-grained rights use RAR, whose
  types and consent texts the console manages.
- An admin never sets a user's password. The admin sends a set-up or reset link, or copies a
  one-time, short-lived link.
- An admin may delete a user's passkey or TOTP: it needs `admin:security` and a fresh passkey, the
  user is notified, and the admin events record it.
- Required actions (renew password, set up MFA, set up a passkey, complete the profile) are
  assigned per user or in bulk to a group.
- A user-event viewer filters by user, client, IP, type and time.
- Admin events are always on and show a diff with secret values masked.
- Retention: user events 90 days by default; admin events one year by default and never less than
  90 days.
- TOTP is fixed at SHA-1, six digits, 30 seconds and one step of tolerance. Other values break
  common authenticator apps without a real security gain.
- An account created through an upstream counts as a verified account. A per-provider switch turns
  that off; QAuth then asks for its own verification. Upstream claims are stored as attributes with
  their source.
- Each upstream provider has a name, an icon, an order and a "hide on login page" switch. A hidden
  provider is still reachable through a direct-routing parameter.
- A server-info screen shows the version, the switches, experimental features, installed plugins
  and role health. Operator-realm admins see all of it; a realm admin sees only what affects that
  realm.
- Console import of users comes in 1.x. In 1.0 the `db:import-users` CLI of ADR-017 F1d does it.
  Inbound SCIM provisioning comes in 1.x, together with organizations.

**Developer portal**

- A CIMD validator fetches a Client ID Metadata Document, runs every rule QAuth applies (realm
  policy included) and explains how to fix each problem. It is in the portal and the CLI, for
  signed-in users only, rate-limited, with the same SSRF-safe fetch as registration.
- A developer can register an MCP server as a resource server, define its scopes and copy its
  protected-resource metadata and its `mcp-guard` configuration. Admin approval of a new resource
  is a realm setting.
- A flow test console runs a real authorization-code flow with PKCE step by step and decodes the
  token in the browser. It works for development and staging clients. In production it runs only
  in the paired sandbox realm (§4).

**Federation section** (admin console)

- A trust-chain resolver shows a chain step by step: entity configuration, authority hints, each
  subordinate statement, the signature checks, metadata policy, trust marks and the resulting
  metadata. It marks the step that breaks. It is also on the identity-provider screen and in the
  CLI.

**Emails**

- Security notices go out for a new-device sign-in, a password change, a passkey or TOTP added or
  removed, an identifier change and a new agent grant. They are on by default. A realm may turn
  some off, but never the ones about credential changes. An account with no contact address sees
  them only in its security log.

### 4. Cross-cutting decisions

**Paired sandbox realm.** Each live realm can have a sandbox twin.

- The twin has its own host, issuer and keys, and its own test users.
- Its environment ceiling is staging, so the flow test console works there.
- The consoles have a Sandbox/Live switch.
- Settings move from sandbox to live through the realm-file diff of fork G.
- Upstream providers in the sandbox use test accounts.
- A sandbox token never passes at a live resource server, because the issuer differs. A
  same-issuer `sandbox` claim was rejected: it would depend on every resource server checking it.
- ADR-019 records the topology.

**Two-admin approval.** Every `admin:security` operation recommends a second admin's approval. A
realm chooses where it is mandatory. A deployment with a single admin sees a warning.

**Event delivery.** QAuth runs no automation itself, but every event is usable for automation. 1.0
delivers events four ways:

- signed webhooks in the [Standard Webhooks](https://www.standardwebhooks.com/) format, with
  retries, per-type subscriptions and a delivery history in the console;
- a cursor-based events API, so a consumer can resume where it stopped;
- Shared Signals (SSF) and CAEP streams for security events, which the Authority Tree's CAEP
  transmitter is a part of;
- OpenTelemetry logs, for the operator's own collector.

Event types and their payload schema are inside the 1.0 stability promise. ADR-018 records this.

**Plugins.** The core stays provider-agnostic.

- The core ships generic OIDC upstream only.
- Google, Microsoft and Apple presets, GitHub (which is not an OIDC provider) and My Number are
  plugins. They are ready with 1.0.
- Other providers become plugins on demand.
- The plugin API (the AuthMethod contract of
  [ADR-003](./003-credential-provider-interface.md) as ADR-018 extends it) is public and
  experimental in 1.0. It becomes stable in 1.x. ADR-018 records the change.

### 5. UX acceptance criteria

A screen is not done until it meets every criterion below. Those marked CI are measured in CI, so
a regression fails the build.

1. **Diff before save.** A security-relevant change shows the old and new values side by side
   before it is saved, then asks for `admin:security` and a fresh passkey.
2. **A reason on every setting.** Each setting has a one-sentence explanation and a link to
   docs.qauth.dev. A value that differs from the default is marked.
3. **Command palette and token inspector.** One search box finds users, clients, sessions, `jti`,
   `sid` and agents. A pasted token shows its realm, its signing key, its revocation state and its
   place in the Authority Tree.
4. **Empty states that work.** The first client, provider or agent screen shows the next step and
   a copyable SDK snippet.
5. **Sign-in without JavaScript (CI).** The password, TOTP and email-code steps work with
   JavaScript off. Passkeys and the wallet QR code use JavaScript. Each ceremony page has a size
   budget.
6. **Accessibility (CI).** [WCAG 2.2](https://www.w3.org/TR/WCAG22/) AA: full keyboard use,
   screen readers and contrast, with automated checks.
7. **Phone first.** The ceremony app and the account console are designed for phones first. The
   admin console is desktop-first but does not break on a phone.
8. **One design system (CI).** `libs/ui` grows into the shared token and component library of all
   surfaces. The brand settings change its tokens. Components are documented and pass visual
   regression tests.
9. **Type-first wizard.** Adding an app starts from what is being built (§3).
10. **Dark mode everywhere.** It follows the system setting and can be switched by hand. A realm
    may turn it off on its login pages.
11. **One error-page design** with a trace id (§3).

### 6. Stack

- All four apps use TanStack Start, React, Tailwind and `libs/ui`.
- A short spike checks that the ceremony app's forms work without JavaScript (criterion 5).
- If the spike fails, only the ceremony app moves to React Router's framework mode. The components
  stay shared.
- The developer portal is served by a small [srvx](https://srvx.h3.dev/) entry around TanStack
  Start's server handler, with no Nitro. The maintainer chose this on 2026-10-10; a separate change
  implements it.
- Each flow and screen is first written as a graph, which this stack implements
  ([ADR-021](./021-flows-and-ui-as-semantic-graphs.md)).

### 7. Delivery

Each area's screens ship with that area's 0.x beta (ADR-018 §2):

1. the core: the ceremony app, the account console, the core sections of the admin console, and
   the developer portal;
2. the Authority Tree: the agent screens of the account console and the admin console, and the
   approval page;
3. federation: the federation section and the federation upstream.

Wallet and PQC screens ship in the beta that carries their back end.

## Consequences

### Positive

- The UI scope is written down row by row, so the betas and the audit can check it.
- The UX bar is testable. Three of the eleven criteria are measured in CI.
- Realm policy can differ per realm, which custom domains and the sandbox twin need.
- A sandbox token cannot pass at a live resource server, by construction.
- Operators can automate on events without QAuth growing a workflow engine.
- The core stays provider-agnostic, while the common providers still ship with 1.0.

### Negative

- The scope is large. Four apps, a design system and four event channels are mostly unbuilt.
- Several items widen the promise: the realm-file format, the event schema and the device grant.
- Multiple accounts in one browser and the sandbox twin complicate the session and realm models.
- Five plugins must be ready with 1.0, on an API that is still experimental.
- English only at 1.0 leaves non-English users waiting for community translations.
- Without a flow editor, some Keycloak migrations will not map one to one in 1.0.

### Neutral

- Keycloak is the breadth reference, not the design reference. Rows marked "No" are deliberate.
- The ceremony app is a reference. A replacement app on the Interaction API is a supported setup.
- The stack choice is reversible for the ceremony app until the spike runs.

## Alternatives considered

- **A flow editor in 1.0.** Rejected for 1.0. It would put every flow shape inside the promise and
  reproduce Keycloak's hardest screen. It comes in 1.x.
- **Template overrides or custom CSS.** Rejected. Both weaken the CSP and create an unpromised
  surface. Replacing the ceremony app gives full control instead.
- **Organizations in 1.0.** Rejected for 1.0. Realms already isolate tenants; organizations come in
  1.x with inbound SCIM.
- **Script mappers, sandboxed or not.** Rejected. Code in the token-signing process is the largest
  surface of all. Plugins cover custom logic.
- **A same-issuer sandbox claim.** Rejected. Safety would depend on every resource server checking
  the claim.
- **A separate federation app.** Rejected. One console gives one design, one session model and one
  sign-in.
- **All UIs in the first beta.** Rejected. The first beta would wait for every area.
- **All settings in environment variables.** Rejected. Per-realm policy is impossible that way.
- **Three end-user languages in 1.0.** Rejected. Each language is a standing maintenance cost; the
  infrastructure ships instead.

## Related

- [ADR-003](./003-credential-provider-interface.md) — the CredentialProvider interface that
  AuthMethod extends
- [ADR-008](./008-environment-aware-authorization.md) — environment posture
- [ADR-014](./014-agent-authority-tree.md) — the Authority Tree, its approval page and dashboard
- [ADR-018](./018-1-0-scope-and-stability.md) — the 1.0 scope; this record answers its open
  question
- [ADR-019](./019-deployment-topology-and-trust-boundaries.md) — UI deployment, the Interaction API
  and the API families
- ADR-015 and ADR-016 — Authority Tree hardening and platform bindings
- ADR-017 — first-party login: the step grammar, hosted pages and the phases F0 to F2b
- [Keycloak 26.8.0 release notes](https://www.keycloak.org/2026/10/keycloak-2680-released) — the
  parity reference

## Appendix: inventory

Every row compares one Keycloak feature with QAuth. "1.0" is in 1.0; "1.x" comes later; "No" is a
deliberate omission. "Decision" rows follow an earlier record or one of the forks A to G; "Row
review" rows were decided one by one on 2026-10-10. "QAuth only" marks a feature with no Keycloak
counterpart. Keycloak locations are admin-console paths or login-theme template names.

### Ceremony app

| Area                  | Feature                                                        | Keycloak location                    | QAuth today                              | 1.0 | Basis      | Note                                                                                                                                   |
| --------------------- | -------------------------------------------------------------- | ------------------------------------ | ---------------------------------------- | --- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Sign-in               | Username and password                                          | Login theme · login.ftl              | `/ui/login`, server-rendered HTML        | 1.0 | Decision   | Through the Interaction API. A password user whose account is not yet verified gets an email-code step (ADR-017).                      |
| Sign-in               | Identifier first                                               | Authentication · Browser flow        | —                                        | 1.0 | Row review | For passkey-only accounts and later routing by domain. An unknown account gets the same next step.                                     |
| Sign-in               | Passkey sign-in (conditional and modal)                        | Login theme · webauthn-authenticate  | —                                        | 1.0 | Decision   | ADR-017 F2b, `WEBAUTHN_ENABLED`. The RP ID is the realm host.                                                                          |
| Sign-in               | Passkey enrolment                                              | webauthn-register                    | —                                        | 1.0 | Decision   | The RP ID locks at the first enrolment. Recovery codes are issued with the first passkey.                                              |
| Sign-in               | TOTP sign-in and set-up                                        | login-otp, login-config-totp         | —                                        | 1.0 | Decision   | ADR-018, human accounts.                                                                                                               |
| Sign-in               | Sign-in with a recovery code                                   | login-recovery-authn-code-input      | —                                        | 1.0 | Decision   | ADR-018.                                                                                                                               |
| Sign-in               | Try another way (method choice)                                | select-authenticator                 | —                                        | 1.0 | Row review | The strongest method is the default; the user can pick passkey, TOTP or a recovery code.                                               |
| Sign-in               | Step-up (re-authentication)                                    | Authentication · ACR / LoA           | Fresh browser sign-in (`evaluateStepUp`) | 1.0 | Decision   | With a passkey. Follows the ADR-008 posture.                                                                                           |
| Sign-in               | Bot challenge                                                  | Registration flow · reCAPTCHA        | —                                        | 1.0 | Decision   | ADR-017 F1b, provider-neutral.                                                                                                         |
| Sign-in               | Account selection (`prompt=select_account`)                    | —                                    | —                                        | 1.0 | Row review | Several accounts in one browser. The session model widens; ADR-019 records it.                                                         |
| Sign-in               | Device code entry (RFC 8628)                                   | login-oauth2-device-verify-user-code | —                                        | 1.0 | Row review | Added to the 1.0 scope (ADR-018). Against device-code phishing, the page shows the client's verified domain.                           |
| Sign-in               | Sign-in with an X.509 client certificate                       | login-x509-info                      | —                                        | 1.x | Row review | Through the AuthMethod contract if enterprise demand appears.                                                                          |
| Sign-up and recovery  | Sign-up                                                        | register.ftl                         | Portal `/register` → `/auth/register`    | 1.0 | Decision   | Hosted sign-up page, off by default (ADR-017 F2a). `/auth/register` is removed in F1c.                                                 |
| Sign-up and recovery  | `prompt=create`                                                | —                                    | —                                        | 1.0 | Decision   | ADR-017 F2a.                                                                                                                           |
| Sign-up and recovery  | Forgot password                                                | login-reset-password                 | None                                     | 1.0 | Decision   | ADR-017 F2a. Always on while hosted pages are on.                                                                                      |
| Sign-up and recovery  | Forced password update                                         | login-update-password                | —                                        | 1.0 | Row review | When an admin asks for it, or when the password appears on a breach list. No periodic expiry.                                          |
| Sign-up and recovery  | Account verification                                           | login-verify-email                   | Portal `/verify`, by link                | 1.0 | Decision   | ADR-017 `email_code` step. The text says "verified account".                                                                           |
| Sign-up and recovery  | Profile completion                                             | login-update-profile                 | —                                        | 1.0 | Decision   | Asked when a required profile-schema field is missing (fork E).                                                                        |
| Sign-up and recovery  | Terms acceptance                                               | terms.ftl                            | —                                        | 1.x | Row review | 1.0 has only a link on the sign-up page.                                                                                               |
| Consent               | OAuth consent screen                                           | login-oauth-grant                    | `/ui/consent`                            | 1.0 | Decision   | Typed data from the authorization server's own records only. The verified domain is shown instead of the client-supplied name.         |
| Consent               | Agent root grant: ceiling, modes, `agent:request` (QAuth only) | —                                    | —                                        | 1.0 | Decision   | ADR-014 §11. Keycloak 26.8 has a `delegation:client` consent (preview).                                                                |
| Consent               | Remote approval page (CIBA, passkey) (QAuth only)              | —                                    | —                                        | 1.0 | Decision   | ADR-014 §14. Only on QAuth's origin. Binding code, typed delta, approve for a while, mute, always block.                               |
| Upstream and wallet   | Upstream IdP buttons                                           | Login theme · social providers       | —                                        | 1.0 | Decision   | Upstream OIDC, including My Number.                                                                                                    |
| Upstream and wallet   | First upstream sign-in: review profile, link account           | First broker login flow              | Wallet linking exists                    | 1.0 | Row review | No automatic merge. Email is only an attribute by default; linking happens when the user signs in to the existing account.             |
| Upstream and wallet   | Wallet sign-in (OID4VP)                                        | 26.8: OID4VP verifier, experimental  | `/ui/wallet-login`                       | 1.0 | Decision   | HAIP 1.0 is stable. The DC API comes in 1.1. Redesigned.                                                                               |
| Upstream and wallet   | Wallet linking (QAuth only)                                    | —                                    | `/ui/wallet-link`                        | 1.0 | Decision   | Redesigned.                                                                                                                            |
| Upstream and wallet   | Upstream OP choice through federation (QAuth only)             | —                                    | —                                        | 1.0 | Decision   | OpenID Federation RP side. A list of OPs with validated trust chains.                                                                  |
| Upstream and wallet   | Organization selection                                         | select-organization                  | —                                        | 1.x | Decision   | Organizations come in 1.x (fork D).                                                                                                    |
| Logout and appearance | Logout confirmation (RP-initiated logout)                      | logout-confirm                       | —                                        | 1.0 | Decision   | ADR-017 F0. No front-channel logout.                                                                                                   |
| Logout and appearance | Error, info and expired pages                                  | error.ftl, info.ftl                  | Scattered                                | 1.0 | Row review | One design: what happened, what to do, a trace id.                                                                                     |
| Logout and appearance | Language choice and dark mode                                  | Realm settings · Themes              | —                                        | 1.0 | Row review | Dark mode everywhere; a realm may disable it on its login pages. The language picker appears once more than one language is installed. |
| Logout and appearance | Theme                                                          | Themes · login                       | —                                        | 1.0 | Decision   | Through brand settings. Full control means replacing the ceremony app (fork C).                                                        |

### Account console

| Area                   | Feature                                                             | Keycloak location                | QAuth today          | 1.0 | Basis      | Note                                                                                                                                                 |
| ---------------------- | ------------------------------------------------------------------- | -------------------------------- | -------------------- | --- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Profile                | Personal info                                                       | Account console · Personal info  | —                    | 1.0 | Decision   | Fields come from the profile schema (fork E).                                                                                                        |
| Profile                | Identifiers and contact address                                     | Update email                     | —                    | 1.0 | Row review | The user changes them with fresh authentication. A new address is verified by code, and the old one is notified. A realm can block username changes. |
| Profile                | Language                                                            | Account console · language       | —                    | 1.0 | Decision   | 1.0 is English only. The picker appears once more than one language is installed (fork F).                                                           |
| Security               | Change password                                                     | Signing in · Password            | —                    | 1.0 | Decision   | —                                                                                                                                                    |
| Security               | Passkeys: add, rename, delete                                       | Signing in · Passkeys            | —                    | 1.0 | Decision   | Deleting needs fresh authentication.                                                                                                                 |
| Security               | Set up and remove TOTP                                              | Signing in · Authenticator app   | —                    | 1.0 | Decision   | —                                                                                                                                                    |
| Security               | Regenerate recovery codes                                           | Signing in · Recovery codes      | —                    | 1.0 | Decision   | —                                                                                                                                                    |
| Security               | Device activity and sign out everywhere                             | Device activity                  | —                    | 1.0 | Decision   | ADR-017 F2a question 9. Sessions live in Postgres, with Redis as a cache.                                                                            |
| Security               | Security log: recent sign-ins, new devices, changes                 | —                                | `audit_logs` (no UI) | 1.0 | Row review | The last 90 days, with a "this wasn't me" button.                                                                                                    |
| Security               | Delete account                                                      | Delete account (required action) | —                    | 1.0 | Row review | Immediate, with fresh authentication. A realm can turn it off.                                                                                       |
| Security               | Download my data                                                    | —                                | —                    | 1.x | Row review | 1.0 has a user export endpoint in the admin API.                                                                                                     |
| Links and applications | Linked upstream accounts                                            | Linked accounts                  | —                    | 1.0 | Decision   | —                                                                                                                                                    |
| Links and applications | Wallets (QAuth only)                                                | —                                | `/ui/wallet-link`    | 1.0 | Decision   | —                                                                                                                                                    |
| Links and applications | Applications and consents, revoke                                   | Applications                     | Portal `/consents`   | 1.0 | Decision   | Moves from the developer portal to the account console.                                                                                              |
| Links and applications | Groups and organizations                                            | Groups, Organizations            | —                    | 1.0 | Decision   | Groups are visible. Organizations come in 1.x (fork D).                                                                                              |
| Links and applications | Resource sharing (UMA)                                              | Resources                        | —                    | No  | Decision   | UMA is not planned (ADR-018).                                                                                                                        |
| My agents              | Agents: list, profile, disable, revoke (QAuth only)                 | —                                | —                    | 1.0 | Decision   | ADR-014 §13.                                                                                                                                         |
| My agents              | Live tree: sessions, nodes, actions (QAuth only)                    | —                                | —                    | 1.0 | Decision   | ADR-014 P3.                                                                                                                                          |
| My agents              | Approvals: pending, open windows, mutes, always-blocks (QAuth only) | —                                | —                    | 1.0 | Decision   | ADR-014 §14.                                                                                                                                         |
| My agents              | Raise the root ceiling (QAuth only)                                 | —                                | —                    | 1.0 | Decision   | ADR-014 decision 17, with a passkey.                                                                                                                 |
| My agents              | Notification channels: web push, webhook (QAuth only)               | —                                | —                    | 1.0 | Decision   | ADR-014 decision 16. No email.                                                                                                                       |
| My agents              | Platform bindings (for example GitHub) (QAuth only)                 | —                                | —                    | 1.0 | Decision   | ADR-016.                                                                                                                                             |
| My agents              | Agent transfer offers (QAuth only)                                  | —                                | —                    | 1.0 | Decision   | ADR-015.                                                                                                                                             |

### Admin console

| Area                         | Feature                                                                       | Keycloak location                                        | QAuth today                                                      | 1.0 | Basis      | Note                                                                                                                                                                         |
| ---------------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------- | --- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Realm                        | Create, list and switch realms                                                | Realm selector · Create realm                            | `realms` table, no UI                                            | 1.0 | Decision   | Operator-realm admins. Each realm has its own host.                                                                                                                          |
| Realm                        | Host and custom domain                                                        | Realm settings · Frontend URL                            | —                                                                | 1.0 | Decision   | ACME and DNS verification come later, with the hosted service.                                                                                                               |
| Realm                        | Environment posture                                                           | Realm settings · Require SSL                             | DB: `realms.max_environment_laxity`, `oauth_clients.environment` | 1.0 | Row review | Tightening is free. Loosening needs `admin:security`, a passkey and, if the realm requires it, a second admin.                                                               |
| Realm                        | Paired sandbox realm and Sandbox/Live switch (QAuth only)                     | —                                                        | —                                                                | 1.0 | Row review | Own host, issuer and keys; staging ceiling. Settings move to live through the realm-file diff.                                                                               |
| Realm                        | Login settings: sign-up, verified-account requirement                         | Realm settings · Login                                   | env (`REQUIRE_VERIFIED_ACCOUNT`)                                 | 1.0 | Decision   | Stored on the realm row, changed from the console and the admin API. env only seeds new realms (fork A).                                                                     |
| Realm                        | Email: SMTP and sender                                                        | Realm settings · Email                                   | env                                                              | 1.0 | Decision   | Stored on the realm row, changed from the console and the admin API. env only seeds new realms (fork A).                                                                     |
| Realm                        | Session lifetimes                                                             | Realm settings · Sessions                                | env                                                              | 1.0 | Decision   | Stored on the realm row, changed from the console and the admin API. env only seeds new realms (fork A).                                                                     |
| Realm                        | Token lifetimes                                                               | Realm settings · Tokens                                  | env                                                              | 1.0 | Decision   | Stored on the realm row, changed from the console and the admin API. env only seeds new realms (fork A).                                                                     |
| Realm                        | Turning refresh-token rotation off                                            | Tokens · Revoke refresh token                            | Always on                                                        | No  | Decision   | OAuth 2.1. Not a setting.                                                                                                                                                    |
| Realm                        | Themes and branding                                                           | Realm settings · Themes                                  | —                                                                | 1.0 | Decision   | Logo, colours, a safe font list, per-locale strings, links, dark mode. No templates, custom CSS or JS (fork C).                                                              |
| Realm                        | Localization and strings                                                      | Realm settings · Localization                            | —                                                                | 1.0 | Decision   | Translation infrastructure and per-locale string overrides. 1.0 ships English only; the community adds languages (forks F and C).                                            |
| Realm                        | Security headers (CSP, HSTS)                                                  | Security defenses · Headers                              | Fixed (security-headers plugin)                                  | No  | Row review | Fixed; the console shows them read-only.                                                                                                                                     |
| Realm                        | Brute-force protection                                                        | Security defenses · Brute force                          | ADR-017 disable ceiling                                          | 1.0 | Row review | Thresholds per realm, increasing delay. No permanent lockout.                                                                                                                |
| Realm                        | Client policies and profiles (FAPI)                                           | Realm settings · Client policies                         | —                                                                | No  | Row review | No policy engine. PAR, JAR and DPoP requirements are client settings.                                                                                                        |
| Realm                        | User profile schema                                                           | Realm settings · User profile                            | `user_attributes` table                                          | 1.0 | Decision   | Fields, validators, who may edit (fork E).                                                                                                                                   |
| Realm                        | Export and import                                                             | Realm settings · Partial export/import                   | Seed manifest, `db:import-users`                                 | 1.0 | Decision   | A declarative realm file without secret values. Admin API and CLI, with a dry-run diff. The seed manifest is its subset (fork G).                                            |
| Realm                        | Workflows (automation)                                                        | Workflows (GA in 26.6)                                   | —                                                                | No  | Row review | Not QAuth's job. Every event is delivered outward; automation is built outside.                                                                                              |
| Keys                         | Keys: active, next, retired; JWKS preview                                     | Realm settings · Keys                                    | env, key file                                                    | 1.0 | Decision   | Per realm and purpose, envelope-encrypted, 90 days. A manual rotation needs `admin:security` and a passkey.                                                                  |
| Keys                         | PQC mode and hybrid-signing state (QAuth only)                                | —                                                        | env                                                              | 1.0 | Decision   | ML-DSA-65 and the hybrid, off by default.                                                                                                                                    |
| Clients                      | Client list, search, create                                                   | Clients                                                  | Portal shows only the developer's own clients                    | 1.0 | Decision   | —                                                                                                                                                                            |
| Clients                      | Type-first "what are you building?" wizard                                    | Create client                                            | —                                                                | 1.0 | Row review | The same wizard in the admin console and the developer portal.                                                                                                               |
| Clients                      | Redirect and post-logout URIs, web origins                                    | Client · Access settings                                 | Portal: redirect URIs                                            | 1.0 | Decision   | —                                                                                                                                                                            |
| Clients                      | Flows: code + PKCE, `client_credentials`, token exchange, ID-JAG              | Client · Capability config                               | —                                                                | 1.0 | Decision   | No ROPC or implicit. PKCE S256 cannot be turned off, except ADR-017's single exception.                                                                                      |
| Clients                      | General CIBA                                                                  | Capability config                                        | —                                                                | 1.x | Row review | 1.x, on the same approval infrastructure. The device grant is in 1.0 (separate row).                                                                                         |
| Clients                      | Device grant capability (RFC 8628)                                            | Capability config · OAuth 2.0 Device Authorization Grant | —                                                                | 1.0 | Row review | Ships with the code-entry page in the ceremony app (ADR-018).                                                                                                                |
| Clients                      | Client secret and `private_key_jwt` (JWKS, `jwks_uri`)                        | Client · Credentials, Keys                               | Portal: client secret                                            | 1.0 | Decision   | Agent types use `private_key_jwt` only.                                                                                                                                      |
| Clients                      | Client secret rotation with two secrets                                       | Client secret rotation (GA in 26.8)                      | —                                                                | 1.0 | Row review | At most two active secrets; use of the old one is visible.                                                                                                                   |
| Clients                      | mTLS client authentication (RFC 8705)                                         | Credentials · X509                                       | —                                                                | 1.x | Row review | —                                                                                                                                                                            |
| Clients                      | Consent required, first-party trust                                           | Client · Login settings                                  | `canSkipConsent`                                                 | 1.0 | Decision   | ADR-017 `first_party_policy`.                                                                                                                                                |
| Clients                      | Display name, logo, verified domain                                           | Client · Display on screen                               | —                                                                | 1.0 | Decision   | Interaction API display rule.                                                                                                                                                |
| Clients                      | Back-channel logout URL                                                       | Client · Logout settings                                 | —                                                                | 1.0 | Decision   | Back-Channel Logout 1.0. No front channel.                                                                                                                                   |
| Clients                      | Per-client token lifetimes                                                    | Client · Advanced                                        | —                                                                | 1.0 | Row review | Only shorter than the realm value.                                                                                                                                           |
| Clients                      | PAR, JAR and DPoP requirements; ID token algorithm                            | Client · Advanced                                        | —                                                                | 1.0 | Decision   | PAR and JAR come with federation.                                                                                                                                            |
| Clients                      | Allowed scopes                                                                | Client · Client scopes                                   | `validateScopes`                                                 | 1.0 | Decision   | —                                                                                                                                                                            |
| Clients                      | Client roles, service-account roles                                           | Client · Roles, Service account roles                    | —                                                                | 1.0 | Decision   | Fork D.                                                                                                                                                                      |
| Clients                      | Authorization tab (UMA resource server)                                       | Client · Authorization                                   | —                                                                | No  | Decision   | RAR and AuthZEN instead.                                                                                                                                                     |
| Clients                      | The client's sessions and refresh families                                    | Client · Sessions                                        | —                                                                | 1.0 | Row review | List, single and bulk revoke. Bulk revoke needs `admin:security` and a passkey.                                                                                              |
| Clients                      | DCR policies, CIMD allow and deny lists                                       | Client registration policies                             | env (`CIMD_*`)                                                   | 1.0 | Row review | On the realm row, changed from the console. MCP 2026-07-28: CIMD is recommended and DCR is deprecated.                                                                       |
| Clients                      | Agent types: `is_agent`, `max_agent_mode`, `spawn_allowlist` (QAuth only)     | —                                                        | Seed manifest                                                    | 1.0 | Decision   | ADR-014.                                                                                                                                                                     |
| Scopes and resources         | Scope catalog, per-locale consent text                                        | Client scopes                                            | Fixed list                                                       | 1.0 | Row review | Per realm. System scopes cannot be deleted and keep their meaning.                                                                                                           |
| Scopes and resources         | Protocol mappers                                                              | Client scopes · Mappers                                  | —                                                                | 1.0 | Decision   | A mapper system separate from the profile schema, with Keycloak's breadth of types. No script mappers, because they run arbitrary code in the authorization server (fork E). |
| Scopes and resources         | Parameterized scopes                                                          | 26.8 preview                                             | —                                                                | No  | Row review | RAR (`authorization_details`) instead.                                                                                                                                       |
| Scopes and resources         | Resource servers: audience, RFC 9728, Bearer leaf, approval-only (QAuth only) | —                                                        | env                                                              | 1.0 | Decision   | ADR-014 and ADR-016.                                                                                                                                                         |
| Scopes and resources         | STS adapters and policies (for example `github`) (QAuth only)                 | —                                                        | —                                                                | 1.0 | Decision   | ADR-014 P0, ADR-016.                                                                                                                                                         |
| Scopes and resources         | Remote approval settings (QAuth only)                                         | CIBA policy                                              | —                                                                | 1.0 | Decision   | `REMOTE_APPROVAL_*` (ADR-014 §14).                                                                                                                                           |
| Roles, groups, organizations | Realm roles                                                                   | Realm roles                                              | `roles`, `user_roles` tables                                     | 1.0 | Decision   | No composite roles. Flat groups carry roles (fork D).                                                                                                                        |
| Roles, groups, organizations | Groups: members, attributes, roles, default groups                            | Groups                                                   | —                                                                | 1.0 | Decision   | Flat groups. Hierarchy comes in 1.x (fork D).                                                                                                                                |
| Roles, groups, organizations | Organizations: domains, members, invitations, IdPs                            | Organizations                                            | —                                                                | 1.x | Decision   | Fork D.                                                                                                                                                                      |
| Users                        | User list, search, filter                                                     | Users                                                    | —                                                                | 1.0 | Decision   | —                                                                                                                                                                            |
| Users                        | Create a user (no password, by invitation)                                    | Users · Add user                                         | —                                                                | 1.0 | Decision   | ADR-017: the admin API creates users without a password.                                                                                                                     |
| Users                        | Admin sets a password (temporary password)                                    | Users · Credentials · Reset password                     | —                                                                | No  | Row review | An admin only sends a set-up or reset link.                                                                                                                                  |
| Users                        | Credentials: delete passkey and TOTP, labels                                  | Users · Credentials                                      | —                                                                | 1.0 | Row review | `admin:security`, a passkey, a notice to the user. A second admin's approval is recommended, and a realm can require it.                                                     |
| Users                        | Required actions: renew password, set up MFA                                  | Users · Required user actions                            | —                                                                | 1.0 | Row review | Per user and in bulk for a group.                                                                                                                                            |
| Users                        | Attributes                                                                    | Users · Attributes                                       | `user_attributes`                                                | 1.0 | Decision   | Follow the profile schema (fork E).                                                                                                                                          |
| Users                        | Consents, linked IdPs, wallets, sessions                                      | Users · Consents, Identity provider links, Sessions      | —                                                                | 1.0 | Decision   | —                                                                                                                                                                            |
| Users                        | The user's agents; revoke by agent (QAuth only)                               | —                                                        | —                                                                | 1.0 | Decision   | ADR-014 §13, owner-or-admin rule.                                                                                                                                            |
| Users                        | Disable and delete                                                            | Users · Enabled, Delete                                  | —                                                                | 1.0 | Decision   | —                                                                                                                                                                            |
| Users                        | Impersonation                                                                 | Users · Impersonate                                      | —                                                                | No  | Decision   | Act-chain delegation instead.                                                                                                                                                |
| Users                        | Bulk import                                                                   | Partial import                                           | `db:import-users` (ADR-017 F1d, CLI)                             | 1.x | Row review | The CLI exists in 1.0.                                                                                                                                                       |
| Users                        | Inbound SCIM provisioning                                                     | SCIM API (GA in 26.8)                                    | Read-only projection for agents                                  | 1.x | Row review | Together with organizations.                                                                                                                                                 |
| Sessions and events          | Active sessions, sign-out, revoke all                                         | Sessions                                                 | Sessions only in Redis                                           | 1.0 | Decision   | Postgres is the source of truth, Redis a cache. Back-channel logout delivery status is visible.                                                                              |
| Sessions and events          | User events                                                                   | Events · User events                                     | `audit_logs`, no UI                                              | 1.0 | Row review | Filtered list with readable descriptions.                                                                                                                                    |
| Sessions and events          | Admin events: who changed what, with a diff                                   | Events · Admin events                                    | —                                                                | 1.0 | Row review | Always on. Secret values are masked.                                                                                                                                         |
| Sessions and events          | Event retention                                                               | Realm settings · Events                                  | —                                                                | 1.0 | Row review | User events 90 days; admin events 1 year, at least 90 days.                                                                                                                  |
| Sessions and events          | Event delivery: signed webhook, cursor API, SSF/CAEP, OpenTelemetry           | Event listeners                                          | —                                                                | 1.0 | Row review | All four in 1.0. Event types and payload schema are inside the 1.0 promise.                                                                                                  |
| Sessions and events          | Agent actions (SET events) (QAuth only)                                       | —                                                        | —                                                                | 1.0 | Decision   | ADR-014 P3 `agent_actions`.                                                                                                                                                  |
| Authentication               | Flow editor                                                                   | Authentication · Flows                                   | —                                                                | 1.x | Decision   | 1.0 has the policy screen; the editor comes in 1.x (fork B).                                                                                                                 |
| Authentication               | MFA requirement and allowed methods                                           | Required actions, Conditional OTP                        | —                                                                | 1.0 | Decision   | Per realm and per client: allowed methods, MFA, passkey first, step-up (fork B).                                                                                             |
| Authentication               | Password policy                                                               | Policies · Password policy                               | zxcvbn and length                                                | 1.0 | Decision   | NIST SP 800-63B-4: at least 15 characters, lowerable to 8. No composition rules and no expiry.                                                                               |
| Authentication               | OTP policy                                                                    | Policies · OTP policy                                    | —                                                                | No  | Row review | Fixed at SHA-1, 6 digits, 30 seconds.                                                                                                                                        |
| Authentication               | WebAuthn policy                                                               | Policies · WebAuthn (passwordless)                       | —                                                                | 1.0 | Decision   | RP ID and its lock state are read-only. User verification is required. An AAGUID allow list comes in 1.x.                                                                    |
| Authentication               | Bot challenge provider                                                        | Registration flow · reCAPTCHA                            | —                                                                | 1.0 | Decision   | ADR-017 F1b.                                                                                                                                                                 |
| Identity providers           | Generic OIDC upstream                                                         | Identity providers · OpenID Connect                      | —                                                                | 1.0 | Decision   | Through the AuthMethod contract.                                                                                                                                             |
| Identity providers           | My Number (Digital Agency authentication app) (QAuth only)                    | —                                                        | —                                                                | 1.0 | Decision   | A plugin, ready with 1.0; the core stays provider-agnostic. Needs `private_key_jwt`.                                                                                         |
| Identity providers           | OIDC presets: Google, Microsoft, Apple                                        | Identity providers · Social                              | —                                                                | 1.0 | Row review | Not in the core; plugins ready with 1.0. The core has only generic OIDC.                                                                                                     |
| Identity providers           | GitHub (not OIDC)                                                             | Identity providers · Social                              | —                                                                | 1.0 | Row review | A plugin ready with 1.0. Other providers become plugins on demand.                                                                                                           |
| Identity providers           | SAML upstream                                                                 | Identity providers · SAML                                | —                                                                | 1.x | Decision   | ADR-018.                                                                                                                                                                     |
| Identity providers           | OpenID Federation upstream (QAuth only)                                       | —                                                        | —                                                                | 1.0 | Decision   | ADR-018.                                                                                                                                                                     |
| Identity providers           | Wallet verifier: HAIP, trusted issuers, status lists                          | 26.8 OID4VP, experimental                                | env (`WALLET_*`)                                                 | 1.0 | Decision   | —                                                                                                                                                                            |
| Identity providers           | IdP mappers (claim to attribute)                                              | Identity providers · Mappers                             | —                                                                | 1.0 | Row review | The same language as the mapper system. Never used to match accounts.                                                                                                        |
| Identity providers           | Counting an upstream account as verified                                      | First login flow, Trust email                            | —                                                                | 1.0 | Row review | An upstream sign-in makes the account a verified account; a per-IdP switch turns this off. Upstream claims are kept as attributes with their source.                         |
| Identity providers           | Hide on login page, order, icon                                               | Identity providers · Display                             | —                                                                | 1.0 | Row review | Name, icon, order, hide; a direct-routing parameter.                                                                                                                         |
| Identity providers           | LDAP and Active Directory                                                     | User federation · LDAP                                   | —                                                                | 1.x | Decision   | An extension of the AuthMethod contract.                                                                                                                                     |
| Identity providers           | Kerberos                                                                      | User federation · Kerberos                               | —                                                                | No  | Decision   | —                                                                                                                                                                            |
| Admins and server            | Admins and their permissions                                                  | Fine-grained admin permissions v2                        | —                                                                | 1.0 | Decision   | Operator and realm admins. `admin:read`, `admin:write` and `admin:security`, intersected with the role catalog.                                                              |
| Admins and server            | Two-admin approval (QAuth only)                                               | —                                                        | —                                                                | 1.0 | Row review | Recommended for every `admin:security` operation; the realm picks where it is mandatory. A warning on single-admin deployments.                                              |
| Admins and server            | Server info: version, switches, experimental features                         | Server info                                              | —                                                                | 1.0 | Row review | Operator-realm admins only. Installed plugins and role health are shown too.                                                                                                 |

### Developer portal

| Area   | Feature                                                                        | Keycloak location | QAuth today                     | 1.0 | Basis      | Note                                                                                         |
| ------ | ------------------------------------------------------------------------------ | ----------------- | ------------------------------- | --- | ---------- | -------------------------------------------------------------------------------------------- |
| Portal | Sign-in and sign-up                                                            | —                 | `/auth/login`, `/auth/register` | 1.0 | Decision   | Sign-in through `/oauth/authorize` (ADR-017 F0); sign-up redirects to the hosted page (F2a). |
| Portal | My clients: create, edit, rotate secrets                                       | DCR               | Exists                          | 1.0 | Decision   | —                                                                                            |
| Portal | Static API keys                                                                | —                 | Exists                          | 1.0 | Decision   | ADR-008: non-production clients only.                                                        |
| Portal | CIMD document validator (QAuth only)                                           | —                 | —                               | 1.0 | Row review | In the portal and the CLI, with SSRF-safe fetching.                                          |
| Portal | MCP server registration: resource and protected-resource metadata (QAuth only) | —                 | —                               | 1.0 | Row review | Admin approval is a realm setting.                                                           |
| Portal | Flow test console: code + PKCE, token decoder                                  | —                 | —                               | 1.0 | Row review | Development and staging clients. In production it runs in the paired sandbox realm.          |

### Admin console — federation section

| Area       | Feature                                                 | Keycloak location | QAuth today | 1.0 | Basis      | Note                                                         |
| ---------- | ------------------------------------------------------- | ----------------- | ----------- | --- | ---------- | ------------------------------------------------------------ |
| Federation | Entity configuration and authority hints (QAuth only)   | —                 | —           | 1.0 | Decision   | Leaf.                                                        |
| Federation | Subordinates, metadata policy, constraints (QAuth only) | —                 | —           | 1.0 | Decision   | Trust anchor and intermediate roles.                         |
| Federation | Trust marks: types, issuance, revocation (QAuth only)   | —                 | —           | 1.0 | Decision   | —                                                            |
| Federation | Explicit registration requests (QAuth only)             | —                 | —           | 1.0 | Decision   | —                                                            |
| Federation | Trust chain resolver (QAuth only)                       | —                 | —           | 1.0 | Row review | In the federation section, on the IdP screen and in the CLI. |
| Federation | Federation keys (QAuth only)                            | —                 | —           | 1.0 | Decision   | The trust-anchor key lives in a separate deployment.         |

### Emails

| Area   | Feature                                                        | Keycloak location                    | QAuth today       | 1.0 | Basis      | Note                                                                              |
| ------ | -------------------------------------------------------------- | ------------------------------------ | ----------------- | --- | ---------- | --------------------------------------------------------------------------------- |
| Emails | Verification code, reset, invitation and set-up                | Email templates                      | Verification link | 1.0 | Decision   | —                                                                                 |
| Emails | Security notices: new sign-in, password changed, passkey added | Event · login error, update password | —                 | 1.0 | Row review | On by default. Notices about credential changes cannot be turned off.             |
| Emails | Template editing                                               | Themes · email                       | —                 | No  | Decision   | Templates are fixed. Logo, colours and strings come from brand settings (fork C). |
