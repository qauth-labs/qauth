# ADR-018: QAuth 1.0 — Scope, Stability Promise and Release Path

**Status:** Accepted 2026-10-11 — records the maintainer's decisions of 2026-10-08, 2026-10-09 and 2026-10-10.
**Date:** 2026-10-09
**Authors:** QAuth Team

> **Amended 2026-10-09** with the effects of the maintainer's 2026-10-09 answers to ADR-014 to
> ADR-017. Those records hold the reasons. This record names only what changes in its scope.
>
> - §3, human accounts: a bot challenge on sign-up, and passkey-only accounts.
> - §4: two more experimental items, and the PKCE rule on the FiPA endpoint.
> - §5: `REQUIRE_EMAIL_VERIFIED` is renamed `REQUIRE_VERIFIED_ACCOUNT`.
>
> **Amended 2026-10-10** with the maintainer's answers on the UI scope, given on 2026-10-09 and
> 2026-10-10. ADR-020 records the UI surfaces,
> their screens and the UX acceptance criteria. This record names only what changes in scope and in
> the promise.
>
> - §2: each area's screens ship in that area's beta.
> - §3: the device authorization grant, more human-account items, event delivery, a paired sandbox
>   realm and a two-admin approval rule. The core keeps only generic OIDC upstream; provider presets
>   are first-party plugins that ship with 1.0.
> - §4: the plugin API is public but experimental.
> - §5: the event schema, the declarative realm file and the realm policies join the contract.
> - §8: My Number arrives through a plugin.
> - Answers: question 12 lists what the UI scope leaves for later. The UI screen list is no longer
>   open.

## Context

QAuth is pre-1.0. The latest tag is `v0.1.0-rc.2`. [`SECURITY.md`](../../SECURITY.md) says that no
release has had an external security audit. It also says that 1.0 will ship its own support policy.

No record yet says what 1.0 contains, what it promises, or how QAuth gets there.
[ADR-007](./007-mcp-first-positioning.md) set the near-term identity. Later records propose large
new areas: the Authority Tree ([ADR-014](./014-agent-authority-tree.md), ADR-015 and ADR-016) and
first-party login (ADR-017). Each record designs one area. None says which areas a 1.0 release must
carry.

### What exists on `main` (checked 2026-10-09)

Shipped:

- OAuth 2.1 and OIDC core, with discovery and JWKS.
- The MCP authorization profile of revision 2026-07-28. CIMD is the primary registration path, and
  RFC 7591 dynamic registration is the fallback. Authorization responses carry the RFC 9207 `iss`.
- The agent layer: the agent client type, RFC 8693 delegation with `act`, scope modes, step-up and
  audit. The environment-aware posture of [ADR-008](./008-environment-aware-authorization.md).
- Enterprise-Managed Authorization in both ID-JAG roles, behind `ID_JAG_ENABLED`
  ([ADR-011](./011-enterprise-managed-authorization.md)).
- Wallet sign-in over OID4VP, behind `WALLET_FEDERATION_ENABLED`. Every result so far is against
  the in-repo mock wallet. The real-wallet pass is open as #376.
- Hybrid ML-DSA-65 signing, behind `HYBRID_SIGNING_ENABLED`. The pre-default-on checklist of the
  [#248 review](../security/005-pqc-hybrid-signing-review.md) still has open items.
- `@qauth-labs/mcp-guard`, a Fastify plugin for resource servers. It is marked private in the
  workspace.

Not built:

- The Authority Tree and first-party login. ADR-014 to ADR-017 are Accepted, and none is built.
- DPoP, passkeys, TOTP, password reset and an account page.
- RP-initiated logout and back-channel logout.
- Request objects and PAR. Discovery advertises request objects as unsupported and publishes no PAR
  endpoint.
- OpenID Federation. [ADR-004](./004-wallet-agnostic-federation.md) notes that version 1.0 is Final
  and that the topic deserves its own record.
- Upstream OIDC login, an admin console, and every SDK in the README's plan.

The [OIDF certification runbook](../oidf-op-certification-runbook.md) already targets the Basic OP
and Config OP profiles. The [spec-conformance matrix](../conformance/README.md) maps normative
requirements to in-repo tests.

This record settles what 1.0 is for, what it promises, what waits, and which gates come first.

## Decision

### 1. Goal and audience

- The first audience is developers who self-host QAuth.
- The target is a stable 1.0 announcement.
- 1.0 carries a stability promise. It covers the stable list in §3, under the contract in §5.

### 2. Release path

0.x betas ship area by area, in this order:

1. the core and the UIs;
2. the Authority Tree;
3. federation.

Each area's screens ship in that area's beta. The core beta brings the ceremony app, the account
console, the core sections of the admin console and the developer portal. The Authority Tree beta
brings the agent screens and the remote approval page. The federation beta brings the federation
section of the admin console and the federation upstream. Decided 2026-10-10 (maintainer).

A public release candidate with external users comes before the freeze.

### 3. Stable in 1.0

Everything in this section is inside the stability promise and inside the audit scope.

**Protocol core**

- OAuth 2.1 and OIDC core.
- The MCP authorization profile of revision 2026-07-28:
  - CIMD;
  - RFC 7591 dynamic registration, kept as deprecated but supported, and gated;
  - the RFC 9207 `iss`;
  - step-up.
- Enterprise-Managed Authorization with ID-JAG, in both roles: consume and mint. It follows the MCP
  EMA extension, at the commit the [spec pin log](../spec-pin-log.md) records. The log tracks the
  ID-JAG revision in its own row.
- The OAuth 2.0 device authorization grant (RFC 8628), with a code-entry page in the ceremony app.
  Against device-code phishing, that page shows the client's verified domain before the user
  approves. Decided 2026-10-10 (maintainer). The verified domain alone does not stop a real
  client's code from being passed to a victim (RFC 8628 §5.4), so the stable page also asks for an
  explicit confirmation, including after `verification_uri_complete`. It warns that nobody else
  should have given the user the code, and shows the requesting device's approximate location,
  network and user agent. User codes are short-lived and single use, and code entry is
  rate-limited. ADR-020 §3 lists the controls.

**Agents and delegation**

- The shipped agent layer: the agent client type, RFC 8693 `act` delegation, scope modes, step-up
  and audit.
- The environment-aware posture (ADR-008).
- The Authority Tree (ADR-014, ADR-015, ADR-016). §9 records its new name.

**Wallet**

- OID4VP 1.0 with the HAIP 1.0 profile.
- SD-JWT VC at the revision HAIP 1.0 pins. The spec pin log records that pin and its basis.

**Post-quantum**

- ML-DSA-65 per RFC 9964.
- The detached-parallel hybrid carrier of [ADR-005](./005-pqc-hybrid-signing.md), under a
  versioned QAuth identifier.
- Hybrid signing stays default-off.
- The pre-default-on checklist from the #248 review is cleared before 1.0.

The IETF composite construction is outside the promise. It stays experimental until it is an RFC.
The PQC library in §7 implements it as experimental.

**OpenID Federation 1.0, in full**

- The leaf entity configuration.
- Automatic and explicit registration.
- Trust chain resolution and validation, metadata policy and trust marks.
- The resolve endpoint.
- The trust anchor and intermediate roles.
- The relying-party side: QAuth trusts upstream OpenID Providers through federation.
- Request objects (RFC 9101) and PAR (RFC 9126), which come with it.
- On the wallet path: the OID4VP `openid_federation` client identifier prefix, and issuer trust
  through federation trust chains.

**Human accounts**

- Hosted sign-up, account verification, password reset and an account page.
- A provider-neutral bot challenge on sign-up. Decided 2026-10-09 (maintainer).
- TOTP, passkeys (WebAuthn) and recovery codes. Decided 2026-10-09 (maintainer).
- Passkey-only accounts, with no email. Recovery codes are mandatory for them. Decided 2026-10-09
  (maintainer).
- Decided 2026-10-10 (maintainer):
  - identifier-first sign-in, with "try another way" between a user's methods;
  - several accounts signed in on one browser, chosen with `prompt=select_account` (ADR-019
    Decision 3);
  - a forced password update, on an admin's request or when the password appears on a breach list.
    There is no periodic expiry;
  - a security log the user sees: recent sign-ins, new devices and security changes;
  - self-service account deletion, which a realm can switch off;
  - security notification emails. Those for credential changes cannot be switched off.
- Upstream OIDC login through an AuthMethod contract. The core ships only generic OIDC upstream and
  names no provider. Decided 2026-10-10 (maintainer).
- Provider presets are first-party plugins on that contract, and they are ready when 1.0 ships:
  Google, Microsoft, Apple, GitHub and My Number. GitHub offers no OIDC sign-in, so its plugin uses
  OAuth 2.0 and GitHub's user API. Decided 2026-10-10 (maintainer).
- The plugin API is public and documented, and experimental in 1.0 (§4). It becomes stable in 1.x.

**Events**

Every QAuth event can be used by automation outside QAuth. QAuth itself runs no workflow engine.
Decided 2026-10-10 (maintainer). Events leave QAuth by four routes, all in 1.0:

- signed webhooks, in the Standard Webhooks format;
- a cursor-based event API, from which a receiver reads on from where it stopped;
- Shared Signals Framework (SSF) streams, with CAEP events for security changes;
- OpenTelemetry export.

The event types and their payload schema are inside the promise (§5). ADR-019 Decision 8 says how
deliveries are made.

**Administration**

- A paired sandbox realm that a live realm can have, with its own host, issuer and keys. ADR-019
  Decision 11 defines it. Decided 2026-10-10 (maintainer).
- A two-admin approval rule. The admin console recommends it for every `admin:security` operation,
  and a realm chooses where it is mandatory. ADR-019 Decision 7 defines it. Decided 2026-10-10
  (maintainer).

**Logout**

- RP-initiated logout, delivered in ADR-017's phase F0.
- OIDC Back-Channel Logout 1.0.
- No front-channel logout.

**UIs**

- Administration and account UIs with good UX. Their breadth matches an established open-source
  identity server, for example Keycloak.
- The UIs are the reference ceremony app, the account console, the admin console with its federation
  section, and the developer portal. ADR-020 lists their screens and the
  UX acceptance criteria every screen meets before 1.0. Decided 2026-10-09 and 2026-10-10
  (maintainer).
- 1.0 ships in English only, with translation infrastructure in place. Further languages come from
  the community. Decided 2026-10-10 (maintainer).

**SDKs and the Rust core** are in §6.

### 4. Experimental in 1.0

Experimental items ship in 1.0 but stay outside the stability promise.

- The FiPA authorization challenge endpoint (ADR-017). It stays experimental until FiPA is an RFC.
  The engine behind it is stable, because the hosted pages use it.
  - PKCE on this endpoint is on by default. A per-client setting can switch it off. This is the
    single exception to mandatory PKCE. Decided 2026-10-09 (maintainer).
- The `/first-party` subpath of `@qauth-labs/node`, which serves FiPA.
- The `oid4vp-1.0-base` verifier profile. It stays supported, but it allows looser options than
  HAIP 1.0, such as unsigned requests. Decided 2026-10-09.
- Attestation-based client authentication for native apps, ADR-017's phase F4. It stays
  experimental unless `draft-ietf-oauth-attestation-based-client-auth` is an RFC before 1.0 is cut.
  Decided 2026-10-09 (maintainer).
- The pass-through leg of ADR-016 §4. The rest of the Authority Tree is stable (§3). Decided
  2026-10-09 (maintainer).
- The plugin API: the AuthMethod contract as plugins see it. It is public and documented, so others
  can write plugins, but it may change in a minor release. It becomes stable in 1.x, after QAuth's
  own plugins have matured on it. The first-party plugins themselves are part of 1.0 (§3). Decided
  2026-10-10 (maintainer).

How an item is marked experimental, and how it becomes stable, is set in §5.

### 5. The stability contract

The promise is wire-level. A black-box HTTP conformance suite guards it. That suite is new work,
because today's conformance matrix maps requirements to in-repo tests.

The contract covers:

- **Wire behaviour** of every stable feature, as a client sees it over HTTP.
- **The Interaction API, version 1**, at `/interaction/v1`. It is published as OpenAPI, with JSON
  Schema for its steps. ADR-019 defines it.
- **The three API families**: admin, account and developer. ADR-019 defines them.
- **Stable SDKs**, per major version.
- **QAuth-defined identifiers.** Each carries a version, for example a `urn:qauth:...:v1` form. A
  future standard identifier can then sit beside it without breaking 1.x.
- **A documented subset of configuration keys:** issuer and host, the database, Redis, the KEK
  provider, proxy trust, and the switches of stable features. Other keys are marked advanced or
  experimental. A renamed key keeps working under its old name, with a warning, for the
  deprecation window.
  - `REQUIRE_EMAIL_VERIFIED` is renamed `REQUIRE_VERIFIED_ACCOUNT`. The old name stays an alias
    for the deprecation window. The key exists on `main` today, default `false`. Decided 2026-10-09
    (maintainer).
- **The event types and their payload schema**, on every delivery route (§3). Decided 2026-10-10
  (maintainer).
- **The declarative realm file.** It describes a realm's configuration and leaves out every secret
  value. The admin API and the CLI export it and import it, and an import first shows a dry-run
  diff. Today's seed manifest becomes a subset of it. Decided 2026-10-10 (maintainer). An import is
  authorized change by change, as the operations it contains, and the strictest change gates it
  (ADR-019 Decisions 7 and 11).
- **Realm policies in the admin API's realm representation.** Realm policies live on the realm row
  and change through the admin API and the console, so the representation is the stable surface for
  them. Environment keys only seed a new realm's defaults. ADR-019 Decision 10 draws the line.
  Decided 2026-10-10 (maintainer).
- **Upgrades within 1.x.** Migrations only go forward. Every upgrade completes by running the
  migration runner, with no manual step. No 1.x migration is destructive; changes use
  expand-then-contract. CI tests an upgrade from every earlier 1.x minor release. Downgrades are not
  supported, so the upgrade guide tells operators to back up first.

The contract does not cover the experimental items in §4, which include the plugin API, or internal
code that no stable surface exposes.

**Deprecation and support.** A deprecation is announced in a minor release. Removal comes no sooner
than 12 months later, and only in a new major release. Security fixes land on the latest 1.x minor
release. The 1.x line is supported for at least five years after 1.0.

**Experimental items.** An experimental item sits behind a switch. Discovery does not mention it
unless the switch is on. The server logs a warning at boot when the switch is on. The docs label it
"Experimental". It may change in a minor release without a deprecation window. It becomes stable in
a minor release once four conditions hold:

1. the spec it implements is an RFC or a Final specification;
2. it has seen external use in a beta;
3. the external audit covered it;
4. conformance tests exist for it.

### 6. SDKs and the Rust core

| Package                                | Purpose                                                                                                                                                                                   | Status in 1.0                                       |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `@qauth-labs/resource-guard`           | Resource servers. JWT and introspection validation, audience and scope checks, RFC 9728 metadata, 401 and 403 challenges, DPoP verification, `act`-chain reading, hybrid PQC verification | Stable. Renamed from `@qauth-labs/mcp-guard`.       |
| `@qauth-labs/node`                     | Server-side apps and BFFs. Redirect login with PKCE, `state`, `nonce` and `iss`; a server-side session store; refresh; logout; `private_key_jwt`; token exchange                          | Stable. The `/first-party` subpath is experimental. |
| `@qauth-labs/agent` and `qauth-broker` | Agents in an Authority Tree. Spawn exchange, narrowing, action events, approval waits                                                                                                     | Stable, because the Authority Tree is stable.       |
| `@qauth-labs/admin`                    | Generated from the admin OpenAPI                                                                                                                                                          | Stable.                                             |

- There is no browser token SDK. Browser apps use a BFF.
- `qauth-broker` is a local process with a language-neutral protocol. It keeps DPoP keys away from
  the model, and it alone decides a new node's parent and type (ADR-014 §12).
- A Python `resource-guard` comes next. Go comes later.
- Every SDK runs shared, language-neutral test vectors.
- This set replaces the README's SDK plan. The vanilla JS and React SDKs listed there are dropped.

The Rust core, `qauth-core`, holds verification primitives:

- JWS, including the hybrid, and DPoP proofs;
- SD-JWT VC and key attestations;
- WebAuthn, through a mature crate.

The server uses `qauth-core` through napi. SDKs use it through WASM and PyO3.

There is no full Rust rewrite before 1.0. A later rewrite stays possible, for three reasons:

1. the promise is wire-level;
2. the black-box HTTP conformance suite guards it;
3. the role split in ADR-019 allows a gradual move.

### 7. Post-quantum community work

1. An individual JOSE Internet-Draft for a backward-compatible parallel hybrid JWS scheme. That is
   the construction ADR-005 chose.
2. Then a vendor-neutral library. Its core is Rust over audited primitives, with WASM and PyO3
   bindings. It implements the parallel profile and, as experimental, the composite draft.
3. Shared test vectors for both.
4. Upstream contributions of ML-DSA support to JOSE libraries that lack it.

### 8. Assurance before 1.0

**External audit.** An independent external security audit is required before 1.0. It covers the
stability promise.

**OIDF certification** before 1.0:

- OpenID Provider: Basic OP and Config OP;
- the logout profiles QAuth implements: RP-initiated and back-channel;
- self-certification of the OID4VP and HAIP verifier, for the wallet path.

**Real-wallet testing** before 1.0 uses the EUDI reference wallet.

**Japan's My Number** enters 1.0 through the My Number plugin on the upstream OIDC contract, not
through the wallet path. The upstream is the authentication app API of Japan's Digital Agency. That
API requires `private_key_jwt`. My Number is not an OID4VP wallet today. The plugin is first-party
and ships with 1.0, like the other provider plugins in §3. Decided 2026-10-10 (maintainer).

### 9. The Authority Tree name

- The title "Agent Authority Tree" becomes "Authority Tree".
- The reason: it is a generic machine-to-machine and process delegation mechanism. AI agents are
  one client class.
- `AGENT_TREE_ENABLED` becomes `AUTHORITY_TREE_ENABLED`.
- `AGENT_APPROVAL_ENABLED` becomes `REMOTE_APPROVAL_ENABLED`. ADR-014 §14 is titled remote
  approval.
- The two approval settings follow the switch: `AGENT_APPROVAL_EXPIRY` becomes
  `REMOTE_APPROVAL_EXPIRY`, and `AGENT_APPROVAL_BUDGET` becomes `REMOTE_APPROVAL_BUDGET`. The
  maintainer decided this on 2026-10-09.
- Identifiers that name an agent keep their names. Examples are the agent principal and the agent
  client type.
- File names stay unchanged, so links keep working.

Neither switch exists in code on `main`, so the rename needs no configuration migration.

### 10. Later

**1.1** brings the first wallet expansion:

- ISO mdoc;
- the W3C Digital Credentials API: ISO/IEC 18013-7 Annex C, and OID4VP over the DC API.

That brings mdoc PIDs, and My Number held on a phone, for example on iPhone.

**With a hosted service:** automatic TLS through ACME, and DNS verification for custom domains.
Custom domains themselves are in 1.0, as ADR-019 records.

### 11. Topology is ADR-019's

[ADR-019](./019-deployment-topology-and-trust-boundaries.md) records the topology and trust
boundaries that 1.0 is built on. That includes realms, hosts, issuers, sessions, UIs, the
Interaction API, the API families and keys. This record does not restate those rules.

## Answers to the open questions (2026-10-09)

The maintainer answered this record's open questions on 2026-10-09. The answers below are
decisions; §4 and §5 carry the ones that change the contract.

1. **SAML, LDAP, Kerberos and UMA** are not in 1.0.
   - SAML comes in 1.x, first as an identity provider, then as an upstream where needed. XML
     signature handling is a defect-prone area, and it would widen the audit.
   - LDAP comes in 1.x as an extension of the AuthMethod contract.
   - Kerberos and UMA are not planned. Fine-grained authorization uses RAR and the AuthZEN decision
     API that ADR-014 §8 describes.
2. **Deprecation and support:** see §5.
3. **Configuration keys:** a documented subset is inside the promise; see §5.
4. **Database migrations:** forward-only, with tested upgrades within 1.x; see §5.
5. **OID4VP profiles:** HAIP 1.0 is stable; `oid4vp-1.0-base` is experimental; see §4.
6. **Audit timing.** The main audit runs on the frozen release candidate, so it covers the code that
   ships. Before that, each area beta gets an internal review and automated scanning. Findings are
   fixed before 1.0, and the report is published.
7. **PQC draft and library.** The Internet-Draft's first revision is submitted before 1.0, so the
   stable hybrid format has a published definition. The library's verification half ships before
   1.0, because `@qauth-labs/resource-guard` promises hybrid verification. Composite support can
   follow later.
8. **Rust layering.** Three layers: a vendor-neutral PQC and JOSE crate in its own repository;
   `qauth-core` on top of it; and its bindings. The napi binding replaces today's
   `@qauth-labs/crypto-native`; WASM and PyO3 serve the SDKs.
9. **Experimental items:** marking and promotion are in §5.
10. **Composite in the server.** Not in 1.0. The server emits only the parallel hybrid. This is
    revisited when the composite draft becomes an RFC.
11. **AuthMethod and CredentialProvider.** AuthMethod extends the `CredentialProvider` interface of
    [ADR-003](./003-credential-provider-interface.md). `CredentialProvider` stays the verification
    half. AuthMethod adds the Interaction API steps and the routes an upstream needs. ADR-003 carries
    a note saying so. `WalletProvider.verify()` keeps throwing, as a deliberate fail-closed property.
    Provider plugins implement AuthMethod; its plugin API is experimental in 1.0 (§4). Added
    2026-10-10 (maintainer).
12. **What the UI scope leaves out of 1.0.** Answered on 2026-10-09 and 2026-10-10 (maintainer),
    with the screens themselves in ADR-020.
    - In 1.x: organizations, with inbound SCIM provisioning alongside them; an authentication flow
      editor, while 1.0 has a policy screen; general CIBA for any client, while 1.0 uses CIBA only
      for Authority Tree approval; mTLS client authentication (RFC 8705); sign-in with an x509
      client certificate; versioned acceptance of terms; a self-service "download my data"; user
      import in the console, while 1.0 has the CLI tool.
    - Not planned: a workflow engine, because QAuth exposes every event instead; a client-policy
      engine; parameterized scopes, because RAR covers them; script mappers; passwords set by an
      admin; configurable security headers.

## Open questions

None. The UI screen list was answered on 2026-10-09 and 2026-10-10; ADR-020 records it.

## Consequences

### Positive

- Self-hosters get a written promise of what will not break within 1.x.
- An external audit, OIDF certification and real-wallet testing give outside evidence before the
  announcement.
- A wire-level promise leaves the internals free to change, including a gradual move to Rust.
- Versioned QAuth identifiers let a future standard sit beside them without a breaking change.
- Area-by-area betas put each area in front of users before the freeze.
- Without a browser token SDK, tokens stay on servers.

### Negative

- The scope is large. OpenID Federation, the Authority Tree, passkeys, logout and the UIs are all
  unbuilt today.
- The audit and the certifications cost time and money.
- Every stable surface is a long-term maintenance load: four SDK packages, three API families and
  the Interaction API.
- The renames change documentation and package imports: `mcp-guard` and the Authority Tree
  switches.
- Unversioned QAuth identifiers in accepted records must gain a version before they ship. ADR-017's
  step URNs are one example.
- Some 1.0 work depends on outside parties: the EUDI reference wallet, the upstream My Number API
  and the auditor.
- The 2026-10-10 answers grow the scope further: the device grant, several accounts on one browser,
  four event routes, a sandbox realm and five provider plugins. The event schema and the realm file
  become long-term surfaces.

### Neutral

- Stable does not mean on by default. Hybrid signing is stable and stays default-off.
- Several stable items cite moving revisions. The spec pin log keeps tracking them.
- This record fixes scope, not design. OpenID Federation, for example, still needs its own record,
  as ADR-004 noted.
- The README's planned-work list, including its SDK plan, needs a follow-up edit to match.
- 1.0 ships in English only. Translations wait for contributors.

## Related

- [ADR-004](./004-wallet-agnostic-federation.md) — wallet federation; notes OpenID Federation
- [ADR-005](./005-pqc-hybrid-signing.md) and its
  [#248 security review](../security/005-pqc-hybrid-signing-review.md) — hybrid signing
- [ADR-007](./007-mcp-first-positioning.md) — MCP-first positioning and spec tracking
- [ADR-008](./008-environment-aware-authorization.md) — environment-aware posture
- [ADR-011](./011-enterprise-managed-authorization.md) — Enterprise-Managed Authorization
- [ADR-014](./014-agent-authority-tree.md), ADR-015 and ADR-016 — the
  Authority Tree
- ADR-017 — first-party login and FiPA
- [ADR-019](./019-deployment-topology-and-trust-boundaries.md) — topology and trust boundaries
- ADR-020 — UI surfaces and UX acceptance criteria
- [`SECURITY.md`](../../SECURITY.md), the [spec pin log](../spec-pin-log.md), the
  [OIDF certification runbook](../oidf-op-certification-runbook.md) and the
  [spec-conformance matrix](../conformance/README.md)
- Issues #248 (PQC security gate) and #376 (real-wallet pass)
- [MCP Authorization 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  and [MCP `ext-auth`](https://github.com/modelcontextprotocol/ext-auth)
- [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html),
  [HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
  [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) and
  [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [Standard Webhooks](https://www.standardwebhooks.com/) and the
  [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
- [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html),
  [`draft-ietf-jose-pq-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/),
  [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628),
  [RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101),
  [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126) and
  [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
