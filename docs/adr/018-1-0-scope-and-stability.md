# ADR-018: QAuth 1.0 — Scope, Stability Promise and Release Path

**Status:** Proposed — records the maintainer's decisions of 2026-10-08 and 2026-10-09; it becomes Accepted when the maintainer has read this text.
**Date:** 2026-10-09
**Authors:** QAuth Team

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

- The Authority Tree and first-party login. ADR-014 to ADR-017 are all Proposed.
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
- TOTP, and passkeys (WebAuthn) with recovery codes.
- Upstream OIDC login through an AuthMethod contract. The TypeScript plugin API behind it stays
  internal and is not promised.

**Logout**

- RP-initiated logout, delivered in ADR-017's phase F0.
- OIDC Back-Channel Logout 1.0.
- No front-channel logout.

**UIs**

- Administration and account UIs with good UX. Their breadth matches an established open-source
  identity server, for example Keycloak.
- The exact UI scope is not decided (see [Open questions](#open-questions)).

**SDKs and the Rust core** are in §6.

### 4. Experimental in 1.0

Experimental items ship in 1.0 but stay outside the stability promise.

- The FiPA authorization challenge endpoint (ADR-017). It stays experimental until FiPA is an RFC.
  The engine behind it is stable, because the hosted pages use it.
- The `/first-party` subpath of `@qauth-labs/node`, which serves FiPA.
- The `oid4vp-1.0-base` verifier profile. It stays supported, but it allows looser options than
  HAIP 1.0, such as unsigned requests. Decided 2026-10-09.

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
- **Upgrades within 1.x.** Migrations only go forward. Every upgrade completes by running the
  migration runner, with no manual step. No 1.x migration is destructive; changes use
  expand-then-contract. CI tests an upgrade from every earlier 1.x minor release. Downgrades are not
  supported, so the upgrade guide tells operators to back up first.

The contract does not cover the experimental items in §4, the TypeScript plugin API, or internal
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
  the model.
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

**Japan's My Number** enters 1.0 through upstream OIDC, not through the wallet path. The upstream
is the authentication app API of Japan's Digital Agency. That API requires `private_key_jwt`. My
Number is not an OID4VP wallet today.

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

## Open questions

- The UI screen list. It is the subject of the next conversation.

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
- Unversioned QAuth identifiers in proposed records must gain a version before they ship. ADR-017's
  step URNs are one example.
- Some 1.0 work depends on outside parties: the EUDI reference wallet, the upstream My Number API
  and the auditor.

### Neutral

- Stable does not mean on by default. Hybrid signing is stable and stays default-off.
- Several stable items cite moving revisions. The spec pin log keeps tracking them.
- This record fixes scope, not design. OpenID Federation, for example, still needs its own record,
  as ADR-004 noted.
- The README's planned-work list, including its SDK plan, needs a follow-up edit to match.

## Related

- [ADR-004](./004-wallet-agnostic-federation.md) — wallet federation; notes OpenID Federation
- [ADR-005](./005-pqc-hybrid-signing.md) and its
  [#248 security review](../security/005-pqc-hybrid-signing-review.md) — hybrid signing
- [ADR-007](./007-mcp-first-positioning.md) — MCP-first positioning and spec tracking
- [ADR-008](./008-environment-aware-authorization.md) — environment-aware posture
- [ADR-011](./011-enterprise-managed-authorization.md) — Enterprise-Managed Authorization
- [ADR-014](./014-agent-authority-tree.md), and ADR-015 and ADR-016, proposed in PR #420 — the
  Authority Tree
- ADR-017, proposed in PR #417 — first-party login and FiPA
- [ADR-019](./019-deployment-topology-and-trust-boundaries.md) — topology and trust boundaries
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
- [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html),
  [`draft-ietf-jose-pq-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/),
  [RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101),
  [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126) and
  [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
