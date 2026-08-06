# ADR-007: MCP-First Positioning — OAuth 2.1 Authorization Server for MCP / AI Agents

**Status:** Accepted
**Date:** 2026-06-23
**Authors:** QAuth Team

> **Implementation status (2026-06-24):** The near-term MCP track has **shipped**. CIMD client registration is live (config-gated via `CIMD_*`, with SSRF guards and an optional domain trust policy); `@qauth-labs/mcp-guard` ships as the resource-server SDK (PRM discovery, `401`/`403` challenges, JWKS/introspection token validation); the agent-facing `GET /api/clients` developer surface exists; and the T0 trust floor is in place — testcontainers-backed repository tests plus a CI gate running `lint typecheck test build` and a repo-wide coverage threshold. The long-term federation/PQC items below remain accepted designs only (see [ADR-002](./002-identifier-abstraction.md) / [ADR-003](./003-credential-provider-interface.md) / [ADR-004](./004-wallet-agnostic-federation.md) / [ADR-005](./005-pqc-hybrid-signing.md)).
>
> **Activation (2026-07-21, #304): T4 (Federation & PQC) is now the active track, and the "accepted designs only" line above is superseded.** This ADR planned exactly this — federation/PQC "retained as the **long-term platform**, resequenced to follow the MCP work" (§Decision); §Consequences records that "only the order changes." Reaching the "follow" step is fulfillment, not a reversal. Current status: **ADR-002 is IMPLEMENTED** (identifier-abstraction migration complete — Epic #224, PRs #225–#230, migrations 0009–0012); **ADR-003 is implemented** (`CredentialProvider` interface + registry, PR #227); **ADR-004 has shipped code** (`WalletProvider` skeleton, #232 — `verify()` throws by design until the OID4VP flow lands; base-profile flow in progress under Epic #231); **ADR-005 has shipped code** (native + noble ML-DSA-65 backends, #243/#244 — no ML-DSA-signed token emitted yet). The gate this deferral hinged on is therefore **cleared**: the "gated on the ADR-002 schema migration, which has not started" statement (§Context) and "**Defer the ADR-002 identifier-abstraction migration**" (§Decision 3) describe the 2026-06-23 posture and no longer hold. T4 re-activation was the maintainer decision recorded on #296 (2026-07-20).
>
> **Progress update (2026-07-31): T4 is now 48 issues closed / 4 open, and the two "shipped code" clauses above understate where ADR-004 and ADR-005 stand.**
>
> - **ADR-004** — the OID4VP base profile is **complete**, not "in progress". All of #233–#240 merged, and a browser wallet sign-in runs end to end behind `WALLET_FEDERATION_ENABLED` (default off), covered by an E2E mock-wallet suite. `WalletProvider.verify()` still throws by design, but the wallet login path does **not** go through it — it runs on `apps/auth-server/src/app/routes/ui/wallet-login.ts` → `helpers/wallet-presentation.ts`. See the [ADR-004 status note](./004-wallet-agnostic-federation.md).
> - **ADR-005** — "no ML-DSA-signed token emitted yet" no longer holds. #245–#247 landed the JWS carrier, mixed `AKP`+`OKP` JWKS and the introspection-first posture, and **#275 wired live hybrid issuance** into `/oauth/token`, `/auth/login` and `/oauth/introspect`. A deployment that enables `HYBRID_SIGNING_ENABLED` (default off) does emit ML-DSA-65 material.
>
> Both features remain **off by default**, so a default deployment's behaviour is unchanged. Open: #376, #377, #379 and the tracking epic #231.

## Context

The OAuth 2.1 work integrated in PR #156 (`integration/oauth-mcp-stack`) was built, in its own words, for _"first-class MCP / third-party client support."_ It delivered, together and in one release:

- Authorization Server Metadata — `/.well-known/oauth-authorization-server` (RFC 8414)
- OIDC discovery + JWKS — `/.well-known/openid-configuration`, `/.well-known/jwks.json`
- Dynamic Client Registration — `POST /oauth/register` (RFC 7591, open mode)
- Resource Indicators — `resource`-bound, audience-scoped tokens across authorize → code → token → refresh (RFC 8707)
- Public-client (`token_endpoint_auth_method=none`) `authorization_code` + PKCE (PR #159)
- A browser consent screen with session cookies and a revocation surface

This was validated end-to-end: **Claude Code**, configured with only a server URL, drove the full `on-401 → discovery → dynamic registration → authorization_code + PKCE → consent → token` handshake against a live MCP server.

Two facts make this strategically significant:

1. **It was off-roadmap.** "MCP" appears nowhere in the MVP-PRD or README. The capability maps to the PRD's vaguest, furthest-out item — "Phase 9: Agent Authentication & Authorization (TBD)" — whose _protocol foundation_ we have now shipped years ahead of plan. The authorization-server side of the MCP authorization profile is essentially complete and live-tested.

2. **The originally-pitched differentiators are still paper.** Wallet federation ([ADR-004](./004-wallet-agnostic-federation.md)), post-quantum hybrid signing ([ADR-005](./005-pqc-hybrid-signing.md)), and the identifier-abstraction model ([ADR-002](./002-identifier-abstraction.md) / [ADR-003](./003-credential-provider-interface.md)) remain accepted designs with no implementing code. All of Phase 4/5 is gated on the ADR-002 schema migration, which has not started. **[Superseded 2026-07-21, #304: the ADR-002 migration has since completed (Epic #224) and T4 is now active — see the Activation note at the top.]**

Externally: the MCP authorization specification is new (2025), adoption is rising quickly, and there is little **self-hostable, open-source** tooling — the space is dominated by hosted identity vendors. A sovereign, OSS, OAuth-2.1-correct MCP authorization server is an underserved niche, and QAuth is already most of the way into it.

The question this ADR settles: how to sequence near-term work given an accidental, timely, validated capability versus the long-planned federation/PQC vision.

## Decision

Adopt **MCP-first positioning** as QAuth's near-term product identity:

> The open-source, self-hostable OAuth 2.1 authorization server for MCP servers and AI agents.

Wallet federation (ADR-004) and post-quantum signing (ADR-005) are retained as the **long-term platform**, resequenced to follow the MCP work rather than precede it. Concretely:

1. **Productize the existing capability into a turnkey MCP-auth offering.**
   - `@qauth-labs/mcp-guard` — a resource-server-side SDK/middleware that serves `/.well-known/oauth-protected-resource` (RFC 9728), emits the `401 + WWW-Authenticate: Bearer resource_metadata=…` challenge, and validates QAuth-issued tokens (JWKS verification + `aud`/scope checks, or introspection). This is the adoption lever: without it, only the maintainer can wire QAuth to an MCP server.
   - **Client registration: adopt Client ID Metadata Documents (CIMD)** as the primary path per MCP 2025-11-25 — advertise `client_id_metadata_document_supported`, fetch + validate the metadata document (`client_id` == URL, redirect-URI checks, SSRF guards, optional domain trust policy). CIMD keeps no persistent registration records, so it also neutralizes the open-DCR abuse surface. Keep RFC 7591 dynamic registration as the documented fallback, and gate open mode (`initial_access_token`, client TTL, optional approval) for any deployment that still exposes it.
   - **Step-up scope challenges:** `mcp-guard` emits `403 insufficient_scope` + `WWW-Authenticate` scope hints; QAuth supports re-authorization for an increased scope set (MCP 2025-11-25 incremental consent).
   - An MCP quickstart and a runnable example (the Claude Code → `memory-mcp` flow), plus `RFC 7009` token revocation.

2. **Build the agent-native authorization substance of Phase 9 as the differentiation.** Agent client type; on-behalf-of delegation via OAuth Token Exchange (RFC 8693, `act` claim — an additive MCP auth _extension_, not core; see the [ext-auth](https://github.com/modelcontextprotocol/ext-auth) repo); agent scope modes (ReadOnly / Admin / Exec); step-up authentication before dangerous operations; per-agent action audit (extending the existing `audit_logs` table). This is what makes QAuth _more_ than a generic OAuth server for agents.

3. **Defer the ADR-002 identifier-abstraction migration.** It is re-scoped as the **gate for Phase 4 (wallet federation)**, not near-term work. **[Done, not deferred — superseded 2026-07-21, #304: the migration completed via Epic #224 (PRs #225–#230); the Phase 4 gate is cleared and T4 is active. See the Activation note at the top.]** MCP authorization is dominated by client identity, audience binding, and consent — not human multi-credential identity — and runs on the current schema. See the implementation-status note added to ADR-002.

4. **Reprioritize the existing roadmap** (see Consequences) so the open issues map to the new track structure.

The NLnet / NGI grant narrative is treated as **reframable**: an MCP framing ("sovereign authentication for the agentic web") is acceptable and may strengthen a resubmission. The MCP work also directly advances the conformance and hardening milestones already in the grant scope.

## Consequences

### Positive

- Shortest path to an adoptable, differentiated product — the authorization-server core is ~90% complete and live-validated.
- Defers the costly, blocking ADR-002 migration until a second human-identity upstream (wallet/OIDC federation) actually requires it.
- The MCP work directly advances OAuth 2.1 / OIDC conformance and production-hardening goals already on the roadmap.
- Sovereign, self-hostable, OSS MCP authentication is underserved relative to the hosted incumbents.

### Negative

- Drifts from the originally-pitched federation/PQC narrative; requires reframing in any grant update.
- Risk of split focus for a small team — federation and PQC slip further out.
- **Open dynamic client registration is unguarded by default.** Any instance exposing the registration endpoint must gate it before the project is promoted for adoption — immediate follow-up; adopting CIMD (see Spec tracking) is the durable fix, since it removes persistent registration records entirely.
- New surface area to maintain: an SDK package and agent-delegation semantics.

### Neutral

- No work is discarded — federation (ADR-004) and PQC (ADR-005) remain on the roadmap; only the order changes.
- ADR-002/003/004/005 remain **Accepted** as designs; only their implementation sequence is affected.
- The MCP authorization specification is still evolving; `mcp-guard` must be versioned against a specific spec revision and tracked as the spec changes.

## Spec tracking

> **Current revision: MCP Authorization 2026-07-28 (final).** Read
> [Delta: 2025-11-25 to 2026-07-28](#delta-2025-11-25-to-2026-07-28) first — it
> is the live compliance picture. Everything between this note and that heading
> is the **superseded 2025-11-25 review**, retained for the audit trail; do not
> read it as current status.
>
> **[Refresh 2026-07-19 — superseded 2026-08-06: that pass reviewed the release
> _candidate_ and the `draft` spec URL, not the published revision, and each of
> its three "gap" bullets has since been closed in code. Re-reviewed against the
> final 2026-07-28 specification; corrections are marked inline in the delta
> section below.]**

Reviewed against MCP Authorization **revision 2025-11-25** (the revision this ADR targets; the implementation in PR #156 was built to 2025-06-18). Auth-relevant deltas and QAuth's posture:

- **Client ID Metadata Documents (CIMD)** — now the _recommended_ client-registration mechanism (client priority: pre-registered → CIMD → DCR → manual). **RFC 7591 Dynamic Client Registration is explicitly demoted to a backwards-compatibility fallback.** → Reshapes T1: adopt CIMD (Decision §1); it supersedes the earlier "DCR abuse controls" framing because there are no persistent registration records to abuse.
- **Incremental scope consent / step-up authorization** — runtime `403 insufficient_scope` + `WWW-Authenticate` scope challenge; clients re-authorize for a larger scope set. → `mcp-guard` (T1) emits the challenge; richer scope _modes_ stay T2.
- **OIDC Discovery accepted as an AS-metadata alternative**, with OIDC-discovery providers **required** to expose `code_challenge_methods_supported`; the PRM `WWW-Authenticate` header is now optional with a `.well-known` fallback. → **Already satisfied:** QAuth serves both RFC 8414 and OIDC discovery, each carrying `code_challenge_methods_supported: ['S256']`.
- **Delegation / on-behalf-of is not core MCP auth** — it lives in the separate [ext-auth extensions](https://github.com/modelcontextprotocol/ext-auth) repo, so QAuth's RFC 8693 token-exchange work (Decision §2 / T2) is an _extension_, not a core requirement.

Unchanged core QAuth already meets: OAuth 2.1 (public + confidential), PKCE S256 (advertised), RFC 9728 PRM discovery, RFC 8707 resource indicators + audience-bound tokens + audience-validated introspection, public-client refresh-token rotation, and consent.

## Delta: 2025-11-25 to 2026-07-28

**Re-reviewed 2026-08-06 against the final, published
[2026-07-28 revision](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)**
([release announcement](https://blog.modelcontextprotocol.io/posts/2026-07-28/),
[changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)).
2026-07-28 is released and final.

**[The original pass here was dated 2026-07-19 and read the release candidate
announced ~2026-07-19 plus the `draft` spec URL. Superseded 2026-08-06: where
the two disagree the statements below are authoritative, its three
implementation-gap claims are corrected in place with the prior wording
preserved, and the items it missed entirely are appended.]**

Only auth-relevant deltas are listed; the release also adds a stateless protocol
core, an Extensions framework, Tasks, and MCP Apps.

- **RFC 9207 issuer identification — NEW in 2026-07-28, and QAuth implements
  it.** The AS **SHOULD** include `iss` in authorization responses _including
  error responses_; clients **MUST** validate a present `iss` before redeeming
  the code (SEP-2468); and an AS that emits it **MUST** advertise
  `authorization_response_iss_parameter_supported: true` in its metadata. The
  spec states a future revision is expected to upgrade the AS-side SHOULD to
  **MUST**. → **Shipped (#282, closed).** `iss` is part of the
  `AuthorizationResponseParams` union in
  `apps/auth-server/src/app/helpers/oauth-redirect.ts`, so every
  `buildRedirectUrl` call site — success _and_ error — must supply it or fail to
  compile; `/oauth/authorize` sources it from
  `resolveIssuerIdentifier(fastify.jwtUtils.getIssuer())` and appends it
  verbatim, never through `new URL(...)`, because RFC 9207 §2.4 requires simple
  string comparison with no normalisation.
  `apps/auth-server/src/app/helpers/discovery.ts` hard-codes
  `authorization_response_iss_parameter_supported: true` on the AS metadata —
  deliberately not configurable, so the advertisement cannot drift from the
  behaviour — and `buildOpenIdConfiguration` inherits it. Covered by
  `oauth-redirect.test.ts` and `well-known.test.ts`.
  **[Was: "NEW, and QAuth does not implement it … QAuth emits neither. →
  Tracked as #282. This is the one hard gap in the delta." Superseded
  2026-08-06 — #282 is closed and shipped, and this is no longer a gap.]**
- **Scope guidance on the 401 — implemented.** Resources **SHOULD** include a
  `scope` parameter in the `WWW-Authenticate` header of the 401, not only on
  `insufficient_scope` (403). → **Shipped (#284, closed).**
  `libs/fastify/plugins/mcp-guard/src/lib/challenge.ts` attaches the route's
  required scopes to the credential-absent 401 as well as the 403, while keeping
  the 401 free of an `error` parameter per RFC 6750 §3.1. `invalid_token` is
  deliberately excluded: the client already holds a token, so the remedy is
  re-authentication rather than a wider scope set, and repeating the requirement
  there would invite pointless re-consent loops. Covered by `challenge.test.ts`.
  **[Was: "`mcp-guard` attaches `scope` to the 403 path only; clients currently
  fall back to PRM `scopes_supported`. → Tracked as #284." Superseded
  2026-08-06.]**
- **`offline_access` is a resource anti-pattern — filtering implemented.** MCP
  servers **SHOULD NOT** advertise `offline_access` in `WWW-Authenticate` scope
  or PRM `scopes_supported`, since refresh tokens are not a resource
  requirement. → **Shipped.** `NON_RESOURCE_SCOPES` in
  `libs/fastify/plugins/mcp-guard/src/lib/scope.ts` backs `advertisableScopes`,
  applied at both advertisement surfaces (`challenge.ts` and `metadata.ts`) and
  never to enforcement — a host that configures such a scope still has it
  checked against the token, so the filter cannot widen access. The AS
  advertising `offline_access` in its own `scopes_supported` is unaffected and
  remains correct.
  **[Was framed as a constraint `mcp-guard` must observe. Superseded
  2026-08-06 — it observes it.]**
- **DCR is now formally DEPRECATED in favour of CIMD** (spec PR #2858), retained
  for backwards compatibility only, and the release adopts a formal
  feature-lifecycle and deprecation policy with a **12-month minimum** window
  (SEP-2596). Precisely what moved: **CIMD's level did not change** — both
  revisions say "Authorization servers and MCP clients **SHOULD** support OAuth
  Client ID Metadata Documents", and DCR is **MAY** in both. What is new is the
  word _deprecated_: 2025-11-25 merely noted DCR was "included for backwards
  compatibility with earlier versions of the MCP authorization spec", whereas
  2026-07-28 states it "is deprecated and retained for backwards compatibility
  with authorization servers that do not support Client ID Metadata Documents".
  The direction ADR-007 already chose is now the specification's stated
  lifecycle position. → **No change required.** QAuth's
  client-resolution priority is pre-registered → CIMD → DCR
  (`apps/auth-server/src/app/helpers/client-resolution.ts`), which already
  matches; this is directional confirmation, not new work. **Forward risk:** the
  12-month policy makes eventual _removal_ of DCR from the specification a real
  possibility, so `POST /oauth/register` should be treated as a spec-deprecated
  surface — keep it, keep it gated, and do not build new capability on it.
  **[Was: "CIMD is now SHOULD; DCR is MAY and explicitly deprecated … In
  2025-11-25 CIMD was 'recommended' … the normative strength has firmed."
  Superseded 2026-08-06 — CIMD was already SHOULD and DCR already MAY in
  2025-11-25; only the deprecation language is new.]**
- **`application_type` on DCR (SEP-837) is a CLIENT-side MUST; nothing is
  required of the AS.** Clients must send `application_type` when registering so
  that an OIDC-aware server does not apply web-client redirect-URI rules to a
  native client. → **QAuth requires no change, and this is not a gap.**
  `apps/auth-server/src/app/routes/oauth/register.ts` strips `application_type`
  as an unrecognised registration field, which is exactly what RFC 7591 §3.2
  prescribes; `register.test.ts` asserts the strip. QAuth never derives
  redirect-URI policy from a self-asserted client hint in the first place —
  loopback handling is decided per RFC 8252 / [ADR-008](./008-environment-aware-authorization.md)
  by `isHttpLocalhostRedirect` in `helpers/oauth-redirect.ts` and by
  `helpers/environment-policy.ts`, keyed on the URI itself. Recorded explicitly
  so a future reader does not re-open this as a compliance gap.
- **Client-credential issuer binding (SEP-2352) is likewise a CLIENT-side
  MUST.** Clients must key persisted client credentials by issuer, must not
  reuse a registration across authorization servers, and must re-register when
  the issuer changes. → **Nothing is required of QAuth as an AS.** It is worth
  recording because it strengthens the CIMD case structurally: CIMD `client_id`s
  are explicitly **exempt**, being portable self-hosted URLs that denote the
  same client identity at every AS. That is a second, independent argument for
  the CIMD-primary posture in Decision §1.
- **Scope hierarchies — NEW MUST, and the one item needing a maintainer
  ruling.** 2026-07-28 adds that servers **MUST** account for scope hierarchies,
  where a broader scope implies narrower ones, when deciding whether a token is
  sufficient for an operation. The sentence is absent from 2025-11-25 and binds
  the resource server. → **Satisfied as-is; no code change.** The requirement is
  conditional — it obliges a server to honour a hierarchy _where one exists_.
  **Maintainer decision (2026-08-06): QAuth's agent scope modes are INDEPENDENT
  OAuth scopes, not a hierarchy.** `agent:admin` does **not** imply
  `agent:readonly`. The per-client `max_agent_mode` cap
  (`isModeWithinCap` in `apps/auth-server/src/app/helpers/scope-modes.ts`) is a
  **maximum requestable ceiling** — it governs which reserved scopes a client
  may ask for, not which requirements an already-granted token satisfies.
  `mcp-guard`'s exact, case-sensitive, non-hierarchical matching
  (`missingScopes` in `libs/fastify/plugins/mcp-guard/src/lib/scope.ts`, per
  RFC 6749 §3.3) is therefore correct and **must not be changed**: inferring an
  implication would silently widen the reach of every `agent:admin` token. What
  is wrong is the prose — [`docs/agent-authorization.md`](../agent-authorization.md)
  described the modes in hierarchical terms and is being corrected to match.
- **Both discovery mechanisms remain acceptable** (RFC 8414 _or_ OIDC Discovery),
  with clients required to support both. → **Already satisfied**, unchanged.
- **RFC 8707 resource indicators remain MUST for clients**, with audience
  validation MUST for servers. → **Already satisfied**, unchanged.
- **Extensions moved to a formal framework** with reverse-DNS IDs, capability
  negotiation, independent versioning, and an Extensions Track in the SEP
  process. QAuth's RFC 8693 token-exchange delegation work remains an
  _extension_ (`ext-auth`), not core — the position ADR-007 already took. The
  formalisation makes that boundary firmer, not weaker.
- **The `ext-auth` catalogue now carries lifecycle status, and QAuth implements
  none of it.** Enterprise-Managed Authorization (EMA) is listed **STABLE** and
  an OAuth **Client Credentials** extension is listed **DRAFT**. Verified in the
  code on 2026-08-06, QAuth supports **neither**: `helpers/discovery.ts`
  advertises `grant_types_supported` of `authorization_code`,
  `client_credentials`, `refresh_token` and
  `urn:ietf:params:oauth:grant-type:token-exchange` — there is no
  `urn:ietf:params:oauth:grant-type:jwt-bearer`; there is no ID-JAG
  (identity-assertion JWT authorization grant) handling anywhere; no
  `authorization_grant_profiles_supported` member exists in either metadata
  document; and `token_endpoint_auth_methods_supported` is
  `['client_secret_basic', 'client_secret_post', 'none']` with **no**
  `private_key_jwt` (`helpers/client-auth.ts` implements only the two
  shared-secret methods plus public clients — the `private_key_jwt` value
  present in the DB enum and the client schemas is not a working token-endpoint
  authentication method). Token exchange is hard-gated to OAuth access tokens:
  `routes/oauth/token.ts` rejects any `subject_token_type` /
  `requested_token_type` / `actor_token_type` other than
  `urn:ietf:params:oauth:token-type:access_token`, so an assertion grant could
  not be smuggled through the existing surface even by accident. → This is **new
  scope, not regression.** Tracked as **#383** (accept ID-JAG assertions at
  `/oauth/token` for EMA) and **#384** (`private_key_jwt` token-endpoint
  authentication), both filed 2026-08-06 and open.
- **The stateless protocol core (SEP-2567, SEP-2575) is transport-level and does
  not bind the AS.** The release removes sessions and `Mcp-Session-Id`, drops
  the `initialize` / `notifications/initialized` handshake in favour of
  per-request `_meta`, and removes SSE resumability. None of that is
  authorization surface, so nothing in QAuth changes. It is worth recording as
  _favourable_: authorization is now unambiguously per-request with no session
  for a token to be bound to, which is precisely the model QAuth issues for —
  self-contained, audience-bound tokens validated on every call by `mcp-guard`
  with no server-side conversation state.

### Underlying spec drift

- **OAuth 2.1 is at `draft-ietf-oauth-v2-1-15`** and is still not an RFC. The
  published MCP 2026-07-28 specification cites `-13` (Standards Compliance,
  Access Token Usage) and `-14` (Refresh Tokens). QAuth's "OAuth 2.1"
  positioning is accurate but the base is still moving.
- **CIMD is at `draft-ietf-oauth-client-id-metadata-document-02`** (6 July 2026);
  QAuth and the MCP 2026-07-28 specification both still cite `-00`. QAuth's own
  `-00` citations live in the header comment of
  `apps/auth-server/src/app/helpers/cimd.ts` and beside the
  `client_id_metadata_document_supported` advertisement in
  `helpers/discovery.ts`. No interop break — but note that `-01` added SSRF
  hardening and required HTTP 200, and `-02` clarified that URL comparison is
  simple string comparison without default-port normalisation.
  **QAuth's implementation already satisfies all of these** (DNS-pinned IP
  validation, no redirect following, https-only, size bounds, non-200 rejection,
  byte-for-byte `client_id` match) — re-verified 2026-08-06. The citation lags
  the code, not the reverse.

### Process note

This refresh, the ADR-004 refresh, and the #274 PQC draft re-pin are the same
failure mode: QAuth's implementation is repeatedly _more_ current than its own
spec citations. The decaying artefacts are the pin constants and ADR
spec-tracking sections, not the code. A standing quarterly re-pin pass would
catch this earlier than an ad-hoc audit does.

**Addendum 2026-08-06.** The re-review found the same failure mode running in
the other direction, which is worse: the 2026-07-19 pass asserted three
implementation gaps (#282, #284, `offline_access` filtering) that were closed
soon afterwards, and the ADR kept advertising them as open for two weeks. A
stale "we don't do X" is more damaging than a stale citation — it invites
duplicate issues and misstates compliance to anyone reading the ADR as status.
Reviewing against a release _candidate_ compounded it. Two rules follow: pin
spec reviews to published revisions only, and re-verify every status claim
against the code at the moment of writing rather than carrying it forward.

## Related

- [ADR-002: Identifier Abstraction](./002-identifier-abstraction.md) — IMPLEMENTED (Epic #224); was the Phase 4 gate, now cleared
- [ADR-003: CredentialProvider Abstraction](./003-credential-provider-interface.md) — implemented (PR #227)
- [ADR-004: Wallet-Agnostic VC Federation](./004-wallet-agnostic-federation.md) — active (T4); OID4VP base profile complete (#233–#240), browser wallet sign-in works end to end behind `WALLET_FEDERATION_ENABLED` (default off)
- [ADR-005: Post-Quantum Hybrid Signing](./005-pqc-hybrid-signing.md) — active (T4); hybrid issuance merged and wired into the live routes (#275), default off via `HYBRID_SIGNING_ENABLED`
- [ADR-006: OAuth Grants and Audience](./006-oauth-grants-and-audience.md) — the foundation this builds on
- PR #156 — `integration/oauth-mcp-stack`; PR #159 — public-client `authorization_code`
- [MCP Authorization specification (2026-07-28 — current)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) · [client registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration) · [changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog) · [release announcement](https://blog.modelcontextprotocol.io/posts/2026-07-28/) · [auth extensions (ext-auth)](https://github.com/modelcontextprotocol/ext-auth)
- [MCP Authorization specification (2025-11-25 — superseded)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) — the revision the 2025-11-25 review above targets
- [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8707 — Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707) · [RFC 7591 — Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591) · [RFC 8414 — Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414) · [OAuth Client ID Metadata Documents — CIMD `draft-00` (the revision QAuth and MCP cite)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00) · [`draft-02` (current, 6 July 2026)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) · [RFC 7009 — Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
