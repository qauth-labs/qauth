# ADR-011: Enterprise-Managed Authorization — Consuming and Minting ID-JAG

**Status:** Proposed
**Date:** 2026-08-06
**Authors:** QAuth Team

> **Proposed 2026-08-06.** Implementing code lands in the same pass (#383, #384),
> but the maintainer has **not** accepted this ADR. Every fork below takes the
> **fail-closed** option: the feature is inert until an operator opts in, an empty
> trust allowlist rejects everything, and no trust edge is ever derived from
> request content. Nothing here changes the behaviour of a default deployment.

## Context

### What EMA is

**Enterprise-Managed Authorization (EMA)** is the first — and currently the only —
extension marked **STABLE** in the MCP [`ext-auth`](https://github.com/modelcontextprotocol/ext-auth)
catalogue (the OAuth Client Credentials extension beside it is **DRAFT**). It
specifies how an MCP client obtains an access token for an MCP server by way of
the enterprise identity provider the resource authorization server already trusts
for single sign-on, using OAuth 2.0 Token Exchange ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693))
and the JWT authorization grant ([RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523)).
The wire format is the **Identity Assertion JWT Authorization Grant (ID-JAG)**,
specified in [`draft-ietf-oauth-identity-assertion-authz-grant`](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant),
pinned at `-04` (verified 2026-08-06; that revision expires **2026-11-22**).
"Currently" was the original wording and could not be falsified — see
[`docs/spec-pin-log.md`](../spec-pin-log.md), which now carries the row and the
expiry date, and whose freshness check fails the build once the re-check is
overdue.

It is a **three-party** flow. The parties are distinct roles, not distinct
products:

```
  ┌─────────────────┐                          ┌──────────────────────┐
  │  Enterprise IdP │                          │  Resource AS         │
  │  (mints ID-JAG) │                          │  (consumes ID-JAG,   │
  └────────┬────────┘                          │   issues the token)  │
           │                                   └──────────┬───────────┘
   1. SSO  │  2. RFC 8693 token exchange                  │
           │     requested_token_type=…:token-type:id-jag │
           │     audience = Resource AS issuer id         │
           ▼                                              │
  ┌─────────────────────────────────────────────┐         │
  │                 MCP Client                  │─────────┘
  └─────────────────────────────────────────────┘  3. RFC 7523 jwt-bearer
                        │                             assertion = ID-JAG
                        ▼                          → access token, aud-restricted
                 ┌─────────────┐                     to the `resource` claim
                 │ MCP Server  │
                 └─────────────┘
```

1. **Single sign-on.** The user authenticates at the enterprise IdP (OIDC or
   SAML) and the client holds an identity assertion.
2. **Token exchange.** The client exchanges that assertion at the **IdP's** token
   endpoint for an ID-JAG: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
   `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`, `audience` =
   the Resource AS's issuer identifier, optional `resource` = the MCP server's
   resource identifier per [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728).
3. **JWT bearer grant.** The client presents the ID-JAG to the **Resource AS**:
   `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion=<ID-JAG>`.
   The Resource AS validates it and issues an access token **audience-restricted
   to the MCP server named by the assertion's `resource` claim**.

Support is advertised by including `urn:ietf:params:oauth:grant-profile:id-jag`
in the authorization-server metadata member `authorization_grant_profiles_supported`.

### Why this matters for QAuth

QAuth's near-term identity is the OAuth 2.1 authorization server for MCP servers
and AI agents ([ADR-007](./007-mcp-first-positioning.md)). EMA is the **enterprise
on-ramp** for exactly that positioning. Without it, every user of every MCP client
must complete a browser authorization per server, per user — workable for an
individual developer, unworkable for an organisation with a thousand employees
and forty internal MCP servers, and unacceptable to a security team that wants a
single place to say _"the engineering group gets read-only access to the source
control server."_ EMA moves that decision into the IdP the enterprise already
runs, and leaves QAuth doing what it is good at: minting audience-bound,
scope-bounded tokens.

The second reason is structural. **QAuth already ships the mint half of this
flow.** RFC 8693 token exchange is live at `/oauth/token` as the agent
on-behalf-of delegation path (ADR-007 §2, epic #181,
`handleTokenExchange` in `apps/auth-server/src/app/routes/oauth/token.ts`), with
a default-deny gate stack — confidential clients only, agent classification,
subject-token-bound-to-the-agent, narrow-never-widen scope and audience, bounded
delegation depth, full audit. Minting an ID-JAG is a different `issued_token_type`
on that same endpoint behind that same gate stack. QAuth is likewise already an
OIDC provider for human identity, which is the other capability the IdP role
needs. Neither half requires a new subsystem.

### Where the code stands today (verified 2026-08-06)

The [ADR-007 delta section](./007-mcp-first-positioning.md#delta-2025-11-25-to-2026-07-28)
records the gap precisely, and it is still accurate:

- `helpers/discovery.ts` advertises `grant_types_supported` of
  `authorization_code`, `client_credentials`, `refresh_token` and
  `urn:ietf:params:oauth:grant-type:token-exchange`. There is **no**
  `urn:ietf:params:oauth:grant-type:jwt-bearer`.
- There is **no** `authorization_grant_profiles_supported` member in either
  metadata document, and no ID-JAG handling anywhere.
- `token_endpoint_auth_methods_supported` is
  `['client_secret_basic', 'client_secret_post', 'none']`.
  `helpers/client-auth.ts` implements only the two shared-secret methods plus
  public clients — the `private_key_jwt` value that exists in the DB enum and the
  client schemas is **not** a working token-endpoint authentication method.
- Token exchange is hard-gated to OAuth access tokens: any `subject_token_type` /
  `requested_token_type` / `actor_token_type` other than
  `urn:ietf:params:oauth:token-type:access_token` is rejected with
  `invalid_request`. An assertion grant cannot be smuggled through the existing
  surface even by accident — which is why adding ID-JAG is **new scope, not a
  regression fix**.

Tracked as **#383** (accept ID-JAG assertions at `/oauth/token`) and **#384**
(`private_key_jwt` token-endpoint authentication), both filed 2026-08-06.

### The question this ADR settles

The ID-JAG draft says what to validate but **deliberately does not say how a
Resource AS decides which issuers it trusts, or how it resolves their signing
keys.** That is left to local policy — and it is the entire security question.
An identity assertion is only as good as the answer to "why do you believe this
issuer?", and getting that answer from the assertion is the classic
self-asserted-escalation failure. This ADR settles the trust model, whether QAuth
implements one role or both, and how the new grant coexists with the RFC 8693
delegation already on the endpoint.

## Decision

Adopt Enterprise-Managed Authorization, **default off**, implementing **both**
roles.

### 1. Implement both sides of EMA

QAuth will:

- **Consume** — accept `urn:ietf:params:oauth:grant-type:jwt-bearer` at
  `/oauth/token`, validate the presented ID-JAG, and issue an access token
  audience-restricted to the MCP server named by the assertion's `resource`
  claim. In this role QAuth is the **Resource Authorization Server**.
- **Mint** — extend the existing RFC 8693 token exchange so that a request
  carrying `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`
  returns an ID-JAG. In this role QAuth is the **enterprise IdP**, minting an
  assertion a third party's authorization server will consume.

**Why both, plainly:** QAuth is already both things. It is an OIDC provider for
human identity (the IdP half needs a subject, a signing key and a token-exchange
endpoint — it has all three) and an OAuth 2.1 authorization server for MCP
servers (the Resource AS half needs client authentication, scope policy and
audience-bound issuance — it has all three). The two halves of EMA fall on
capabilities that already exist and are already gated; implementing only one
would leave a capability on the floor for no security gain, since the risk in
each half is governed by its own switch. An organisation self-hosting QAuth can
therefore use it as the enterprise IdP for third-party MCP servers, as the AS in
front of its own MCP servers, or both.

### 2. Consume — the `jwt-bearer` gate stack

Gates are evaluated in order and **every one of them is a deny**. Unknown,
absent, malformed or unparseable input rejects; there is no lenient branch.

| #   | Gate                  | Rule                                                                                                                                                                                                                                                                                                                           | Failure                  |
| --- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------ |
| 1   | Feature               | `ID_JAG_ENABLED` must be `true`. When false the grant is neither advertised nor accepted.                                                                                                                                                                                                                                      | `unsupported_grant_type` |
| 2   | Client authentication | Confidential clients only (`client_secret_basic`, `client_secret_post`, `private_key_jwt`). The draft says the profile SHOULD be confidential-only; QAuth makes it MUST, matching the token-exchange floor already in place.                                                                                                   | `invalid_client`         |
| 3   | JWT type              | Header `typ` must be exactly `oauth-id-jag+jwt` (RFC 8725 §3.11). Nothing else is an ID-JAG.                                                                                                                                                                                                                                   | `invalid_grant`          |
| 4   | Issuer allowlist      | `iss` must be present and a **byte-exact** member of `ID_JAG_TRUSTED_ISSUERS`. Exact string comparison on the issuer identifier — no normalisation, no trailing-slash tolerance, the same discipline RFC 9207 §2.4 forces on the `iss` authorization-response parameter.                                                       | `invalid_grant`          |
| 5   | No self-issuance      | `iss` must **not** equal QAuth's own issuer identifier. Checked independently of the allowlist, so a misconfigured allowlist containing QAuth's own issuer still cannot close a self-issuance loop. The draft's security considerations forbid an IdP issuing access tokens for an ID-JAG it issued itself in the same domain. | `invalid_grant`          |
| 6   | Key resolution        | OIDC discovery against the **allowlisted issuer only**, then that document's `jwks_uri`. The discovery document's own `issuer` member must equal the allowlisted issuer (OIDC Discovery 1.0 §4.3). Never a URL taken from the assertion; never an unlisted issuer.                                                             | `invalid_grant`          |
| 7   | Signature             | Verified against a key from that JWKS, `kid`-matched, under an **asymmetric-only** algorithm allowlist. `none` and every MAC algorithm are rejected outright.                                                                                                                                                                  | `invalid_grant`          |
| 8   | Audience              | `aud` must equal QAuth's own issuer identifier (RFC 8414 sense).                                                                                                                                                                                                                                                               | `invalid_grant`          |
| 9   | Client binding        | The `client_id` claim must identify the **authenticated** client. Compared timing-safely.                                                                                                                                                                                                                                      | `invalid_grant`          |
| 10  | Freshness             | `exp` and `iat` required; small bounded clock skew; assertion lifetime capped — an assertion whose `exp - iat` exceeds the configured maximum is rejected even if currently unexpired.                                                                                                                                         | `invalid_grant`          |
| 11  | Replay                | `jti` required and recorded until `exp`. A second presentation of the same `(iss, jti)` is rejected.                                                                                                                                                                                                                           | `invalid_grant`          |
| 12  | Resource              | `resource` must be present and must be a resource identifier this deployment serves; the issued access token's `aud` is restricted to it (RFC 8707 §2, RFC 9068). **An assertion with no `resource` is denied** — a token that cannot be audience-restricted is exactly the token EMA exists to avoid.                         | `invalid_target`         |
| 13  | Scope                 | The assertion's `scope` is intersected with the client's server-side allowlist and never widened. Reserved `agent:*` scopes remain subject to the operator-set `max_agent_mode` cap; an over-cap scope rejects the **whole** request rather than being silently reduced.                                                       | `invalid_scope`          |
| 14  | Subject               | The `(iss, sub)` pair must resolve to an existing, enabled local identity. There is **no** just-in-time provisioning in this pass — an unresolvable subject is a deny, not an enrolment.                                                                                                                                       | `invalid_grant`          |
| 15  | Unknown constraints   | An assertion carrying `authorization_details` (RFC 9396) is **rejected**, not ignored. Silently dropping an authorization constraint you do not implement is a downgrade.                                                                                                                                                      | `invalid_grant`          |

**No refresh token is issued** on this path. The client re-presents a fresh
ID-JAG, which keeps the IdP's policy in the loop on every renewal — the point of
the flow. Every accept and every reject is audit-logged (§6).

### 3. Mint — ID-JAG via the existing token-exchange endpoint

Same endpoint, same grant type, same authentication, same default-deny gates as
the delegation path (confidential client, agent classification, token-exchange
grant allowed, subject token cryptographically verified and bound to the
requesting client, subject user present and enabled), plus `ID_JAG_ENABLED`.

The minted assertion carries `typ: oauth-id-jag+jwt` and the draft's required
claims: `iss` (QAuth's issuer identifier), `sub` (the end user), `aud` (the
target Resource AS's issuer identifier, taken from the request's `audience`
parameter), `client_id` (the **authenticated** client — never a self-declared
value), `jti`, `iat`, `exp` (short, minutes), and `scope` where present, with
`resource` copied from the request's `resource` parameter when supplied. It is
signed with QAuth's normal signing key, so [ADR-001](./001-jwt-key-management.md)
key management and [ADR-005](./005-pqc-hybrid-signing.md) crypto-agility apply
unchanged.

Per RFC 8693 §2.2.1 the response carries the assertion in `access_token`,
`issued_token_type: urn:ietf:params:oauth:token-type:id-jag`, and
`token_type: N_A` — an ID-JAG is not usable as an access token and must not be
labelled `Bearer`.

**A minted ID-JAG must never be accepted as a QAuth access token.** The `typ`
header differs, the access-token use marker is absent, and `aud` names a foreign
issuer; `verifyAccessToken` must reject it on all three counts. This is a
cross-path confusion risk created by minting, and it is closed by test, not by
assumption.

### 4. Trust model — an operator-configured issuer allowlist

Two new settings, mirroring the existing `CIMD_*` block in
`libs/server/config/src/lib/schemas/auth.ts`:

| Setting                  | Type                       | Default     | Meaning                                                                                                                                                     |
| ------------------------ | -------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ID_JAG_ENABLED`         | boolean                    | **`false`** | Master switch for both halves. When false, `jwt-bearer` is not advertised and not accepted, and `requested_token_type=…:id-jag` is rejected as it is today. |
| `ID_JAG_TRUSTED_ISSUERS` | comma/space-separated list | **empty**   | Trusted enterprise IdP **issuer identifiers**. The complete set of issuers whose assertions may be consumed.                                                |

The rules that make this a trust model rather than a list:

- **Signing keys are resolved by running OIDC discovery against an allowlisted
  issuer, and only against an allowlisted issuer**, then fetching that document's
  `jwks_uri`. Never against an issuer that is not on the list, and **never from
  any URL supplied in the assertion itself.**
- **An empty allowlist rejects every ID-JAG.** Not "accepts any", not "accepts
  none but logs a warning and continues" — rejects. The feature is inert until an
  operator explicitly opts in, exactly as `WALLET_FEDERATION_ENABLED` (ADR-004)
  and `max_agent_mode` (ADR-007 §2) are inert until provisioned.
- **Trust is never self-asserted by a client and never derived from assertion
  content.** The draft's own security considerations point the same way: when an
  ID-JAG carries a `sub_id` claim, the Resource AS MUST NOT use `sub_id.issuer`
  to establish trust in the ID-JAG issuer. QAuth generalises that to every field
  of the assertion.
- **Discovery and JWKS advertisement track actual capability.** The
  `jwt-bearer` entry in `grant_types_supported` and the
  `urn:ietf:params:oauth:grant-profile:id-jag` entry in
  `authorization_grant_profiles_supported` appear **only** when `ID_JAG_ENABLED`
  is true **and** the allowlist is non-empty. ADR-007 already established that an
  advertisement must not be able to drift from the behaviour it describes.
- **Every outbound fetch uses the CIMD SSRF-guard pattern** —
  `apps/auth-server/src/app/helpers/ssrf-safe-fetch.ts`: https-only, no
  credentials in the URL, DNS-pinned TOCTOU-safe IP validation, **no redirect
  following**, response size and time bounds, non-200 rejection, and a bounded
  cache with a TTL ceiling mirroring `CIMD_CACHE_MAX_TTL`.

### 5. Why an allowlist, and not the alternatives

Three designs were available. The choice is the same one QAuth has made every
previous time an escalation boundary appeared.

**(a) Open discovery — trust whatever `iss` says and resolve keys from it.**
Rejected. This makes `iss` an attacker-controlled trust primitive: anyone able to
host an OIDC discovery document becomes an identity source for your authorization
server, and the fetch itself becomes an SSRF surface driven by request content.
It is the same failure mode as an `is_agent` flag that grants agent privilege on
its own word.

**(b) Per-client trust stored in the database — a client row names its trusted
IdP.** Rejected, and more subtly wrong than it looks. Client rows are created by
client-controlled paths: RFC 7591 dynamic registration and CIMD documents. A
trust edge created by the party being trusted is not a trust edge. It would also
place an escalation boundary in a table reachable from a self-registration
request — precisely what ADR-007 §2 refused for `max_agent_mode` (absent from the
DCR schemas entirely) and ADR-008 §4 refused for `environment` (not accepted from
DCR or a CIMD document).

**(c) Operator configuration allowlist.** Chosen. Config is operator-owned by
construction, unreachable from any request path, reviewable in a deployment
manifest, and inert until deliberately set. It is the same shape as
`CIMD_TRUST_POLICY=allowlist` + `CIMD_TRUSTED_DOMAINS`, and it composes with the
existing controls rather than introducing a second, competing notion of trust.

The general rule this ADR reaffirms: **an escalation boundary must be
operator-set, never self-asserted.** Accepting an identity assertion from a new
issuer is an escalation — it adds a party that can name users of your system.

### 6. Relationship to the existing RFC 8693 delegation work

Both features live on `/oauth/token` under
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, so the difference
must be unambiguous at the wire level.

**Disambiguation is `requested_token_type`, and nothing else:**

| `requested_token_type`                                     | Branch                                           | Behaviour                                                                     |
| ---------------------------------------------------------- | ------------------------------------------------ | ----------------------------------------------------------------------------- |
| absent, or `urn:ietf:params:oauth:token-type:access_token` | **Delegation** (existing, unchanged)             | Issues a delegated access token: `sub` stays the user, `act` names the agent. |
| `urn:ietf:params:oauth:token-type:id-jag`                  | **ID-JAG mint** (new, gated by `ID_JAG_ENABLED`) | Issues an ID-JAG for a third-party Resource AS.                               |
| anything else                                              | —                                                | `invalid_request`, exactly as today.                                          |

How the two differ, beyond the output format:

|                         | Delegation (ADR-007 §2)                                              | ID-JAG mint (this ADR)                                                                                                       |
| ----------------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| QAuth's role            | Authorization server for its own resources                           | **Enterprise IdP** for someone else's AS                                                                                     |
| Output                  | Access token, `token_type: Bearer`                                   | Assertion, `token_type: N_A`                                                                                                 |
| Consumer                | A QAuth-protected resource server                                    | A **third-party** authorization server                                                                                       |
| `audience` / `resource` | Must fall **within** the subject token's `aud` — narrow, never widen | `audience` is **required** and is a foreign AS's issuer identifier, which is by definition outside the subject token's `aud` |
| Identity semantics      | `sub` = user, `act` = agent                                          | `sub` = user, `client_id` = the client that will present it                                                                  |

The fourth row is the load-bearing one. The delegation path's central invariant —
audience may only be narrowed relative to the subject token — **cannot apply** to
minting, because the whole point is to name an authorization server QAuth does
not serve. The mint branch therefore must not fall through to the delegation
audience check, and must instead be bounded by its own gates: the feature flag,
confidential-client authentication, the token-exchange grant on the client, the
subject token being bound to the requesting client, and a short lifetime with no
refresh. Sharing an endpoint must not be allowed to become sharing a code path.

### 7. `private_key_jwt` (#384) — additive, no flag

`private_key_jwt` (RFC 7523 §2.2, OIDC Core 1.0 §9;
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`)
ships alongside EMA because EMA needs it: the extension notes that clients may
authenticate with `private_key_jwt` when not pre-registered, leveraging their
Client ID Metadata Document — and a CIMD-registered client has no shared secret
to present at the token endpoint.

**It gets no feature flag.** It is additive and opt-in per client via
`token_endpoint_auth_method`, and it closes a value that already exists in the DB
enum and the client schemas but has never been a working method.

**It must not change behaviour for any existing client.** A client registered
with `client_secret_basic` continues to authenticate exactly as before. The one
direction that does change only ever tightens: a client whose
`token_endpoint_auth_method` is `private_key_jwt` **must not** be authenticable
with a shared secret. There is no fallback and no "either will do" — an
authentication method is a requirement, not a hint.

Assertion validation follows the same shape as the ID-JAG stack: `iss` and `sub`
both equal to the `client_id`, `aud` the token endpoint URL or QAuth's issuer
identifier, bounded `exp`, required and replay-tracked `jti`, asymmetric-only
algorithms, keys taken from the client's registered `jwks` / `jwks_uri` — the
latter fetched through the same SSRF-guarded path.

### 8. Audit

Every accept and every reject on both paths is written through
`fastify.repositories.auditLogs.create`, matching the shape already used
throughout `token.ts` (`userId`, `oauthClientId`, `event`, `eventType: 'token'`,
`success`, `ipAddress`, `userAgent`, `metadata`). The `metadata` records the
reason, the asserted issuer, the `jti` and the target `resource` — **never the
assertion itself, never a key, never a secret**. A rejected assertion from an
unknown issuer is exactly the event a security team needs to see, so the reject
path is audited at least as carefully as the accept path.

## Consequences

### Positive

- **The enterprise on-ramp exists.** An organisation with an IdP can grant its
  users access to QAuth-fronted MCP servers under central policy, with no
  per-user, per-server browser consent. This is the single largest adoption
  blocker EMA removes, and it lands on QAuth's stated positioning rather than
  beside it.
- **The mint half is a branch, not a subsystem.** It reuses the token-exchange
  endpoint, its client authentication, its default-deny gates, its audit and its
  signing keys.
- **EMA is the only STABLE `ext-auth` extension.** Implementing it is the highest
  value-per-unit-risk conformance move available in that catalogue, and it closes
  the one substantive gap the ADR-007 delta review found.
- **`private_key_jwt` unlocks secret-less confidential clients**, which is what
  CIMD-registered clients need and what key rotation wants, while closing an
  enum value that has been advertised in the schema but absent in behaviour.
- To our knowledge no other open-source, self-hostable authorization server
  implements **both** EMA roles. The claim is hedged deliberately; the value does
  not depend on it.

### Negative

- **`/oauth/token` acquires an outbound network dependency, on its hot path.**
  Consuming an ID-JAG requires reaching each allowlisted IdP's discovery and JWKS
  endpoints. This is a change in kind: CIMD fetches happen on authorize and
  register, never during token issuance. The failure modes are real — an IdP
  outage fails token requests for that issuer; a slow IdP adds token-endpoint
  latency and can exhaust connections; JWKS rotation trades cache staleness
  against re-fetch storms; and an IdP domain that is compromised or expires and
  is re-registered becomes a valid identity source until an operator removes it.
  Mitigations (SSRF-guarded fetch, bounded cache with a TTL ceiling, per-fetch
  timeout, negative caching, and the allowlist bounding which hosts can ever be
  dialled) reduce this but do not remove it.
- **Minting makes QAuth a credential source for third parties — a genuinely
  larger blast radius than issuing its own tokens.** Every other token QAuth
  signs is only meaningful to resource servers that validate `aud` against
  QAuth's issuer; the damage from a mistake stays inside the deployment. A minted
  ID-JAG is designed to be accepted by an authorization server QAuth does not
  operate, cannot revoke against, and cannot observe. A signing-key compromise or
  a scope bug therefore spills outside the deployment's own trust domain. The
  controls are short lifetimes, no refresh, a single pinned `aud`,
  confidential-client-only issuance, full audit, and default-off — and the
  residual risk is accepted knowingly rather than argued away.
- **Maintaining the allowlist is real operational burden.** Onboarding an IdP is
  a configuration change, not an API call. Removing an issuer immediately
  invalidates every in-flight assertion from it (intended, and worth documenting
  as such). Wrong-but-plausible entries — a trailing slash, `http` versus
  `https`, a tenant-scoped issuer URL — all fail closed, which is correct but
  opaque, so rejection diagnostics must name the reason precisely enough to be
  actionable without leaking assertion contents.
- **Three JWT shapes now circulate** — access token, ID token, ID-JAG — and a
  verifier that accepts the wrong one is a privilege bug. Mitigated by the `typ`
  header check, the existing access-token use marker, and explicit negative tests
  in both directions.
- **More branches on the most branch-heavy route in the codebase.** `/oauth/token`
  already carries four grants; this adds a fifth plus a second `issued_token_type`
  on an existing one.

### Neutral

- **Default off means no behaviour change.** `ID_JAG_ENABLED=false` with an empty
  allowlist is the shipped default; the grant is not advertised and not accepted,
  and existing clients are untouched. Same posture as `WALLET_FEDERATION_ENABLED`
  and `HYBRID_SIGNING_ENABLED`.
- **`private_key_jwt` is additive and per-client** — no flag, no dimension, no
  change for any client that does not select it.
- **Nothing here is QAuth-proprietary.** Every wire artefact is an IETF
  construct; a client written against the draft and the MCP extension interoperates.
- **The base specification is still moving.** The MCP extension is STABLE but
  `draft-ietf-oauth-identity-assertion-authz-grant` is an Internet-Draft at
  `-04`, which expires **2026-11-22**. Per the ADR-007 process note, the
  implementation must pin the revision it targets in code and be re-reviewed on
  a schedule rather than ad hoc — and the citation must be re-verified against
  the code at the moment of writing, not carried forward. That schedule is now
  kept in [`docs/spec-pin-log.md`](../spec-pin-log.md), whose freshness check
  fails the build once this row's re-check date passes. This ADR is **Proposed**
  with merged code, so it re-verifies its own rows before moving to Accepted.

## Explicitly out of scope

Recorded so a future reader does not re-open these as gaps:

- **SAML assertions as the subject token** on the mint path
  (`urn:ietf:params:oauth:token-type:saml2` and the `sub_id` SAML `NameID`
  handling in the draft). QAuth has no SAML stack. The subject token on the mint
  path remains a QAuth-issued access token.
- **Cross-IdP federation / issuer chaining.** QAuth will not treat an inbound
  ID-JAG as evidence about a further upstream issuer. An `act` claim on an
  inbound assertion may be recorded for audit; it grants nothing.
- **Just-in-time user provisioning** from an ID-JAG subject. An unresolvable
  `(iss, sub)` is a deny. Enrolment is a separate decision with its own account
  linking questions (see [ADR-009](./009-wallet-account-resolution.md) for why
  that is not a small question).
- **`authorization_details` (RFC 9396).** Rejected on presence, not honoured and
  not ignored.
- **Revocation or introspection of a minted ID-JAG.** No such surface ships in
  this pass; the short lifetime is the only control.
- **Trust-on-first-use, or any dynamic issuer discovery.** The allowlist is the
  whole trust model.

## Implementation sequencing (issues derived separately; not part of this ADR)

1. Config: `ID_JAG_ENABLED` and `ID_JAG_TRUSTED_ISSUERS` in the auth env schema,
   mirroring the `CIMD_*` block.
2. Issuer key resolver: OIDC discovery + JWKS over `ssrfSafeFetch`, bounded
   cache, allowlist-only resolution.
3. Consume: the `jwt-bearer` branch on `/oauth/token`, the `jti` replay store,
   and audit on both outcomes (#383).
4. Mint: the `requested_token_type=…:id-jag` branch in `handleTokenExchange`,
   plus the negative tests that a minted ID-JAG never verifies as an access token.
5. Discovery: `grant_types_supported` and `authorization_grant_profiles_supported`
   conditional on the flag **and** a non-empty allowlist.
6. `private_key_jwt` in `helpers/client-auth.ts` and
   `token_endpoint_auth_methods_supported` (#384).
7. Documentation: an EMA section in [`docs/agent-authorization.md`](../agent-authorization.md)
   and the operator-facing allowlist guidance.

## Related

- [ADR-007: MCP-First Positioning](./007-mcp-first-positioning.md) — the
  positioning this serves; §2 is the RFC 8693 delegation work the mint half
  extends, and the 2026-07-28 delta section is where the EMA gap was recorded
  as #383 / #384.
- [ADR-006: OAuth Grants and Audience](./006-oauth-grants-and-audience.md) — the
  audience-binding foundation the issued token relies on.
- [ADR-008: Environment-Aware Authorization Posture](./008-environment-aware-authorization.md) —
  the operator-set-never-self-asserted precedent, reused here for issuer trust.
- [ADR-001: JWT Key Management](./001-jwt-key-management.md) ·
  [ADR-005: Post-Quantum Hybrid Signing](./005-pqc-hybrid-signing.md) — the keys
  a minted ID-JAG is signed with.
- [`docs/agent-authorization.md`](../agent-authorization.md) — the existing
  agent-native layer, including the token-exchange gate stack.
- Issues **#383** (accept ID-JAG assertions at `/oauth/token`) and **#384**
  (`private_key_jwt` token-endpoint authentication).
- [MCP Enterprise-Managed Authorization (`ext-auth`, STABLE)](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx) ·
  [`ext-auth` extension catalogue](https://github.com/modelcontextprotocol/ext-auth)
- [Identity Assertion Authorization Grant — `draft-ietf-oauth-identity-assertion-authz-grant`](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant)
  (ID-JAG; `-04` at the time of writing)
- [RFC 7521 — Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7521)
- [RFC 7523 — JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523)
  (`jwt-bearer` grant §2.1; `private_key_jwt` client assertion §2.2)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
  (`issued_token_type` and `token_type: N_A`, §2.2.1)
- [RFC 8707 — Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)
- [RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)
- [RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414) ·
  [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728) ·
  [RFC 8725 — JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725) ·
  [RFC 9396 — OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396) ·
  [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700)
