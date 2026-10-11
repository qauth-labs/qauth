# ADR-011: Enterprise-Managed Authorization — Consuming and Minting ID-JAG

**Status:** Accepted
**Date:** 2026-08-06
**Authors:** QAuth Team

> **Proposed 2026-08-06, accepted 2026-10-11.** The code for this record landed on
> 2026-08-06 (#383, #384). Every fork below takes the
> **fail-closed** option: the feature is inert until an operator opts in, an empty
> trust allowlist rejects everything, and no trust edge is ever derived from
> request content. Nothing here changes the behaviour of a default deployment.
>
> **Reviewed against the code on 2026-10-11.** Every claim below was compared with
> `id-jag.ts`, `id-jag-issuer-keys.ts`, `token.ts`, `discovery.ts` and the config
> schema. Where the code is stricter or different, the text now says what the code
> does. Three claims were not true of the code. They were fixed before acceptance, and
> [Review findings](#review-findings-2026-10-11) lists them.

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
records the gap precisely. The list below was accurate on 2026-08-06, **before**
#383 and #384 merged. Both gaps are closed in code now:

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

| #   | Gate                  | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Failure                                                      |
| --- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------ |
| 1   | Feature               | `ID_JAG_ENABLED` must be `true`. When false the grant is neither advertised nor accepted.                                                                                                                                                                                                                                                                                                                                                              | `unsupported_grant_type`                                     |
| 2   | Client authentication | Confidential clients only (`client_secret_basic`, `client_secret_post`, `private_key_jwt`). The draft says the profile SHOULD be confidential-only; QAuth makes it MUST, matching the token-exchange floor already in place.                                                                                                                                                                                                                           | `invalid_client`                                             |
| 2a  | Grant registration    | The client must list `urn:ietf:params:oauth:grant-type:jwt-bearer` among its registered grant types. Neither dynamic registration nor the developer API can add it. An operator provisions it through the seed manifest.                                                                                                                                                                                                                               | `unauthorized_client`                                        |
| 3   | JWT type              | Header `typ` must be exactly `oauth-id-jag+jwt` (RFC 8725 §3.11). Nothing else is an ID-JAG. The check runs on the unverified header first, then again on the verified one.                                                                                                                                                                                                                                                                            | `invalid_grant`                                              |
| 4   | Issuer allowlist      | `iss` must be present and a member of `ID_JAG_TRUSTED_ISSUERS` after one canonicalisation: a single trailing `/` is removed from both sides. Nothing else is normalised: no case folding, no default-port removal, no percent-decoding. This is the rule QAuth applies to its own issuer (`resolveIssuerIdentifier`). It keeps issuers that end in a slash, such as Auth0's, working.                                                                  | `invalid_grant`                                              |
| 5   | No self-issuance      | `iss` must **not** equal QAuth's own issuer identifier. Checked independently of the allowlist, so a misconfigured allowlist containing QAuth's own issuer still cannot close a self-issuance loop. The draft's security considerations forbid an IdP issuing access tokens for an ID-JAG it issued itself in the same domain. Implemented in `validateIdJagAssertion`, before the allowlist and before any key lookup, and mirrored on the mint path. | `invalid_grant`                                              |
| 6   | Key resolution        | OIDC discovery against the **allowlisted issuer only**, then that document's `jwks_uri`, which must be `https`. The discovery document's own `issuer` member must equal the allowlisted issuer (OIDC Discovery 1.0 §4.3). Never a URL taken from the assertion; never an unlisted issuer.                                                                                                                                                              | `invalid_grant`                                              |
| 7   | Signature             | Verified against a key from that JWKS under an **asymmetric-only** algorithm allowlist. With a `kid`, exactly one key must carry it. Without a `kid`, the set must hold exactly one key. `none` and every MAC algorithm are rejected outright. A published key that carries private members is refused.                                                                                                                                                | `invalid_grant`                                              |
| 8   | Audience              | `aud` must equal QAuth's own issuer identifier (RFC 8414 sense) and must be the only audience. A multi-valued `aud` is rejected (draft §4.4.1).                                                                                                                                                                                                                                                                                                        | `invalid_grant`                                              |
| 9   | Client binding        | The `client_id` claim must identify the **authenticated** client. A `client_id` is a public identifier, so a plain comparison is enough. The check runs before the `jti` is burned. Otherwise a client holding another client's assertion could destroy it.                                                                                                                                                                                            | `invalid_grant`                                              |
| 10  | Freshness             | `exp` and `iat` required; small bounded clock skew; assertion lifetime capped — an assertion whose `exp - iat` exceeds the configured maximum is rejected even if currently unexpired. An `iat` in the future beyond the skew is rejected.                                                                                                                                                                                                             | `invalid_grant`                                              |
| 11  | Replay                | `jti` required. It is recorded for `ID_JAG_MAX_ASSERTION_LIFETIME` plus the skew leeway. A second presentation of the same `(iss, jti)` is rejected. If the replay store is unavailable, the assertion is rejected.                                                                                                                                                                                                                                    | `invalid_grant`                                              |
| 12  | Resource              | `resource` must be present and must appear in the client's `audience` allowlist (`oauth_clients.audience`). An empty allowlist denies. The issued access token's `aud` is restricted to it (RFC 8707 §2, RFC 9068). A `resource` request parameter may only agree with the claim. **An assertion with no `resource` is denied** — a token that cannot be audience-restricted is exactly the token EMA exists to avoid.                                 | `invalid_target` (`invalid_grant` when the claim is missing) |
| 13  | Scope                 | The assertion's `scope` is intersected with the client's server-side allowlist and never widened. A `scope` request parameter may only narrow it. Reserved `agent:*` scopes remain subject to the operator-set `max_agent_mode` cap; an over-cap scope rejects the **whole** request rather than being silently reduced.                                                                                                                               | `invalid_scope`                                              |
| 14  | Subject               | The `(iss, sub)` pair must match a `user_credentials` row in the realm with provider type `oidc_<issuer>` and `external_sub` equal to `sub`, and that user must be enabled. Email is never used to find or link a user. There is **no** just-in-time provisioning in this pass — an unresolvable subject is a deny, not an enrolment.                                                                                                                  | `invalid_grant`                                              |
| 15  | Unknown constraints   | An assertion carrying `authorization_details` (RFC 9396) is **rejected**, not ignored. Silently dropping an authorization constraint you do not implement is a downgrade.                                                                                                                                                                                                                                                                              | `invalid_grant`                                              |

**Order matters in one place.** The `jti` is burned only after every check that has no
side effect: gates 3 to 10 and 15. Gates 12 to 14 run after the burn. A request that
fails them has spent its assertion, and the client must get a fresh one from the IdP.

**No code creates the link behind gate 14.** The `oidc_<issuer>` credential row must be
inserted by an operator. No endpoint, command or seed script does it today. Until one
exists, the consume side cannot succeed in a real deployment.

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

In code `resource` is required, not optional. A request needs exactly one `audience`
and exactly one `resource`.

**Targets are bounded by an operator allowlist.** Both values must appear in the
client's `audience` column (`oauth_clients.audience`). An empty column denies. This is
the administrator-defined policy of EMA §4.1, in the form QAuth already has. The
`audience` must also differ from QAuth's own issuer. That is gate 5 on the mint side.

**The Authority Tree closes this path for agent types.** [ADR-014](./014-agent-authority-tree.md)
decides that, with `AUTHORITY_TREE_ENABLED` on, an agent type is refused at the exchange
GATE 2 when it asks for an ID-JAG ([ADR-015](./015-agent-tree-hardening.md), question 3).
That flag is not in the code yet. Until it ships, any agent client with the
token-exchange grant and a target allowlist can mint.

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
  following**, response size and time bounds, non-200 rejection, and a bounded Redis cache (`ID_JAG_JWKS_CACHE_TTL`, default 5 minutes). Unlike
  `CIMD_CACHE_MAX_TTL`, that TTL has no hard ceiling yet.
- **One escape hatch exists.** `ID_JAG_ALLOW_PRIVATE_ADDRESSES` (default `false`) turns the
  address check off so tests can use a localhost IdP. The config schema does not stop it
  being set in production. The operator guide says to leave it off.

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
confidential-client authentication, the token-exchange grant on the client, the subject token being bound to the requesting client, the per-client target allowlist,
and a short lifetime with no refresh. Sharing an endpoint must not be allowed to become sharing a code path.

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
  Mitigations in the code today: SSRF-guarded fetch, a bounded cache, a per-fetch timeout,
  and the allowlist that bounds which hosts can ever be dialled. Negative caching, a
  refresh cooldown and a hard TTL ceiling are not implemented. They reduce the risk but
  would not remove it.
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
- **A `kid` miss costs the issuer two fetches, and nothing limits how often.** A miss
  forces one cache refresh: discovery and JWKS. The bound is one refresh per request, not
  per minute. A client that holds the grant can send assertions with a valid `iss` and
  random `kid` values. Only the endpoint's rate limit slows it. A per-issuer refresh
  cooldown would close this.
- **Mint targets and consume resources share a column with `client_credentials`.** All
  three read `oauth_clients.audience`. An operator who lists a foreign authorization
  server there also lets the client request QAuth access tokens that name it. The `typ`
  header keeps those from being accepted as ID-JAGs. The coupling is still unintended. A
  dedicated column would remove it.
- **The consume side needs a link that nothing creates.** See gate 14.
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
  fails the build once this row's re-check date passes. This ADR re-verified its own rows on 2026-10-11, before moving to Accepted: `-04` is still the newest revision and the `ext-auth` EMA file is unchanged since `e5eef54`.

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

## Review findings (2026-10-11)

This review compared each claim with the code on `main` (f126821) and with ADR-014 to
ADR-020 as accepted on 2026-10-11.

### Closed before acceptance

1. **Gate 5 had no implementation.** `validateIdJagAssertion` never compared `iss` with
   QAuth's own issuer, and the mint path did not refuse an own-issuer `audience`. Both
   needed a misconfiguration to matter: the own issuer in `ID_JAG_TRUSTED_ISSUERS` and in a
   client's `audience`. With both set, a client could mint an assertion for QAuth and redeem
   it, which skips the narrow-never-widen audience rule of the delegation path. Now the
   consume side refuses it as `self_issued` before the allowlist and before any fetch. The
   mint side refuses it as `invalid_target`. Both spellings of the issuer (with and without a
   trailing slash) are covered, and so is an assertion this server minted for itself.
2. **Discovery advertised on the flag alone.** §4 asks for the flag **and** a non-empty
   allowlist. `well-known.ts` now passes both conditions to the metadata builder. Both
   discovery documents are tested in the enabled-but-empty state.
3. **No test proved a minted ID-JAG fails as an access token.** §3 said this was "closed by
   test". Now a test registers the real JWT plugin, mints an ID-JAG, and shows that
   `verifyAccessToken` refuses it on `typ`. It runs with the `typ` rollout switch on and
   off, and with the optional issuer and audience checks both used and unused, so none of
   them can be what saves it.

Each new test was checked to fail when its fix is removed.

### Accepted for now, to be tracked as follow-ups

- A refresh cooldown, a negative cache and a hard TTL ceiling for the issuer key resolver.
- A dedicated target column instead of reusing `oauth_clients.audience`.
- An operator way to link `(iss, sub)` to a user. Without it the consume side cannot be
  used in a real deployment.
- `ID_JAG_ALLOW_PRIVATE_ADDRESSES` refused when the environment profile is `production`
  ([ADR-008](./008-environment-aware-authorization.md)).
- §7 accepts the token endpoint URL or the issuer as `aud` of a client assertion.
  [ADR-017](./017-first-party-login.md) requires the issuer alone for first-party and agent
  clients. That is the direction of `rfc7523bis`. Whether every client moves is open.

### The draft dependency

This record rests on `draft-ietf-oauth-identity-assertion-authz-grant-04`. The OAuth
working group adopted the draft, and it is still an Internet-Draft. On 2026-10-11 the
newest revision in the IETF archive was `-04`, dated 21 May 2026. No `-05` existed.
`-04` expires on 2026-11-22.

Acceptance covers the trust model and the gates. The wire constants follow the draft: the
`typ` value, the claim names, the token-type URN and the profile URN. They are pinned in
`id-jag.ts` and in [`docs/spec-pin-log.md`](../spec-pin-log.md). If a later revision
changes one of them, the matching section is amended. The record is not superseded.

### Checked and sound

- The allowlist is consulted before any network call. Keys come only from the allowlisted
  issuer's own discovery. The discovery `issuer` must match. A published key with private
  members is refused.
- `none` and the MAC algorithms never reach key resolution. The verification algorithm is
  pinned to the one the header names.
- The `jti` store fails closed, and the burn comes after the client binding.
- `authorization_details` is rejected on the verified claims, before the schema can strip
  it.
- The mint path omits `email` and `act`, signs with the access-token key and never with the
  hybrid signer, and returns `token_type: N_A` with no refresh token.
- Failure reasons go to the audit log. The wire answer is one `invalid_grant`.
- `private_key_jwt` (§7) requires and burns the `jti`, bounds the lifetime, checks `aud`,
  and refuses a shared secret from a client registered for it.

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
- [ADR-014: Agent Authority Tree](./014-agent-authority-tree.md) ·
  [ADR-015: Agent Tree Hardening](./015-agent-tree-hardening.md) — the decision that an
  agent type cannot mint an ID-JAG once the tree ships.
- [ADR-017: First-Party Login](./017-first-party-login.md) — the stricter `aud` rule for
  client assertions of first-party and agent clients.
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
