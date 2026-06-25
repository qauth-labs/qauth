# Agent Authorization — how an AI agent acts on behalf of a user

> ADR-007 §2 · epic #181 · the agent-native authorization layer.

QAuth is an OAuth 2.1 authorization server for MCP servers and AI agents. The
[MCP Quickstart](./mcp-quickstart.md) and [OAuth 2.1 Flow](./oauth-flow.md) cover
the generic handshake any client uses. **This guide covers the agent-native
layer on top of it** — the five pieces that let an autonomous agent act _on
behalf of_ a user with bounded, auditable authority:

1. [**Agent client type** (`is_agent`)](#1-agent-client-type-is_agent) — marking a
   client as an agent, and why the flag is treated as untrusted.
2. [**Token Exchange** (RFC 8693)](#2-token-exchange-rfc-8693--on-behalf-of-delegation) —
   exchanging a user's token for a delegated one carrying an `act` (actor) claim.
3. [**Scope modes**](#3-scope-modes-readonly--admin--exec) — `agent:readonly` /
   `agent:admin` / `agent:exec` reserved scopes bounded by an operator-set cap.
4. [**Step-up authentication**](#4-step-up-authentication-before-dangerous-operations) —
   forcing fresh auth / re-consent before dangerous operations.
5. [**Per-agent audit**](#5-per-agent-action-audit) — what every delegated action
   records.

The unifying principle is **default-deny on untrusted input**: a client can
_claim_ to be an agent, but every capability that claim would unlock is gated by
an independent, server-side criterion. A client that omits `is_agent` to dodge
controls simply is not an agent and gets nothing extra; a client that asserts it
still cannot exceed what an operator provisioned for it.

---

## 1. Agent client type (`is_agent`)

An **agent** is an OAuth client whose `oauth_clients.is_agent` column is `true`.
There are three ways it is set, all of which write the same column:

| Path                                       | How                                                                                                                                                   |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Dynamic Client Registration** (RFC 7591) | Send `"is_agent": true` in the `POST /oauth/register` body. Optional boolean, defaults to `false`; echoed back in the response as `"is_agent": true`. |
| **Client ID Metadata Documents** (CIMD)    | Include `"is_agent": true` in the hosted metadata document the `client_id` URL resolves to.                                                           |
| **Seed / operator provisioning**           | Set `"is_agent": true` on a client entry in the `seed-oauth-clients` manifest.                                                                        |

Register an agent via DCR:

```bash
curl -s -X POST http://localhost:3000/oauth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "My Agent",
    "grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"],
    "token_endpoint_auth_method": "client_secret_basic",
    "is_agent": true
  }' | jq
# → { "client_id": "…", "client_secret": "…", "is_agent": true, … }
```

### `is_agent` is self-asserted and untrusted

`is_agent` is **client-controlled input** — the client sets it in its own DCR
body or CIMD document. QAuth therefore **never trusts it alone**. It is read
through a fail-closed accessor (`isAgentClient(client)`, which is true only for
an explicit `isAgent === true`, never a missing/null value), and on its own it
gates nothing dangerous. Every agent capability requires a _second_,
**server-side** condition:

- **Token Exchange** additionally requires confidential-client authentication
  _and_ that the subject token was minted for this agent (see §2).
- **Scope modes** additionally require an operator-set `max_agent_mode` cap that
  covers the requested mode (see §3) — and that cap is **not** accepted from the
  client's own registration request.

The safe outcome is the same whether a client lies, omits, or sends a malformed
value: no agent privilege.

---

## 2. Token Exchange (RFC 8693) — on-behalf-of delegation

> On-behalf-of delegation is an MCP auth **extension**
> ([ext-auth](https://github.com/modelcontextprotocol/ext-auth)), not core MCP —
> QAuth provides it as a value-add.

An agent exchanges a user's access token (`subject_token`) for a **delegated**
access token whose `sub` remains the user and whose `act` (actor) claim
identifies the agent. Chained delegation nests `act` (RFC 8693 §4.1).

```bash
curl -s -X POST http://localhost:3000/oauth/token \
  -u "AGENT_CLIENT_ID:AGENT_CLIENT_SECRET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=USERS_ACCESS_TOKEN \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d 'scope=read:docs' | jq
```

Response — `issued_token_type` is required by RFC 8693 §2.2.1:

```jsonc
{
  "access_token": "eyJ…", // sub = user, act = { "sub": "AGENT_CLIENT_ID" }
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read:docs",
}
```

### Request parameters

| Parameter               | Required | Notes                                                                                         |
| ----------------------- | -------- | --------------------------------------------------------------------------------------------- |
| `grant_type`            | yes      | Exactly `urn:ietf:params:oauth:grant-type:token-exchange`.                                    |
| `subject_token`         | yes      | The user's QAuth-issued access token (the party being acted for).                             |
| `subject_token_type`    | yes      | Must be `urn:ietf:params:oauth:token-type:access_token`. Any other type → `invalid_request`.  |
| `actor_token`           | no       | The acting party's token. When present, `actor_token_type` is **required** (RFC 8693 §2.1).   |
| `actor_token_type`      | cond.    | Required iff `actor_token` is sent; must be the access-token type, else `invalid_request`.    |
| `requested_token_type`  | no       | If present, must be the access-token type; anything else → `invalid_request`.                 |
| `scope`                 | no       | Space-separated; a **subset** of the subject token's scope. Omit to inherit the full set.     |
| `resource` / `audience` | no       | RFC 8707 / RFC 8693 targets; must fall **within** the subject token's `aud`. Omit to inherit. |

### The `act` claim shape

The delegated access token carries an RFC 8693 §4.1 `act` claim. The current
actor (the authenticated agent's own `client_id`) is the outermost `act`; any
pre-existing delegation chain on the subject token nests beneath it:

```jsonc
{
  "sub": "<user-id>", // the delegated token's subject stays the USER
  "act": {
    "sub": "AGENT_CLIENT_ID", // the agent acting now
    "act": { "sub": "UPSTREAM_AGENT_ID" }, // a prior actor, if re-exchanged
  },
}
```

The `act.sub` is always the **authenticated agent's** `client_id` — never a
value self-declared in an `actor_token`. Access tokens also carry a
`token_use: "access"` marker.

### Security model (default-deny)

These guarantees hold even against an attacker who has captured a user's token
and knows a public agent `client_id`:

- **Agent-only.** The client must be classified as an agent
  (`isAgentClient(client)`, fail-closed) **and** be granted the token-exchange
  grant type. Otherwise → `unauthorized_client`.
- **Confidential clients only.** Token exchange requires confidential client
  authentication (`client_secret_basic` / `client_secret_post`). A public agent
  (`token_endpoint_auth_method=none`) presents no secret and is rejected with
  `invalid_client`. This is a deliberate security floor (RFC 9700): on-behalf-of
  delegation must not be mintable by a client that proves only knowledge of a
  `client_id`.
- **Subject token must be bound to the agent.** The `subject_token` must verify
  as a QAuth-issued **access token** — EdDSA signature + `exp`, QAuth's own
  `iss`, and an access-token use marker (ID tokens and other JWTs are rejected
  with `invalid_request`) — **and** its `aud` must contain the requesting
  agent's `client_id`. Combined with the confidential-client requirement, this
  closes the unauthorized-delegation gap: a captured token alone is not enough.
  The subject user must also still exist and be enabled.
- **Scope and audience are narrowed, never widened.** A requested `scope` must
  be a subset of the subject token's scope (else `invalid_scope`); `resource` /
  `audience` must fall within the subject token's `aud` (else `invalid_target`).
- **Scope-mode cap still applies.** Any reserved `agent:*` scope that survives
  narrowing is additionally clamped to the agent's server-side `max_agent_mode`
  (see §3), so a capped agent cannot launder a higher mode through delegation
  even when the subject token carried it.
- **Lifetime never exceeds the subject token.** `expires_in` is clamped to
  `min(configured_lifespan, subject_token_remaining)`, so a delegated token can
  never outlast — or be re-exchanged to extend — the authority it derives from.
- **Bounded delegation depth.** Each re-exchange nests another `act`. The chain
  is capped at **4 actors**; a deeper request → `invalid_request`.
- **No refresh token** is issued — a delegated token is intentionally
  short-lived; the agent re-exchanges as needed.
- **Every exchange is audited** (success and failure), including the actor and
  delegation depth (see §5).

For copy-paste `curl` and the full error table, see the
[Token Exchange section of the OAuth 2.1 Flow guide](./oauth-flow.md#token-exchange--agent-on-behalf-of-delegation-rfc-8693).

---

## 3. Scope modes (ReadOnly / Admin / Exec)

QAuth bounds what an agent can do with a small, opinionated capability taxonomy
layered over raw OAuth scopes, so operators get a coarse, legible control
instead of hand-curating scope strings.

### The taxonomy

| Mode     | Reserved scope   | Meaning                            |
| -------- | ---------------- | ---------------------------------- |
| ReadOnly | `agent:readonly` | Read-only access                   |
| Admin    | `agent:admin`    | Administrative; **⊇ ReadOnly**     |
| Exec     | `agent:exec`     | Action-taking; the most privileged |

Cap ordering: **ReadOnly ⊂ Admin ⊂ Exec**. A client whose maximum mode is
`admin` may request `agent:readonly` and `agent:admin`, but not `agent:exec`.
The cap is a **maximum**, not an exact match.

The modes are plain OAuth scopes (`agent:*`), so the **existing** scope
machinery enforces them with no new claim system — the per-client allowlist and
`validateScopes` at the token endpoint, scope filtering at the authorize /
consent screens, and `@qauth-labs/mcp-guard`'s resource-server scope checks. The
granted mode is therefore already visible to resource servers in the token's
`scope` set.

### Enforcement: deny-by-default, untrusted `is_agent`

A reserved `agent:*` scope is granted **only** when **both** hold:

1. the client is classified as an agent via the fail-closed `isAgentClient`
   accessor (`isAgent === true`, never missing/null), **and**
2. the requested mode is within the client's **server-side** `max_agent_mode`
   cap.

`oauth_clients.max_agent_mode` is **operator-set server state** — provisioned
via the seed script or admin, and **never** accepted from a client's own
registration request (an escalation control must not be self-asserted). It is
**absent from the DCR request and response schemas entirely.** It defaults to
`NULL`, meaning **no agent mode is permitted**.

Consequences (all fail-closed):

- A client that **omits** `is_agent` is not an agent → **no** `agent:*` scope.
- A client with **no cap** (`NULL`) gets **no** `agent:*` scope — not even
  ReadOnly.
- An **unknown** stored mode parses to `null` and denies.
- A capped agent **cannot** obtain a higher mode (`admin`-capped → `agent:exec`
  rejected with `invalid_scope`).

### Where the cap is enforced

The cap is enforced on **every** path that can grant a reserved-mode scope, so
the control holds wherever the code is actually issued:

| Grant / surface           | Where                                                                                             |
| ------------------------- | ------------------------------------------------------------------------------------------------- |
| `/oauth/authorize`        | `findExceedingAgentScopesForClient` → `invalid_scope` redirect (fast path, prior consent covers). |
| `/ui/consent`             | The same gate on the POST (code issuance) **and** GET (render) — the common first-time path.      |
| `client_credentials`      | `validateScopes(scope, client.scopes, toAgentScopeContext(client))` in the token endpoint.        |
| Token Exchange (RFC 8693) | `enforceAgentScopeCap` against the narrowed scope set before the delegated token is minted.       |

Provision an agent with a cap via the `seed-oauth-clients` manifest:

```jsonc
{
  "realm": "master",
  "clients": [
    {
      "client_id": "my-agent",
      "name": "My Agent",
      "grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"],
      "scopes": ["agent:readonly", "agent:admin"],
      "token_endpoint_auth_method": "client_secret_basic",
      "is_agent": true, // self-asserted classification
      "max_agent_mode": "admin", // operator-set ceiling — agent:exec stays denied
    },
  ],
}
```

```bash
DATABASE_URL="postgresql://qauth:${DB_PASSWORD}@localhost:5432/qauth" \
  pnpm nx run infra-db:db:seed-oauth-clients -- --manifest=/path/to/manifest.json
```

---

## 4. Step-up authentication before dangerous operations

`mcp-guard` emits the runtime `403 insufficient_scope` + `WWW-Authenticate`
challenge when a resource needs a scope the presented token lacks (shipped in
T1). The authorization-server half of that loop lives in `/oauth/authorize`:
when a client returns asking for an **increased** scope set, QAuth must not
silently widen an existing grant. Crossing into a more-privileged scope set is a
**step-up** — it requires a **fresh authentication** and/or **explicit
re-consent** (MCP 2025-11-25 incremental consent).

### What counts as "dangerous"

The classification is conservative and **server-side only** — never driven by a
client signal:

- any `write:*` scope (mutating access), and
- the higher agent modes **`agent:admin`** and **`agent:exec`** (both are
  action-taking). `agent:readonly` is **not** dangerous.

### The decision

Evaluated from the requested scopes versus what a prior consent already covers,
plus the standard OIDC `prompt` / `max_age` request parameters:

- **Any newly-requested scope** beyond a prior consent ⇒ **re-consent**
  required (never auto-widen).
- **`prompt=consent`** ⇒ re-consent even with no elevation.
- **Any dangerous scope being granted** — whether newly elevated _or_ already
  covered by a remembered prior consent ⇒ **fresh login** required. A
  state-changing capability is only granted right after the user proves
  presence; a stale grant cannot satisfy it, and no client opt-in is involved.
- **`prompt=login`** ⇒ fresh login.
- **`max_age`** present and the session is older than it ⇒ fresh login
  (`max_age=0` demands a brand-new authentication; second-granularity flooring
  makes the post-login round-trip terminate instead of looping).

### The 403 → re-authorize → retry loop

```
1. Agent calls the resource with a token lacking the needed (e.g. write/exec) scope.
   → mcp-guard returns 403 insufficient_scope + WWW-Authenticate scope hint.
2. Agent re-runs /oauth/authorize requesting the larger scope set.
   → the agent scope-mode cap is checked first; an over-cap agent:* scope
     yields an invalid_scope redirect.
   → step-up evaluation decides fresh login / re-consent is needed.
3. User re-authenticates at /ui/login (and/or re-consents), creating a fresh session.
4. User returns to the original /oauth/authorize URL; the session is now fresh,
   step-up is satisfied, and the authorization code is issued.
```

### `prompt=none` (no UI allowed)

When the caller forbids UI but step-up would otherwise display a screen, the
authorize endpoint returns the matching OIDC error as an `error=` redirect
instead of silently elevating (OIDC Core §3.1.2.1):

| Condition                          | Error code             |
| ---------------------------------- | ---------------------- |
| A fresh authentication is required | `login_required`       |
| Only re-consent is required        | `consent_required`     |
| Generic interaction fallback       | `interaction_required` |

A fresh-login requirement takes precedence over a pending consent — the user
cannot consent before re-authenticating.

---

## 5. Per-agent action audit

Every agent-attributable action is written to `audit_logs` with structured,
queryable columns **on top of** the existing event metadata. The agent-specific
columns are:

| Column             | What it records                                                                                                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `user_id`          | The end user the agent acted **on behalf of** (the subject). Null for `client_credentials` (no subject user).                                                                            |
| `actor_client_id`  | The denormalized `client_id` **string** of the agent that performed the action — stored as a string (not the FK) so the attribution survives deletion of the client row.                 |
| `delegation_chain` | The RFC 8693 `act` chain flattened to an ordered list of actor `client_id`s — index 0 is the outermost (most recent) actor, each following entry a prior actor. Null when not delegated. |
| `scope_mode`       | The effective agent scope mode (`readonly` \| `admin` \| `exec`) the action ran under — the highest mode in the granted scope set. Null when the action carries no agent-mode scope.     |

What each grant attributes:

- **Token Exchange** — `user_id` = the subject user, `actor_client_id` = the
  agent, `delegation_chain` = the flattened `act` chain, `scope_mode` = the
  highest granted agent mode. Failures are audited too, with the delegation
  depth.
- **`client_credentials`** (agent acting as itself) — `actor_client_id` and
  `scope_mode` are set when the client is a verified agent; `user_id` and
  `delegation_chain` stay null (no subject user, no `act` chain). An ordinary
  (non-agent) machine client records **no** agent fields — existing behavior is
  unchanged.

**No tokens or secrets are ever logged.** Only public client identifiers reach
the audit table — the `subject_token` / `actor_token`, client secrets, and any
sensitive material are never persisted. The `delegation_chain` is constrained at
the database level to a JSON array of strings.

The full granted scope set (including every `agent:*` scope) is preserved
verbatim in the audit row's `metadata.scope`; `scope_mode` is the queryable
rollup over that detail.

---

## See also

- [OAuth 2.1 Flow](./oauth-flow.md) — the underlying endpoints with copy-paste
  `curl`, including the [Token Exchange](./oauth-flow.md#token-exchange--agent-on-behalf-of-delegation-rfc-8693)
  section.
- [API Reference](./api-reference.md) — endpoint contracts, including the
  `is_agent` DCR field and the token-exchange grant.
- [MCP Quickstart](./mcp-quickstart.md) — end-to-end QAuth → MCP handshake.
- [ADR-007: MCP-First Positioning](./adr/007-mcp-first-positioning.md) — why the
  agent-native layer is QAuth's differentiation.
- [`@qauth-labs/mcp-guard`](../libs/fastify/plugins/mcp-guard/README.md) — the
  resource-server SDK that emits the `403 insufficient_scope` step-up challenge.
