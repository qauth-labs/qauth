# Agent Scope Modes (ReadOnly / Admin / Exec)

> ADR-007 §2 · epic #181 · issue #184

QAuth bounds what an **agent client** can do with a small, opinionated
capability taxonomy layered over raw OAuth scopes. Operators get a coarse,
legible control instead of hand-curating scope strings.

## The taxonomy

| Mode     | Reserved scope   | Meaning                            |
| -------- | ---------------- | ---------------------------------- |
| ReadOnly | `agent:readonly` | Read-only access                   |
| Admin    | `agent:admin`    | Administrative; **⊇ ReadOnly**     |
| Exec     | `agent:exec`     | Action-taking; the most privileged |

Cap ordering: **ReadOnly ⊂ Admin ⊂ Exec**. A client whose maximum mode is
`admin` may request `agent:readonly` and `agent:admin`, but not `agent:exec`.
The cap is a **maximum**, not an exact match.

## Why reserved scopes (not a parallel claim)

The modes are plain OAuth scopes (`agent:*`), so the **existing** scope
machinery enforces them with no new claim system:

- `validateScopes` / the per-client allowlist (token endpoint),
- `filterRequestedScopes` (authorize endpoint, consent screen),
- `@qauth-labs/mcp-guard`'s resource-server scope checks.

The granted mode is therefore already visible to resource servers in the
token's `scope` set and enforceable with the scope checks they already run.

## Enforcement: deny-by-default, untrusted `is_agent`

`oauth_clients.is_agent` is **self-asserted, unverified client input** (set in
the client's own DCR body or CIMD document). Mode enforcement never trusts it
alone. A reserved `agent:*` scope is granted **only** when **both** hold:

1. the client is classified as an agent — via the fail-closed
   `isAgentClient(client)` accessor (`isAgent === true`, never a missing/null
   value), **and**
2. the requested mode is within the client's **server-side** `max_agent_mode`
   cap.

`max_agent_mode` is an `oauth_clients` column that is **operator-set server
state** — provisioned via seed/admin, **not** accepted from a client's own
registration request (an escalation control must not be self-asserted). It
defaults to `NULL`, meaning **no agent mode is permitted**.

Consequences (all fail-closed):

- A client that **omits** `is_agent` to dodge controls is simply not an agent
  and gets **no** `agent:*` scope.
- A client with **no cap** (`NULL`) gets **no** `agent:*` scope — not even
  ReadOnly.
- An **unknown** stored mode parses to `null` and denies.
- A capped agent **cannot** obtain a higher mode (`admin`-capped → `agent:exec`
  rejected with `invalid_scope`).

## Enforcement points

| Surface              | Path                                                                                         |
| -------------------- | -------------------------------------------------------------------------------------------- |
| Authorize endpoint   | `routes/oauth/authorize.ts` calls `findExceedingAgentScopes` → `invalid_scope` redirect      |
| Scope validation     | `helpers/client-auth.ts` — `validateScopes(scope, allow, agentCtx)` + `enforceAgentScopeCap` |
| Taxonomy + cap logic | `helpers/scope-modes.ts` — modes, ordering, `isModeWithinCap`, `findExceedingAgentScopes`    |
| Persistence          | `oauth_clients.max_agent_mode` (`agent_mode` enum, nullable; migration `0005`)               |
| Provisioning         | `seed-oauth-clients.ts` manifest field `max_agent_mode` (operator-only)                      |

## Follow-up

The `client_credentials` grant validates scopes via `validateScopes` inside
`routes/oauth/token.ts`. Wiring the cap there is a one-line change —
`validateScopes(body.scope, client.scopes, toAgentScopeContext(client))` — left
as a TODO(#184) because `token.ts` is owned by a parallel PR (#183). The
user-facing agent flow (`authorization_code`) is fully enforced at the
authorize endpoint, where the agent-mode scopes are bound into the
authorization code.
