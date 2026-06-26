# ADR-008: Environment-Aware Authorization Posture

**Status:** Accepted · **Implemented (June 2026)**
**Date:** 2026-06-25
**Authors:** QAuth Team

> **Accepted 2026-06-25.** Every fork below takes the **fail-safe** option
> (default to the strictest posture; relaxation is operator-controlled, never
> self-asserted). Implementation issues are derived from the sequencing section.

> **Implemented (June 2026, T5 milestone).** All four sequencing items shipped:
> the environment schema + `resolveEnvironmentPolicy` resolver (#196), the
> production profile wired as the T3 hardening bundle (#197), and the
> environment-gated developer API keys — backend (#97) and portal UI (#98).
> The rate-limit tier was wired to the live `/oauth/token` and `/oauth/authorize`
> limits as a realm-level seam in the #209 follow-up.

## Context

Two needs collided while finishing the MVP and planning T3:

1. **Developer experience.** Static, long-lived API keys (issues #97/#98) make
   local development trivial — one header, no token-exchange dance. We want that
   ergonomics.
2. **Production safety.** A static, non-expiring bearer is exactly what you do
   **not** want facing the internet. The same tension applies across the board:
   `http://localhost` redirect URIs, long token lifespans, lenient rate limits,
   open dynamic registration, and relaxed agent step-up are all fine for local
   work and dangerous in production.

Today these are scattered, mostly-global knobs. T3 (OIDC conformance &
hardening — #108 CSRF, #109 secure cookies, #113 helmet, …) is about to add more.
Without a unifying concept, an operator hardening for production has to flip a
dozen independent switches and get every one right, and a developer who wants
local convenience has no safe way to opt into it.

**The agent track already established the pattern we need.** ADR-007 §2 shipped
`oauth_clients.max_agent_mode` as an **operator-set** cap (its schema comment:
_"Unlike `is_agent` (self-asserted client input), this is OPERATOR-SET … A client
omitting `is_agent` to dodge controls simply fails the check"_), and
`realms.dynamic_registration_allowed_scopes` is a realm-level **hard cap** on what
self-registration may request. Environment posture is the same shape of problem:
a security-relevant attribute whose **relaxation direction must not be
self-assertable**.

**Prior art (so the novelty claim is precise).** The notion that environment
changes credential policy is not new in SaaS: Stripe ships `sk_test_`/`sk_live_`
keys; Clerk, Auth0, and WorkOS separate **development** and **production**
instances/tenants with different rules. What does **not** exist, to our
knowledge, in the **open-source, self-hostable** OAuth/OIDC space (Keycloak, Ory
Hydra, Authentik, etc. treat environments only as a deployment/realm convention):
a **first-class environment dimension on the realm/client _within a single
server_ that selects a security policy profile** — and certainly not one that
also modulates **agent** credential strictness. That synthesis is where QAuth is
first.

## Decision

Introduce **environment** as a first-class, policy-profile dimension.

### 1. The dimension

`environment ∈ { development, staging, production }`. It selects a **policy
profile** — one attribute that flips a coordinated bundle of security defaults,
instead of N independent knobs.

### 2. Granularity — client-level, bounded by a realm-level ceiling

- `oauth_clients.environment` — the client's declared environment.
- `realms.max_environment_laxity` — a realm-level **ceiling** on how lax any
  client in that realm may be, mirroring `dynamic_registration_allowed_scopes`.
  A client's effective environment is the **stricter** of its own value and the
  realm ceiling. A realm set to `production` forces every client to the
  production profile regardless of the client's own field — the ceiling can
  never be exceeded.

This serves the DX goal (a developer can mark one client `development` for local
work) while giving operators a single realm-level lever to lock an entire
deployment to production.

### 3. Fail-safe defaults (the safe method)

- **Unset client `environment` → `production`.** An unconfigured client gets the
  strictest profile, never the laxest.
- **Unset realm `max_environment_laxity` → `production`.** A fresh realm caps
  everything at production until an operator deliberately widens it.
- Net effect: **the relaxed posture is opt-in and bounded; the default everywhere
  is the hardened one.** Misconfiguration fails closed.

### 4. Relaxation is operator-controlled, never self-asserted

`environment` (in the relaxation direction) is set **only** by an operator —
seed/manifest, admin API, or realm config. It is **NOT** accepted from
`POST /oauth/register` (DCR) or a CIMD metadata document. A client cannot declare
itself `development` to escape production gates, exactly as a client cannot
self-grant `max_agent_mode`. (A client _may_ be allowed to self-declare the
**stricter** direction, since that only reduces its own privilege — but the
simplest safe rule is operator-set, period, which this ADR adopts.)

### 5. The profiles

`production` is the strict baseline — and **is the T3 hardening bundle**. The
laxer profiles relax specific knobs. Security-relevant relaxations apply to
**`development` only**; **`staging` keeps production-grade security** and relaxes
only operational conveniences (so promoting dev→staging surfaces security
posture before production).

| Knob                                          | development         | staging                    | production |
| --------------------------------------------- | ------------------- | -------------------------- | ---------- |
| **Static API keys (#97/#98)**                 | allowed, long-lived | off (or short-TTL, opt-in) | off        |
| `http://localhost` redirect URIs              | allowed             | https-only                 | https-only |
| PKCE (`S256`)                                 | recommended         | required                   | required   |
| Access-token lifespan                         | long                | short                      | short      |
| Refresh-token rotation                        | optional            | required                   | required   |
| Rate limits                                   | lenient             | lenient (load testing)     | strict     |
| Open DCR / CIMD                               | open                | gated                      | gated      |
| Agent step-up before dangerous ops            | relaxed             | enforced                   | enforced   |
| Security headers / CSRF / secure cookies (T3) | relaxed             | enforced                   | enforced   |

Each row is a default; an operator may override a single knob, but **only within
the realm ceiling** and never below the hard security floors (e.g. a client
secret is always hashed; audience binding always holds).

### 6. Static developer API keys (#97/#98), reframed

Build them — but **environment-gated from day one**. A static API key is a
`development` (optionally `staging`) convenience; in `production` the API-key
path is off and developers use OAuth `client_credentials`. This makes API keys
the deliberate **DX half** of this ADR rather than a redundant second credential
system competing with `client_credentials`.

### 7. Enforcement

A single `resolveEnvironmentPolicy(client, realm)` helper returns the effective
profile (stricter of client vs realm ceiling, default `production`). Policy
checkpoints — token issuance, the API-key gate, redirect-URI validation, DCR,
agent step-up — consult it rather than re-deriving rules. This mirrors the
`toAgentScopeContext` / `enforceAgentScopeCap` pattern from ADR-007 §2.

## Consequences

### Positive

- **One lever for posture.** `environment=production` flips the whole hardened
  bundle on; operators stop hand-wiring a dozen switches.
- **Safe DX.** Static keys and local conveniences exist without ever weakening a
  production deployment — relaxation is opt-in, bounded by the realm, and
  defaults off.
- **Gives T3 a backbone.** The hardening work (#108/#109/#112/#113/…) becomes the
  _production profile_ instead of scattered global flags; dev can relax
  individually without disabling it globally.
- **Env-aware agent strictness** — novel: agent delegation/step-up can be strict
  in production and relaxed for local agent development.
- **First in OSS/self-hostable** for environment-as-policy-dimension within one
  server (see Context).

### Negative

- New schema dimension + migration; `environment` must be threaded through every
  policy checkpoint (mitigated by the single resolver).
- Operator misconfiguration is possible — mitigated by fail-safe defaults
  (unset = production) and the realm ceiling.
- Three profiles add documentation and test surface; mitigated by keeping
  security relaxations to `development` only.

### Neutral

- Protocol-transparent: no OAuth/OIDC wire change; clients are unaffected by
  which profile they're under beyond the policy outcomes.
- Compatible with the realm-per-environment convention operators already use —
  this adds intra-server granularity, it doesn't forbid the old pattern.

## Implementation sequencing (issues to be derived; not part of this ADR)

1. Schema + migration: `oauth_clients.environment` + `realms.max_environment_laxity` (default `production`); operator-only write paths.
2. `resolveEnvironmentPolicy(client, realm)` resolver + the policy-profile table.
3. Environment-gated static developer API keys (#97 backend / #98 portal UI).
4. Wire the T3 hardening (#108/#109/#112/#113/…) as the production profile, with the dev relaxations.

## Related

- [ADR-007: MCP-First Positioning](./007-mcp-first-positioning.md) — the
  operator-set `max_agent_mode` / untrusted-`is_agent` precedent this reuses.
- [ADR-006: OAuth Grants and Audience](./006-oauth-grants-and-audience.md).
- MVP #97 / #98 (developer API keys) — reframed here as environment-gated.
- T3 milestone — OIDC conformance & hardening (the production profile).
