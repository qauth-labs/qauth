# Environment-Aware Authorization

QAuth treats **environment** — `development`, `staging`, or `production` — as a
first-class **policy-profile dimension**. One attribute flips a coordinated bundle
of security and operational defaults, so an operator hardens a deployment by
setting a single value instead of getting a dozen independent switches right.

This is the operator/how-to guide. For the design rationale, the fail-safe
reasoning, and the prior-art comparison, see
[ADR-008](./adr/008-environment-aware-authorization.md). The resolver itself lives
in `apps/auth-server/src/app/helpers/environment-policy.ts`.

## The two knobs

Environment is set on two columns, both defaulting to `production`:

| Column                          | Meaning                                                               |
| ------------------------------- | --------------------------------------------------------------------- |
| `oauth_clients.environment`     | The client's **declared** environment.                                |
| `realms.max_environment_laxity` | A realm-level **ceiling** on how lax any client in that realm may be. |

The **effective** environment is the **stricter** of the two
(`production` > `staging` > `development`). A realm pinned to `production` forces
every client in it to the production profile regardless of the client's own field.

```
effective = stricter(client.environment, realm.max_environment_laxity)
```

## Fail-safe defaults

- **Unset / unknown client `environment` → `production`.**
- **Unset / unknown realm `max_environment_laxity` → `production`.**

A fresh realm caps everything at production until an operator deliberately widens
it, and any malformed value resolves to the strictest profile. **Misconfiguration
fails closed** — the relaxed posture is always opt-in and bounded.

## Relaxation is operator-set, never self-asserted

The relaxation direction is set **only** by an operator — seed/manifest, admin
API, or realm config. It is **not** accepted from `POST /oauth/register` (dynamic
client registration) or a CIMD metadata document. A client cannot declare itself
`development` to escape production gates, exactly as it cannot self-grant
`max_agent_mode` (ADR-007 §2).

## The profiles

Security-relevant relaxations apply to **`development` only**. **`staging` keeps
production-grade security** and relaxes only operational conveniences (rate limits,
token lifespan), so promoting dev → staging surfaces the real security posture
before production.

| Knob (`EnvironmentPolicy` field)            | development | staging | production |
| ------------------------------------------- | ----------- | ------- | ---------- |
| `staticApiKeysAllowed`                      | ✅ allowed  | ❌ off  | ❌ off     |
| `localhostRedirectAllowed`                  | ✅          | ❌      | ❌         |
| `pkceRequired`                              | recommended | ✅      | ✅         |
| `accessTokenLifespanTier`                   | long        | short   | short      |
| `refreshRotationRequired`                   | ❌          | ✅      | ✅         |
| `rateLimitTier`                             | lenient     | lenient | strict     |
| `openDynamicRegistration`                   | open        | gated   | gated      |
| `agentStepUpEnforced`                       | ❌          | ✅      | ✅         |
| `t3SecurityEnforced` (headers/CSRF/cookies) | ❌          | ✅      | ✅         |

Notes:

- `pkceRequired` here governs whether the **environment profile** hard-requires
  PKCE. QAuth's project-wide floor still defaults `oauth_clients.require_pkce=true`
  regardless, so PKCE is on unless a client is explicitly a `development` client
  that opts out.
- `staging` and `production` are **https-only** for redirect URIs. The RFC 8252
  `http://` loopback carve-out for native / CLI clients (including MCP clients) is
  handled by redirect validation and is permitted in any PKCE-enforcing
  environment — it is not the same flag as `localhostRedirectAllowed`.
- Hard security floors always hold and are **not** environment-tunable: client
  secrets are always hashed (Argon2id), and audience (`aud`) binding always holds.

## Static developer API keys

Static, long-lived API keys are the deliberate **developer-experience half** of
this feature — and they are environment-gated from day one:

- **`development`**: a client may issue and authenticate with static API keys.
- **`staging` / `production`**: the API-key path is **off**; use OAuth
  `client_credentials` instead.

Keys have the layout `qauth_<keyId>_<secret>` and are presented as a bearer
credential:

```http
Authorization: Bearer qauth_<keyId>_<secret>
```

Only `keyHash` / `prefix` (`qauth_<keyId>`) / `last4` are ever persisted; the full
key is surfaced exactly once at creation. Manage them from the developer portal
(**API keys** section) or the `/api/clients` API. The gate is enforced centrally
via `resolveEnvironmentPolicy(client, realm).staticApiKeysAllowed`, so a key that
exists on a client later moved to `production` simply stops authenticating.

## Concrete values behind the tiers

The profile table is deliberately coarse — it carries legible **tier labels**, not
magic numbers. The concrete values come from configuration so an operator tunes
one place:

- **Access-token lifespan** — `short` maps to `ACCESS_TOKEN_LIFESPAN` (default
  `900` seconds); `long` is the development convenience.
- **Rate limits** — `strict` vs `lenient` select between configured per-window
  caps (`RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` and the per-endpoint limits); only
  the cap moves with environment, the window is unchanged.

## Recommended operator setup

- **Production deployment**: leave both columns at their `production` default, or
  explicitly pin `realms.max_environment_laxity = production` to lock the entire
  realm. Nothing else to configure — the T3 hardening bundle is on.
- **Local development**: set the developer's realm `max_environment_laxity` to
  `development` (or `staging`) and mark specific clients `environment = development`
  to opt into static API keys, localhost redirects, and long-lived tokens — without
  ever weakening the production realm.
- **Staging / load testing**: use `staging` to keep full production security while
  relaxing only rate limits and token lifespans.

## Related

- [ADR-008: Environment-Aware Authorization Posture](./adr/008-environment-aware-authorization.md) — rationale, fail-safe design, prior art.
- [ADR-007: MCP-First Positioning](./adr/007-mcp-first-positioning.md) — the operator-set `max_agent_mode` precedent this reuses.
- [Agent Authorization](./agent-authorization.md) — agent step-up, which this posture enforces in `staging`/`production`.
- [Browser Security](./browser-security.md) — the T3 hardening bundle that the production profile turns on.
