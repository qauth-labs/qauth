---
name: schema
description: Database schema rules for QAuth. Use when working with the identity model, Drizzle ORM, migrations, repositories, or claim resolution. Reflects the CURRENT shipped schema (monolithic users table). The identifier-abstraction model (ADR-002) is planned but NOT yet implemented.
---

# Schema Rules

You are working with the QAuth database layer. This document reflects the
**CURRENT shipped schema** (Phase 1–3 modular monolith, MCP-first per
[ADR-007]). The planned identifier-abstraction migration ([ADR-002]) is
**deferred to the Phase 4 wallet-federation gate** and is summarised in the
"Planned (not yet implemented)" section at the end. Write code against the
shipped schema, not the planned one.

[ADR-007]: ../../docs/adr/007-mcp-first-positioning.md
[ADR-002]: ../../docs/adr/002-identifier-abstraction.md

## Identity Model (CURRENT — shipped)

The `users` table IS the identity anchor **and** carries the password
credential. There is no `user_credentials` or `user_attributes` table today.
The columns QAuth persists on `users` are (see `libs/infra/db/src/lib/schema/core.ts`):

- `id` (uuidv7, PK)
- `realm_id` (FK → realms, cascade delete)
- `email` (varchar(255), NOT NULL)
- `email_normalized` (varchar(255), NOT NULL) — `(realm_id, email_normalized)` is `UNIQUE`
- `password_hash` (text, NOT NULL) — Argon2id hash of the password
- `email_verified` (boolean, default false)
- `email_verified_at` (bigint, epoch-ms, nullable)
- `enabled` (boolean, default true)
- `first_name`, `last_name` (varchar(255), nullable) — sourced into the OIDC `name` claim
- `metadata` (jsonb, nullable)
- `created_at`, `updated_at` (bigint NOT NULL, epoch-ms)
- `last_login_at` (bigint, nullable)

### Login lookup (password auth)

```sql
SELECT * FROM users
WHERE realm_id = $realm_id
  AND email_normalized = $normalized_email
```

The repository method is `usersRepository.findByEmail(realm_id, email, tx?)`,
which normalises the email before querying. There is no `user_credentials`
join — password auth reads `users.password_hash` directly.

### Registration (`POST /auth/register`)

1. `INSERT INTO users (realm_id, email, email_normalized, password_hash, email_verified=false)` —
   identity anchor + password credential in one row.
2. `INSERT INTO email_verification_tokens (user_id → users.id, token_hash, expires_at)` —
   the verification token references `users.id`, NOT a credential id.
3. On email verification: set `users.email_verified=true` and `users.email_verified_at=now()`.

## OIDC Claims (shipped behaviour)

- `sub` — always `users.id` (UUIDv7). Never the email.
- `email` — `users.email`. **Present even when unverified** today; the login
  route does NOT block unverified emails (the check is commented out at
  `apps/auth-server/src/app/routes/auth/login.ts:85`). This is an MVP posture
  — see finding F-08 and the planned `REQUIRE_EMAIL_VERIFIED` config flag.
- `email_verified` — `users.email_verified`.
- `name` — derived from `users.first_name` + `users.last_name` (omitted when
  both are empty, never an empty string).

> NOTE: OIDC Core 1.0 says `email` should be **omitted** when unverified. The
> planned identifier-abstraction model (ADR-002) tightens this; today QAuth
> emits it. Document this trade-off rather than silently changing it.

## Core Tables (shipped)

Schema lives in `libs/infra/db/src/lib/schema/`:

| Table                       | Schema file   | Purpose                                                                                                       |
| --------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------- |
| `realms`                    | `core.ts`     | Multi-tenancy root; realm-level policy (env ceiling, rate-limit tier, allowed scopes, password policy)        |
| `users`                     | `core.ts`     | Identity anchor + password credential (monolithic, not abstracted yet)                                        |
| `oauth_clients`             | `core.ts`     | OAuth 2.1 client registrations; ADR-007 `is_agent`/`max_agent_mode`, ADR-008 `environment`                    |
| `api_keys`                  | `core.ts`     | Static developer API keys (ADR-008 §6, env-gated)                                                             |
| `oauth_consents`            | `consents.ts` | User consent grants; unique per `(user_id, client_id) WHERE revoked_at IS NULL`                               |
| `email_verification_tokens` | `tokens.ts`   | Token hash + `user_id` (references `users.id`)                                                                |
| `authorization_codes`       | `tokens.ts`   | OAuth codes with PKCE (S256) challenge, nonce, RFC 8707 `resource`                                            |
| `refresh_tokens`            | `tokens.ts`   | Opaque refresh tokens with `family_id` (RFC 9700 rotation family) + `resource`                                |
| `audit_logs`                | `audit.ts`    | Auth/token/consent/client events with agent attribution (`actor_client_id`, `delegation_chain`, `scope_mode`) |
| `sessions`                  | `sessions.ts` | DB session table (PHASE-5+, **currently unused** — sessions live in Redis via `fastify.sessionUtils`)         |
| `roles`, `user_roles`       | `roles.ts`    | RBAC (PHASE-5+, **currently unused** by auth-server routes)                                                   |

See `libs/infra/db/src/qauth-schema.dbml` for the full visual schema.

## Constraints

- All primary keys use `uuidv7()` (PostgreSQL 18+ native). Plugins/extensionless.
- Use `bigint` epoch-ms timestamps (via the `EPOCH_MS_NOW` SQL helper), not `TIMESTAMP`.
- `code_challenge_method` enum is `['S256']` only — `plain` is not supported.
- `oauth_clients.audience` has a check: `IS NULL OR jsonb_typeof = 'array'`.
- FKs use explicit `onDelete` (cascade for children, `set null` for optional refs).
- Use the Drizzle ORM. Never write raw SQL in service code. The `sql` template
  tag is only for expressions inside schema definitions.
- Repositories live in `libs/infra/db/src/lib/repositories/` and are exposed
  via **factory functions** (`createUsersRepository(db)`, etc.), NOT singletons.
  In the Fastify app the `@qauth-labs/fastify-plugin-db` plugin instantiates them
  and decorates `fastify.repositories.*` — route code uses those decorators.

## Migrations

After schema changes, generate a migration and review it:

```bash
pnpm nx run infra-db:db:generate
```

Never apply migrations blindly — review the generated SQL first. Migrations
live in `libs/infra/db/drizzle/` (`0000_young_verim.sql` through the latest
`00NN_*.sql`) with `meta/_journal.json` tracking order. Integration tests apply
the real migrations against a PG18 testcontainer.

---

## Planned (NOT yet implemented — Phase 4 gate)

The **identifier-abstraction** model ([ADR-002]) is the planned future schema.
It is **deferred** to the Phase 4 wallet-federation gate and is NOT the shape
of the code today. Do NOT write code against it unless explicitly working on the
ADR-002 migration. For reference, the planned model:

- `users` loses `email` / `email_normalized` / `password_hash` and becomes an
  identity anchor only (`id`, `realm_id`, `enabled`, `metadata`, timestamps).
- Credentials live in a new `user_credentials` table keyed by
  `(realm_id, provider_type, external_sub)` with `credential_data` jsonb
  (`provider_type ∈ {'password','wallet','oidc_*'}`).
- Attributes live in a new `user_attributes` table with a `source` trust order
  (`wallet > oidc_* > self_reported`).
- `email_verification_tokens.credential_id` → `user_credentials.id`.
- The OIDC `email` claim is omitted entirely when no verified email exists.

See `docs/adr/002-identifier-abstraction.md` for the full design and the
migration plan. Only touch this when beginning the Phase 4 wallet work.

## Related

- OAuth flows / token claims: `oauth-oidc`, `auth-oauth`, `auth-engine` skills
- The schema for agent auth (ADR-007): `oauth-oidc` skill, `auth-engine` skill
