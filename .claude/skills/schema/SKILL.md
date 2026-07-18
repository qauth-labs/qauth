---
name: schema
description: Database schema rules for QAuth. Use when working with the identity model, Drizzle ORM, migrations, repositories, or claim resolution. Reflects the CURRENT shipped schema — the identifier-abstraction model (ADR-002, IMPLEMENTED via Epic #224) with users as a pure identity anchor, credentials in user_credentials, and claims in user_attributes.
---

# Schema Rules

You are working with the QAuth database layer. This document reflects the
**CURRENT shipped schema**: the identifier-abstraction model ([ADR-002],
**implemented** via Epic #224, PRs #225–#230, migrations 0009–0011). `users`
is a pure identity anchor; authentication methods live in `user_credentials`;
identity data lives in `user_attributes`. The legacy monolithic columns
(`users.email`/`email_normalized`/`password_hash`) were dropped in migration
0011 and no longer exist.

[ADR-007]: ../../docs/adr/007-mcp-first-positioning.md
[ADR-002]: ../../docs/adr/002-identifier-abstraction.md

## Identity Model (CURRENT — shipped)

Three tables (see `libs/infra/db/src/lib/schema/core.ts` + `identity.ts`):

- **`users`** — identity anchor ONLY: `id` (uuidv7 PK — the stable OIDC `sub`),
  `realm_id`, `enabled`, `first_name`/`last_name` (→ OIDC `name` claim),
  `metadata`, timestamps, `last_login_at`. Plus two **vestigial** columns —
  `email_verified`, `email_verified_at` — no writers since #230; the single
  sanctioned reader is the register 201 response surfacing the column's
  default (always false). Verified state lives in
  `credential_data`/`user_attributes`; drop tracked in #261 (migration 0012).
- **`user_credentials`** — one row per authentication method per user.
  `provider_type` (`'password' | 'wallet' | 'oidc_*'`, plain text — no enum),
  `external_sub` (normalized email for password; DID/upstream sub later),
  `credential_data` jsonb (for `'password'`: `{ password_hash, email_verified }`
  snake_case — shape owned by `passwordCredentialDataSchema` in
  `@qauth-labs/server-federation`). UNIQUE
  `(realm_id, provider_type, external_sub)` — since #230 this is the **sole
  duplicate-registration guard**.
- **`user_attributes`** — claims as data: `(user_id, source, attr_key)` UNIQUE,
  `attr_value`, `verified`, optional `expires_at`. Trust order
  (`wallet > oidc_* > self_reported`) is app-code policy
  (`selectTrustedAttribute`), not a DB constraint.

### Login lookup (password auth)

```sql
SELECT * FROM user_credentials
WHERE realm_id = $realm_id
  AND provider_type = 'password'
  AND external_sub = $normalized_email
```

Repository method: `userCredentials.findByRealmProviderSub(realmId,
'password', normalizedEmail)` (unique-indexed). Argon2 verification compares
the presented plaintext against `credential_data.password_hash`
(`verifyPasswordCredential` in `apps/auth-server/src/app/helpers/credential-auth.ts`).
`users.findByEmail` no longer exists.

### Registration (`POST /auth/register`)

One transaction (users insert first — `user_credentials.user_id` FKs it):

1. `INSERT INTO users (realm_id)` — pure anchor.
2. `INSERT INTO user_credentials (provider_type='password',
external_sub=normalized_email, credential_data={password_hash,
email_verified: false})` — a duplicate registration surfaces HERE via the
   credentials unique index (409, genericized).
3. `user_attributes` upsert from `PasswordProvider.extractAttributes()`.
4. `INSERT INTO email_verification_tokens (credential_id, token_hash,
expires_at)` — the token's ONLY identity link is the credential.

On email verification (one transaction): mark the token used, set
`credential_data.email_verified = true` (race-safe `jsonb_set`), and set the
`(user_id, 'self_reported', 'email')` attribute `verified = true`.

## OIDC Claims (shipped behaviour — #229, BREAKING)

- `sub` — always `users.id` (UUIDv7). Never the email. Stable across the
  whole ADR-002 migration.
- `email` — resolved from **verified** `user_attributes` rows
  (`attr_key='email' AND verified=true`, non-expired) via the ADR-002 trust
  order `wallet > oidc_* > self_reported` (app-code policy:
  `selectTrustedAttribute` in `libs/server/federation`; ties within a rank
  break lexicographically by `source`). **Omitted entirely when no verified
  email attribute exists** — never `null`. Applies to ID tokens, userinfo,
  AND the non-standard access-token convenience claims (all six user-bound
  emission sites go through `resolveEmailClaims` in
  `apps/auth-server/src/app/helpers/email-claims.ts`). Additionally (#259,
  BREAKING): ID tokens and userinfo release the pair only when the `email`
  SCOPE was granted; the access-token convenience claims are not scope-gated.
- `email_verified` — always `true` when `email` is present (presence IS the
  verification signal); omitted together with `email` otherwise. The
  email-present-plus-verified-false shape no longer exists.
- `name` — derived from `users.first_name` + `users.last_name` (omitted when
  both are empty, never an empty string).

> The login-time `REQUIRE_EMAIL_VERIFIED` gate (F-08) is a SEPARATE control:
> it blocks unverified logins pre-token (reading
> `credential_data.email_verified`) and does not affect claim resolution.

## Core Tables (shipped)

Schema lives in `libs/infra/db/src/lib/schema/`:

| Table                       | Schema file   | Purpose                                                                                                       |
| --------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------- |
| `realms`                    | `core.ts`     | Multi-tenancy root; realm-level policy (env ceiling, rate-limit tier, allowed scopes, password policy)        |
| `users`                     | `core.ts`     | Pure identity anchor (ADR-002) — the stable OIDC `sub`                                                        |
| `user_credentials`          | `identity.ts` | One row per authentication method; UNIQUE (realm_id, provider_type, external_sub)                             |
| `user_attributes`           | `identity.ts` | Claims as data with source trust order; UNIQUE (user_id, source, attr_key)                                    |
| `oauth_clients`             | `core.ts`     | OAuth 2.1 client registrations; ADR-007 `is_agent`/`max_agent_mode`, ADR-008 `environment`                    |
| `api_keys`                  | `core.ts`     | Static developer API keys (ADR-008 §6, env-gated)                                                             |
| `oauth_consents`            | `consents.ts` | User consent grants; unique per `(user_id, client_id) WHERE revoked_at IS NULL`                               |
| `email_verification_tokens` | `tokens.ts`   | Token hash + `credential_id` (NOT NULL → `user_credentials.id`; `user_id` dropped in #230)                    |
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
- `oauth_clients.audience` and `user_credentials.credential_data` carry
  `jsonb_typeof` CHECK guards.
- FKs use explicit `onDelete` (cascade for children, `set null` for optional
  refs). Deletion cascades user → credentials → verification tokens.
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
live in `libs/infra/db/drizzle/` (`0000_young_vermin.sql` through the latest
`00NN_*.sql`) with `meta/_journal.json` tracking order. Integration tests apply
the real migrations against a PG18 testcontainer; migrations 0010/0011 also
have dedicated seed-then-migrate tests (their harnesses pin `idx <` bounds —
follow that pattern for future destructive migrations). Migration 0011 is
guarded and **irreversible**: it aborts if any user lacks credential coverage,
and there is no down migration — restore-from-backup is the only undo.

## Related

- OAuth flows / token claims: `oauth-oidc`, `auth-oauth`, `auth-engine` skills
- The schema for agent auth (ADR-007): `oauth-oidc` skill, `auth-engine` skill
- Credential providers / claim policy: `libs/server/federation`
  (`CredentialProvider`, `selectTrustedAttribute`, `passwordCredentialDataSchema`)
