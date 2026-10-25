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
  `metadata`, timestamps, `last_login_at`. (The vestigial
  `email_verified`/`email_verified_at` columns were dropped in #261,
  migration 0012; verified state lives in `credential_data`/`user_attributes`.)
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
   credentials unique index. The route catches it and answers the same `202`
   as for a free address (ANT-2026-SPEMY9GU); the existing owner gets a mail
   instead. Never let it reach the error handler's `409`.
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
  AND access tokens (every emission site goes through
  `resolveEmailClaimsForScopes` in
  `apps/auth-server/src/app/helpers/email-claims.ts`). Additionally (BREAKING):
  the pair is released only when the `email` SCOPE was granted — ID tokens
  since #259, access tokens on every grant since 2026-10-19
  (ANT-2026-2O0T72HY). The scope-less `/auth/login` token carries none.
- `email_verified` — always `true` when `email` is present (presence IS the
  verification signal); omitted together with `email` otherwise. The
  email-present-plus-verified-false shape no longer exists.
- `name` — derived from `users.first_name` + `users.last_name` (omitted when
  both are empty, never an empty string). Released only when the `profile`
  SCOPE was granted, in the ID token (since #755) and at userinfo; both call
  `resolveProfileClaimsForScopes`
  (`apps/auth-server/src/app/helpers/profile-claims.ts`). Access tokens never
  carry it.

> The login-time `REQUIRE_VERIFIED_ACCOUNT` gate (F-08, default `true`) is a
> SEPARATE control: it blocks logins by an unverified account pre-token, with
> the same `401` as a wrong password, and does not affect claim resolution. For a password account it reads `credential_data.email_verified`.
> `REQUIRE_EMAIL_VERIFIED` is its deprecated alias (renamed 2026-10-09).

## Core Tables (shipped)

Schema lives in `libs/infra/db/src/lib/schema/`:

| Table                         | Schema file      | Purpose                                                                                                        |
| ----------------------------- | ---------------- | -------------------------------------------------------------------------------------------------------------- |
| `realms`                      | `core.ts`        | Multi-tenancy root; realm-level policy (env ceiling, rate-limit tier, allowed scopes, password policy)         |
| `users`                       | `core.ts`        | Pure identity anchor (ADR-002) — the stable OIDC `sub`                                                         |
| `user_credentials`            | `identity.ts`    | One row per authentication method; UNIQUE (realm_id, provider_type, external_sub)                              |
| `user_attributes`             | `identity.ts`    | Claims as data with source trust order; UNIQUE (user_id, source, attr_key)                                     |
| `oauth_clients`               | `core.ts`        | OAuth 2.1 client registrations; ADR-007 `is_agent`/`max_agent_mode`, ADR-008 `environment`                     |
| `api_keys`                    | `core.ts`        | Static developer API keys (ADR-008 §6, env-gated)                                                              |
| `oauth_consents`              | `consents.ts`    | User consent grants; unique per `(user_id, client_id) WHERE revoked_at IS NULL`                                |
| `email_verification_tokens`   | `tokens.ts`      | Token hash + `credential_id` (NOT NULL → `user_credentials.id`; `user_id` dropped in #230)                     |
| `authorization_codes`         | `tokens.ts`      | OAuth codes with PKCE (S256) challenge, nonce, RFC 8707 `resource`                                             |
| `refresh_tokens`              | `tokens.ts`      | Opaque refresh tokens with `family_id` + `family_created_at` (RFC 9700 rotation family) + `resource`           |
| `audit_logs`                  | `audit.ts`       | Read-only since #458 (rows copied into `events` by 0031); nothing may write it — `emitUserEvent` instead       |
| `events`                      | `events.ts`      | Event store: outbox + log (ADR-019 D8); write via `emitUserEvent(request, type, data, { tx })` in auth-server  |
| `admin_audit_log`             | `admin-audit.ts` | Admin operations, append-only (triggers), one hash chain per target realm; write via `appendAdminAudit(tx, …)` |
| `admin_audit_log_checkpoints` | `admin-audit.ts` | `seq` + `row_hash` of the last row each `admin_audit_log_prune()` removed; the chain verifies from there       |
| `realm_hosts`                 | `core.ts`        | Host → realm, PK `host`; `primary` (one per realm, permanent) or `endpoint`; written via `normaliseRealmHost`  |
| `realm_keys`                  | `keys.ts`        | Envelope-encrypted keys per realm and purpose (ADR-019 D9); only `getWrappedForSigner` reads wrapped columns   |
| `realm_public_keys`           | `keys.ts`        | Public JWK of each published key, `(realm_id, kid)` → `realm_keys`; every role reads it (JWKS, verify)         |
| `sessions`                    | `sessions.ts`    | Browser sessions (ADR-019 D3), `id` is the `sid`, `(user_id, realm_id)` → `users`; unused until #469           |
| `session_clients`             | `sessions.ts`    | Clients a session served, PK `(session_id, oauth_client_id)`; cascades from both; for back-channel logout      |
| `roles`, `user_roles`         | `roles.ts`       | RBAC (PHASE-5+, **currently unused** by auth-server routes)                                                    |

A realm's `issuer` and its `primary` host in `realm_hosts` are **permanent**
(ADR-019 Decision 1, migration 0025): triggers allow each to be set once, from
nothing, and refuse every later change. Store and look up hosts only through
`normaliseRealmHost()` (`@qauth-labs/shared-validation`) and the realms
repository's host methods. At most one realm has `is_operator = true`.
The auth-server's boot step (#484) fills the default realm's issuer and primary
host from `JWT_ISSUER` (`assignIssuer` for a realm from before 0025) under
`lockProvisioning`, and marks it the operator realm when none is.
`realms.webauthn_rp_id` is the realm's passkey RP ID setting (migrations 0028
and 0034, #467, #553): NULL means the primary host, a value is an opted-in
parent domain; `resolveRpId(realm)` (`@qauth-labs/shared-validation`) reads it.
`realms.webauthn_rp_id_locked_at` is its lock: `lockRpIdForEnrolment(tx,
realmId)` sets it in the first passkey enrolment's transaction, and the trigger
`realms_webauthn_rp_id_locked` then refuses any change of either. Passkeys are
`user_credentials` rows with `provider_type = 'webauthn'` and the credential id
as `external_sub`; their `credential_data` shape belongs to
`webauthnCredentialDataSchema` in `@qauth-labs/server-federation`.
`oauth_clients.webauthn_allowed_origins` is operator-set (seed manifest only).

See `libs/infra/db/src/qauth-schema.dbml` for the full visual schema.

## Constraints

- All primary keys use `uuidv7()` (PostgreSQL 18+ native). Plugins/extensionless.
- Use `bigint` epoch-ms timestamps (via the `EPOCH_MS_NOW` SQL helper), not `TIMESTAMP`.
- `code_challenge_method` enum is `['S256']` only — `plain` is not supported.
- `oauth_clients.audience`, `oauth_clients.id_jag_targets` and
  `user_credentials.credential_data` carry `jsonb_typeof` CHECK guards.
  `audience` bounds the tokens QAuth issues; `id_jag_targets` (seed manifest
  only, ADR-011) bounds ID-JAG mint targets and redeemable resources. Never
  read one for the other's job.
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
