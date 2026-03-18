---
name: schema
description: Database schema rules for QAuth. Use when working with the identity model, user_credentials, user_attributes, Drizzle ORM, migrations, or claim resolution. Enforces the identifier-abstraction design (no email/password on users table).
---

# Schema Rules

You are working in the QAuth database layer.

## Identity Model

The `users` table is an identity anchor only. It has no email, no password_hash,
and no credential-specific fields. Its columns are: `id`, `realm_id`, `enabled`,
`metadata`, `created_at`, `updated_at`, `last_login_at`.

Authentication methods live in `user_credentials`:

- `provider_type = 'password'` → `external_sub` is the normalized email address,
  `credential_data` has `{ password_hash, email_verified, email_verified_at? }`
- `provider_type = 'wallet'` → `external_sub` is a DID or issuer-assigned subject,
  `credential_data` has `{ wallet_provider, assurance_level, vc_types, last_vp_verified_at? }`
- `provider_type = 'oidc_*'` → `external_sub` is the upstream `sub` claim,
  `credential_data` has `{ iss, email?, email_verified? }`

Attributes (email, name, birthdate) live in `user_attributes` with source tracking.
Each attribute row has a `source` field indicating where it came from.

## OIDC Claims

Email is present in tokens only if verified. The `email` claim is **omitted entirely**
when no verified email exists — it is not set to null. Applications must handle
absent email claims. This is correct OIDC behaviour per OIDC Core 1.0.

OIDC `sub` claim is always `users.id` (UUID). Never email. Never `external_sub`.

## Constraints

- Never add `email`, `password_hash`, or credential columns directly to `users`
- `email_verification_tokens.credential_id` references `user_credentials.id` (not `users.id`)
- `UNIQUE` on `user_credentials` is `(realm_id, provider_type, external_sub)`
- All primary keys use `uuidv7()` (PostgreSQL 18+ native). Use `gen_random_uuid()` only as a documented fallback.
- Use Drizzle ORM. Never write raw SQL in service code. Use the `sql` template tag only for expressions in schema definitions.
- Drizzle schema lives in `libs/infra/db/src/lib/schema/`
- Repositories live in `libs/infra/db/src/lib/repositories/`

## Trust Order for Claim Resolution

When multiple sources provide the same attribute, use the highest-trust source:

```
wallet > oidc_* > self_reported
```

For SQL ordering: `CASE source WHEN 'wallet' THEN 1 WHEN 'self_reported' THEN 4 ELSE 2 END`

## Adding a New Provider Type

1. Add the `provider_type` string as a constant in `libs/server/federation/`
2. Implement `CredentialProvider` interface
3. No schema changes required — the JSONB `credential_data` column accommodates new shapes

## Migrations

After schema changes, generate a migration with:

```bash
pnpm nx run infra-db:generate
```

Review the generated SQL before applying. Never apply migrations to production without review.
