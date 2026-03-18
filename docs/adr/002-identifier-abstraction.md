# ADR-002: Identifier Abstraction — Email as Credential, Not Identity

**Status:** Accepted
**Date:** 2026-03-11
**Authors:** QAuth Team

## Context

The Phase 1 schema used email as the primary user identifier, with `email`, `email_normalized`, `password_hash`, and `email_verified` columns directly on the `users` table. This design creates a hard dependency between the authentication method (password/email) and the identity anchor.

W3C Verifiable Credentials wallets — including EUDI-compliant wallets mandated for EU member states by December 2026 — carry no email address. Their subject identifier is a pseudonymous DID or issuer-assigned opaque identifier. Adding wallet federation to a schema where `users.email NOT NULL` would require a nullable-email migration and special-case logic throughout the codebase.

The eIDAS 2.0 regulation (EU 2024/1183) creates a firm deadline: by December 2027, regulated EU businesses must accept EUDI Wallet authentication. QAuth's role is to serve as the OAuth 2.1 bridge between any credential wallet and standard OAuth application stacks. That bridge must not be locked to email-based identity.

## Decision

Adopt a three-table identity model:

1. **`users`** — Identity anchor only. UUID primary key, realm scoping, enabled flag. No credential-specific columns.

2. **`user_credentials`** — One row per authentication method per user. `provider_type` discriminates the method (`'password'`, `'wallet'`, `'oidc_*'`, `'did'`). `external_sub` is the method-specific subject identifier. `credential_data` is a JSONB blob carrying method-specific data (password hash, wallet metadata, upstream OIDC claims). A unique constraint on `(realm_id, provider_type, external_sub)` enforces uniqueness with the same query performance as the previous `(realm_id, email_normalized)` index.

3. **`user_attributes`** — Claims and attributes as data, not identity anchors. Each row has a `source` field (`'self_reported'`, `'wallet'`, `'oidc_google'`) and a trust order used during claim resolution. Email is stored here, not on `users`.

Email verification tokens reference `user_credentials.id` (the password credential) rather than `users.id`, because email verification is a property of the password authentication method, not of the abstract identity.

### Phase 1 Flow Mapping

Registration (`POST /auth/register { email, password }`):

1. `INSERT INTO users (realm_id)` → identity anchor created
2. `INSERT INTO user_credentials (provider_type='password', external_sub=email, credential_data={password_hash, email_verified:false})`
3. `INSERT INTO user_attributes (source='self_reported', attr_key='email', attr_value=email, verified=false)`
4. `INSERT INTO email_verification_tokens (credential_id, token_hash, expires_at)`
5. On verification: set `credential_data.email_verified=true`, `user_attributes.verified=true`

Login lookup:

```sql
SELECT * FROM user_credentials
WHERE provider_type = 'password'
  AND external_sub = $email
  AND realm_id = $realm_id
```

Performance is identical to before — `(realm_id, provider_type, external_sub)` is unique-indexed.

### OIDC Token Claims

- `sub`: always `users.id` (UUID). Never email, never `external_sub`.
- `email`: looked up from `user_attributes WHERE attr_key='email' AND verified=true`. Resolved using trust order: `wallet > oidc_* > self_reported`. If no verified email exists, the claim is **omitted entirely** — not set to null. Applications must handle absent email claims; this is correct OIDC behaviour per the OIDC Core 1.0 specification.

## Alternatives Considered

### Keep email as primary key, add a separate wallet table

The `users` table retains `email NOT NULL`. A separate `user_wallet_credentials` table holds DID-based credentials as a parallel path. Wallet users would have a synthetic email generated at account creation.

Rejected because: generating synthetic emails for wallet users pollutes the email namespace, breaks email enumeration protections, and creates a fork in the authentication path rather than a unified model.

### Nullable email on users, separate wallet credential table

Make `users.email` nullable. Add `user_wallet_credentials` when wallet support is needed.

Rejected because: nullable email on the identity anchor still leaks credential semantics into the anchor table. Every query that needs email must handle null. The three-table model is strictly cleaner and has the same query performance.

## Consequences

### Positive

- Wallet federation (Phase 4) requires zero schema migration — it is a new `user_credentials` row with `provider_type='wallet'`
- Account linking (one user identity, multiple authentication methods) is a first-class model rather than a workaround
- OIDC `sub` claim is stable across authentication method changes (user adds or removes a wallet without changing their UUID)
- Trust-ordered claim resolution is explicit and auditable

### Negative

- Registration and login flows require joining two or three tables instead of one
- More complex repository layer
- Existing Phase 1 data requires a migration to populate `user_credentials` and `user_attributes` from old `users` columns

### Neutral

- Query performance is equivalent — the unique index on `(realm_id, provider_type, external_sub)` replaces the old `(realm_id, email_normalized)` index

## Related

- [ADR-003: CredentialProvider Abstraction](./003-credential-provider-interface.md)
- [ADR-004: Wallet-Agnostic VC Federation](./004-wallet-agnostic-federation.md)
- [OIDC Core 1.0 — UserInfo Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
- [eIDAS 2.0 (EU 2024/1183)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1183)
