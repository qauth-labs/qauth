---
name: auth-engine
description: Auth engine rules for QAuth. Use when working with CredentialProvider implementations, token claim generation, the provider registry, or the federation layer. Enforces the pluggable provider pattern and correct token claim behaviour.
---

# Auth Engine Rules

You are working in the QAuth authentication core.

## CredentialProvider Pattern

Every authentication method implements the `CredentialProvider` interface:

```typescript
// libs/server/federation/src/providers/credential-provider.interface.ts
export interface CredentialProvider {
  readonly type: string;
  verify(input: unknown): Promise<VerifiedIdentity>;
  extractAttributes(result: VerifiedIdentity): UserAttribute[];
}
```

The auth engine:

1. Looks up the credential from `user_credentials` by `(realm_id, provider_type, external_sub)`
2. Passes credential data to `provider.verify()`
3. Receives `VerifiedIdentity`
4. Upserts `user_attributes` from `provider.extractAttributes()`
5. Issues tokens with `sub = users.id`

The engine does not contain provider-specific logic. Switch/case on `provider_type`
belongs only in the provider registry, not in service routes.

## Current Providers

- `PasswordProvider` (`provider_type: 'password'`) — Phase 1, COMPLETE
  - Located at `libs/server/federation/src/providers/password.provider.ts`
  - `externalSub` is the normalized email address
  - `assuranceLevel: 'low'` — no `acr` claim in tokens
- `WalletProvider` (`provider_type: 'wallet'`) — T4, IN PROGRESS (Epic #231)
  - Skeleton shipped (#232): `libs/server/federation/src/providers/wallet.provider.ts`
  - `verify()` throws by design until a validated OID4VP presentation exists — proving key possession is not authentication (see #233); do not wire it into a login path yet

## Token Claims

- `sub`: always `users.id` (UUID) — never email, never `external_sub`
- `email`: from `user_attributes WHERE attr_key='email' AND verified=true`, highest-trust source
  OMIT entirely if no verified email — do not set null
- `acr`: eIDAS assurance level from `VerifiedIdentity.assuranceLevel`
  Omit for password credentials (`assuranceLevel: 'low'` → no `acr` claim)
- All other claims: from `user_attributes`, same trust-ordered resolution

## Claim Resolution

```typescript
// Claim resolution order by source trust level
// wallet > oidc_* > self_reported
const emailAttr = await fastify.repositories.userAttributes.findVerifiedByUserIdAndKey(
  userId,
  'email'
);
// Returns undefined if no verified email → omit claim from token
```

## Crypto

All signing, hashing, and key operations go through `libs/server/jwt/` and `libs/server/password/`.
Never implement crypto directly in TypeScript service code.
The `libs/server/password/` library wraps Argon2id for password hashing — use it via
the `passwordHasher` Fastify decorator. Do not call Argon2 directly.

## Phase Status

- Phase 1 (email/password + OAuth 2.1 / OIDC): COMPLETE after identifier-abstraction refactor
- Phase 2 (Developer Portal): IN PROGRESS — no new providers
- Phase 4 (WalletProvider + OID4VP 1.0): NOT YET STARTED. The mechanism is
  **OID4VP 1.0**, not SIOPv2 — HAIP 1.0 §5 mandates `response_type=vp_token`,
  which excludes the Self-Issued ID Token. Do not implement SIOPv2. See
  [ADR-004 § Spec status (2026-07-20)](../../../docs/adr/004-wallet-agnostic-federation.md);
  profile targeting is an open decision (#296).
- The `PasswordProvider` is permanent infrastructure, not a legacy path to be deprecated
