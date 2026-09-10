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
- `WalletProvider` (`provider_type: 'wallet'`) — T4, Epic #231 (checked 2026-08-31)
  - `libs/server/federation/src/providers/wallet.provider.ts`
  - **`verify()` throws unconditionally and must keep throwing.** That is a permanent
    fail-closed property, not a stage in an implementation — a stub resolving a
    placeholder `VerifiedIdentity` would be an authentication-bypass primitive. Never
    "finish" it, and never wire it into a login path. See `AGENTS.md`.
  - Wallet login itself **is merged**, flag-gated behind `WALLET_FEDERATION_ENABLED`
    (default off). It does **not** go through this provider: it runs on the dedicated
    `/ui/wallet-login` + `/oid4vp/response` seam
    (`apps/auth-server/src/app/routes/ui/wallet-login.ts`,
    `apps/auth-server/src/app/routes/oid4vp/response.ts`), validated end-to-end against a
    mock wallet on the `oid4vp-1.0-base` profile.
  - `extractAttributes()` is implemented (#235) and is the half of this provider that does
    real work.

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

Status below was checked against `origin/main` on **2026-08-31**. Re-derive it from the
tree rather than trusting this list — a stale "we don't do X" misdirects every agent that
loads this skill (ADR-007:319-327).

- Phase 1 (email/password + OAuth 2.1 / OIDC): COMPLETE after identifier-abstraction refactor
- Developer Portal: shipped (`apps/developer-portal`) — no new providers came with it
- T4 (OID4VP 1.0 wallet federation): the sign-in flow is **merged and flag-gated** behind
  `WALLET_FEDERATION_ENABLED` (default off), covering the OID4VP verifier, SD-JWT VC
  validation, key attestations, status-list revocation, the claims pipeline and the browser
  flow, with an E2E suite over first-time enrolment, returning login, account linking and
  `acr`. Validated only on the `oid4vp-1.0-base` profile against a mock wallet; the
  `haip-1.0` profile and real-wallet interop are still open (#377, #376). The mechanism is
  **OID4VP 1.0**, not SIOPv2 — HAIP 1.0 §5 mandates `response_type=vp_token`,
  which excludes the Self-Issued ID Token. Do not implement SIOPv2. See
  [ADR-004 § Spec status (2026-07-20)](../../../docs/adr/004-wallet-agnostic-federation.md);
  profile order is decided (#296 locked): `oid4vp-1.0-base` first, `haip-1.0` second.
- The `PasswordProvider` is permanent infrastructure, not a legacy path to be deprecated
