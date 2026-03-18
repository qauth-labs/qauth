# ADR-003: CredentialProvider Abstraction for Authentication Methods

**Status:** Accepted
**Date:** 2026-03-11
**Authors:** QAuth Team

## Context

Phase 1 authentication logic (password verification, email claim extraction) is implemented directly in the auth service routes. Login looks up a user by email, verifies the password hash, and builds JWT claims from the user record. This works for a single authentication method, but it cannot accommodate multiple methods without expanding the service layer with provider-specific conditionals.

Phase 4 adds wallet federation (SIOPv2 / OID4VP). Phase 6+ adds external OIDC federation. Each addition would require changes to the authentication core — adding new conditionals, new lookup paths, new claim extraction rules — if the core is not abstracted.

## Decision

Define a `CredentialProvider` interface in `libs/server/federation/`. Every authentication method implements this interface. The authentication engine calls `provider.verify()` and receives a `VerifiedIdentity`. It does not contain provider-specific logic.

```typescript
// libs/server/federation/src/providers/credential-provider.interface.ts

export type AssuranceLevel = 'low' | 'substantial' | 'high'; // eIDAS LoA / ISO 29115

export interface VerifiedIdentity {
  externalSub: string;
  assuranceLevel: AssuranceLevel;
  rawClaims: Record<string, unknown>;
}

export interface UserAttribute {
  source: string;
  attrKey: string;
  attrValue: string;
  verified: boolean;
  expiresAt?: Date;
}

export interface CredentialProvider {
  readonly type: string;
  verify(input: unknown): Promise<VerifiedIdentity>;
  extractAttributes(result: VerifiedIdentity): UserAttribute[];
}
```

The `PasswordProvider` is the Phase 1 implementation:

- `type = 'password'`
- `verify()` accepts `{ email, passwordHash, emailVerified }`, returns `VerifiedIdentity` with `assuranceLevel: 'low'`
- `extractAttributes()` returns the email attribute with the appropriate `verified` flag and `source: 'self_reported'`

The auth engine flow is:

1. Determine `provider_type` from the request (Phase 1: always `'password'`)
2. Look up the appropriate `CredentialProvider` from the registry
3. Call `provider.verify(input)` → `VerifiedIdentity`
4. Upsert `user_attributes` rows from `provider.extractAttributes(identity)`
5. Issue JWT with `sub = users.id`, `email` from verified attributes if present

### Phase 4 Extension

Adding `WalletProvider` does not change the auth engine. It is a new `CredentialProvider` implementation:

- `type = 'wallet'`
- `verify()` validates a Verifiable Presentation per OID4VP
- `extractAttributes()` extracts claims from Verifiable Credentials into `user_attributes` rows with `source: 'wallet'`

The engine calls the same interface. The only change is registering the new provider.

### Provider Placement

All providers live in `libs/server/federation/`:

```
libs/server/federation/
  src/
    providers/
      credential-provider.interface.ts
      password.provider.ts
      # Phase 4: wallet.provider.ts
      # Phase 6+: oidc-federation.provider.ts
    index.ts
```

## Alternatives Considered

### Switch/case on provider_type in the service layer

Service code checks `if (providerType === 'password') { ... } else if (providerType === 'wallet') { ... }`.

Rejected because: each new provider requires modifying the auth engine. Violates the Open/Closed Principle. Makes the service layer a growing accumulation of credential-specific logic rather than a stable flow.

### Plugin registry pattern with dynamic discovery

Providers register themselves via a plugin system at startup. The auth engine discovers providers from the registry by type string.

Rejected for MVP because: adds runtime complexity and late binding for no benefit when the set of providers is known at build time. Can be layered on top of the interface pattern in Phase 3 if needed.

## Consequences

### Positive

- Auth engine is stable across provider additions
- Each provider is independently testable
- Assurance level (`acr` claim) is a property of `VerifiedIdentity`, naturally propagated without service-layer conditionals
- `PasswordProvider` is a first-class peer of future providers — not a legacy path

### Negative

- Phase 1 password auth is split across two layers (service routes + provider) where it was previously consolidated in the route
- Interface adds one level of indirection for the simplest case

### Neutral

- Standard strategy pattern — well-understood by TypeScript developers

## Related

- [ADR-002: Identifier Abstraction](./002-identifier-abstraction.md)
- [ADR-004: Wallet-Agnostic VC Federation](./004-wallet-agnostic-federation.md)
