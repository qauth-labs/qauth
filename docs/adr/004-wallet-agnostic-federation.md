# ADR-004: Wallet-Agnostic VC Federation via SIOPv2/OID4VP

**Status:** Accepted
**Date:** 2026-03-11
**Authors:** QAuth Team

## Context

The eIDAS 2.0 regulation (EU 2024/1183) requires EU member states to provide EUDI-compliant digital identity wallets by December 2026. By December 2027, regulated EU businesses across banking, healthcare, transport, energy, and telecommunications must accept EUDI Wallet authentication. The EU's Web 4.0 strategy (COM(2023) 442) identifies portable, user-controlled digital identity as foundational infrastructure.

However, the ecosystem extends beyond EUDI. W3C Verifiable Credentials wallets exist across jurisdictions and use cases: Lissi (Germany), Sphereon (Netherlands), walt-id (Austria), and any future SIOPv2-compatible wallet. Enterprise identity use cases require trust registries and issuer validation that are not EUDI-specific.

QAuth's role is to serve as the OAuth 2.1 / OIDC bridge between any VC wallet and standard OAuth application stacks. A downstream application authenticating via QAuth receives standard tokens regardless of whether the user authenticated with a password, an EUDI wallet, or a third-party VC wallet.

## Decision

Implement wallet federation as a `WalletProvider implements CredentialProvider` in `libs/server/federation/`. The implementation is wallet-agnostic — it does not contain EUDI-specific code. Any SIOPv2/OID4VP-compatible wallet authenticates through the same interface.

The reference implementation for patterns and flows is [waltid-identity](https://github.com/walt-id/waltid-identity) (Kotlin). Key patterns to adopt:

- OID4VC presentation request construction
- Verifiable Presentation validation
- Claim extraction from Verifiable Credentials
- Trust registry integration for issuer validation

The Phase 4 implementation adds:

- `WalletProvider implements CredentialProvider` (type: `'wallet'`)
- SIOPv2 authorization request endpoint
- OID4VP Verifiable Presentation validation
- Trust registry integration (configurable per realm)
- `acr` claim in ID tokens carrying `VerifiedIdentity.assuranceLevel`
- Account linking: one `users.id`, multiple `user_credentials` rows

### Federation Model

```
[Any SIOPv2 Wallet] → OID4VP Presentation → QAuth WalletProvider
                                                        ↓
                                              VerifiedIdentity (DID sub, assurance level, raw VC claims)
                                                        ↓
                                              user_credentials row (provider_type='wallet', external_sub=DID)
                                              user_attributes rows (source='wallet', from VC claims)
                                                        ↓
                                              Standard OAuth 2.1 token (sub=users.id)
```

### Assurance Level Propagation

The `VerifiedIdentity.assuranceLevel` value (`'low'` | `'substantial'` | `'high'`, per eIDAS LoA and ISO 29115) is included in the ID token as the `acr` (Authentication Context Class Reference) claim when the authentication method produces a meaningful assurance level. Password credentials (`assuranceLevel: 'low'`) do not produce an `acr` claim — this is consistent with the OIDC Core specification's treatment of `acr` as an optional higher-assurance indicator.

### Account Linking

A user with an existing password account can link a wallet credential. This creates a second `user_credentials` row for the same `users.id`. Subsequent logins via either method return tokens with the same `sub` claim. The downstream application is unaware of the linking.

## Alternatives Considered

### EUDI-specific implementation

Build directly against EUDI Wallet architecture reference framework (ARF). Use EUDI-specific credential formats and trust registry.

Rejected because: locks QAuth to a single wallet ecosystem. Non-EU deployments (which represent the majority of potential self-hosted users) cannot use wallet federation. EUDI-specific code creates maintenance obligations tied to EU policy changes.

### Build a wallet ourselves

Include a W3C DID / VC issuance and storage wallet in the QAuth monorepo.

Rejected because: this is a separate product category. waltid-identity already implements this well in open source. QAuth's value is the OAuth 2.1 bridge layer — consuming VC presentations, not issuing or storing credentials. The scope would be incompatible with the MVP timeline and the NGI Zero grant narrative (which positions QAuth as the bridge, not the wallet).

## Consequences

### Positive

- Works with any SIOPv2-compatible wallet — EUDI, Lissi, Sphereon, walt-id, or any future implementation
- eIDAS 2.0 compliance is achievable without EUDI lock-in
- `acr` claim enables downstream applications to apply assurance-level-based access controls (e.g., require `acr=substantial` for sensitive operations)
- Account linking allows gradual migration from password to wallet authentication

### Negative

- SIOPv2/OID4VP adds protocol complexity to the authorization endpoint
- Trust registry integration requires per-realm configuration
- Wallet authentication requires user-side wallet app — cannot be a drop-in replacement for users without wallets

### Neutral

- `PasswordProvider` remains a first-class authentication method alongside wallet providers
- eIDAS compliance is an emergent property of supporting the right protocols, not a hardcoded feature

## Related

- [ADR-002: Identifier Abstraction](./002-identifier-abstraction.md)
- [ADR-003: CredentialProvider Abstraction](./003-credential-provider-interface.md)
- [waltid-identity Reference Implementation](https://github.com/walt-id/waltid-identity)
- [OpenID for Verifiable Presentations (OID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
- [eIDAS 2.0 (EU 2024/1183)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1183)
