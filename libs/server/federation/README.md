# @qauth-labs/server-federation

Federation layer for the QAuth OAuth 2.1 authorization server.

## Overview

QAuth is a **federated identity platform**: upstream identity sources
(email/password, OIDC providers, and — later — Verifiable Credential wallets)
plug in through the `CredentialProvider` interface, while downstream apps receive
only standard OAuth 2.1 access tokens and OIDC ID tokens.

This library defines that abstraction (see
[ADR-003](../../../docs/adr/003-credential-provider-interface.md)):

- **`CredentialProvider`** — the strategy interface every authentication method
  implements. The auth engine resolves a provider by `type`, calls `verify()`,
  and upserts the attributes from `extractAttributes()`; it contains no
  provider-specific logic, so new providers are added without engine changes.
- **`VerifiedIdentity` / `UserAttribute` / `AssuranceLevel`** — the normalized
  types a provider returns.
- **`ProviderRegistry`** — a `type` → `CredentialProvider` lookup, created via
  `createProviderRegistry()` and populated from config/DI at auth-server
  bootstrap.

> **Status:** interface + registry only. No concrete provider ships here —
> `PasswordProvider` (#228) and `WalletProvider` (#232) implement
> `CredentialProvider` in follow-up work.

## Usage

```typescript
import { createProviderRegistry, type CredentialProvider } from '@qauth-labs/server-federation';

// At auth-server bootstrap, seed the registry from the configured providers:
const registry = createProviderRegistry([passwordProvider /*, walletProvider */]);

// The auth engine resolves by type and delegates verification:
const provider: CredentialProvider = registry.resolve('password');
const identity = await provider.verify(input);
```

`register()` and `createProviderRegistry([...])` fail fast with
`ProviderAlreadyRegisteredError` on a duplicate `type`; `resolve()` throws
`ProviderNotRegisteredError` for an unregistered `type`. Both come from
`@qauth-labs/shared-errors`.

## OID4VP presentation validation (#234)

`oid4vp/` carries the wallet-federation protocol layer: request generation and
`direct_post` intake (#233), and — since #234 — cryptographic validation of the
returned `vp_token`.

```typescript
import {
  createStaticIssuerKeyResolver,
  parseVpToken,
  validatePresentations,
} from '@qauth-labs/server-federation';

// #233: correlate the response and parse it STRUCTURALLY.
const presentations = parseVpToken(rawVpToken, state.dcqlQuery, profile.credentialFormats);

// #234: validate it CRYPTOGRAPHICALLY.
const credentials = await validatePresentations(presentations, state.dcqlQuery, {
  clientId, // the KB-JWT `aud` must equal this
  nonce: state.nonce, // the KB-JWT `nonce` must equal this
  signatureAlgorithms: ['ES256'], // caller-pinned allowlist (HAIP §7)
  permittedFormats: profile.credentialFormats,
  resolveIssuerKey: createStaticIssuerKeyResolver(configuredIssuerKeys),
});
```

Validation proves the issuer signature, every selective-disclosure digest, the
credential's validity window and holder binding to this exact request. It
produces a `ValidatedCredential` — a **cryptographic finding, not an identity**:

- **it does not decide trust.** `ValidatedCredential.issuer` is the
  `ValidatedIssuer` #236's `assertIssuerTrusted` consumes;
- **it resolves no subject.** There is no protocol-guaranteed stable wallet
  subject identifier ([ADR-009](../../../docs/adr/009-wallet-account-resolution.md)),
  and wallet key material must never become one — the holder's `cnf` key and the
  raw `iss` are stripped from the returned claims;
- **it checks no revocation.** `assurance.statusChecked` is the literal `false`
  until Token Status List support (#297) lands.

`WalletProvider.verify()` therefore still fails closed. Every refusal is a
`PresentationValidationRejection`: a distinct server-side `reason` for logs, and
one non-enumerating `InvalidCredentialsError` on the wire via `toClientError()`.

A second credential format registers as ONE adapter in
`CREDENTIAL_FORMAT_ADAPTERS` — the request builder, the intake and the
validation dispatcher name no format.

## Installation

This library is part of the QAuth monorepo and is automatically available to
other projects within the workspace.

## Development

### Running unit tests

```bash
pnpm nx test server-federation
```

### Type-checking

```bash
pnpm nx typecheck server-federation
```

## License

Apache-2.0
