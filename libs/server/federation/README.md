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
- **it checks no revocation.** `assurance.statusChecked` is the literal `false`.
  The Token Status List checker below (#297) ships alongside this, but nothing
  calls it from the validation path yet.

`WalletProvider.verify()` therefore still fails closed. Every refusal is a
`PresentationValidationRejection`: a distinct server-side `reason` for logs, and
one non-enumerating `InvalidCredentialsError` on the wire via `toClientError()`.

A second credential format registers as ONE adapter in
`CREDENTIAL_FORMAT_ADAPTERS` — the request builder, the intake and the
validation dispatcher name no format.

## Credential revocation — Token Status List (#297)

`src/status/` implements HAIP §6.1 credential revocation over the IETF Token
Status List, pinned to **draft-14** (HAIP §9.4) in a single constant,
`TOKEN_STATUS_LIST_DRAFT`.

```typescript
import {
  createCredentialStatusChecker,
  createStatusListTrustAnchors,
  createStatusListUriAllowlist,
  createStatusEndpointBreaker,
} from '@qauth-labs/server-federation';

const checker = createCredentialStatusChecker({
  // x5c chains must terminate at one of these, and the anchor itself must NOT
  // appear in the chain (HAIP §6.1.1).
  trustAnchors: createStatusListTrustAnchors([operatorAnchorPem]),
  // SSRF boundary: the status list URI comes off an unverified credential.
  uriAllowlist: createStatusListUriAllowlist(['https://issuer.example/statuslists']),
  breaker: createStatusEndpointBreaker(),
  onAudit: (event) => request.log.info(event, 'credential status check'),
});

// Takes ONLY the credential's `status` claim. Throws the same non-enumerating
// InvalidCredentialsError as the issuer-trust path on anything but VALID.
await checker.assertCredentialNotRevoked(credentialClaims.status, {
  statusRequired: profile.requireCredentialStatus,
});
```

**Fail-closed, without exception.** An unreachable endpoint, an unverifiable
Status List Token, an unanchored status issuer, an out-of-range index, an
unknown status value and an open circuit are all _rejections_. There is no
timeout fallback and no stale-on-error path — every one of those would let an
attacker who can degrade a third party's availability un-revoke credentials.

Verified lists are cached for `min(ttl, exp, maxCacheTtlSeconds)` (default
ceiling 5 minutes), and concurrent lookups of the same URI are coalesced into
one fetch, so a wallet login is not an outbound HTTP round-trip.

Known limits, stated rather than implied: DNS rebinding against an allowlisted
hostname is not defended here (supply your own `fetch` over an
address-pinning agent); redirects are refused outright; the `x5c` chain is not
checked for revocation (CRL/OCSP), name constraints or policy OIDs.

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
