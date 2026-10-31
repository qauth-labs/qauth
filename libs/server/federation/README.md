# @qauth-labs/server-federation

Federation layer for the QAuth OAuth 2.1 authorization server.

## Overview

QAuth is a **federated identity platform**: upstream identity sources
(email/password, Verifiable Credential wallets behind the default-off
`WALLET_FEDERATION_ENABLED`, and external OIDC providers, which are not built
yet) plug in through the `CredentialProvider` interface, while downstream apps receive
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

> **Status (2026-07-31):** this is no longer interface-and-registry only — an
> earlier revision said so, and that is superseded. Shipping here now:
>
> - `providers/` — **`PasswordProvider`** (#228), live on the production login
>   path, and **`WalletProvider`** (#232), whose `verify()` throws
>   unconditionally **by design** and must keep doing so. Wallet login does not
>   go through it; it runs on the auth-server's own OID4VP seam.
> - `oid4vp/` — OID4VP 1.0 request generation, `direct_post` intake and SD-JWT VC
>   presentation validation (#233, #234)
> - `claims/` — VC claims normalization and the ADR-002 attribute trust order
>   (#235)
> - `trust/`, `x509/` — per-realm issuer trust registry and chain validation
>   (#236)
> - `status/` — Token Status List revocation checking (#297)
> - `attestation/` — HAIP Interoperable Key Attestations (#308)
> - `assurance/` — eIDAS level-of-assurance resolution feeding the `acr` claim
>   ([ADR-010](../../../docs/adr/010-acr-assurance-mapping.md), #237)
> - `subject/` — configurable `SubjectResolutionStrategy` and account linking
>   (#300, #238)
> - `profiles/` — the `VerifierProfile` abstraction (#299)
> - `providers/webauthn.provider.ts` and `webauthn/` — the **`WebAuthnProvider`**
>   (#467) and the relying-party ID rules, below
> - `auth-method/` — the **AuthMethod contract** (#599), EXPERIMENTAL: the
>   plugin API of ADR-018 §4. `AuthMethod` extends `CredentialProvider` with an
>   `id`, the contract version, display data, a config schema, the steps it
>   contributes, the routes it mounts under `/upstream/<type>` and `start()`;
>   the engine's checks around it (`startUpstreamStep`, `completeUpstreamStep`),
>   the context a method is handed (`createAuthMethodContext`) and the contract
>   test kit (`checkAuthMethod`). See
>   [the docs page](../../../apps/docs-site/src/content/docs/extend/auth-method-contract.md).

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
  // #297: the revocation gate. The process-wide checker, plus the profile's
  // posture copied verbatim — see "Credential revocation" below.
  credentialStatus: statusChecker,
  requireCredentialStatus: profile.requireCredentialStatus,
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
- **it checks revocation only when you wire it.** Pass `credentialStatus` and the
  Token Status List gate below (#297) runs inside validation, as the last gate of
  all, and `assurance.statusChecked` is `'checked'` when a bit was read and said
  `VALID`. Omit it and the value is `'not-required'` — nobody looked. Omitting it
  under a profile whose `requireCredentialStatus` is `true` is not a pass: it is
  refused as `credential-status-unestablished`, because a mandate no code can
  satisfy must not resolve to "accepted".

`WalletProvider.verify()` therefore still fails closed. Every refusal this layer
reaches itself is a `PresentationValidationRejection`: a distinct server-side
`reason` for logs, and one non-enumerating `InvalidCredentialsError` on the wire
via `toClientError()`. The status checker's own refusals propagate unwrapped —
they are already that same `InvalidCredentialsError`, and their precise reason is
deliberately kept off the error and delivered to `onAudit` instead.

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

// ONCE per process, never per request: the cache, the in-flight coalescing map
// and the breaker are properties of THIS instance.
const statusChecker = createCredentialStatusChecker({
  // x5c chains must terminate at one of these, and the anchor itself must NOT
  // appear in the chain (HAIP §6.1.1).
  trustAnchors: createStatusListTrustAnchors([operatorAnchorPem]),
  // SSRF boundary: the status list URI comes off an unverified credential.
  uriAllowlist: createStatusListUriAllowlist(['https://issuer.example/statuslists']),
  breaker: createStatusEndpointBreaker(),
  // The ONLY place the fine-grained reason surfaces. Server-side log only: the
  // event carries the status list URI and index, which the wallet chose.
  onAudit: (event) => logger.info(event, 'credential status check'),
});
```

Hand it to `validatePresentations` (above) rather than calling it yourself:

```typescript
await validatePresentations(presentations, state.dcqlQuery, {
  /* ...bindings... */
  credentialStatus: statusChecker,
  requireCredentialStatus: profile.requireCredentialStatus,
});
```

The gate then runs inside the format adapter, **after** the Issuer-signed JWS has
verified and after Key Binding — a status list URI read from an unverified
payload is an SSRF primitive — and it is the only thing that makes
`assurance.statusChecked` truthful, since the adapter freezes that object. The
checker itself still takes only the `status` claim, as `unknown`; the adapter
receives the interface, not the implementation.

In `apps/auth-server` none of this is assembled by hand. The two operator
variables `OID4VP_STATUS_LIST_TRUST_ANCHORS` (or its `_PATH` sibling) and
`OID4VP_STATUS_LIST_URI_ALLOWLIST` are turned into the checker above by
`createConfiguredCredentialStatusChecker`
(`@qauth-labs/fastify-plugin-federation`), which passes a real breaker and is
called once from `resolveWalletVerificationSetup`. Configuring exactly one of the
two fails the boot, and so does selecting a profile whose
`requireCredentialStatus` is `true` with neither configured
(`assertCredentialStatusProvisioned`) — a mandate nothing can satisfy must not
become a deployment that boots and then refuses every login (#378).

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

## WebAuthn — passkeys (#467)

The one WebAuthn `CredentialProvider` QAuth has
([ADR-017](../../../docs/adr/017-first-party-login.md) Decision 14, phase F2b):
first-party sign-in, the hosted account pages, admin sign-in and the Authority
Tree approval all use it. The deployment switch `WEBAUTHN_ENABLED` stays refused
at boot until F2b's ceremonies land, so nothing calls it yet.

- `provider_type` is `webauthn` and `external_sub` is the credential id
  (base64url). `credential_data` holds the COSE public key, its algorithm, the
  sign counter, transports, the BE and BS backup flags, the AAGUID, the RP ID,
  the user handle, a nickname and timestamps (`webauthnCredentialDataSchema`).
- Ceremonies are two rounds around ADR-003's single-shot `verify()`:
  `startRegistration` / `finishRegistration` for enrolment, and
  `startAuthentication` then `verify()` for an assertion. Options ask for
  `attestation: "none"` and the algorithms EdDSA, ES256 and RS256 only.
- Each ceremony's state (challenge, RP ID, origins, purpose) is stored under its
  transaction through the `WebAuthnChallengeStore` port and taken atomically
  before an answer is checked, so a challenge answers once and only for its
  transaction.
- Sign-in requires the UV flag; a second factor requires UP only. A sign
  counter that does not grow past a nonzero stored one is flagged
  (`sign_counter_regressed`), not refused.
- Every refusal is a `WebAuthnRejection` whose `reason` is for logs only.

The WebAuthn library, `@simplewebauthn/server` (pinned exactly), sits behind the
`WebAuthnVerifier` port (`webauthn/simplewebauthn-verifier.ts`); nothing else
imports it, so moving verification to the Rust core (ADR-018 §6) replaces one
adapter. The adapter checks the ceremony itself, each step with its own reason,
before the library does the CBOR, COSE, attestation and signature work.

`webauthn/relying-party-id.ts` holds the RP ID rules of
[ADR-019](../../../docs/adr/019-deployment-topology-and-trust-boundaries.md)
Decision 2: the realm's exact host by default, a parent domain only with the
operator's opt-in (`allowParentDomainRpId`), returned with a warning, and a lock
once the realm has a passkey. A parent domain must cover the realm host on a
label boundary and must not be a public suffix. The Public Suffix List comes
from `tldts`, private section included as browsers read it, because no
hand-written rule tells `co.uk` from `example.com`. The realm row stores the RP
ID and its lock; `resolveRpId(realm)` and `expectedOrigin(realm)` in
`@qauth-labs/shared-validation` read them (#553).

The unit tests run the WebAuthn Level 3 §16 test vectors
(`testing/webauthn-w3c-vectors.fixture.ts`, copied from the specification).

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
