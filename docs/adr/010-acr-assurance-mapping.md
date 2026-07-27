# ADR-010: eIDAS Level of Assurance → OIDC `acr` Value Mapping

**Status:** Accepted
**Date:** 2026-07-27
**Authors:** QAuth Team

## Context

[ADR-004](./004-wallet-agnostic-federation.md) decided that
`VerifiedIdentity.assuranceLevel` (`'low'` | `'substantial'` | `'high'`, eIDAS
LoA / ISO 29115) is carried downstream as the OIDC `acr` (Authentication Context
Class Reference) claim, and that `'low'` credentials produce no `acr` claim at
all. Its 2026-07-20 correction then changed the **input** to that decision: with
no wallet-signed identity assertion, the level must be derived from the presented
credential and its issuer.

Two questions were left open, and issue #237 required both to be settled before
any string was emitted:

1. **What value does QAuth actually put in `acr`?** The issue explicitly framed
   this as research, not naming: are there registered URI values for eIDAS LoA
   `substantial` / `high`, and what is a conformant `acr` value for these levels?
2. **Where does the level come from,** given that neither the protocol nor the
   credential carries one?

### What the research found

**There is no registered `acr` value for an eIDAS Level of Assurance.** RFC 6711
establishes an IANA registry for "Level of Assurance Profiles"/`acr` values; no
eIDAS entry could be confirmed in it, and no OIDF-registered eIDAS `acr` URI could
be confirmed either. Two conventions exist in practice and neither is normative:

- the **eIDAS SAML-era URIs** — `http://eidas.europa.eu/LoA/low`,
  `.../substantial`, `.../high` — defined by the eIDAS SAML attribute profile and
  widely reused by national eID nodes;
- **bare LoA names** — `low` / `substantial` / `high` — common in national
  eID→OIDC bridges.

OIDC Core 1.0 §2 says of `acr`: _"An absolute URI or an RFC 6711 registered name
SHOULD be used as the `acr` value; registered names MUST NOT be used with a
different meaning than that which is registered."_ A bare `high` is neither an
absolute URI nor a registered name; the eIDAS URI form is an absolute URI.

**The level does not arrive in the protocol.** OID4VP 1.0 §5 fixes the response
type to `vp_token`, so there is no wallet-signed assertion for a level to travel
in. HAIP 1.0 §1 says the same from the other direction, verbatim: _"This
specification fulfils some, but not all, of the requirements to meet the 'High'
Level of Assurance (LoA) as defined in the eIDAS Regulation … these features must
be combined with additional measures outside of the scope of HAIP to achieve LoA
High compliance."_ A Level of Assurance is a property of the ecosystem — identity
proofing, wallet certification, secure cryptographic device — not of a message.

**`acr` is not the place for claim provenance.** Which trust framework vouched
for which individual attribute belongs in OIDC Identity Assurance
`verified_claims` (`trust_framework`, `assurance_level`). `acr` describes the
authentication **event**. Overloading it would make the claim mean two things at
once and would break Relying Parties that compare it literally.

## Decision

### 1. The emitted `acr` value is a deployment choice from a closed set of two

`ACR_VALUE_STYLE` selects the vocabulary:

| Style                 | `substantial`                            | `high`                            |
| --------------------- | ---------------------------------------- | --------------------------------- |
| `eidas-uri` (default) | `http://eidas.europa.eu/LoA/substantial` | `http://eidas.europa.eu/LoA/high` |
| `loa-name`            | `substantial`                            | `high`                            |

The default is `eidas-uri` because OIDC Core §2 asks for an absolute URI and
because a URI cannot be mistaken for a registered name that means something else.
The `http:` scheme is quoted verbatim: these are identifiers, nothing
dereferences them, and rewriting them to `https:` produces strings no
eIDAS-aware Relying Party recognises.

**There is no free-text option.** An arbitrary operator-supplied string could
collide with an RFC 6711 registered name while meaning something else, which OIDC
Core §2 forbids. A closed set of two documented vocabularies keeps the emitted
value reviewable.

These values are **QAuth-selected, not standard**. A deployment that must emit an
ecosystem-specific value its Relying Parties already consume should say so on an
issue; widening the set is a deliberate edit to one table, pinned by a cross-lib
test.

### 2. `'low'` emits no `acr` claim

Unchanged from ADR-003/ADR-004 and restated here because it is the invariant the
whole feature rests on. A password login is `'low'` and its ID token carries no
`acr` at all. OIDC Core treats `acr` as an optional higher-assurance indicator, so
its **absence** is meaningful: a Relying Party may gate on presence. Emitting
`.../LoA/low` for every password login would tell every RP that every password
session is assured.

Consequently `'low'` is not a configurable level, and the
`authorization_codes.assurance_level` column stores `NULL` — never `'low'` — for
an unassured authentication, so "no assurance" has exactly one representation
from the browser session to the token.

### 3. The level is derived from the issuer, under operator configuration

`OID4VP_ISSUER_ASSURANCE` maps, **per realm**, an issuer identifier (and
optionally a set of `vct` values) to `substantial` or `high`. The derivation runs
`resolveCredentialAssurance` over the `ValidatedCredential` #234 produced, and
**after** #236's `assertIssuerTrusted` gate has thrown for an untrusted issuer.

That ordering is load-bearing. An untrusted issuer and an unassured trusted issuer
both resolve to `'low'`, so running the assurance step first would let a caller
read "authenticated at low assurance" where the correct answer is "not
authenticated at all". The gate throws; the derivation returns.

Trust and assurance are **separate variables** (`OID4VP_TRUSTED_ISSUERS` vs
`OID4VP_ISSUER_ASSURANCE`), so neither answer can be read out of the other. An
issuer must appear in both to produce an assured session.

### 4. The value is rendered at issuance, not at code-mint time

The authorization code stores the internal LEVEL; `/oauth/token` renders it into
the configured vocabulary. Storing the rendered string would freeze in-flight
codes into whichever vocabulary was configured when they were minted, so a config
change would be observable as two different `acr` values for the same level.

### 5. Key attestations are a documented seam, not a hard-coded assumption

eIDAS LoA `high` requires a secure cryptographic device, which is a property of
the wallet's key store and cannot be observed from a credential. HAIP §9.2 key
attestations are how a wallet proves it, and their validation is issue #308.

`resolveCredentialAssurance` therefore accepts an optional `AssuranceEvidence`
carrying a `KeyStorageAssurance`, and a policy entry may set
`requiresKeyStorage: 'hardware'`. Until #308 lands nothing produces that evidence,
so such an entry can never grant — fail-closed by construction. When #308 lands it
populates the field at the call site and the entry starts being satisfiable, with
no change to this module or to any consumer.

## Consequences

### Positive

- Downstream applications can gate on `acr` presence (any assured session) or on
  a specific value (eIDAS `high` for a sensitive operation), and the absence of
  the claim is a reliable signal rather than an omission.
- Deployments whose Relying Parties already consume bare LoA names are supported
  without QAuth inventing a third vocabulary.
- No unearned assurance: every path that cannot positively establish a level
  resolves to `'low'`, and `'low'` is indistinguishable from a password login.
- The `acr` emission logic is profile-independent — it operates on a resolved
  level — so it behaves identically under `oid4vp-1.0-base` and `haip-1.0`.

### Negative

- Assurance is operator configuration, so a misconfigured deployment can assert a
  level its issuers do not actually operate at. QAuth cannot verify the claim; it
  can only refuse to invent one.
- The emitted values are not standard, so a Relying Party integrating against a
  QAuth deployment must be told which vocabulary it uses.
- Two vocabularies means two strings for one level across the ecosystem. This is a
  property of the ecosystem, not of this decision; a registered value would
  supersede both.

### Neutral

- Claim provenance stays out of scope. If OIDC Identity Assurance
  `verified_claims` is ever needed, it is a separate surface and a separate ADR.
- Credential status (#297) is not yet an input to the assurance decision. Wiring
  revocation checking into the level — e.g. refusing `high` for a credential whose
  status was never checked — is a tightening this ADR anticipates but does not
  make, because `CredentialAssuranceSignal.statusChecked` is still the literal
  `false`.

## Related

- [ADR-003: CredentialProvider Abstraction](./003-credential-provider-interface.md) — `'low'` carries no `acr`
- [ADR-004: Wallet-Agnostic VC Federation via OID4VP](./004-wallet-agnostic-federation.md) — the original `acr` decision and its 2026-07-20 correction
- [ADR-009: Wallet Account Resolution](./009-wallet-account-resolution.md)
- [OpenID Connect Core 1.0 §2](https://openid.net/specs/openid-connect-core-1_0.html) — the `acr` claim
- [RFC 6711](https://www.rfc-editor.org/rfc/rfc6711) — IANA Level of Assurance Profiles registry
- [OID4VP 1.0 (Final, 2025-07-09)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) — §5 response type MUST be `vp_token`
- [HAIP 1.0 (Final, 2025-12-24)](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) — §1 LoA scope statement, §9.2 key attestations
- Issues: #237 (this ADR), #234 (presentation validation), #236 (issuer trust), #308 (key attestations), #297 (credential status)
