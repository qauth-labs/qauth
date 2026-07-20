# ADR-004: Wallet-Agnostic VC Federation via OID4VP

**Status:** Accepted
**Date:** 2026-03-11
**Authors:** QAuth Team

> **Implementation status (2026-06-24):** Accepted as design; not implemented. Deferred per [ADR-007](./007-mcp-first-positioning.md) to the long-term platform; gated on the [ADR-002](./002-identifier-abstraction.md) migration.
>
> **Spec refresh (2026-07-19): this ADR predates the finalisation of its own core specs and MUST NOT be implemented as originally written.** It was authored 2026-03-11, before OpenID for Verifiable Presentations reached Final. See [Spec status](#spec-status-2026-07-19) — the credential query mechanism changed, and an interoperability profile now exists that this ADR does not name.
>
> **Correction (2026-07-20): SIOPv2 is not the wallet authentication mechanism, and the 2026-07-19 refresh was wrong to say it was.** See [Spec status (2026-07-20)](#spec-status-2026-07-20), which supersedes that statement and records the OID4VP 1.0 / HAIP 1.0 corrections. Open questions arising from it are tracked in issue #296 and are **not** decided here.

## Context

The eIDAS 2.0 regulation (EU 2024/1183) requires EU member states to provide EUDI-compliant digital identity wallets by December 2026. By December 2027, regulated EU businesses across banking, healthcare, transport, energy, and telecommunications must accept EUDI Wallet authentication. The EU's Web 4.0 strategy (COM(2023) 442) identifies portable, user-controlled digital identity as foundational infrastructure.

However, the ecosystem extends beyond EUDI. W3C Verifiable Credentials wallets exist across jurisdictions and use cases: Lissi (Germany), Sphereon (Netherlands), walt-id (Austria), and any future OID4VP-compatible wallet. Enterprise identity use cases require trust registries and issuer validation that are not EUDI-specific.

QAuth's role is to serve as the OAuth 2.1 / OIDC bridge between any VC wallet and standard OAuth application stacks. A downstream application authenticating via QAuth receives standard tokens regardless of whether the user authenticated with a password, an EUDI wallet, or a third-party VC wallet.

## Decision

Implement wallet federation as a `WalletProvider implements CredentialProvider` in `libs/server/federation/`. The implementation is wallet-agnostic — it does not contain EUDI-specific code. Any OID4VP-compatible wallet authenticates through the same interface.

The reference implementation for patterns and flows is [waltid-identity](https://github.com/walt-id/waltid-identity) (Kotlin). Key patterns to adopt:

- OID4VP credential request construction — **as DCQL**, see [Spec status](#spec-status-2026-07-19)
- Verifiable Presentation validation
- Claim extraction from Verifiable Credentials
- Trust registry integration for issuer validation

The Phase 4 implementation adds:

- `WalletProvider implements CredentialProvider` (type: `'wallet'`)
- OID4VP authorization request endpoint — see [Spec status](#spec-status-2026-07-20)
- OID4VP Verifiable Presentation validation
- Trust registry integration (configurable per realm)
- `acr` claim in ID tokens carrying `VerifiedIdentity.assuranceLevel`
- Account linking: one `users.id`, multiple `user_credentials` rows

### Federation Model

```
[Any OID4VP Wallet] → OID4VP Presentation → QAuth WalletProvider
                                                        ↓
                                              VerifiedIdentity (DID sub, assurance level, raw VC claims)
                                                        ↓
                                              user_credentials row (provider_type='wallet', external_sub=DID)
                                              user_attributes rows (source='wallet', from VC claims)
                                                        ↓
                                              Standard OAuth 2.1 token (sub=users.id)
```

> **Correction (2026-07-20):** the `DID sub` / `external_sub=DID` element of this
> 2026-03-11 model does not survive the spec corrections below — OID4VP 1.0
> provides no stable subject identifier by design. The diagram is retained as the
> original record; see [Spec status (2026-07-20) § Subject identity](#subject-identity-there-is-no-stable-wallet-identifier).
> The replacement strategy is OPEN, tracked in #296.

### Assurance Level Propagation

The `VerifiedIdentity.assuranceLevel` value (`'low'` | `'substantial'` | `'high'`, per eIDAS LoA and ISO 29115) is included in the ID token as the `acr` (Authentication Context Class Reference) claim when the authentication method produces a meaningful assurance level. Password credentials (`assuranceLevel: 'low'`) do not produce an `acr` claim — this is consistent with the OIDC Core specification's treatment of `acr` as an optional higher-assurance indicator.

> **Correction (2026-07-20):** this decision stands, but its **input** changes.
> There is no wallet-signed ID token to read an assurance level from, so
> `assuranceLevel` must be derived from the presented credential and its issuer.
> See [Spec status (2026-07-20) § Assurance level](#assurance-level-derives-from-the-credential-not-from-a-wallet-signed-token) (#237).

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

- Works with any OID4VP-compatible wallet — EUDI, Lissi, Sphereon, walt-id, or any future implementation
- eIDAS 2.0 compliance is achievable without EUDI lock-in
- `acr` claim enables downstream applications to apply assurance-level-based access controls (e.g., require `acr=substantial` for sensitive operations)
- Account linking allows gradual migration from password to wallet authentication

### Negative

- OID4VP adds protocol complexity to the authorization endpoint
- Trust registry integration requires per-realm configuration
- Wallet authentication requires user-side wallet app — cannot be a drop-in replacement for users without wallets

### Neutral

- `PasswordProvider` remains a first-class authentication method alongside wallet providers
- eIDAS compliance is an emergent property of supporting the right protocols, not a hardcoded feature

## Spec status (2026-07-19)

This ADR was written 2026-03-11 against then-draft specifications. All of them
have since reached Final, and the ecosystem moved in ways that change what an
implementation should target. Recorded here rather than silently rewriting the
2026-03-11 decision.

### DCQL replaces Presentation Exchange

**OID4VP 1.0 is Final**, and its credential query mechanism is **DCQL** (Digital
Credentials Query Language) — a JSON-encoded query language that replaced the
earlier `presentation_definition` model from OID4VP Draft 22 (October 2024).

DIF **Presentation Exchange** remains a `PRE-DRAFT` specification and has been
operationally superseded for OID4VP flows. An implementation built on
`presentation_definition` today would target the pre-1.0 model.

**Consequence:** the `WalletProvider` presentation-request path MUST be built on
DCQL. QAuth carries no DIF Presentation Exchange dependency in code today, so
there is nothing to unwind — this is a forward constraint, not a migration.

### HAIP 1.0 is the profile eIDAS aligns to

This ADR's Context is entirely eIDAS-driven, but it names no interoperability
profile. **OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0** is now
published and is the profile the EUDI ecosystem aligns to. Generic "OID4VP
support" does not imply HAIP conformance — HAIP constrains credential formats,
cryptographic suites, and client authentication beyond base OID4VP.

**Consequence:** the eIDAS claim in Consequences ("eIDAS 2.0 compliance is
achievable without EUDI lock-in") should be re-stated against HAIP, which is the
testable form of that claim. HAIP 1.1 is an adopted work item with a planned
publication date of 2026-12-21.

> **Correction (2026-07-20):** whether QAuth targets HAIP at all is **OPEN**
> (#296). The consequence above describes the testable _form_ of the eIDAS
> claim; it is not a commitment to conform.

### Certification now exists for these specs

OIDF **self-certification** for OID4VP 1.0, OID4VCI 1.0 and HAIP 1.0 opened
2026-02-26, with accredited third-party labs from Q2 2026. Wallet federation is
therefore no longer a claim QAuth would have to self-assert — it is certifiable.
Sequenced behind OP certification (#286), which is achievable against what is
already built.

### OpenID Federation is Final and strategically adjacent

**OpenID Federation 1.0** was approved Final 2026-02-17; **1.1** followed in May
2026, separating protocol-independent federation from the OpenID Connect-specific
parts. Nine-country interoperability has been demonstrated.

This is directly relevant to the trust-registry problem this ADR defers to
"per-realm configuration": OpenID Federation's multi-path trust chains are the
standardised answer to wallet–issuer trust **without a central registry**, which
is precisely the open problem raised at the OIDF-Japan academic credentials
roundtable (2026-07-15). Worth its own ADR rather than being folded in here.

### Unchanged — first clause SUPERSEDED 2026-07-20

> **The paragraph below is retained verbatim because it is wrong, and the error
> is worth keeping traceable.** Its first clause is the root cause of issue #295:
> it propagated into nine issues (#233–#240 under epic #231) before being caught.
> Superseded by [Spec status (2026-07-20)](#spec-status-2026-07-20).
>
> ~~SIOPv2 remains the self-issued-OP mechanism this ADR describes~~, and the
> `CredentialProvider` bridge design is unaffected. The decision to be a bridge
> rather than a wallet or issuer still holds.

The second and third clauses stand unchanged: the `CredentialProvider` bridge
design is unaffected, and the decision to be a bridge rather than a wallet or
issuer still holds. Only the mechanism claim is withdrawn.

## Spec status (2026-07-20)

The [2026-07-19 refresh](#spec-status-2026-07-19) was right that this ADR must
not be implemented as written, and right to name HAIP 1.0. Its "Unchanged"
paragraph was wrong. This section supersedes that paragraph and records the
corrections against the Final specifications.

Inline occurrences of "SIOPv2" in the 2026-03-11 title, Context, Decision and
Consequences above were corrected to OID4VP on this date — the title became
"Wallet-Agnostic VC Federation via OID4VP", and the ADR index row in
[`./README.md`](./README.md) was updated to match. Nothing else in the
2026-03-11 text was reworded; where a decision is contradicted rather than
misnamed, the original wording is kept and annotated in place.

### HAIP 1.0 excludes SIOPv2 — it does not merely omit it

**OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0** (Final,
published 2025-12-24, OIDF Digital Credentials Protocols WG) forecloses the
self-issued mechanism. §5 states verbatim:

> The Response type MUST be `vp_token`.

`vp_token` is the presentation-only Response Type. The alternative that carries
a Self-Issued ID Token — `vp_token id_token`, OID4VP 1.0 §8, which returns "a
Self-Issued ID Token as defined in [SIOPv2]" — is therefore unavailable under
the profile. Consistently, across the whole of HAIP 1.0 the strings `SIOP`,
`Self-Issued` and `id_token` each occur **zero** times.

SIOPv2 is itself **draft 13** (published 2023-11-28, OIDF **Connect** WG — a
different working group from the one that owns OID4VP, OID4VCI and HAIP) and has
never reached Final. OID4VP 1.0 §13.4 "Pre-Final Specifications" lists "SIOPv2
draft -13" among its own non-final dependencies, and OID4VP retains it only as
an optional combination in Appendix C ("Combining this specification with
SIOPv2"), reachable solely through the `vp_token id_token` Response Type that
HAIP forbids.

**Consequence:** the wallet authentication mechanism is **OID4VP 1.0** (Final,
published 2025-07-09). SIOPv2 is not a component of it. Issue #233 has been
retitled to "OID4VP 1.0 authorization request generation + `direct_post`
response intake" accordingly.

Note that `direct_post` there is the base OID4VP 1.0 Response Mode. HAIP 1.0
§5.1 requires the encrypted `direct_post.jwt` variant instead ("Response
encryption MUST be used by utilizing response mode `direct_post.jwt`"). Which
one #233 implements follows the profile decision (#296) and the JWE
prerequisite (#298); the title records the base-spec mode, not a choice between
them.

### OID4VP 1.0 corrections to the request model

- **`client_id_scheme` no longer exists.** It occurs zero times in OID4VP 1.0.
  It is replaced by a **Client Identifier Prefix** carried _inside_ `client_id`
  as `<client_id_prefix>:<orig_client_id>` (§5.9.1). The prefixes defined by
  §5.9.3 are `redirect_uri`, `openid_federation`, `decentralized_identifier`,
  `verifier_attestation`, `x509_san_dns`, `x509_hash`, and `origin` — the last
  reserved for the Digital Credentials API, where "The Wallet MUST NOT accept
  this Client Identifier Prefix in requests."
- **`direct_post` and `redirect_uri` are mutually exclusive.** §8.2 defines
  `response_uri` as "REQUIRED when the Response Mode `direct_post` is used", and
  states: "When the `response_uri` parameter is present, the `redirect_uri`
  Authorization Request parameter MUST NOT be present. If the `redirect_uri`
  Authorization Request parameter is present when the Response Mode is
  `direct_post`, the Wallet MUST return an `invalid_request` Authorization
  Response error."
- **The `redirect_uri` prefix cannot be signed.** §5.9.3: "Requests using the
  `redirect_uri` Client Identifier Prefix cannot be signed because there is no
  method for the Wallet to obtain a trusted key for verification." Since HAIP
  §5.1 mandates signed requests via JAR [RFC 9101] with `request_uri`, and HAIP
  §5 mandates the `x509_hash` prefix for signed requests, the simplest prefix to
  implement is the one a high-assurance profile cannot use.

Which prefixes QAuth implements is **OPEN** (#296). The point recorded here is
that the choice is load-bearing, not cosmetic.

### Credential formats

HAIP §5 requires that the Wallet and Verifier "MUST support at least one of the
following Credential Format Profiles defined in Section 6: IETF SD-JWT VC or ISO
mdoc." The format identifiers are `dc+sd-jwt` for SD-JWT VC (§5.3.2) and
`mso_mdoc` for mdoc (§5.3.1). Note that `vc+sd-jwt` occurs zero times in HAIP
1.0 — an implementation emitting it is targeting a pre-final draft.

Which format(s) QAuth accepts, and in what order, is **OPEN** (#296).

### Issuer trust under HAIP is X.509, and the trust anchor is out of scope

HAIP §6.1.1 verbatim:

> This specification mandates the support for X.509 certificate-based key
> resolution to validate the issuer signature of an SD-JWT VC. This MUST be
> supported by all entities (Issuer, Wallet, Verifier). The SD-JWT VC MUST
> contain the credential issuer's signing certificate along with a trust chain
> in the `x5c` JOSE header parameter … The X.509 certificate of the trust anchor
> MUST NOT be included in the `x5c` JOSE header of the SD-JWT VC. The X.509
> certificate signing the request MUST NOT be self-signed.

`JWT VC Issuer Metadata` occurs zero times in HAIP 1.0 — X.509 is the mandated
path, not one option among several. And HAIP §3.4 places the hard part outside
the spec: "the methods for establishing trust or obtaining root certificates are
out of the scope of this specification."

**Consequence:** _if_ QAuth targets HAIP, the "trust registry integration" of
the 2026-03-11 Decision (#236) becomes X.509 chain validation against
operator-supplied trust anchors, rather than the static per-realm issuer
allowlist #236 currently describes. Note that this is a profile mandate, not a
base-protocol one: X.509 key resolution for the _issuer_ signature is imposed by
HAIP §6.1.1 ("This specification mandates…"), whereas base OID4VP 1.0 uses X.509
only for _Verifier_ authentication, via the `x509_san_dns` and `x509_hash`
Client Identifier Prefixes (§5.9.3). Which mechanism #236 implements therefore
follows the profile decision and is **OPEN** (#296).

What does not depend on the profile: under either mechanism QAuth ships no trust
list, and validates against one an operator configures. That much is the shape
the Decision already chose with "Trust registry integration (configurable per
realm)".

### Version pinning: the Final specs depend on drafts

HAIP §9.4 "Pre-Final Specifications" pins "SD-JWT-based Verifiable Credentials
(SD-JWT VC) draft -13" and "Token Status List draft -14", and directs that
implementations "should continue to use the specifically referenced versions
above in preference to the final versions". The pins are per-document, not
per-family: HAIP's normative references already cite the _base_ SD-JWT as a
published RFC (`[RFC9901]` — "Selective Disclosure for JSON Web Tokens", RFC
9901, November 2025), and §6.1 requires "Compact serialization … as defined in
[RFC9901]", while §9.4 still pins SD-JWT **VC** at draft -13. So the existence
of an RFC for the base format does not license upgrading a pinned draft, and
"newest draft" is the wrong default: the pinned version is the interoperable
one, and an implementation should track the pin until a new HAIP revision moves
it. Credential revocation via Token Status List is tracked in #297.

### Subject identity: there is no stable wallet identifier

This is the correction with the widest blast radius, because it contradicts a
decision rather than a name.

SIOPv2 draft 13 §11 defined `sub` as REQUIRED, being "either the base64url
encoded representation of the thumbprint of the key in the `sub_jwk` Claim or a
Decentralized Identifier". That is exactly the "DID sub" the Federation Model
diagram above assumes and stores as `external_sub`. With no ID Token under HAIP,
that identifier does not exist.

Nor is there a substitute, because OID4VP 1.0 treats the obvious candidates as
privacy defects to be engineered away. §15.5 "Verifier-to-Verifier Unlinkable
Presentations":

> with Credential formats such as SD-JWT and mdoc, the Issuer signature on a
> Credential or the public key a Credential is bound to, can provide a Verifier
> with a way to link the Credential across different Presentations or sessions.
> In order to avoid such linking, a Wallet can use multiple instances of a
> Credential, each with unique Issuer signatures and associated public keys

§15.6 adds: "A Verifier SHOULD NOT attempt to fingerprint the End-User based on
metadata that may be available in the interaction with the End-User's wallet."

**Consequence:** a Verifier cannot key accounts on wallet cryptography. Every
identifier a well-behaved wallet exposes is designed to rotate. Account linking
(#238) and `user_credentials.external_sub` therefore need a different basis —
a claim from the credential itself, or an explicit linking ceremony. Which one
is **OPEN** (#296). Note the tension to resolve there: any stable identifier
QAuth derives is, by construction, the correlation vector §15.5 asks wallets to
destroy.

> **Proposed resolution (2026-07-20):** a replacement strategy is proposed in
> [ADR-009](./009-wallet-account-resolution.md) (Status: Proposed — this
> subsection stays OPEN until that ADR is accepted) — `asserted-lookup` as the
> default (the user asserts an identifier; the presentation proves entitlement),
> with `issuer-scoped-claim` opt-in per named issuer and `rp-pseudonym` reserved
> and gated. The tension noted above would be resolved by observing that the
> unlinkability machinery targets _unwanted_ correlation: a user asserting their
> own identifier is participating in their own recognition.

### Assurance level derives from the credential, not from a wallet-signed token

The `acr` propagation decision above stands; its input changes. With no
self-issued ID token, `assuranceLevel` cannot be read from a wallet-signed
assertion. It must be derived from the presented credential and its issuer —
which issuer signed it, under which trust anchor, and which credential type it
is. That is a property of the issuer trust decision, not of the wallet. Affects
#237.

### Crypto prerequisite: QAuth cannot speak this profile today

QAuth's crypto layer is EdDSA-only: `libs/core/crypto/src/lib/algorithms.ts`
declares `JwsAlgorithm = 'EdDSA'`, and its `SignatureAlgorithm` union admits
only `'EdDSA'` and `'ML-DSA-65'`. No signing backend produces `ES256`, and there
is no JWE support at all. HAIP requires both:

- **ES256** — §7: Issuers, Verifiers and Wallets "MUST, at a minimum, support
  ECDSA with P-256 and SHA-256 (JOSE algorithm identifier `ES256`…)". §8 adds
  SHA-256 for digests.
- **JWE** — §5.1: "Response encryption MUST be used by utilizing response mode
  `direct_post.jwt`". §5 constrains it to JWE `alg` `ECDH-ES` with key agreement
  on P-256, `enc` values `A128GCM` and `A256GCM`, with Verifiers supplying
  "ephemeral encryption public keys specific to each Authorization Request".

This is a hard prerequisite, not an implementation detail: no amount of
federation code compensates for a crypto layer that cannot produce the required
signature or encryption. Sequenced in #298 (Phase 1 ES256, Phase 2 JWE).

### Profile layering — the wallet-agnostic decision, restated

HAIP is a **profile over** OID4VP 1.0, not an alternative protocol; its abstract
describes it as defining "a profile of OpenID for Verifiable Credentials". Its
constraints — formats, prefixes, algorithms, response modes — are therefore
_configuration of one OID4VP implementation_, not a second protocol stack.

That is the direct consequence of the decision this ADR already made:
"The implementation is wallet-agnostic — it does not contain EUDI-specific
code", and "eIDAS compliance is an emergent property of supporting the right
protocols, not a hardcoded feature". Ecosystem-specific constraints belong in a
configurable profile layer — a `VerifierProfile` abstraction, tracked in #299 —
which generalises what the Decision already anticipated with "Trust registry
integration (configurable per realm)". HAIP §9.3 anticipates the same shape from
the other side: "This specification intentionally leaves certain extensions for
Ecosystems to define, in order to enable broad compatibility across differing or
even conflicting requirements."

Regulatory obligations that attach to the deployer rather than the software —
eIDAS Relying Party registration being the concrete case — read as operator
concerns and operator documentation rather than product code, following from the
same "not a hardcoded feature" position. That is the reading this section
proposes and #296 is asked to confirm; it is not decided here.

### Still open — do not read a target out of this section

This section corrects facts. It does not select a target, and nothing in this
ADR — including the [2026-07-19 refresh](#spec-status-2026-07-19) above, whose
HAIP subsection reads as a prescription — should be read as QAuth committing to
HAIP conformance. Tracked in **#296**:
which profile ships first and what the default posture is; which Client
Identifier Prefixes to implement; the subject-identity strategy (a resolution is
proposed in [ADR-009](./009-wallet-account-resolution.md), not yet accepted); and
confirmation that eIDAS RP registration is operator-documentation scope.

## Related

- [ADR-002: Identifier Abstraction](./002-identifier-abstraction.md)
- [ADR-003: CredentialProvider Abstraction](./003-credential-provider-interface.md)
- [waltid-identity Reference Implementation](https://github.com/walt-id/waltid-identity)
- [OpenID for Verifiable Presentations 1.0 (Final, 2025-07-09)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) — the protocol
- [OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0 (Final, 2025-12-24)](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) — a profile over OID4VP 1.0; profile targeting is OPEN (#296)
- Superseded mechanism, cited for traceability only: [Self-Issued OpenID Provider v2 — draft 13 (2023-11-28)](https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html). Not Final, and excluded by HAIP 1.0 §5 — see [Spec status (2026-07-20)](#spec-status-2026-07-20). Do not implement against it.
- [OpenID Federation 1.0 Final approved](https://openid.net/openid-federation-1-0-final-specification-approved/) · [Federation 1.1 Final](https://openid.net/openid-federation-1-1-final-specifications-approved/)
- [OID4VC self-certification (from 2026-02-26)](https://openid.net/openid-for-verifiable-credential-self-certification-to-launch-feb-2026/)
- [eIDAS 2.0 (EU 2024/1183)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1183)
