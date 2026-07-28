# ADR-010: eIDAS Level of Assurance → OIDC `acr` Value Mapping

**Status:** Accepted
**Date:** 2026-07-27
**Updated:** 2026-07-28 — §5 rewritten and §6 added (issue #379: decisions D1, D1a, D2)
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

### 5. Key attestations reach the level through ONE translation, defaulting strict

**Updated 2026-07-28 (issue #379).** The original text of this section said that
when #308 landed it would populate `AssuranceEvidence` "at the call site … with no
change to this module or to any consumer". That was wrong on both counts and is
replaced here. #308 landed and populated nothing: `keyStorageAssuranceGateFor`,
`createKeyStorageAssuranceResolver` and `createStaticAttestingIssuers` shipped with
zero non-test callers, so every `ValidatedCredential` the auth-server produced
carried `assurance.keyStorageAssurance === { assurance: 'none' }` unconditionally
and an entry demanding hardware key storage was unsatisfiable by construction. The
two sides also do not speak the same vocabulary, so connecting them is a decision,
not a wire.

eIDAS LoA `high` requires a secure cryptographic device, which is a property of the
wallet's key store and cannot be observed from a credential. HAIP §9.2 key
attestations are how a wallet proves it; #308 validates them and reports EVIDENCE —
`assurance: 'none' | 'issuer-attested' | 'key-attested'`, plus an OID4VCI Appendix D
§D.2 attack-potential grade. This module consumes a LEVEL vocabulary,
`AssuredKeyStorage: 'software' | 'hardware'`. The two are not a rename, and
`credential-assurance.ts` says why: _"Collapsing them would let an attestation's mere
presence decide a Level of Assurance."_

**D1 — the translation is one exported function, and the entry states the floor.**
`AssuredKeyStorage` stays the policy vocabulary. The mapping lives in exactly one
place, `libs/server/federation/src/assurance/key-storage-evidence.ts`, with its own
tests; no call site re-derives it and no consumer reads `assurance !== 'none'` as a
level. A policy entry may state its own attack-potential floor
(`requiresKeyStorageAttackPotential`), which also makes `requiresKeyStorage`
authorable through `OID4VP_ISSUER_ASSURANCE` rather than reachable only from a
programmatic `createIssuerAssurancePolicy` call.

The rule:

| evidence                                                       | reads as                                         |
| -------------------------------------------------------------- | ------------------------------------------------ |
| `assurance: 'none'`, or a source this build does not recognise | nothing — an entry demanding key storage refuses |
| a recognised source whose graded key storage clears the floor  | `hardware`                                       |
| a recognised source graded BELOW the floor                     | `software`                                       |
| a recognised source with no grade, or an unrecognised grade    | nothing                                          |

**An unstated floor defaults to `iso_18045_high`.** This is the load-bearing half of
the decision. An operator who writes `requiresKeyStorage: 'hardware'` and nothing
else is asking for eIDAS `high`'s secure cryptographic device, so the unstated
reading must be the STRICT one. The permissive alternative would let an
`iso_18045_basic` claim satisfy a `high` entry — precisely the collapse this seam
exists to prevent — and a default may only ever be the reading that refuses more,
never the one that grants more. Every comparison is delegated to
`meetsAttackPotential` (with `isAttackPotentialResistance` narrowing the inputs), so
an unrecognised grade and an unrecognised FLOOR both fail closed without this module
restating the ordering. Note it is `meetsAttackPotential` rather than the
coarser-grained `keyStorageAssuranceMeets`: the latter answers "does this evidence
meet a floor" for #308's own resolver and pins the floor to the evidence's key-storage
grade, whereas this seam must compare against an entry's operator-stated floor. The
stricter unit is the correct one here, and it is the only one this translation calls.

**D1a — `issuer-attested` DOES qualify as `hardware`, with the source recorded.**
Per #308's own finding, the transitive path is the only key-storage assurance HAIP
actually gives a Verifier today, and it is already an explicit operator opt-in via
`createStaticAttestingIssuers`; excluding it would leave the machinery unreachable in
every deployment that can exist. But inherited assurance is a recorded belief about
an issuance ecosystem and verified assurance is an artifact QAuth checked against
this credential's own key, and the two must stay distinguishable. So the translation
returns the resolved SOURCE alongside the value, and the wallet login path logs it
server-side.

The source is deliberately NOT on `AssuranceEvidence`: an `AssurancePolicy` must not
be able to branch on it. D1 settled the operator's knob as an attack-potential floor,
and putting the source in front of every policy implementation would add a second,
undocumented axis. It is reported to the operator, and to nothing that makes a
decision. On the wire nothing changes — `acr`'s absence remains indistinguishable
from a password login either way.

### 6. Subject resolution is refused at BOOT, not per request

**Decided 2026-07-28 (issue #379, D2).** #300 and #238 each deferred a
subject-resolution boot gate "to the first consumer" on the grounds that nothing
consumed the strategy. The wallet login path now does, so the deferral has expired.

The gate is `assertSubjectResolutionProvisioned(env)`
(`apps/auth-server/src/app/helpers/assert-subject-resolution.ts`), called from
`apps/auth-server/src/app/app.ts` beside `assertTrustedIssuersUsable` and gated on
`WALLET_FEDERATION_ENABLED`. Not inside `createConfiguredProviders`: that stays a
pure function of its options and knows nothing about `OID4VP_SUBJECT_*`, so the
option it would take is a boolean the bootstrap has to compute anyway. The gate reuses
`resolveSubjectResolution` as the single authority — no second implementation to
drift — and surfaces the real `InvalidConfigurationError` message rather than a
boolean's worth of it, naming the variable to set.

It takes the environment alone and resolves the profile itself, rather than being
handed one. A profile that cannot resolve is deliberately NOT this gate's business:
it returns quietly and lets `createConfiguredProviders` — registered a few lines
later — raise its own refusal, which names the profile and the unmet capability.
Pre-empting that would replace _"verifier profile 'haip-1.0' requires …"_ with a
complaint about a subject-resolution variable, which is neither the operator's first
problem nor one they could act on. `crypto-capabilities.test.ts`, which asserts
`createConfiguredProviders` does not throw without subject-resolution input, is
untouched by this placement — the check that D2 landed where it was meant to.

This is a **breaking change** for a deployment running `WALLET_FEDERATION_ENABLED=true`
with no `OID4VP_SUBJECT_*` variables, which is the shape `.env.example` documented.
It is intended: the profile default is `asserted-lookup`, and an unconfigured
`asserted-lookup` is ADR-009 §1's total authentication bypass, so that deployment
already refused every presentation — it simply learned about it from a 100%
login-failure rate instead of from a failed start.

The **request path is unchanged**. `resolveWalletPresentation` still catches
`InvalidConfigurationError`, still logs at `error`, and still returns the single
uniform `{ status: 'rejected' }`. A boot gate replaces the operator's discovery
channel; it must not change one byte of what an anonymous caller can observe. That
is pinned by a test asserting the half-configured refusal is the identical object a
forged credential produces, not merely the same shape.

### 7. The evidence surface: `OID4VP_ATTESTING_ISSUERS`

§5's translation is only reachable if something establishes evidence, and before
#379 nothing could: `createStaticAttestingIssuers` had no configuration surface and
`app.ts` never passed `keyStorageAssuranceProvisioned`, so
`assertKeyStorageAssuranceProvisioned` was a constant refusal rather than a
predicate.

`OID4VP_ATTESTING_ISSUERS` records which issuance chains validate a wallet's key
attestation per HAIP §4.5.1, and at what §D.2 grade. It is **deployment-wide**,
unlike `OID4VP_TRUSTED_ISSUERS` and `OID4VP_ISSUER_ASSURANCE` which are keyed by
realm, because what an issuer's issuance process establishes is a property of that
ECOSYSTEM rather than of any realm's opinion of it — the same grade whichever tenant
is looking. That is safe because an entry produces EVIDENCE and never a level: a
realm grants nothing unless its own `OID4VP_ISSUER_ASSURANCE` names the issuer with
`requiresKeyStorage` and its own `OID4VP_TRUSTED_ISSUERS` accepts it, so listing an
issuer cannot raise any realm's assurance on its own. It is also what makes the gate
constructible where it is built — once per deployment, before any realm is known.

Only the TRANSITIVE path is provisionable. The DIRECT path (verifying an Appendix D
attestation conveyed into a presentation against anchored trust) needs the X.509
configuration surface #233 still owes `provisionedVerifierMaterial`.

Note that `oid4vp-1.0-base` declares `keyStorageAssurance: 'forbidden'`, and the
resolver returns before it reads the record at all. So on the only profile that
boots today this whole mechanism establishes nothing and changes no behaviour; it
becomes reachable when a profile whose posture is `permitted` or `required` can
start, which `haip-1.0` cannot until #298.

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
- The eIDAS reading of a key attestation is stated ONCE, in one tested function
  with a strict default, so widening it is a reviewable edit to a single file
  rather than a judgement each call site makes for itself.
- An operator can tell an assured session that rests on a verified attestation
  from one that rests on a recorded belief about an issuance ecosystem, without
  that distinction becoming something a Relying Party or an attacker can observe.
- A half-configured wallet deployment fails to START rather than serving a 100%
  login-failure rate whose only symptom on the wire is the same refusal a forged
  credential gets.

### Negative

- Assurance is operator configuration, so a misconfigured deployment can assert a
  level its issuers do not actually operate at. QAuth cannot verify the claim; it
  can only refuse to invent one.
- The emitted values are not standard, so a Relying Party integrating against a
  QAuth deployment must be told which vocabulary it uses.
- Two vocabularies means two strings for one level across the ecosystem. This is a
  property of the ecosystem, not of this decision; a registered value would
  supersede both.
- D1a means an eIDAS `hardware` reading can rest on the operator's belief about an
  issuance chain rather than on anything QAuth verified. That is a real weakening
  against the strictest possible reading, taken knowingly: the strict-only reading
  makes the feature unreachable in every ecosystem that exists today, since HAIP
  puts key attestations on the ISSUANCE path and does not hand one to a Verifier.
  The mitigations are that the opt-in is explicit per issuer, that the operator's
  recorded grade CAPS whatever the issuer claims, and that the source is on the
  record for every assured session.
- §6's boot gate is a breaking change for existing wallet deployments and ships
  with the `.env.example` and `docs/wallet-login.md` changes that make the
  subject-resolution variables required rather than optional.

### Neutral

- Claim provenance stays out of scope. If OIDC Identity Assurance
  `verified_claims` is ever needed, it is a separate surface and a separate ADR.
- Credential status (#297) is not yet an input to the assurance decision. Wiring
  revocation checking into the level — e.g. refusing `high` for a credential whose
  status was never checked — is a tightening this ADR anticipates but does not
  make. As of #378 the input now exists:
  `CredentialAssuranceSignal.statusChecked` is `'checked' | 'not-required'`
  rather than the literal `false`, so an `IssuerAssuranceEntry.requiresStatusCheck`
  knob mirroring `requiresKeyStorage` could gate `substantial`/`high` on
  `statusChecked === 'checked'`. That remains a separate decision; nothing in the
  assurance path reads the signal today. Note that #379 removed the excuse: since
  §5 the assurance path DOES read `CredentialAssuranceSignal`, so wiring the second
  field is now a policy question rather than a plumbing one.
- The `userAuthentication` grade #308 reports alongside `keyStorage` is still
  ignored. §D.2 keeps the two apart deliberately — a key in certified hardware that
  anyone holding the phone can exercise is not the same proposition as the same key
  behind a certified authenticator — but requiring both floors is the "both axes"
  option D1 did not take, and no ecosystem conveys the second signal in a
  presentation today. Adding it is one more optional floor on the entry.

## Related

- [ADR-003: CredentialProvider Abstraction](./003-credential-provider-interface.md) — `'low'` carries no `acr`
- [ADR-004: Wallet-Agnostic VC Federation via OID4VP](./004-wallet-agnostic-federation.md) — the original `acr` decision and its 2026-07-20 correction
- [ADR-009: Wallet Account Resolution](./009-wallet-account-resolution.md)
- [OpenID Connect Core 1.0 §2](https://openid.net/specs/openid-connect-core-1_0.html) — the `acr` claim
- [RFC 6711](https://www.rfc-editor.org/rfc/rfc6711) — IANA Level of Assurance Profiles registry
- [OID4VP 1.0 (Final, 2025-07-09)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) — §5 response type MUST be `vp_token`
- [HAIP 1.0 (Final, 2025-12-24)](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) — §1 LoA scope statement, §4.5.1 issuance-time key attestation, §9.2 key attestations
- [OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) — Appendix D (Key Attestation), §D.2 (Attack Potential Resistance), the grade vocabulary §5 reads
- Issues: #237 (this ADR), #234 (presentation validation), #236 (issuer trust), #308 (key attestations), #297 (credential status), #300 (subject resolution), #379 (§5 rewrite, §6, decisions D1/D1a/D2)
