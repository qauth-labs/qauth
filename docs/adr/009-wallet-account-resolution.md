# ADR-009: Wallet Account Resolution — `asserted-lookup` Default and the Subject-Identity Model

**Status:** Proposed
**Date:** 2026-07-20
**Authors:** QAuth Team

> [ADR-004](./004-wallet-agnostic-federation.md) established _that_ QAuth bridges
> OID4VP wallets to OAuth 2.1, and its
> [2026-07-20 correction](./004-wallet-agnostic-federation.md#spec-status-2026-07-20)
> established that no stable wallet identifier exists — leaving the replacement
> explicitly OPEN. **This ADR proposes to close that question.** It records which
> account a presentation resolves to, and why keying on wallet cryptography is not
> a fragile choice but a wrong one.
>
> Answers Q3 of #296; supplies the strategy defaults for `SubjectResolutionStrategy`
> (#300). Does **not** decide profile targeting, Client Identifier Prefixes,
> credential formats, or whether eIDAS relying-party registration is
> operator-documentation scope (Q4) — all of those remain open in #296.

## Context

### Why this is a decision record and not another ADR-004 amendment

ADR-004 asserted that "SIOPv2 remains the self-issued-OP mechanism this ADR
describes". That single clause propagated into nine issues (#233–#240 under epic
#231) before anyone checked it against a Final specification, and correcting it took
[PR #301](https://github.com/qauth-labs/qauth/pull/301). The root cause was not
the error itself but its **location**: the reasoning lived in issue comments and
prose, so nothing forced a re-derivation to confront it.

The findings below currently live in exactly that failure mode — GitHub comments
on #296 and #300. At least three of them are counter-intuitive enough that a
future implementer will "fix" them on sight:

- that the system deliberately provides no stable identifier,
- that the correct response is to **ask the user who they are**, and
- that a wallet login is not a session-authentication event.

Each looks like an oversight and is a decision. They are recorded here so that
changing them requires superseding an ADR rather than editing a comment.

### The question

An OID4VP presentation arrives and validates. Which `users` row does it resolve
to — and on re-presentation next month, how does QAuth know it is the same
person?

QAuth's identity model ([ADR-002](./002-identifier-abstraction.md), implemented)
answers this for every other provider with
`user_credentials (realm_id, provider_type, external_sub)`, unique-indexed
(`libs/infra/db/src/lib/schema/identity.ts:89`). `PasswordProvider` sets
`externalSub` to the normalized email; an `oidc_*` provider sets it to the
upstream `sub`. The wallet case needs a value for that column, and the 2026-03-11
model's answer — the holder's DID — does not survive contact with the Final
specifications.

### Finding 1 — there is no persistent subject identifier, and that is deliberate

**The mandatory PID attribute set contains no identifier.** Commission
Implementing Regulation (EU) 2024/2977 of 28 November 2024 (OJ L, 2024/2977,
4.12.2024; applicable since 24 December 2024), Annex, point 1, Table 1
"Mandatory person identification data for the natural person", lists exactly five
attributes: `family_name`, `given_name`, `birth_date`, `birth_place`,
`nationality`. None is an identifier. (That is the position under the act
currently in force; a pending amendment would add a sixth — see
[Citation notes](#citation-notes).)

Table 5 (metadata about the person identification data) adds mandatory
`expiry_date`, `issuing_authority` and `issuing_country`, plus an **optional**
`document_number`. That last one is identifier-like and worth naming explicitly
so it is not mistaken for an oversight — but it is optional, and Finding 4 shows
why an issuer-assigned document number is the wrong thing to key on in any case.

Two qualifications matter. Presence is not meaning — the sentence immediately
below Table 1 reads:

> Where an attribute value is not known for the person or cannot otherwise be
> issued as part of the person identification dataset, Member States shall use an
> attribute value appropriate to the situation instead.

And the CIR does impose a uniqueness duty, just not an attribute-level one.
Article 3(4):

> Member States shall ensure that the person identification data issued to a
> given wallet user is unique for the Member State.

That is a duty on the **dataset**, dischargeable by the combination of name and
birth data. It does not create a field QAuth can key on.

**The optional identifier that exists is provider-scoped.** The same Annex,
Table 2 "Optional person identification data for the natural person", defines:

> `personal_administrative_number` | A value assigned to the natural person that
> is unique among all personal administrative numbers issued by the provider of
> person identification data. Where Member States opt to include this attribute,
> they shall describe in their electronic identification schemes under which the
> person identification data is issued, the policy that they apply to the values
> of this attribute, including, where applicable, specific conditions for the
> processing of this value. | optional

Uniqueness is scoped to one provider's own issuance namespace, so two Member
States may issue two different values to the same human. Note precisely what the
second sentence delegates: **value policy**, not stability. The regulation never
uses "stable", "persistent" or any cognate here — and the drafters plainly knew
how to require persistence, because Table 3 (legal persons) asks for an
identifier "which is as persistent as possible in time". Its absence from Table 2
is a choice, not an oversight.

**The user may refuse to present it.** EUDI PID Rulebook v1.7 (17 July 2026) §2.1:

> Note that, when requesting PID attributes from a Wallet Unit, a Relying Party
> is not required to request all mandatory attributes. Also, a User is allowed to
> refuse to present a mandatory attribute, if it is requested by a Relying Party.

This is a descriptive Note, not a SHALL — it imposes no requirement on relying
parties. But it describes behaviour a conformant wallet is free to permit, which
is all the fallback argument needs: if a _mandatory_ attribute may be refused, an
optional one may be more so. Any design keyed on
`personal_administrative_number` must therefore have a fallback path regardless —
which is the `asserted-lookup` path, arrived at by a second route.

**There is no `sub` claim to fall back to.** The PID Rulebook's SD-JWT VC
encoding (chapter 4) never mentions one: a whole-document search of v1.7 returns
zero occurrences of `sub` as a claim name and zero of "subject"; neither
claim-mapping table in §4.1.1 has a `sub` row; and the worked example in §4.3
carries `vct`, `given_name`, `family_name`, `birthdate`, `address`,
`nationalities`, `sex`, `place_of_birth`, `cnf`, `issuing_authority` and
`issuing_country` — no `sub`. Holder binding is expressed exclusively through
`cnf`. (This is a negative finding established by exhaustive search of a
425-line document, stated as such.)

Where `sub` does exist in the format, it guarantees nothing. SD-JWT VC draft-13
§3.2.2.2 "Registered JWT Claims" — the revision HAIP 1.0 §9.4 pins:

> `sub`: OPTIONAL. The identifier of the Subject of the Verifiable Credential.
> The Issuer MAY use it to provide the Subject identifier known by the Issuer.
> There is no requirement for a binding to exist between sub and cnf claims.

**Nothing cryptographic is guaranteed stable either.** PID Rulebook v1.7 §2.5,
`expiry_date` row, is explicit that the churn is a privacy feature:

> The technical validity period is a mandatory element of all technical PIDs (and
> also attestations) in the EUDI Wallet ecosystem. It typically is short, a few
> days or weeks at most, if not shorter, to mitigate challenges regarding
> tracking of Users by malicious Relying Parties based on the repeated
> presentation of the same PID. … During the administrative validity period of a
> logical PID, the PID Provider will therefore provide multiple successive
> technical PIDs to a User, typically without any actions being expected from the
> User.

The specifications push key material to rotate alongside it. OID4VCI 1.0 (Final,
16 September 2025) §3.3.2 "Batch Credential Issuance":

> In the context of a single request, the batch of issued Credentials sent in
> response MUST share the same Credential Format and Credential Dataset, but
> SHOULD contain different Cryptographic Data. For example to achieve
> unlinkability between the Credentials, each credential should be bound to
> different cryptographic keys.

And §15.4.1 "Unique Values Encoded in the Credential":

> Credential Issuers specifically SHOULD discard values that can be used in
> collusion with a Verifier to track a user, such as the Issuer's signature or
> cryptographic key material to which an issued credential was bound to.

Read these at their true normative strength: the §3.3.2 key-binding sentence is
introduced by "For example" with a lowercase "should", i.e. illustrative, and
§15.4.1 is a SHOULD scoped to issuer–verifier collusion. Neither _forbids_ a
stable key. The point is not that the specifications prohibit what QAuth wants —
it is that they instruct the entire ecosystem to build the opposite, so a
well-behaved wallet will not supply it. Designing against the exception is how
QAuth ends up working with one wallet and no others.

Combined with OID4VP 1.0 §15.5–§15.6, already recorded in ADR-004: **cross-session
recognition of a returning user is not a protocol feature. The specifications
treat it as a correlation risk to be engineered away.**

### Finding 2 — even where an identifier exists, an ordinary relying party is unlikely to be able to obtain it

**GDPR.** Article 87 of Regulation (EU) 2016/679 permits Member States to lay
down further specific conditions for processing "a national identification number
or any other identifier of general application", subject to appropriate
safeguards. This is an optional specification clause layered on top of the GDPR,
which continues to apply in full — not a delegation of the field to national law.
The practical effect is nonetheless 27 possible regimes on top of a uniform
baseline. Note the closing phrase: "any other identifier of general application"
reaches beyond state-issued numbers, and is worth remembering when designing any
universally-applied subject identifier.

**National constitutional culture.** Germany is the standard example, and the
standard framing overstates it. The _Volkszählungsurteil_ (BVerfG, 15 December
1983, 1 BvR 209/83 et al., BVerfGE 65, 1) established informational
self-determination — Leitsatz 1: the individual's authority "grundsätzlich selbst
über die Preisgabe und Verwendung seiner persönlichen Daten zu bestimmen"
(in principle to decide themselves on the disclosure and use of their personal
data). Its remarks on a uniform personal identifier are real but non-operative:
Rn. 190 discusses the introduction of "eines einheitlichen, für alle Register und
Dateien geltenden Personenkennzeichens" inside a proportionality analysis of
whether linking registers would be a _milder_ means than a census (the Court held
it would not), and Rn. 176 is expressly conditional, condemning comprehensive
profiling with the identifier as its mechanism.

The reading that this _bars_ a universal identifier is scholarly reception, not
the holding — and German practice has since moved: the
Registermodernisierungsgesetz (2021, BGBl. I S. 591) makes the Steuer-ID a
cross-register identifier across major public registers, and it stands. A
constitutional challenge was announced publicly; as of July 2026 no BVerfG
decision on the IdNrG could be located. **So the accurate statement is that
Germany is the strongest constitutional-culture argument against universal
identifiers, not a jurisdiction where they are prohibited.** QAuth should not
claim German law forbids what German law currently does.

**eIDAS relying-party registration.** From 24 December 2026, a relying party must
be registered and must declare what it intends to request. Commission
Implementing Regulation (EU) 2025/848 of 6 May 2025, Article 1: "This Regulation
lays down rules for the registration of wallet-relying parties"; Article 11: "It
shall apply from the 24 December 2026" (quoted as printed). Article 3(1) requires
each Member State to "establish and maintain at least one national register of
wallet-relying parties". The underlying obligation is Article 5b of Regulation
(EU) No 910/2014, as inserted by Article 1(5) of Regulation (EU) 2024/1183.

On over-asking, be careful which text is operative. The often-quoted phrase about
a party that has not "rightfully minimised the set of attributes it requests
access to" appears in **recital 11** of 2025/848 — interpretive, non-binding. The
operative provision is Article 9(2)(c), which is a **register-mismatch** test, not
a general data-minimisation test: it addresses a wallet-relying party "requesting
more attributes than they have registered in accordance with Article 5 and
Article 6". Article 9(2) is discretionary ("may") and gated by a proportionality
assessment under Article 9(4).

That is narrower than the maximalist reading — but it is sufficient here, and in
a way that matters more for being precise. **A national identifier requested for
"recognise returning users" is unlikely to survive the declaration step in the
first place**, and QAuth's operators, not QAuth, carry that filing. A product
default that only works once every operator has declared a national identifier as
an intended-use attribute is not a viable default.

### Finding 3 — the sanctioned returning-user mechanism is an RP-scoped pseudonym, i.e. a passkey

This is the finding that determines the shape of the decision.

**Wallets must generate pseudonyms.** Article 5a(4)(b) of Regulation (EU) No
910/2014, as inserted by Regulation (EU) 2024/1183, requires wallets to enable
the user to "generate pseudonyms and store them encrypted and locally within the
European Digital Identity Wallet". Note the obligation is to _enable the user_;
it says nothing about RP-scoping or WebAuthn. Both come from the implementing act.

**They are per-relying-party.** Commission Implementing Regulation (EU) 2024/2979
of 28 November 2024 (applicable since 24 December 2024), Article 14(2):

> Wallet units shall support the generation, upon the request of a wallet-relying
> party, of a pseudonym which is specific and unique to that wallet-relying party
> and provide this pseudonym to the wallet-relying party, either standalone or in
> combination with any person identification data or electronic attribute
> attestation requested by that wallet-relying party.

Two details carry weight: the RP _requests_ it, so this is not unilateral wallet
behaviour; and it composes with attribute disclosure ("either standalone or in
combination with"), so pseudonymity and attribute verification are not
alternatives.

**The named technical specification is WebAuthn.** CIR (EU) 2024/2979, Annex V
"Technical specifications for pseudonym generation referred to in Article 14",
has exactly one entry:

> — WebAuthn – W3C Recommendation, 8 April 2021, Level 2,
> https://www.w3.org/TR/2021/REC-webauthn-2-20210408/.

The Level 2 pin remains current: WebAuthn Level 3 was still a Candidate
Recommendation as of mid-2026.

**And they must not be correlatable.** EUDI ARF v2.9.0 (2026-05-21), Annex 2,
Topic 11 (Pseudonyms), PA_17:

> The Wallet Provider SHALL use method(s) and/or protocol(s) to implement
> pseudonyms which make it impossible to correlate Pseudonyms based on their
> values or on metadata sent by the Wallet Unit to Relying Parties during
> registration and authentication. _Note: This implies that colluding Relying
> Parties will not be able to conclude that different Pseudonyms belong to the
> same User._

So the ecosystem's intended shape is **not** "present a credential on every
login". It is:

> **wallet presentation = high-assurance onboarding or step-up (one-shot)
> → passkey = routine returning-user login.**

That is a coherent division of labour, and it vindicates ADR-004's framing of the
credential as an assurance input rather than a session primitive.

**It is not ready, and QAuth cannot do it today.** Three independent gates:

1. **No technical specification exists.** ARF v2.9.0 Annex 2, Topic 11, PA_21
   still reads as a forward obligation: "The Commission SHALL create or reference
   a technical specification containing a profile or extension of the [W3C
   WebAuthn] specification compliant with the HLRs specified in this Topic." The
   Commission's published technical-specification register (TS1–TS14) contains no
   pseudonym TS. Note that the 2026 refinement round (18 May 2026) marks **both
   PA_21 and PA_22 "Remove"** — so this gate may clear by the obligation being
   deleted rather than discharged, which is a materially different outcome and
   would leave the mechanism unspecified rather than specified.
2. **The requirement is being weakened, not hardened.** ARF Annex 2 `PA_22` changed
   from SHALL to MAY between v2.5.0 and v2.9.0 — v2.5.0: "Wallet Providers SHALL
   ensure that their Wallet Solution supports the [W3C WebAuthn] specification…";
   v2.9.0: "Wallet Providers MAY ensure that their Wallet Solution supports the
   HLRs defined for this topic by letting their Wallet Units perform the role of a
   WebAuthn authenticator…" (emphasis on the modal verbs added). ARF Discussion
   Paper Topic E proposes going further, "such that it becomes _optional_ for a
   Wallet Unit to also be a WebAuthn authenticator". A wallet may therefore
   conformantly not be an authenticator at all.
3. **QAuth has no WebAuthn implementation.** `webauthn` and `passkey` appear only
   in `README.md`, `MVP-PRD.md` and `.claude/agents/product-manager.md` —
   documentation, no code. Adopting the sanctioned path is gated on a workstream
   that has not started.

On deployment evidence, state the limit honestly: **we found no published evidence
that any Large-Scale Pilot (POTENTIAL, EWC, NOBID, DC4EU) deployed pseudonym-based
returning-user login**, and the four pilots' documented use cases do not include
it. That is not the same as confirming none did; the pilots' final technical
deliverables were not obtained.

### Finding 4 — non-EU ecosystems are not better

Surveyed to check whether the EU constraints are parochial. They are not — but the
reasons differ from the ones assumed, and two prior claims do not survive.

**ISO mDL does not prevent linking.** The standard (ISO/IEC 18013-5:2021) is
paywalled and was not read; no clause of it is quoted here. What is publicly
verifiable contradicts the assumption that mDL solves this. AAMVA's _Mobile
Driver's License Implementation Guidelines_ r1.3 §4.6 "No tracking" (r1.3 is the
release read end-to-end; r1.4 and a v1.6 for Digital Trust Service participants
have since been published, and §4.6 numbering was not re-checked against them):

> Tracking by an mDL verifier can be performed as soon as two different mDL
> transactions can be linked to each other. This can be countered by designing the
> solution to maximize anonymity … Anonymity can be hampered by metadata that may
> be associated with multiple mDL transactions, e.g. hardware or network
> addresses, long-term public keys, or session tokens.

AAMVA names long-term public keys as a live hazard rather than an eliminated one,
concedes that residual risk is handled by law ("it is recommended that Issuing
Authorities pursue regulatory protection against tracking by mDL verifiers"), and
notes that post-matched transactions have limited anonymity "since the portrait
image is always shared". Session encryption uses ephemeral ECDH keys (per
third-party analysis of the standard, whose body is paywalled), but that protects
the channel; it is not a pairwise subject identifier.

The prior claim that `document_number` rotates on renewal does not hold either:
it is issuer-assigned and typically lifelong, and the one prominent
counter-example (Florida's 2024 renumbering under Fla. Stat. 322.14(1)(a)) was a
one-time migration, not a privacy mechanism. **So mDL offers no unlinkability
guarantee, and the stable identifier it does carry — `document_number`,
issuer-assigned and typically lifelong — is the correlation handle AAMVA §4.6
warns about rather than a privacy-preserving key. That is the worst of both:
linkable in practice, with no pairwise mechanism to key on instead.**

**Japan keeps the number away from private parties.** The My Number Act (Act No.
27 of 31 May 2013) Article 20 provides that "It is prohibited for any person to
collect or keep Specific Personal Information (limited to information including
another person's Individual Number)", with Article 15 restricting even _requesting_
it. The enforcement chain should be stated accurately: a private party that
merely collects in breach is not directly criminally liable — enforcement runs
through the Personal Information Protection Commission, with criminal penalties
attaching on violation of a PPC order. (Article numbers for the penal provisions
conflict between the Digital Agency's table and the Japanese Law Translation text,
apparently through renumbering; none is cited here.)

What a private verifier gets instead is a JPKI certificate — the Digital Agency's
own parenthetical emphasis, on its JPKI guidance for private business: the service
"uses the electronic certificate installed in My Number Card's IC chips (not My
Number)". But this is not the privacy win it first appears, and it is instructive.
Per the JPKI Portal FAQ on electronic certificates, the user-identification
certificate carries none of the basic four identity items
(「利用者の氏名、住所、生年月日、性別は記載されない」), is valid until the holder's
fifth birthday after issuance (「申請者の5回目の誕生日」), and is not revoked on
moving house or marriage (「引っ越しや結婚によっても失効しません」). It also
presents the **same serial to every verifier** — so it is a shared,
five-year-stable correlation handle rather than a pairwise one. J-LIS is
additionally reported to operate a service letting certified businesses map a new
serial to the previous generation's, so that identity continuity survives renewal
(not verified against J-LIS primary text — `j-lis.go.jp` returned HTTP 403 on
2026-07-20).

So Japan supplies a stable identifier that is explicitly _not_ pairwise. It
supports the thesis from the opposite direction: where an ecosystem does provide
continuity, it does so by accepting cross-verifier correlation.

**Academic credentials have no usable persistent learner identifier.** The
European Student Identifier exists — `urn:schac:personalUniqueCode:int:esi:<country-code>:<code>`
— and the European Commission's _European Student Card Initiative — State of Play_
(doc. ref. 2022_057), Annex 2, describes it as "globally unique, persistent,
non-targeted…". "Non-targeted" is the operative word: it is the opposite of a
pairwise identifier, one value shown to every relying party. Its persistence is
also bounded — federation operators gloss it as following the student through the
mobility period rather than as a lifelong identifier. And it is structurally
coupled to eduGAIN issuance and scoped to higher-education mobility, not general
commercial relying parties.

Open Badges 3.0 is often cited as having abandoned email identifiers; it did not.
It **added** DID and wallet-controlled subject identifiers while retaining
hashed-email recipient identification in its verification algorithm. The
graduation problem is nonetheless real and sits in the specification itself —
1EdTech Open Badges Specification 3.0, Document Version 1.4.5 (29 June 2026),
use case §3.10, where a learner loses a school-provided address and "requests that
the school reissue the badges to the identifier he created in the wallet". That is
an argument for `asserted-lookup` with re-binding, not for a persistent learner
key.

## Decision

### 1. `asserted-lookup` is the default strategy

The user asserts an identifier (email, username); the presentation proves
entitlement to it. **The wallet is the proof, not the lookup key.**

This is the only strategy viable in every ecosystem surveyed. It survives
credential re-issuance, key rotation, device change and selective-disclosure
refusal, because it depends on none of them. It stays inside declared intended
use, because it asks for no identifier attribute. And it is the shape that already
matches QAuth's model: `external_sub` for a wallet credential holds the asserted,
normalized identifier — the same column `PasswordProvider` fills. ADR-002's
positive consequence, "Wallet federation (Phase 4) requires zero schema
migration", therefore still holds **under the realm scoping that ships today**;
per-client scoping would change the key, which is the open question recorded
below.

The cost is one UI step: #239's login flow needs an identifier field. That is the
price of working everywhere, and it is the same trade passkeys make between
usernameless and username-first flows.

The unlinkability machinery is not violated by this. It exists to prevent
_unwanted_ correlation; a user creating an account is asking to be recognised. What
the specifications refuse to provide is recognition **without** the user's
participation — and `asserted-lookup` obtains exactly that participation.

> **Security constraint, restated because it is the likeliest way this gets built
> wrong:** validity is necessary but not sufficient. Verifying that a presentation
> is well-formed and issuer-trusted proves only that the holder has _a_ valid
> credential. The strategy MUST additionally verify that the presented credential
> matches the binding stored for the asserted account. Omitting that check means
> anyone holding any valid credential can log in as anyone. Detailed in #300.
>
> **Bootstrap — the case that constraint does not by itself cover.** At first
> presentation there is no stored binding to match, so the rule needs a stated
> starting point. Two cases, and they must not be conflated:
>
> - **No account exists for the asserted identifier** — the presentation
>   establishes the account and the binding together.
> - **An account already exists without a wallet binding** (typically a password
>   account on the same email) — the presentation MUST NOT silently create one.
>   Allowing it would let any holder of any trusted credential claim an existing
>   account by asserting its email, which is the takeover the constraint exists to
>   prevent. That path is account linking (#238) and requires an authenticated
>   session — see `session-binding` below.

### 2. `issuer-scoped-claim` is opt-in, per named issuer

Permitted where a specific, named issuer contractually guarantees a stable,
disclosed claim — a workforce credential with an employee number, a national
scheme that has published a value policy under CIR 2024/2977 Table 2. Keyed on
`(validated issuer, claim)`, **never the claim value alone**, and the issuer
component MUST come from the validated issuer certificate chain (`x5c` for
SD-JWT VC, `x5chain` in the COSE MSO for mdoc — #236), never from an unverified
`iss` value. Always with fallback to `asserted-lookup` when the claim is withheld,
since the holder may refuse it.

Demoted from a plausible default to opt-in: no Member State policy guaranteeing
`personal_administrative_number` stability was found, only the enabling clause.

### 3. `rp-pseudonym` is the intended endpoint, and is gated

Reserved as a named strategy so the abstraction has a seat for it, with nothing
filling that seat today. Gated on all three of: a WebAuthn workstream in QAuth
(not started), publication of the Commission technical specification mandated by
ARF PA_21 (does not exist), and wallet-side support surviving as more than a MAY.

Note that the second gate may clear the wrong way. The 2026 refinement round marks
both PA_21 and PA_22 "Remove", so the obligation to produce the specification
could be deleted rather than discharged — which would leave the mechanism
permanently unspecified rather than eventually specified. Treat "the gate cleared"
as requiring a published specification, not merely the disappearance of the
requirement to write one.

Recording it now is the point. When the gates clear, the correct move is to add a
strategy — not to rediscover the problem and invent a private identifier.

### 4. `key-thumbprint` is actively discouraged

Not merely fragile. The PID Rulebook's guidance that technical validity
"typically is short, a few days or weeks at most, if not shorter" makes an
RFC 7638 thumbprint of the `cnf` key wrong even in ecosystems that do not
batch-issue. (Guidance, not a mandate — what is mandatory is only that a technical
validity period exists. It is enough: a key QAuth cannot rely on is not a key.)
It may remain in the strategy enum for controlled deployments that pin a
long-lived credential, but it must carry an explicit warning and must never be a
profile default.

### 5. `session-binding` is retained as the linking strategy

Binding a presentation to the account the user is **already authenticated as**,
rather than resolving an account from the presentation at all. Carried forward
from #300's strategy list unchanged, and named here because the bootstrap rule
above and #238 both depend on it: it is the only correct path for attaching a
wallet credential to a pre-existing account.

It is not an alternative to `asserted-lookup` — it answers a different question
(link, not log in), and it is the strategy that survives #238 losing its
identifier-based premise.

### 6. Wallet presentation is onboarding and assurance-raising, not session authentication

**This is the framing most likely to be "fixed" by a future implementer, so it is
stated as a decision rather than left implicit.**

A wallet presentation is a one-shot, high-assurance event: it establishes an
account, raises its assurance level, or authorises a step-up. It is not the
routine returning-user login primitive, and QAuth must not be designed on the
assumption that a user presents a credential on every sign-in. The ecosystem is
explicitly built the other way — short-lived credentials, rotating keys,
per-RP pseudonyms — and the EU's answer to routine return is a passkey.

Concretely: a wallet login resolves to an account via strategy 1 or 2, and the
resulting session is an ordinary QAuth session. `assuranceLevel` derived from the
credential and its issuer propagates as `acr` (#237, per ADR-004). Nothing in
the wallet path becomes a long-lived authentication credential.

## Open — pseudonym and account scoping in a multi-tenant IdP

**Recorded as open. Not decided here.**

Pseudonyms under CIR 2024/2979 Article 14(2) are scoped to a wallet-relying party.
QAuth is an IdP fronting many downstream applications, so to a wallet it is _one_
relying party — one registration, one access certificate, one pseudonym. Every
downstream client would therefore share a single pseudonym, making QAuth a
correlation point across the applications it fronts.

That may be exactly right: correlating a user across the applications it fronts is
what an IdP is _for_, and it is what QAuth already does for password and OIDC
logins. But it is a design decision, not a protocol given, and it must be taken
deliberately.

The question has a concrete anchor in shipped code, which sharpens it. QAuth's
account scope today is the **realm**, not the client:
`uniqueIndex(realm_id, provider_type, external_sub)`
(`libs/infra/db/src/lib/schema/identity.ts:89`). A realm fronts many OAuth
clients. So the options are:

| Option                 | Scope                                         | Consequence                                                                                                                     |
| ---------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **Realm-scoped**       | one pseudonym per realm                       | matches the existing unique index and existing IdP semantics; QAuth correlates across clients in a realm                        |
| **Per-client derived** | KDF from the wallet pseudonym per `client_id` | downstream apps cannot correlate; QAuth still can, and it breaks the "same user, two apps" property most IdP deployments assume |
| **Per-deployment**     | one pseudonym for the whole instance          | correlates across realms — almost certainly wrong for a multi-tenant server                                                     |

Note the protocol constraint on option 2: the wallet generates the pseudonym per
relying party, so per-client separation requires either registering each client as
its own relying party (multiplying the eIDAS registration burden onto operators)
or deriving locally (which does not reduce what QAuth itself learns).

**The same question applies to `asserted-lookup` account scoping** and is
therefore live now, before any pseudonym work. To be precise about what is and is
not settled: `asserted-lookup` **inherits** realm scoping from the shipped unique
index, and this ADR does not change that — Decision §1's zero-migration property
is exactly that inheritance. What is open is whether the realm is the _right_
boundary for wallet-established accounts. Answering "no" later is a migration,
not a contradiction of this ADR.

## Consequences

### Positive

- Wallet-as-primary-login becomes viable in **every** target ecosystem, not only
  in controlled ones — primary login and attribute verification become the same
  machinery rather than alternatives.
- No schema migration under the realm scoping that ships today. `external_sub`
  holds the asserted identifier and ADR-002's three-table model absorbs wallet
  federation as designed; per-client scoping would change the key (see Open).
- Robust to the things that actually happen: re-issuance, key rotation, device
  change, a user declining an attribute.
- Operators are not pushed into declaring national identifiers as intended-use
  attributes under the eIDAS registration regime.
- `rp-pseudonym` has a reserved seat, so the eventual EU-sanctioned path is an
  addition rather than a redesign.

### Negative

- **#238's third acceptance criterion loses its premise.** Rejecting a link when
  the wallet is "already linked to a different user" assumed a stable, unique
  `external_sub` per wallet; there is no such value. Its other criteria stand —
  the flow is already session-bound, which is `session-binding` (Decision §5).
- **#239 needs an identifier field** in the wallet-login UI. There is no
  usernameless wallet login.
- Users get one extra step at login relative to the (unachievable) auto-recognition
  model.
- QAuth cannot offer EU-sanctioned returning-user login until a WebAuthn
  workstream exists — a real capability gap, honestly a roadmap item rather than a
  bug.
- `issuer-scoped-claim` deployments carry a per-issuer contractual dependency that
  QAuth cannot verify in code.

### Neutral

- ADR-004's assurance-level propagation (#237) is unaffected: `acr` still derives
  from the credential and its issuer.
- The `VerifierProfile` abstraction (#299) gains a per-profile default strategy;
  the two abstractions compose without either changing shape.
- eIDAS relying-party registration is unaffected by this ADR. Whether it is
  documentation-and-configuration scope rather than product code is **Q4 of #296
  and remains open** — ADR-004 proposed that reading and expressly declined to
  decide it.

## Citation notes

Claims above were verified on 2026-07-20 against the best available source for
each — primarily EUR-Lex/CELLAR, the ARF and attestation-rulebook repositories,
openid.net and the IETF Datatracker; non-EU claims rest on AAMVA r1.3, Japanese
Law Translation and Digital Agency material, the BVerfG text at DFR/Universität
Bern, the European Commission ESI factsheet, and 1EdTech. Three items could not be
verified against a primary source and are marked as such where they appear:
**ISO/IEC 18013-5** (paywalled, never read), the **J-LIS previous-serial service**
(HTTP 403), and the **adoption status of the draft act amending CIR 2025/848**
(secondary tracker only). Recorded here because several widely-repeated
formulations did not survive, and the corrections are worth keeping traceable —
the same reasoning that kept the erroneous paragraph visible in ADR-004.

**The blocking citation conflict was a false contradiction.** #302 flagged
CIR (EU) 2025/848 and CIR (EU) 2024/2977 as competing authorities for
relying-party registration. They govern disjoint subject matter under different
legal bases: 2025/848 (Article 5b(11)) is registration; 2024/2977 (Article 5a(23))
is the PID/EAA attribute specification; 2024/2979 (also Article 5a(23)) is
integrity and pseudonyms. Both prior passes were right about their own act. Only
the applicability date was at risk of attaching to the wrong proposition —
24 December 2026 belongs to 2025/848; 2024/2977 has no deferred application date
and has applied since 24 December 2024.

Claims corrected or weakened before being written above:

- **"GDPR Art. 87 delegates national identification numbers to Member State law"**
  — overstated. It is an optional specification clause; the GDPR continues to
  apply in full. Rewritten, and its "any other identifier of general application"
  limb added.
- **"a registrar may suspend a party that has not rightfully minimised…"** — that
  phrase is **recital 11**, non-binding, and truncated. The operative test
  (Article 9(2)(c)) is register-mismatch, discretionary, and proportionality-gated.
  Rewritten; the ADR's conclusion is now carried by the declaration step rather
  than by a suspension power.
- **`personal_administrative_number` stability "delegated to Member State policy"**
  — the regulation delegates _value policy_ and never addresses stability. Table 3
  (legal persons) shows the drafters requiring persistence elsewhere.
- **ARF PA_17 "colluding Relying Parties SHALL NOT be able to conclude…"** — the
  historical text reads "SHALL NOT able" (sic), so the familiar quote silently
  corrects its source; and PA_17 was rewritten in v2.9.0, where the normative SHALL
  binds the Wallet Provider and the colluding-RP sentence survives only as a
  non-normative Note. Quoted from v2.9.0 above.
- **ARF "a Technical Specification … will be created in the future"** — that NOTE
  was deleted in ARF v2.6.0 (2025-10-13) and must not be quoted in the present
  tense. The substantive conclusion survives via PA_21's forward-looking SHALL and
  the absence of a pseudonym TS from the Commission register.
- **WebAuthn optionality** — understated as "proposed". PA_22 already moved
  SHALL → MAY between ARF v2.5.0 and v2.9.0.
- **SD-JWT VC §2.2.2.2** — that numbering is draft-17. HAIP 1.0 §9.4 pins
  **draft-13**, where the identical sentence sits at **§3.2.2.2**. Cited as
  draft-13 above. (ARF v2.9.0 PID_20 likewise cites §3.2.2.2.)
- **PID Rulebook as an ARF annex** — no longer true; it moved to the attestation
  rulebooks catalog. Cited as PID Rulebook v1.7 (17 July 2026).
- **ISO mDL "pairwise identifiers prevent cross-transaction linking"** —
  **refuted**. AAMVA r1.3 §4.6 documents linkability as an open hazard. The
  finding was inverted above: mDL offers neither a stable identifier nor
  unlinkability.
- **mDL `document_number` "changes on renewal"** — **refuted** as a general
  proposition; inverted and restated in Finding 4, where the stability of
  `document_number` is now part of the argument rather than a counter to it.
- **My Number criminal penalties for private collection** — the chain is
  prohibition → PPC order → criminal liability for defying the order. Restated.
- **JPKI serial "rotates"** — misleading: stable for up to five years, identical
  across verifiers, with an official previous-serial lookup service.
- **Open Badges 3.0 "moved to DIDs"** — it added DIDs while retaining hashed-email
  identifiers. Restated; the graduation use case (§3.10) is genuine spec text.
- **Volkszählungsurteil "bars a universal identifier"** — scholarly reception, not
  the holding; both identifier passages are non-operative, and Germany enacted a
  cross-register identifier in 2021 that stands. Restated. (A trap for future
  editors: much secondary literature quotes near-identical language from Rn.
  118–119, which is the Federal Government's _submission_, not the Court's
  reasoning. Cite Rn. 176 and Rn. 190 only.)

Excluded as unverified, per #302: the `client_id_scheme: origin` construct and an
associated Chrome 151 DC-API deprecation timeline. Neither appears above, and
neither was re-verified here — ADR-004's
[Spec status (2026-07-20)](./004-wallet-agnostic-federation.md#spec-status-2026-07-20)
already records the Client Identifier Prefix position against OID4VP 1.0.

**Three live version-drift risks**, all of which should be re-checked before this
ADR is relied on for implementation:

1. A draft act amending **CIR 2024/2977 itself** would add a sixth mandatory PID
   attribute, `portrait`. PID Rulebook v1.7 already lists it, citing the amending
   regulation (EUR-Lex PI_COM:Ares(2026)1286304, feedback closed March 2026); no
   adopted counterpart was found in CELLAR as of 2026-07-20. This does not disturb
   Finding 1 — a portrait is not an identifier — but the "exactly five attributes"
   statement is the position under the act currently in force.
2. A draft implementing regulation amending **Annex I of CIR 2025/848** (the
   fields relying parties must supply to national registers) was in public
   consultation 5 February – 5 March 2026; no adoption was located and CELLAR
   holds no consolidated version, but adoption between March and July 2026 could
   not be positively excluded. Nothing above enumerates Annex I fields.
3. A draft act amending **Annex V of CIR 2024/2979** would touch the WebAuthn
   Level 2 pin.

## Related

- [ADR-002: Identifier Abstraction](./002-identifier-abstraction.md) — the model
  this decision fills in. **Note:** ADR-002's Context states that wallet
  credentials' "subject identifier is a pseudonymous DID or issuer-assigned opaque
  identifier". That premise is superseded by this ADR, in the same way ADR-004's
  DID-`sub` model was. ADR-002's _decision_ is unaffected and arguably vindicated:
  email-as-credential-not-identity is precisely what makes `asserted-lookup` fit
  without a migration.
- [ADR-003: CredentialProvider Abstraction](./003-credential-provider-interface.md)
- [ADR-004: Wallet-Agnostic VC Federation via OID4VP](./004-wallet-agnostic-federation.md)
  — §"Subject identity: there is no stable wallet identifier" left this OPEN; this
  ADR closes it.
- Issues: #296 (Q3 answered here) · #300 (`SubjectResolutionStrategy`) ·
  #299 (`VerifierProfile`) · #238 (account linking — premise changed) ·
  #239 (login UI needs an identifier field) · #234 / #235 · epic #231
- [Regulation (EU) No 910/2014](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32014R0910)
  as amended by [Regulation (EU) 2024/1183](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1183) — Articles 5a, 5b
- [CIR (EU) 2024/2977](https://eur-lex.europa.eu/eli/reg_impl/2024/2977/oj/eng) — PID and EAA attributes
- [CIR (EU) 2024/2979](https://eur-lex.europa.eu/eli/reg_impl/2024/2979/oj/eng) — wallet integrity and core functionalities; Article 14 and Annex V (pseudonyms)
- [CIR (EU) 2025/848](https://eur-lex.europa.eu/eli/reg_impl/2025/848/oj/eng) — relying-party registration; applies from 24 December 2026
- [EUDI Architecture and Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework) — v2.9.0 (2026-05-21), Annex 2 Topic 11
- [EUDI PID Rulebook v1.7](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/6d8f7f8422e5/rulebooks/pid/pid-rulebook.md)
  — pinned to commit `6d8f7f8422e5` (17 July 2026). **The catalog repository has
  no releases and no tags**, and the rulebook changed twice in July 2026 alone, so
  every §-pinpoint above is against that commit rather than `main`.
- [OpenID for Verifiable Credential Issuance 1.0 (Final, 2025-09-16)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [SD-JWT VC draft-13](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/) — the revision pinned by HAIP 1.0 §9.4
- [W3C WebAuthn Level 2 (REC, 2021-04-08)](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/) — named in CIR 2024/2979 Annex V
- [AAMVA Mobile Driver's License Implementation Guidelines v1.3](https://www.aamva.org/getmedia/261ed16b-3f5c-4678-a2db-cc3016934234/MobileDLImplementationGuidelines-Version1-3.pdf)
  — §4.6 "No tracking"; superseded by r1.4 / v1.6, not re-checked
- [1EdTech Open Badges Specification 3.0](https://www.imsglobal.org/spec/ob/v3p0/) — Document Version 1.4.5 (29 June 2026), §3.10
- [Japan Digital Agency — JPKI for private business](https://www.digital.go.jp/policies/myna_card_jpki) · [JPKI Portal FAQ](https://www.jpki.go.jp/faq/)
- [My Number Act (Act No. 27 of 2013)](https://www.japaneselawtranslation.go.jp/en/laws/view/3120) — Japanese Law Translation
- [BVerfGE 65, 1 — Volkszählungsurteil (15 December 1983)](https://www.servat.unibe.ch/dfr/bv065001.html) — Rn. 176, Rn. 190
- European Commission, _European Student Card Initiative — State of Play_ (doc. ref. 2022_057), Annex 2 — European Student Identifier
