# EUDI / eIDAS 2 Regulatory Drift Log

**Purpose.** [ADR-009](./adr/009-wallet-account-resolution.md) and
[ADR-004](./adr/004-wallet-agnostic-federation.md) rest on EU implementing
regulations and on specifications that move independently of QAuth. This file is
the standing record of every re-verification pass: what was checked, against
which version/date of which source, at which URL, and the verdict.

It exists so that a re-check is a diff against a previous pass rather than a
fresh investigation, and so that a negative result carries its controls with it.

| Pass         | Trigger                    | Headline outcome                                                                                 |
| ------------ | -------------------------- | ------------------------------------------------------------------------------------------------ |
| `2026-07-20` | ADR-009 acceptance (#305)  | All three drift risks **pending** — nothing published in the OJ.                                 |
| `2026-07-26` | #306, pre-24-December-2026 | **Drift landed.** Two amending acts adopted 15 July 2026, published **22 July 2026**. See below. |

---

## Pass 2026-07-26 (issue #306)

**Verified on:** 2026-07-26
**Scope:** the ADR-009 drift set — CIR (EU) 2025/848, CIR (EU) 2024/2977,
CIR (EU) 2024/2979 — plus the ARF, W3C WebAuthn, OID4VP 1.0, HAIP 1.0 and the
PID Rulebook pins those findings depend on.

### Headline

Two Commission Implementing Regulations amending the whole eIDAS 2 wallet
package were **adopted on 15 July 2026 and published in the Official Journal on
22 July 2026**. Both enter into force on **11 August 2026** (publication + 20
days, no deferred application date for the amending acts themselves).

**The timeline, stated once so it is not garbled again.** ADR-009 carries
`Date: 2026-07-20`, and the 2026-07-20 drift pass ran on that same date — the
acceptance pass and the re-check are one event, not two. Against that single
fixed point:

| Date        | Event                                                  | Offset from 2026-07-20 |
| ----------- | ------------------------------------------------------ | ---------------------- |
| 15 Jul 2026 | Both CIRs adopted ("Done at Brussels, 15 July 2026")   | **five days before**   |
| 20 Jul 2026 | ADR-009 accepted; drift pass concludes "still pending" | —                      |
| 22 Jul 2026 | OJ publication                                         | **two days after**     |
| 11 Aug 2026 | Entry into force (publication + 20 days)               | 22 days after          |

So publication followed the pass by two days, and adoption preceded it by five.
Earlier revisions of this log and of ADR-009 attached "five days" to publication
and "two days" to acceptance; both offsets cannot be true of the same date, and
the table above is the arithmetic.

| CELEX        | Act                    | Amends                                              | In force    |
| ------------ | ---------------------- | --------------------------------------------------- | ----------- |
| `32026R1730` | CIR (EU) **2026/1730** | CIR (EU) 2025/848                                   | 11 Aug 2026 |
| `32026R1731` | CIR (EU) **2026/1731** | CIR (EU) 2024/2977, 2024/2979, 2024/2980, 2024/2982 | 11 Aug 2026 |
| `32026R1735` | CIR (EU) **2026/1735** | CIR (EU) 2025/1569 (catalogue of schemes)           | 11 Aug 2026 |

`32026R1735` is outside the ADR-009 drift set and was not read; it is named here
only so a future pass does not treat it as newly discovered.

This vindicates the residual uncertainty ADR-009 recorded as item (a) —
_"adopted-but-unpublished acts are invisible to every method above"_. The 2026-07-20
pass was correct about publication and wrong about the world: the acts had already
been adopted at the moment it ran.

**The forward-looking, secondary-sourced predictions did not survive.** The
unofficial mirror of the draft annexes — the only source ADR-009 ever had for the
drafts' content — was wrong or described a superseded revision on every
load-bearing point. See [What the secondary source got wrong](#what-the-secondary-source-got-wrong).

### Verdicts

| #   | Item                                            | Verdict                   | Effect on ADR-009                                                                  |
| --- | ----------------------------------------------- | ------------------------- | ---------------------------------------------------------------------------------- |
| 1   | CIR 2024/2977 Annex (PID attribute set)         | **Drifted — act amended** | Finding 1 factual corrections; core conclusion **survives**                        |
| 2   | CIR 2025/848 (relying-party registration)       | **Drifted — act amended** | Finding 2 **strengthened**; no correction needed to the ADR's claims               |
| 3   | CIR 2024/2979 Art. 14 + Annex V (pseudonyms)    | **Superseded**            | Finding 3's WebAuthn anchor **deleted from EU law** — needs a human decision       |
| 4   | ARF release after v2.9.0                        | **Drifted — v3.0.0**      | Topic 11 (`PA_01`–`PA_31`) **substantively unchanged**; Decision §3 gate unchanged |
| 5   | W3C WebAuthn Level 3 advancement                | **Confirmed — no change** | Still Candidate Recommendation Snapshot, 26 May 2026                               |
| 6   | OID4VP 1.0 / HAIP 1.0 / SD-JWT VC draft-13      | **Confirmed — no change** | ADR-004 and ADR-009 citations stand                                                |
| 7   | EUDI PID Rulebook pin (`6d8f7f8422e5`)          | **Confirmed — no change** | Still the latest commit; its portrait text is now **vindicated**                   |
| 8   | AAMVA mDL Implementation Guidelines r1.6        | **Confirmed — no change** | Finding 4 unchanged, and corroborated by new CIR text                              |
| 9   | SD-JWT VC / mdoc issuer-chain header parameters | **Drifted**               | Decision §2's `x5c` / `x5chain` instruction is wrong for PID — human decision      |

---

### 1. CIR (EU) 2024/2977 — PID attribute set — **DRIFTED**

**Source.** CIR (EU) 2026/1731, **Article 1, points (1) to (4)**, and Annex I.
Point (4) plus Annex I replace the Annex to CIR (EU) 2024/2977 in its entirety;
point (1) inserts a new **Article 3a**, read in full below. (Point (2) replaces
Article 4(1), point (3) replaces Article 5(4)(b); neither bears on ADR-009.)
Retrieved from CELLAR: `http://publications.europa.eu/resource/celex/32026R1731`
(`Accept: application/xhtml+xml`, `Accept-Language: eng`).
ELI: <http://data.europa.eu/eli/reg_impl/2026/1731/oj>

#### New Article 3a — "Protection of the portrait" — **binds relying parties directly**

This was missed by the first writing of this pass and is recorded here with the
prominence it deserves: it is the **only provision in CIR 2026/1731's amendments
to CIR 2024/2977 that imposes an obligation on wallet-relying parties**, i.e. on
the role QAuth would occupy. Article 1(1) inserts, verbatim:

> **Article 3a — Protection of the portrait**
>
> 1. In addition to information requirements pursuant to Regulation (EU) 2016/679,
>    wallet providers shall ensure that the wallet solutions they provide issue
>    warnings to wallet users where wallet-relying parties request the disclosure
>    of the portrait, indicating that the request involves the sharing of biometric
>    data and requires confirmation for the selective disclosure of the portrait.
>
> 2. For the implementation of selectively disclosing the portrait to a
>    wallet-relying party, the wallet providers shall ensure the wallet solutions
>    require the wallet user to explicitly and specifically confirm the presentation
>    of the portrait.
>
> 3. The portrait shall not be retained by wallet-relying parties unless its
>    processing is necessary for the purposes of identification and authentication
>    in compliance with Union data protection law or where this is provided for by
>    Union or national law, in compliance with Union data protection law. The
>    portrait shall not be transferred to third countries or international
>    organisations unless permitted by Union data protection law.

**Who is bound by what.** Paragraphs 1 and 2 bind **wallet providers** (warning
and explicit per-presentation confirmation). Paragraph 3 binds **wallet-relying
parties** directly, and is the operative one for QAuth:

- **Retention** — a relying party **shall not retain** the portrait unless
  processing it is necessary for identification and authentication under Union
  data protection law, or retention is provided for by Union or national law.
  Note the shape: this is a prohibition with a narrow carve-out, not a permission.
- **Third-country transfer** — the portrait **shall not be transferred** to third
  countries or international organisations unless Union data protection law permits
  it.

**Why this is material now.** Article 3a is not deferred: it enters into force with
the rest of CIR 2026/1731 on **11 August 2026**. Only the `portrait` attribute's
_mandatory_ status in Table 1 waits until 11 August 2028. So the RP-side duty exists
two years before the attribute becomes mandatory — a portrait presented voluntarily
in the interim is already covered.

For the T4 verifier track and for #236's claim mapping this means: a QAuth verifier
that receives a `portrait` claim must be able to **not store it by default**, and any
storage must be justifiable as necessary for identification/authentication. This is a
data-handling default, not a protocol feature — but it is a legal obligation on the
verifier, so it belongs in the same bucket as `OIDFVP-HAIP-SUPPORT-05` (see item 6)
rather than in the wallet-side bucket.

The new **Table 1 — "Mandatory person identification data for the natural person
for selective disclosure"** has **two columns** (`Data identifier`, `Definition`;
the "Presence" column is gone, membership in Table 1 having become the mandatory
marker) and **six rows**: `family_name`, `given_name`, `birth_date`,
`birth_place`, `nationality`, `portrait`.

The `portrait` row reads, verbatim:

> Except where the user explicitly opts out, where applicable, the facial image of
> the user to whom the person identification data relates, compliant with the
> quality requirements for a full frontal image type as set out in ISO/IEC 39794-5
> or, for backward compatibility, ISO/IEC 19794-5, clauses 8.2, 8.3 and 8.4,
> provided as encoded image data without the headers or blocks as specified in
> clause 5 of ISO/IEC 19794-5, except for the image data itself (a JPEG) **shall
> apply from 11 August 2028**.

Recital 3 of CIR 2026/1731 confirms the deferral:

> To give Member States sufficient time to adapt their national procedures, the
> wallet user's portrait may be part of the mandatory person identification data
> for the natural person only as of 11 August 2028.

Table 1 also carries a standalone note: _"Member States may provide that the user
has the option to decline the insertion of the portrait to the person
identification data."_

**What this changes in ADR-009 Finding 1:**

- **"lists exactly five attributes"** — false from 11 August 2026. Six data
  identifiers, one of which (`portrait`) does not apply until 11 August 2028 and is
  subject to a user opt-out. The correct statement for the period 11 Aug 2026 →
  11 Aug 2028 is _five operative mandatory attributes out of six listed_.
- **The "attribute value appropriate to the situation" sentence** no longer sits
  under Table 1. It now appears **only under Table 3 (legal persons)**. Table 1's
  unknown-value handling is specific: an appropriate value for an unknown
  `birth_date`, `'QU'` for unknown nationality, `'QS'` for stateless, and an empty
  value where the user opts out of `portrait`.
- **Table 5 metadata**: `expiry_date` moved from **mandatory to optional**.
  `issuing_authority` and `issuing_country` remain mandatory; `document_number`
  remains optional. Two new optional fields appear: `issuing_jurisdiction` and
  `issuance_date`.
- **PID encoding** now delegates to CIR 2024/2979 Annex II, clauses 5 (SD-JWT VC)
  and 6 (ISO/IEC-mdoc), rather than specifying formats in the 2977 Annex itself.

**What survives unchanged — the load-bearing part of Finding 1:**

- **No identifier attribute in Table 1.** A `portrait` is a biometric, not a
  subject identifier. The finding's conclusion is untouched.
- **`personal_administrative_number` is byte-identical** in the new Table 2 —
  still optional, still scoped to _"unique among all personal administrative
  numbers issued by the provider of person identification data"_, still delegating
  **value policy** and never addressing stability.
- **Table 3 (legal persons)** still requires an identifier _"which is as persistent
  as possible in time"_. The drafters-knew-how contrast in Finding 1 still holds.
- **Article 3(4)** of CIR 2024/2977 (the dataset-level uniqueness duty) is not
  among the provisions amended by CIR 2026/1731 Article 1 and stands.

**Resolves ADR-009 residual uncertainty (c).** The PID Rulebook was **not**
glossing. The adopted text contains both things the Rulebook asserted and the
mirrored draft lacked — ISO/IEC 39794-5 as primary, and an explicit user opt-out —
and the deferral to 11 August 2028 is **exactly 24 months after entry into force**
(11 August 2026), which is what the Rulebook said. The Rulebook was tracking a
later draft than the mirror. ADR-009's instruction to _"treat the 24-month
transition as unsupported by any legal text"_ is now superseded: it is supported,
expressed as a hard date.

---

### 2. CIR (EU) 2025/848 — relying-party registration — **DRIFTED (strengthens the ADR)**

**Source.** CIR (EU) 2026/1730, of 15 July 2026, _amending Implementing Regulation
(EU) 2025/848 as regards applicable standards and specifications_.
CELLAR: `http://publications.europa.eu/resource/celex/32026R1730`
ELI: <http://data.europa.eu/eli/reg_impl/2026/1730/oj>

**The base act's load-bearing provisions are untouched.** CIR 2026/1730 Article 1
amends only Article 6(3)(a), deletes Article 6(3)(c), inserts Article 6(3a),
replaces Article 8(1) and 8(2), and amends Annexes I, IV and V. Re-confirmed
verbatim in the base text as unamended:

- Article 1 — _"This Regulation lays down rules for the registration of
  wallet-relying parties."_
- Article 3(1) — _"Member States shall establish and maintain at least one national
  register of wallet-relying parties…"_
- Article 9(2)(c) — the register-mismatch test, _"requesting more attributes than
  they have registered in accordance with Article 5 and Article 6"_.
- Article 11 — _"It shall apply from the 24 December 2026."_ (quoted as printed).
- Recital 11 — the non-binding _"rightfully minimised"_ language.

**So the 24 December 2026 date stands**, and ADR-009 Finding 2 needs no
correction. What applies from that date is now the _amended_ 2025/848.

**What is new, and why it strengthens Finding 2.** New Article 8(2), points (c)
and (d), require Member States to:

> (c) ensure that wallet-relying party registration certificates include a general
> access policy, being syntactically and semantically harmonised across the Union,
> informing users that the wallet-relying party is only allowed to request the data
> specified in the registration certificates for the intended use registered in the
> registration certificates;
>
> (d) ensure that providers of wallet solutions established in that Member State
> comply with the general access policy by informing users when a wallet-relying
> party requests data that is not specified in the registration certificates;

Finding 2's argument was that _"a national identifier requested for 'recognise
returning users' is unlikely to survive the declaration step in the first place"_.
That argument previously rested on a discretionary, proportionality-gated
registrar power (Article 9(2)). It now also rests on a mandatory, user-facing
warning surfaced by the wallet at request time. The reasoning that led to
`asserted-lookup` is better supported than when it was written.

Also new: Annex I gains point 16 (association to a wallet-relying party relying on
an intermediary); Annex IV's certificate-policy pin moves from ETSI EN 319 411-1
v1.4.1 to **ETSI TS 119 411-8 V1.1.1 (2025-10)**; Annex V's moves to
**ETSI TS 119 475 V1.2.1 (2026-03)**. Article 8(1) now requires registration
certificates to be issued _"in an automated manner and without undue delay after
the registration"_.

---

### 3. CIR (EU) 2024/2979 Article 14 and Annex V — pseudonyms — **SUPERSEDED**

This is the finding that changed, and it changed in the direction nobody predicted.

**Source.** CIR (EU) 2026/1731, Article 2, points (8) and (14):

> (8) in Article 14, paragraph 1 is deleted;
>
> …
>
> (14) Annex V is deleted.

For reference, the deleted text of CIR 2024/2979 as originally published:

> **Article 14 — Pseudonyms**
>
> 1. Wallet units shall support the generation of pseudonyms for wallet users in
>    compliance with the technical specifications set out in Annex V.
>
> **ANNEX V — TECHNICAL SPECIFICATIONS FOR PSEUDONYM GENERATION REFERRED TO IN
> ARTICLE 14**
> — WebAuthn – W3C Recommendation, 8 April 2021, Level 2,
> <https://www.w3.org/TR/2021/REC-webauthn-2-20210408/>

**Article 14(2) survives unamended** — the provision ADR-009 Finding 3 quotes:

> 2. Wallet units shall support the generation, upon the request of a wallet-relying
>    party, of a pseudonym which is specific and unique to that wallet-relying party
>    and provide this pseudonym to the wallet-relying party, either standalone or in
>    combination with any person identification data or electronic attribute
>    attestation requested by that wallet-relying party.

**Consequence.** From 11 August 2026, EU law requires wallets to produce
relying-party-specific pseudonyms **and names no technical specification for doing
so**. "WebAuthn" does not appear anywhere in CIR 2026/1730 or CIR 2026/1731
(verified: zero occurrences, case-insensitive, in both full texts). The only
FIDO-family reference in either act is CTAP 2.3, cited in CIR 2026/1731 recital 5
and in the new Annexes to CIR 2024/2982 — and it is about **cross-device proximity
and data transfer**, not pseudonyms.

This directly contradicts ADR-009 Finding 3's sub-heading _"The named technical
specification is WebAuthn"_, and it weakens — without refuting — the
_"`rp-pseudonym` = passkey"_ equation on which Finding 3's whole shape rests. It
does **not** touch Article 5a(4)(b) of Regulation (EU) No 910/2014, which is
primary legislation and still requires wallets to let users generate pseudonyms.

**Flagged for a human decision.** ADR-009 Decision §3 has not been rewritten. See
[ADR-009 § Drift re-check (2026-07-26)](./adr/009-wallet-account-resolution.md#drift-re-check-2026-07-26).

---

### 4. EUDI ARF — **DRIFTED to v3.0.0, but Topic 11 is substantively unchanged**

**Source.** ARF **v3.0.0**, released **2026-07-23** (GitHub release `v3.0.0`,
`published_at 2026-07-23T19:10:17Z`) — the first release after v2.9.0. Its release
notes name CIR 2026/1730, 2026/1731 and 2026/1735 as the legal basis for the
alignment.

Checked directly against the tag:
`docs/annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md` at `v3.0.0`,
section A.2.3.8 _"Topic 11 — Pseudonyms"_.

- **`PA_21` is present and normative, verbatim unchanged:** _"The Commission SHALL
  create or reference a technical specification containing a profile or extension of
  the [W3C WebAuthn] specification compliant with the HLRs specified in this Topic…"_
- **`PA_22` is present, still a MAY** (unchanged since v2.9.0).
- **`PA_17` is present, verbatim as quoted in ADR-009 Finding 3**, including the
  non-normative colluding-relying-parties Note.
- `PA_14`, `PA_15`, `PA_16` all survive.
- The relying-party HLRs `PA_10`–`PA_13` carry **no** _"if a common technical
  specification enabling this is available"_ qualifier.
- The Commission technical-specification register at `v3.0.0`
  (`docs/technical-specifications/`) contains **TS1–TS14 and still no pseudonym
  technical specification**.

**Topic 11 is byte-for-byte stable across the release.** All 32 pseudonym HLRs
(`PA_01`–`PA_09`, `PA_08a`, `PA_10`–`PA_31`) were compared mechanically between the
`v2.9.0` and `v3.0.0` tags after whitespace normalisation. **Exactly one differs, and
only in markup**: `PA_08a`'s cross-reference to Topic 19 changed from an inline
markdown link to a reference-style link (`[Topic 19][topic-19]`). Its requirement text
is unchanged. Every other HLR, `PA_20` included, is verbatim identical.

#### Scope rate-limited pseudonyms — `PA_23`–`PA_31`, and a claim they refute

**Correction to the first writing of this pass**, which said _"New `PA_23`–`PA_26`
cover scope rate-limited pseudonyms"_. That was wrong twice over:

1. **The range is `PA_23`–`PA_31`, not `PA_23`–`PA_26`** — nine HLRs, all normative
   SHALL, under Annex 2 §A.2.3.8 heading _"E. HLRs related to scope rate-limited
   pseudonyms"_.
2. **They are not new.** The identical heading and the identical nine requirements
   are present in **`v2.9.0`** — the release ADR-009 was written against — at lines
   452–465 of the same annex file, differing only in that v2.9.0 renders HLRs as a
   markdown table and v3.0.0 as `<div class="eudi-hlr">` blocks. Nothing about this
   mechanism drifted in v3.0.0. It was there all along and this log, and ADR-009,
   simply did not read that far down the topic.

The five that were omitted, verbatim:

> **`PA_27`** — A protocol enabling scope rate-limited pseudonyms SHALL NOT allow any
> entity or collusion of entities not including the User, to link scope rate-limited
> pseudonyms of the same User when used across several different Relying Parties. This
> SHALL hold even if the scope and rate are identical across the different Relying
> Parties and both for registration and authentication of the scope rate-limited
> pseudonym
>
> **`PA_28`** — A protocol enabling scope rate-limited pseudonyms SHALL ensure that if
> the rate is larger than 1, a User's different pseudonyms SHALL be unlinkable for the
> same scope. This SHALL hold against any entity or collusion of entities, not
> including the User. Further, such protocol SHALL ensure that during registration or
> authentication with such a pseudonym, it SHALL NOT be possible for the Relying Party
> to deduce any information about how many pseudonyms the User has already registered
> (except that it does not exceed the predetermined rate).
>
> **`PA_29`** — A protocol enabling scope rate-limited pseudonyms SHALL ensure that no
> entity or collusion of entities, not including a User, is able to authenticate or
> register with a scope rate-limited pseudonym of this User.
>
> **`PA_30`** — A Wallet Unit SHALL store cryptographic material necessary for
> authenticating as a scope rate-limited pseudonyms in either a WSCA/WSCD or in a
> keystore.
>
> **`PA_31`** — A User's scope rate limited pseudonyms for a particular scope and rate
> SHALL be persistent over time even if they start using another Wallet Unit.

(`PA_23`–`PA_26`, already summarised above, require the protocol to use only
ECCG Agreed Cryptographic Mechanisms v2.0 algorithms, to let a User generate and
register such a pseudonym and prove it is within the restrictions, to let the Relying
Party verify the rate is not exceeded, and to let the Relying Party choose the scope
and rate.)

**Why this matters more than a numbering slip.** `PA_31` is a normatively specified
**persistence guarantee across Wallet Units**: the same scope and rate yields the same
pseudonym for the same User even after the User migrates to a different wallet. That
is precisely the property ADR-009 exists to interrogate — _can an RP-scoped pseudonym
serve as a durable account key?_ — and it is stated in the ARF as a SHALL, not as a
discussion proposal. `PA_27` and `PA_28` bound the answer from the other side: whatever
mechanism delivers `PA_31` must **not** let colluding relying parties link a User's
pseudonyms across RPs (`PA_27`), and must keep a User's several pseudonyms within one
scope mutually unlinkable and their count unknowable to the RP (`PA_28`). `PA_29` adds
impersonation resistance; `PA_30` puts the key material in a WSCA/WSCD or keystore.

Note what section E does **not** say: **it never names WebAuthn.** It speaks throughout
of _"a protocol enabling scope rate-limited pseudonyms"_, unnamed. And `PA_31`'s
cross-Wallet-Unit persistence sits awkwardly with a plain WebAuthn credential, which is
authenticator-bound by construction — delivering `PA_31` implies deriving the pseudonym
from something the User carries between wallets rather than from a freshly generated
key pair. So the ARF describes, in normative language, a **non-WebAuthn RP-scoped
pseudonym mechanism with a durability guarantee**, alongside the WebAuthn profile
`PA_21` still demands.

**Two honest caveats, so this correction does not overreach.**

- **`PA_21` nominally covers section E too.** It requires a WebAuthn profile
  _"compliant with the HLRs specified in this Topic"_, and section E is in that Topic.
  Whether the Commission reads `PA_21` as also having to satisfy `PA_23`–`PA_31`, or
  treats scope rate-limited pseudonyms as a separate protocol family, is **not
  resolved by any text read in this pass**. Both readings are open.
- **No specification exists for it either.** Section E constrains a protocol that the
  register (TS1–TS14) does not contain. `PA_23`–`PA_31` are requirements on a
  specification yet to be written, exactly as `PA_21` is. Nothing here discharges any
  gate in ADR-009 Decision §3.

**Consequence for ADR-009.** Its re-check claimed Finding 3's conclusion "may well
survive on other grounds (ARF `PA_21` still names WebAuthn; **nothing else has been
proposed**)". The parenthetical is false, and was false when written: `PA_23`–`PA_31`
had been normative since at least v2.9.0. Corrected in the ADR — see
[ADR-009 § Drift re-check (2026-07-26)](./adr/009-wallet-account-resolution.md#drift-re-check-2026-07-26).

**The Topic E revision-round paper is unchanged** — still
`docs/discussion-topics/e-rr-pseudonyms-including-user-authentication-mechanism.md`,
still _"Version 1.2, updated 26 June 2026"_, still proposing a bare "Remove" for
`PA_21` and `PA_22`. One full release cycle later, **that proposal was not
implemented**.

> **Corrected 2026-07-26 (same pass, second reading).** This log previously added
> _"Partial adoption is visible — `PA_20`'s Note was updated along the lines the paper
> proposed — so this is a decision not to delete, not an oversight."_ **That is false.**
> `PA_20`, Note included, is verbatim identical between `v2.9.0` and `v3.0.0`; see the
> mechanical comparison above. **No** part of the Topic E paper was implemented in
> v3.0.0. The inference built on it — that non-deletion was deliberate rather than an
> oversight — therefore has **no evidential support** and is withdrawn. What can be
> said is only the observable fact: one release after the paper, nothing it proposed
> has been actioned. Whether that is a decision or a backlog is unknown.

**Effect on ADR-009 Decision §3.** Gate 2 (_"publication of the Commission
technical specification mandated by ARF `PA_21`"_) is **unchanged and still not
discharged**. The vacuous-clearing hazard ADR-009 warned about has **not**
materialised. But ADR-009's forecast — _"the deletion reading is the
better-supported one"_ — is now contradicted by the evidence and should not be
repeated. Note the resulting tension, which is new and real: **the ARF keeps a
WebAuthn-based obligation that the implementing regulation has just deleted.**

---

### 5. W3C WebAuthn Level 3 — **CONFIRMED, no change**

<https://www.w3.org/TR/webauthn-3/> — status line reads _"W3C Candidate
Recommendation Snapshot, 26 May 2026"_. The CR review period closed 23 June 2026
and the document has not advanced to Proposed Recommendation or Recommendation.

Level 2 (8 April 2021) therefore remains the only operative Recommendation. This is
now a fact about W3C only: after CIR 2026/1731 deleted Annex V, **no EU legal
instrument pins any WebAuthn level at all**, so the "would Annex V follow Level 3
automatically?" question recorded in ADR-009 is moot.

### 6. OID4VP 1.0 / HAIP 1.0 / SD-JWT VC — **CONFIRMED, no change**

| Spec               | Status                                       | Source                                                                                |
| ------------------ | -------------------------------------------- | ------------------------------------------------------------------------------------- |
| OpenID4VP 1.0      | Final, published 9 July 2025                 | <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>                 |
| OpenID4VCI 1.0     | Final, 16 September 2025 (unchanged)         | <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>           |
| OpenID4VC HAIP 1.0 | Final, published 24 December 2025            | <https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html> |
| SD-JWT VC          | `draft-ietf-oauth-sd-jwt-vc-13` (6 Nov 2025) | pinned by HAIP 1.0 §12 normative references                                           |

ADR-009's citation of SD-JWT VC **draft-13 §3.2.2.2** via HAIP 1.0 stands.

**New, and material for the T4 verifier work:** CIR 2024/2982's Annex II is
replaced (CIR 2026/1731 Annex XII) and now incorporates clauses 4.1, 4.2, 5 and 6 of
**ETSI TS 119 472-2 V1.2.1 (2026-03)** _"with the following adaptations"_, the
adaptations being set out at length in Annex XII itself. The result defines an
_OpenID4VC-HAIP profile_ and, in one clause, **binds relying parties directly**:

> `OIDFVP-HAIP-SUPPORT-05`: A Relying Party shall meet the requirements specified in
> clauses 6.5 of the present Annex.

HAIP conformance for an EU relying party is therefore a legal requirement rather than
a best practice.

> **Corrected 2026-07-26 (same pass, second reading) — `WRP-VALIDATION-01`/`-02` bind
> the Wallet, not the relying party.** This log previously listed them alongside
> `OIDFVP-HAIP-SUPPORT-05` as obligations that "bind relying parties directly". They do
> not. **Read who the subject of each sentence is** — in Annex XII clause 4.4,
> _"Wallet-relying party validation and overasking checks"_:
>
> > `WRP-VALIDATION-01`: **The EUDI Wallet** shall validate the wallet-relying party
> > registration certificate received in the request before presenting any requested PID
> > or electronic attestation of attributes to the wallet user for approval.
> >
> > `WRP-VALIDATION-02`: Where the validation of the wallet-relying party registration
> > certificate fails, including where the certificate is expired, revoked, not issued by
> > a valid trusted provider of wallet-relying party registration certificates, malformed,
> > or cannot be cryptographically verified, **the EUDI Wallet** shall warn the wallet user
> > that the wallet-relying party could not be validated and shall not present the request
> > as successfully validated. The wallet user shall explicitly approve the request of the
> > relying party. Silence or pre-ticked boxes shall not suffice for explicit approval.
> >
> > `WRP-VALIDATION-03`: **The wallet provider** shall determine, based on its risk
> > analysis and security policy, whether and under which conditions specific failed
> > validation checks may be bypassed by the wallet user.
>
> The "wallet-relying party" in the identifier name is the **object** being validated,
> not the actor doing the validating. The same pattern holds for the sibling
> requirements in the same clause: `WRP-OVERASKING-01` and `-02` bind **the EUDI
> Wallet**, `WRP-OVERASKING-03` binds **the wallet provider**.

**Who is bound by what — clause 4.4 and clause 6.2, stated plainly.**

| Requirement                     | Actor bound         | Substance                                                            |
| ------------------------------- | ------------------- | -------------------------------------------------------------------- |
| `WRP-VALIDATION-01`, `-02`      | **EUDI Wallet**     | Validate the RP registration certificate; warn the user on failure   |
| `WRP-VALIDATION-03`             | **Wallet provider** | Decide whether failed checks may be bypassed                         |
| `WRP-OVERASKING-01`, `-02`      | **EUDI Wallet**     | Compare request against certificate; warn the user on overasking     |
| `WRP-OVERASKING-03`             | **Wallet provider** | Decide whether the user may proceed despite the warning              |
| `OIDFVP-HAIP-SUPPORT-02`, `-03` | **EUDI Wallet**     | Meet clause 6.5; should not use redirect-based cross-device flows    |
| **`OIDFVP-HAIP-SUPPORT-05`**    | **Relying Party**   | **Meet the requirements of clause 6.5 — the only RP-binding clause** |

**What this changes for QAuth's backlog.** Certificate-chain validation, revocation
checking and a "silence or pre-ticked boxes shall not suffice" consent screen are
**wallet-side obligations**. They must **not** enter #236 or the T4 verifier track as
QAuth work on the strength of this Annex. What Annex XII does put on a QAuth-shaped
relying party is `OIDFVP-HAIP-SUPPORT-05`: conformance to clause 6.5. The RP-side
consequence of clause 4.4 is indirect but real — a wallet **will** refuse or flag a
request whose registration certificate does not validate or which overasks, so the
operator-side duty to hold a correct, current registration certificate and to request
only registered attributes is load-bearing. That is a registration and deployment
concern, not a protocol feature, which is exactly the distinction #296 Q4 is asking
about. This sharpens Q4; it does not answer it.

**Not verified.** ETSI TS 119 472-2 V1.2.1 itself was **not retrieved**. Annex XII's
preamble incorporates clauses 4.1, 4.2, 5 and 6 of that document and then sets out
adaptations covering clauses 4.3 and 4.4 among others, so it is **not established here**
whether clause 4.4 originates in the ETSI text or is inserted by the CIR. Every
requirement quoted above is quoted from **CIR 2026/1731 Annex XII**, which is binding
either way.

### 7. EUDI PID Rulebook — **CONFIRMED, no change**

Latest commit to `rulebooks/pid/pid-rulebook.md` in
`eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog` is
**`6d8f7f8422e5` (2026-07-17)** — the exact commit ADR-009 pins. The repository
still has no releases and no tags. Its portrait text is now vindicated (item 1).

### 8. AAMVA mDL Implementation Guidelines — **CONFIRMED, no change**

r1.6 remains the current release. Finding 4 is unchanged, and is now corroborated
from an EU primary source: CIR 2026/1731 Annex XII, `ISO/IEC 18013-SUPPORT-01`:

> Wallet Units, PID Providers, Attestation Providers, Wallet Providers, and Relying
> Parties **shall not support server retrieval** as specified in ISO/IEC 18013-5
> [10] for requesting and presenting PID or attestation attributes.

The EU has independently reached AAMVA's r1.5 conclusion — the tracking hazard is
addressed by prohibiting the feature. ISO/IEC 18013-5 remains paywalled and unread;
no clause of it is quoted anywhere in ADR-009 or here.

### 9. Issuer certificate-chain header parameters — **DRIFTED**

ADR-009 **Decision §2** instructs that the issuer component _"MUST come from the
validated issuer certificate chain (`x5c` for SD-JWT VC, `x5chain` in the COSE MSO
for mdoc — #236)"_. For **PID**, the amended CIR 2024/2977 Annex now says otherwise:

> The Protected Header of the digital signature signing a person identification data
> in SD-JWT VC format shall contain the `x5u` and the `x5t#S256` header parameters,
> specified in RFC 7515.

> The Protected Header of the CB-AdES digital signature signing a person
> identification data in ISO/IEC-mdoc format shall contain the `x5u` and the `x5t`
> header parameters, both specified in RFC 9360. […] The digest algorithm used in the
> `x5t` header parameter shall be SHA-256.

`x5c` does still appear in the amended acts, but for **wallet instance attestations
and key attestations** (CIR 2026/1731 Annex II, `TR-WIA-4`, `TR_KA-5`), and
`x5chain` appears for **MSO revocation lists**. So the parameter names are
context-specific, and ADR-009 generalised from the wrong context for PID.

The **security principle is untouched**: the issuer must still come from a
validated chain anchored in a trusted list, never from an unverified `iss`. What
changes is that a PID verifier must resolve `x5u` (a URI) and match `x5t#S256` /
`x5t`, which is a different — and network-facing — implementation shape.

**Not verified.** The general EAA format rules now live in **ETSI TS 119 472-1
V1.2.1 (2026-02)**, incorporated by reference into the replaced Annex II of CIR
2024/2979. That ETSI document was **not retrieved or read** in this pass, so this
log states nothing about header parameters for non-PID attestations. Anyone
implementing #236 must read it.

---

### What the secondary source got wrong

ADR-009 recorded three forward-looking claims about the draft amending CIR 2025/848,
each explicitly marked **secondary-sourced** (an unofficial mirror of the draft
annexes; the operative articles were never retrievable). All three are **refuted**
by the adopted text of CIR 2026/1730:

| Claim (secondary-sourced, ADR-009)                                           | Adopted text                                               |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------- |
| Inserts _"shall accept WebAuthn as authentication mechanism for pseudonyms"_ | **No occurrence of "WebAuthn" anywhere in CIR 2026/1730.** |
| Replaces Annex II                                                            | Annex II is not touched. Annexes I, IV and V are amended.  |
| Adds a new Annex VI                                                          | **No Annex VI is added.**                                  |
| Its Article 2 gives entry into force at publication + 20 days, no deferral   | **Correct** — the one claim that held.                     |

And the fourth, about the same draft instrument's treatment of CIR 2024/2979
Annex V:

| Claim (secondary-sourced, ADR-009)                                                                                           | Adopted text                                     |
| ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| Annex V replaced so the requirement becomes _"any WebAuthn Authenticator of the user's choice"_, Level 2 surviving in a NOTE | **Annex V is deleted outright.** No replacement. |

**Lesson worth keeping.** ADR-009 marked every one of these secondary and refused
to let them carry a decision. That discipline is what kept the ADR correct while
its inputs were wrong. The practice to continue: an unofficial mirror of a
comitology draft predicts the _subject matter_ of an act reasonably well and its
_operative content_ not at all.

### Method and controls

Unchanged from the 2026-07-20 pass and repeated here because it is what works.
EUR-Lex web endpoints (`eur-lex.europa.eu/eli/…`, `/legal-content/…`) return HTTP
202 with an empty body to automated fetches and carry **no information** about
whether a document exists. Two endpoints do work:

```bash
# CELLAR. Accept-Language is NOT optional: without it CELLAR returns HTTP 400
# "Invalid content type CONTENT_STREAM for WORK ... without language",
# which reads like "nothing there". Follow redirects (-L): /resource/celex/ 303s.
curl -sL -H 'Accept: application/xhtml+xml' -H 'Accept-Language: eng' \
  http://publications.europa.eu/resource/celex/32026R1731

# SPARQL: answers the adoption question directly.
curl -s -G http://publications.europa.eu/webapi/rdf/sparql \
  --data-urlencode 'query=PREFIX cdm: <http://publications.europa.eu/ontology/cdm#>
    PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
    SELECT ?basecelex ?celex ?date WHERE {
      VALUES ?basecelex { "32024R2977"^^xsd:string "32024R2979"^^xsd:string
                          "32024R2980"^^xsd:string "32024R2982"^^xsd:string
                          "32025R0848"^^xsd:string }
      ?base   cdm:resource_legal_id_celex ?basecelex .
      ?amender cdm:resource_legal_amends_resource_legal ?base .
      OPTIONAL { ?amender cdm:resource_legal_id_celex ?celex }
      OPTIONAL { ?amender cdm:work_date_document     ?date }
    }' --data-urlencode 'format=application/sparql-results+json'
```

**Two SPARQL traps, both of which produce a convincing false negative.**

1. The `^^xsd:string` datatype suffix is required. A bare `"32024R2977"` in a
   `VALUES` clause matches nothing and the query returns zero rows with no error.
2. `/resource/celex/` returns HTTP 303; without `-L`, `curl` reports 0 bytes.

**Controls applied before believing any result:**

- **Query validity** — the same `amends` pattern returns 2 rows for eIDAS
  (`32014R0910`): `32022L2555` and `32024R1183`. Positive control passed.
- **Store freshness** — CELLAR served the full text of acts published **22 July
  2026**, four days before this pass. No ingestion lag at the relevant horizon.
- **Cross-check** — the ARF v3.0.0 release notes, published independently on
  2026-07-23, name exactly the same three amending acts. Two independent sources
  agree.

**Residual uncertainty, stated rather than resolved.**

- **(a) Adopted-but-unpublished acts remain invisible.** This pass caught the July
  2026 package because it had been published; the same blind spot applies to
  anything adopted since. Nothing in this method fixes that.
- **(b) ETSI TS 119 472-1/-2/-3 and ETSI TS 119 475 were not retrieved.** They are
  now incorporated by reference into binding EU law and govern the formats and the
  relying-party protocol profile. Every statement here about them comes from the
  CIR's own adaptation clauses, not from the ETSI text.
- **(c) ISO/IEC 18013-5 and 18013-7 remain paywalled and unread.**
- **(d) Consolidated versions of the amended acts did not yet exist** at the time of
  this pass; everything above is read from the base acts plus the amending
  instruments, and the amendments were applied by hand.

### Next re-check

Trigger dates now on the calendar:

| Date        | What happens                                                                            |
| ----------- | --------------------------------------------------------------------------------------- |
| 11 Aug 2026 | CIR 2026/1730 and 2026/1731 enter into force                                            |
| 24 Dec 2026 | CIR 2025/848 (as amended) applies — wallet-relying party registration becomes operative |
| 11 Aug 2028 | `portrait` becomes a mandatory PID attribute; CIR 2024/2982 Art. 3(4) applies           |

Re-check before 24 December 2026. Watch specifically for: a Commission pseudonym
technical specification (would discharge ARF `PA_21` and reopen Decision §3), the
consolidated versions of the amended acts, and any further ARF release.
