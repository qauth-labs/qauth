# Specification Pin Log

**Purpose.** QAuth's requirements are written by the IETF and the OpenID
Foundation, not by us, and a good part of what we cite is still moving.
[ADR-007](./adr/007-mcp-first-positioning.md) mandates "a standing quarterly
re-pin pass" over exactly these citations;
[ADR-011](./adr/011-enterprise-managed-authorization.md) restates the
obligation. This file is where that pass lives: what is pinned, to which
revision, **on what basis**, when it was last verified, and when it must be
looked at again.

It is the sibling of [`eudi-regulatory-drift-log.md`](./eudi-regulatory-drift-log.md),
which keeps sole ownership of the **EU legal instruments** — the eIDAS 2
implementing regulations, the ARF, ISO/IEC and ETSI. Nothing in that domain gets
a row here; go there instead. What this file owns is everything else that moves:
Internet-Drafts, OpenID Foundation specifications, the MCP authorization
specification and the MCP `ext-auth` extension catalogue.

**Published RFCs get no rows.** An RFC is immutable — RFC 8693 will not change
under us. Pin what moves.

> **This document is itself a status surface, and status surfaces decay.** It is
> only worth having because
> `apps/docs-site/src/invariants/spec-pins.test.ts` fails the build on a past
> `Re-check by` date, a missing or malformed date, a row with no consumers, an
> unrecognised pin basis, or a `Consumers` path that no longer exists. That
> check compares against the REAL current date, not a pinned one, so it goes red
> on the day a row falls due even if nobody touched the repository. If it is
> ever made warn-only or frozen to a fixed date, delete this file: a table of
> dates that looks maintained and is not is worse than no table at all.

---

## Pass ledger

| Pass         | Trigger                          | Headline outcome                                                                                                                                                                                                                                                                                                                                                  |
| ------------ | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `2026-08-31` | #401 — first pass, log created   | Rows established from citations already recorded in the ADRs and the code. **No new drift found; nothing re-pinned.**                                                                                                                                                                                                                                             |
| `2026-09-26` | Second pass; every row re-opened | Every row re-verified against upstream. **OAuth 2.1 re-pinned `-15` → `-16`.** Five rows added. An `Expires` column added. The Token Status List verdict corrected from HAIP 1.0 §6.1 to §9.4. The `Re-check by` rule made explicit: the expiry date applies to `latest` Internet-Draft rows only. `deliberate` widened to cover a spec QAuth does not implement. |

The first pass deliberately re-stated what ADR-005, ADR-007, ADR-009 and ADR-011
had already recorded, rather than re-investigating each source. Its
`Last verified` dates were the dates of those earlier checks. Inventing a fresh
"verified today" date for a source nobody opened would have been exactly the
unfalsifiable claim this log exists to stop.

The 2026-09-26 pass re-opened every upstream source, so every `Last verified`
in the table is now that date. Where a verdict still rests on an older check of
QAuth's own code, the cell says so and gives that check's date. The pass also
added five rows, the draft expiries, the HAIP §9.4 quote and the method notes.
Every number in it comes from a fresh fetch (see
[Method and controls](#method-and-controls)).

It also changed two definitions. First, the `Re-check by` rule now says
which expiry it means. The 2026-08-31 text said "for an Internet-Draft, its
expiry". Now the expiry counts only for a `latest` row, and it is the expiry of
the pinned revision. A `derived` or `deliberate` row keeps the quarterly date.
Second, the `deliberate` basis now also covers a spec QAuth knowingly does not
implement. The PQC rows already used it that way.

The pass also found one row the rule, as now written, should have caught. The
2026-08-31 pass pinned OAuth 2.1 at `-15` with `Re-check by` 2026-11-30. But
`-15` expired on 2026-09-03, so the rule gave 2026-09-03, and the row ran 23
days past its own expiry with nothing flagged. Read literally, the 2026-08-31
wording would also have caught SD-JWT VC `-13`, Token Status List `-14` and
CIMD `-00`, which had all expired by then. Those rows are `derived` or
`deliberate`, so under the rule as now written they keep the quarterly date.
The new `Expires` column puts each expiry in the table, where a reader can see
it. The freshness check still does not compare the two columns (see
[Residual uncertainty](#residual-uncertainty)).

---

## Why `Pin basis` is a column and not prose

The EUDI log implies a pin basis in its narrative; this log makes it a field,
because without it the log has a failure mode with no visible symptom.

**SD-JWT VC is pinned at `-13` while `-19` is current.** That is not six
revisions of rot. HAIP 1.0 §9.4 names `-13`, and QAuth targets HAIP, so `-13` is
the correct revision to cite. It stays correct even though `-13` expired as an
Internet-Draft on 2026-05-10: HAIP 1.0 is Final and still names it. A
well-meaning "update everything to latest" pass would break EUDI conformance
while making the docs look **more** current — a regression that reads as an
improvement in every diff.

With the column, the re-check question for that row stops being "is there a
newer draft?" and becomes **"did HAIP change what it references?"** — which is
the question that can actually be wrong.

For the same reason, if an automated refresher is ever added, **it may only
open an issue. It must never commit a revision bump.** A bot that cannot read
this column cannot tell a derived pin from a latest-published one.

### The three bases

| Basis        | Meaning                                                                                                     | Re-check question                |
| ------------ | ----------------------------------------------------------------------------------------------------------- | -------------------------------- |
| `derived`    | The revision is fixed by a **profile or spec we conform to**, not by us. Bumping it is a conformance break. | Did the pinning document change? |
| `latest`     | We track the newest published revision.                                                                     | Is there a newer revision?       |
| `deliberate` | We knowingly cite an older revision, or knowingly do not implement the spec, for a recorded reason.         | Does the reason still hold?      |

---

## Pin table

**How `Re-check by` is set.** It is the earlier of two dates:

1. the next quarterly pass, **2026-11-30**; and
2. for a `latest` row pinned to an Internet-Draft, that revision's own expiry.

A `derived` or `deliberate` row pinned to a revision that has already expired
keeps the quarterly date. The document that dictates the pin keeps it alive, so
the draft's expiry is not a reason to look sooner. That expiry is still recorded
in `Expires`, so for those rows the two columns disagree on purpose. OpenID
Foundation Finals, MCP revisions and the `ext-auth` branch do not expire: their
`Expires` is `—` and they take the quarterly date. A `deliberate` row that pins
no revision also shows `—`.

`Expires` comes from Datatracker for a draft's current revision and from the
archived text's `Expires:` line for a superseded one (see
[Method and controls](#method-and-controls)).

`Consumers` are paths that must exist; the freshness check fails when one does
not, because a pin nothing consumes is a pin nobody will notice going stale.

| Spec                                                                    | Pinned revision                                | Expires            | Pin basis    | Last verified | Re-check by  | Verdict                                                                                                  | Consumers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ----------------------------------------------------------------------- | ---------------------------------------------- | ------------------ | ------------ | ------------- | ------------ | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc`)                                | `-13`                                          | expired 2026-05-10 | `derived`    | `2026-09-26`  | `2026-11-30` | Current for HAIP 1.0 §9.4; upstream is at `-19`                                                          | `libs/server/federation/src/oid4vp/sd-jwt-vc.ts`, `libs/server/federation/src/oid4vp/sd-jwt-vc.test.ts`, `libs/server/federation/src/oid4vp/sd-jwt-vc.credential-status.test.ts`, `libs/server/federation/src/oid4vp/presentation-rejection.ts`, `libs/server/config/src/lib/schemas/federation.ts`, `apps/auth-server/src/testing/mock-wallet.ts`, `apps/auth-server/src/testing/mock-wallet.test.ts`, `docs/adr/004-wallet-agnostic-federation.md`, `docs/adr/009-wallet-account-resolution.md`, `apps/docs-site/src/invariants/spec-pins.test.ts` |
| Token Status List (`draft-ietf-oauth-status-list`)                      | `-14`                                          | expired 2026-06-13 | `derived`    | `2026-09-26`  | `2026-11-30` | Current for HAIP 1.0 §9.4; upstream is at `-21`, in the RFC Editor queue                                 | `libs/server/federation/src/status/status-list-spec.ts`, `libs/server/federation/src/status/status-list-spec.test.ts`, `libs/server/federation/src/status`, `libs/server/federation/README.md`, `apps/auth-server/src/testing/mock-status-list.ts`, `docs/adr/004-wallet-agnostic-federation.md`                                                                                                                                                                                                                                                     |
| ID-JAG (`draft-ietf-oauth-identity-assertion-authz-grant`)              | `-04`                                          | 2026-11-22         | `latest`     | `2026-09-26`  | `2026-11-22` | Current; `-04` is the newest revision                                                                    | `apps/auth-server/src/app/helpers/id-jag.ts`, `apps/auth-server/src/app/helpers/id-jag-draft-pin.test.ts`, `docs/adr/011-enterprise-managed-authorization.md`, `apps/docs-site/src/invariants/spec-pins.test.ts`                                                                                                                                                                                                                                                                                                                                     |
| CIMD (`draft-ietf-oauth-client-id-metadata-document`)                   | `-00` cited, `-02` current                     | expired 2026-04-11 | `deliberate` | `2026-09-26`  | `2026-11-30` | Reason holds: MCP 2026-07-28 still cites `-00`; code meets `-02` per ADR-007 (2026-08-06, not re-tested) | `apps/auth-server/src/app/helpers/cimd.ts`, `apps/auth-server/src/app/helpers/discovery.ts`, `libs/server/config/src/lib/schemas/auth.ts`, `apps/auth-server/src/app/helpers/ssrf-safe-fetch.ts`, `apps/docs-site/src/content/docs/integrate/mcp-quickstart.md`, `docs/adr/007-mcp-first-positioning.md`                                                                                                                                                                                                                                             |
| OAuth 2.1 (`draft-ietf-oauth-v2-1`)                                     | `-16`                                          | 2027-03-07         | `latest`     | `2026-09-26`  | `2026-11-30` | Re-pinned from `-15`, which expired 2026-09-03; still not an RFC                                         | `docs/adr/007-mcp-first-positioning.md`, `.claude/skills/oauth-oidc/SKILL.md`, `.claude/skills/auth-oauth/reference.md`                                                                                                                                                                                                                                                                                                                                                                                                                              |
| JWT client authentication update (`draft-ietf-oauth-rfc7523bis`)        | `-11`                                          | 2026-10-30         | `latest`     | `2026-09-26`  | `2026-10-30` | Current; in the RFC Editor queue, so the next change is an RFC number                                    | `.claude/agents/auth-specialist.md`, `docs/adr/014-agent-authority-tree.md`                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| OAuth security BCP update (`draft-ietf-oauth-security-topics-update`)   | `-03`                                          | 2027-01-07         | `latest`     | `2026-09-26`  | `2026-11-30` | Current; `-03` is the newest revision                                                                    | `.claude/skills/auth-oauth/reference.md`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| OpenID4VP                                                               | 1.0 Final (2025-07-09)                         | —                  | `latest`     | `2026-09-26`  | `2026-11-30` | Final; no newer published revision                                                                       | `libs/server/federation/src/oid4vp`, `libs/server/federation/src/profiles/verifier-profile.types.ts`, `apps/auth-server/src/app/routes/oid4vp`, `docs/adr/004-wallet-agnostic-federation.md`, `docs/adr/010-acr-assurance-mapping.md`, `docs/conformance/requirements/oid4vp-1_0.json`, `docs/conformance/specs.json`                                                                                                                                                                                                                                |
| OpenID4VC HAIP                                                          | 1.0 Final (2025-12-24)                         | —                  | `latest`     | `2026-09-26`  | `2026-11-30` | Final; §9.4 still names the two derived pins above                                                       | `libs/server/federation/src/profiles/verifier-profiles.ts`, `docs/conformance/requirements/haip-1_0.json`, `docs/conformance/specs.json`, `docs/adr/004-wallet-agnostic-federation.md`, `docs/adr/010-acr-assurance-mapping.md`, `docs/adr/013-same-device-return-leg.md`, `docs/wallet-interop-manual-validation.md`                                                                                                                                                                                                                                |
| OpenID4VCI                                                              | 1.0 Final (2025-09-16)                         | —                  | `latest`     | `2026-09-26`  | `2026-11-30` | Final; no newer published revision. Appendix D and §3.3.2 are what QAuth cites                           | `libs/server/federation/src/attestation/attack-potential.ts`, `libs/server/federation/src/attestation/key-attestation.ts`, `libs/server/config/src/lib/schemas/key-attestation.ts`, `libs/server/config/src/lib/schemas/assurance.ts`, `libs/server/federation/src/subject/subject-resolution.types.ts`, `libs/server/federation/src/subject/subject-resolution-strategies.ts`, `docs/adr/009-wallet-account-resolution.md`, `docs/adr/010-acr-assurance-mapping.md`                                                                                 |
| OpenID Connect Core 1.0                                                 | Final, incorporating errata set 2 (2023-12-15) | —                  | `latest`     | `2026-09-26`  | `2026-11-30` | Errata set 2 is still the latest approved text; errata set 3 is only a draft                             | `docs/adr/002-identifier-abstraction.md`, `docs/adr/010-acr-assurance-mapping.md`, `docs/adr/011-enterprise-managed-authorization.md`, `docs/conformance/requirements/oidc-core-1_0.json`, `docs/conformance/specs.json`                                                                                                                                                                                                                                                                                                                             |
| MCP authorization                                                       | `2026-07-28`                                   | —                  | `latest`     | `2026-09-26`  | `2026-11-30` | Current published revision                                                                               | `docs/adr/007-mcp-first-positioning.md`, `libs/fastify/plugins/mcp-guard`, `apps/docs-site/src/content/docs/integrate/mcp-quickstart.md`, `apps/docs-site/src/content/docs/integrate/agent-authorization.md`, `apps/docs-site/src/content/docs/integrate/api-reference.md`, `apps/docs-site/src/content/docs/operate/docker.md`, `README.md`, `apps/auth-server/src/app/helpers/discovery.ts`, `docs/adr/014-agent-authority-tree.md`                                                                                                                |
| MCP `ext-auth` EMA extension (STABLE)                                   | repo `main` at `e5eef54` (2026-06-18)          | —                  | `latest`     | `2026-09-26`  | `2026-11-30` | Still the only STABLE extension; the file is unchanged since the pinned commit                           | `docs/adr/011-enterprise-managed-authorization.md`, `apps/auth-server/src/app/routes/oauth/token.ts`, `apps/auth-server/src/app/routes/oauth/token.test.ts`, `apps/auth-server/src/app/helpers/id-jag.ts`, `docs/adr/007-mcp-first-positioning.md`, `docs/adr/014-agent-authority-tree.md`                                                                                                                                                                                                                                                           |
| PQC composite signatures for JOSE (`draft-ietf-jose-pq-composite-sigs`) | not implemented                                | —                  | `deliberate` | `2026-09-26`  | `2026-11-30` | Reason holds at `-04`: QAuth signs in parallel, not composite (ADR-005 amendment #245)                   | `docs/adr/005-pqc-hybrid-signing.md`, `apps/docs-site/src/content/docs/operate/pqc-verifier-guide.md`, `libs/core/crypto/src/lib/hybrid-signing.ts`                                                                                                                                                                                                                                                                                                                                                                                                  |
| Composite ML-DSA for X.509 (`draft-ietf-lamps-pq-composite-sigs`)       | not implemented                                | —                  | `deliberate` | `2026-09-26`  | `2026-11-30` | Reason holds at `-19`, now in the RFC Editor queue; drop the row once it is an RFC                       | `docs/adr/005-pqc-hybrid-signing.md`, `MVP-PRD.md`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

### Row notes

- **CIMD is `deliberate`, not `derived`.** The reason is recorded in ADR-007's
  "Underlying spec drift" section. QAuth cites `-00` because the MCP 2026-07-28
  specification does. QAuth's implementation already meets everything `-01` and
  `-02` added (ADR-007 re-verified this on 2026-08-06; this pass did not re-test
  the code). Re-pinning the citation alone would put QAuth's advertised
  profile ahead of the MCP specification its clients implement. So the re-check
  question is: does MCP still cite `-00`? It does (see finding 3). A move to
  `-02` would not be text-only: QAuth's "CIMD §6" and "CIMD §6.2" references use
  `-00`/`-01` numbering, and `-02` moved Security Considerations to §8.
- **The two PQC composite rows are `deliberate`, and pin nothing.** ADR-005's
  amendment #245 chose a parallel hybrid: two separate signatures over the same
  input. The ML-DSA-65 signature travels outside the token. The LAMPS and JOSE
  drafts define a composite instead: one algorithm id and one concatenated
  signature. QAuth's hybrid token stays an ordinary Ed25519 compact JWS, so a
  stock JOSE verifier checks it unmodified. The re-check question is whether
  that reason still holds at the newest revision. At JOSE `-04` (2026-09-11) it
  does: §4.4 still concatenates the component signatures under one algorithm
  id such as `ML-DSA-65-Ed25519`. `-04` also changed the ECDSA component
  encoding (new §4.5), which does not touch the Ed25519 pair. LAMPS `-19` (2026-04-21) is in the RFC Editor queue; once it is
  an RFC, the row goes, because published RFCs get no rows.
- **rfc7523bis `-11` has two expiry dates upstream.** Datatracker says
  2026-10-30: `-11` was posted on 2026-04-28, and an I-D expires 185 days after
  posting. The archived text's header says 27 September 2026, because the
  authors have not changed the date line since `-07` (posted 2026-03-26). This
  log uses Datatracker. ADR-014's watch list took the header date.
- **The `ext-auth` pin is a branch.** The repository publishes no tags and no
  releases, so the pin is `main` plus the last commit that touched
  `specification/stable/enterprise-managed-authorization.mdx`. The file's blob
  is `586ce278` at both `e5eef54` and the `main` head on 2026-09-26. Two open
  pull requests (#12 and #30) change that file; neither has merged.

### Rows that were considered and deliberately excluded

- **RFC 9964** (ML-DSA for JOSE/COSE) and **RFC 9864** — published RFCs, and the
  reason `draft-ietf-cose-dilithium` has no row: #274 re-pinned QAuth off that
  draft onto its published successor, which is precisely the outcome this log
  wants. `libs/core/crypto/src/lib/hybrid-constants.ts` records it.
- **`draft-prabel-jose-pq-composite-sigs-02`** — cited only as the historical
  wrong answer that #274 corrected. It names a frozen revision; the correction
  is what a reader needs, not a freshness date.
- **EUDI ARF, the eIDAS 2 CIRs, ISO/IEC 18013-5, ETSI, W3C WebAuthn** — owned by
  [`eudi-regulatory-drift-log.md`](./eudi-regulatory-drift-log.md). QAuth cites
  WebAuthn only inside ADR-009's analysis of EU law. Two logs tracking one
  source is how they disagree.
- **Unpublished editor's drafts** — HAIP 1.1, the OID4VP 1.0 and HAIP 1.0
  errata-set-1 drafts, OIDC Core draft 36 and the MCP `draft` tree. This log
  pins published revisions only. They are watch items in the findings below.
- **RFC 6749, 7636, 8693, 8707, 9700, 7591, 8414, 7523, 9101, 9728** — immutable.

---

## Findings of the 2026-09-26 pass

### 1. HAIP 1.0 §9.4 dictates the two derived pins

Read on 2026-09-26 from
<https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html>
(HTTP 200). The `-final` URL served the same bytes (sha256 `3996e0479d06b72d…`).
The page header says Status: Final, Published 24 December 2025. §9.4
"Pre-Final Specifications", verbatim, with the pilcrows removed and whitespace
normalised:

> Implementers should be aware that this specification uses several
> specifications that are not yet final specifications. Those specifications
> are:
>
> - SD-JWT-based Verifiable Credentials (SD-JWT VC) draft -13
>   [I-D.ietf-oauth-sd-jwt-vc]
> - Token Status List draft -14 [I-D.ietf-oauth-status-list]
>
> While breaking changes to the specifications referenced in this specification
> are not expected, should they occur, implementations compliant with this
> specification should continue to use the specifically referenced versions above
> in preference to the final versions, unless updated by a profile or new version
> of this specification.
>
> Note that specification versions mentioned in this specification overwrite the
> versions previously mentioned in [OIDF.OID4VCI] and [OIDF.OID4VP].

The specification writes "draft -13" with a space, and the quote keeps it.

**The Token Status List row used to say §6.1. That was the wrong section.**
§6.1, "IETF SD-JWT VC Profile", uses the Status List: the `status` claim, if
present, MUST contain `status_list`, and the public key that validates the
Status List Token's signature MUST be in its `x5c` header. But §6.1 cites the
draft by tag only and names no revision. §9.4 is the section that names `-14`. The row now says §9.4, like the SD-JWT VC
row and the comment beside the `TOKEN_STATUS_LIST_DRAFT` constant.

**§12 is not a second pin.** The published Final's Normative References list
`draft-ietf-oauth-sd-jwt-vc-13` and `draft-ietf-oauth-status-list-14`. But the
source cites both drafts without a revision, and the renderer fills in whatever
is current when the page is built. The HAIP 1.1 editor's draft, as rendered on
2026-09-26, lists `-19` and `-21` in its references while its own §9.4 still
says `-13` and `-14`. So §9.4 alone carries the pin.

**Nothing upstream is moving it yet.** HAIP 1.1 is not published: its `1_1`
URL returns 404. Two unpublished editor's drafts sit in the
`openid/OpenID4VC-HAIP` GitHub repository, one for HAIP 1.0 "incorporating
errata set 1" (`-1_0-09`) and one for HAIP 1.1 (`-1_1-01`). Both still name
SD-JWT VC draft -13 and Token Status List draft -14 in their Pre-Final
Specifications section.

### 2. SD-JWT VC has no pin constant

Token Status List is pinned in code: `TOKEN_STATUS_LIST_DRAFT` in
`libs/server/federation/src/status/status-list-spec.ts`, with a test that
asserts the literal. SD-JWT VC has no such constant. The only file near the
code that names `-13` is a comment in
`libs/server/config/src/lib/schemas/federation.ts`. The `@see` in
`libs/server/federation/src/oid4vp/sd-jwt-vc.ts` links the unversioned
Datatracker URL, which on 2026-09-26 resolved to `-19`. The section numbers the code
cites (§3.2.2.2, §3.2.1) are `-13` numbers; `-19` puts "Registered JWT Claims"
at §2.2.2.3.

So SD-JWT VC is the pin most likely to be "helpfully" refreshed by someone who
has not read HAIP §9.4. A re-pin would not be text-only either: `-18` and `-19`
add `aka_vcts` to the claims that must not be selectively disclosable, so
`NON_SELECTIVELY_DISCLOSABLE_CLAIMS` would have to change too.

This pass records the risk only. It adds no constant.

### 3. What MCP 2026-07-28 cites for OAuth 2.1

Counted on 2026-09-26 in the four source files under
`docs/specification/2026-07-28/basic/authorization/` on the `main` branch of
`modelcontextprotocol/modelcontextprotocol`. 2026-07-28 is still the newest
dated revision: `docs.json` labels it "(latest)", `/specification/latest`
redirects to it, and it is the newest non-prerelease GitHub release.

| Draft cited | Revision | Links |
| ----------- | -------- | ----- |
| OAuth 2.1   | `-13`    | 17    |
| OAuth 2.1   | `-14`    | 1     |
| CIMD        | `-00`    | 10    |

The counts are of link URLs. A few links also use the draft name as their
text, so a plain count of the draft name reads them twice and gives 18 and 12.

The one `-14` link is the refresh-token rule in `index.mdx` ("OAuth 2.1 Section
4.3"). It came in with SEP-2207 in March 2026. The refresh-token rotation rule
in `security-considerations.mdx` still cites `-13`. So MCP's OAuth 2.1 citation is
mixed, not one revision.

All three cited revisions had expired before 2026-07-28 was published. OAuth 2.1
`-13` expired on 29 November 2025, `-14` on 23 April 2026, and CIMD `-00` on 11
April 2026.

This does not move QAuth's OAuth 2.1 row. That row is `latest`, so it follows
the IETF draft (`-16`), not MCP. It does keep the CIMD row where it is: MCP
still cites `-00`, which is the reason that row records.

The unpublished `draft` tree (`docs/specification/draft/`) is the working text
of the next MCP revision, so it is a watch item too. On 2026-09-26 its four
authorization files cite the same revisions in the same counts as 2026-07-28:
OAuth 2.1 `-13` 17 times and `-14` once, CIMD `-00` 10 times. Nothing there is
moving the CIMD pin yet.

### 4. The OpenID Foundation errata trap

OID4VP 1.0 §1.2, OID4VCI 1.0 §1.1 and HAIP 1.0 §1.2 carry the same paragraph,
apart from the spec name. From OID4VP, read 2026-09-26:

> The latest revision of this specification, incorporating any errata updates,
> is published at openid-4-verifiable-presentations-1_0. The text of the final
> specification as approved will always be available at
> openid-4-verifiable-presentations-1_0-final. When referring to this
> specification from other documents, it is recommended to reference
> openid-4-verifiable-presentations-1_0.

QAuth follows that advice and cites the unversioned URLs. So an approved errata
set changes the text under QAuth's citations, with no new revision number and no
diff in this repository. OIDC Core 1.0 has no such paragraph, but its
unversioned URL behaves the same way: on 2026-09-26 it served errata set 2.

What the unversioned URLs served on 2026-09-26:

- **OID4VCI and HAIP:** byte-identical to their `-final` copies. No errata.
- **OID4VP:** differs from its `-final` copy in one reference entry only, its
  OID4VCI citation ("1.0 - draft 16" against "draft 15"). No errata.
- **OIDC Core:** errata set 2 (Final, 2023-12-15), byte-identical to
  `openid-connect-core-1_0-errata2.html`.

Errata work is under way for three of them. None of it is published:

- An OID4VP 1.0 "incorporating errata set 1" editor's draft (`-31`) on GitHub.
  Among other changes, it adds a sentence to §8.2 telling wallets not to follow
  HTTP redirects from the Response URI.
- A HAIP 1.0 "incorporating errata set 1" editor's draft (`-09`). It rewords one
  §5 bullet to name the `dcql_query` parameter.
- OIDC Core "draft 36 incorporating errata set 3", posted 2025-01-30 and marked
  Draft. It makes the OP's Issuer Identifier the **sole** audience of
  `private_key_jwt` and `client_secret_jwt` assertions and of Request Objects.

That last one matters to QAuth. `acceptedClientAssertionAudiences` in
`apps/auth-server/src/app/helpers/client-assertion.ts` accepts both the issuer
and the token endpoint URL, and ADR-011 records that design. It is compliant
under errata set 2. It would not be under errata set 3.
`draft-ietf-oauth-rfc7523bis-11`, now in the RFC Editor queue, says the same:
the issuer identifier as the sole audience value. This pass changes no code; it
records the watch item.

The conformance files quote these specifications verbatim
(`docs/conformance/requirements/*.json`). When an errata set is published, the
next pass should re-check those quotes against what the unversioned URLs then
serve. This trap is also listed under [Residual uncertainty](#residual-uncertainty).

### 5. Stale citations found, not changed in this pass

These were found while checking consumers. Each is a text fix for a later
change; none of them changes a pin.

- `apps/docs-site/src/invariants/spec-pins.test.ts` — a comment says SD-JWT VC
  "`-18` is current". It is `-19`. The assertions themselves still hold. The
  `realToday()` comment also says this test goes red when ID-JAG `-04` expires
  on 2026-11-22. The earliest `Re-check by` is now rfc7523bis `-11`, on
  2026-10-30, so the test goes red on 2026-10-31.
- `libs/server/config/src/lib/schemas/federation.ts` — cites "SD-JWT VC draft-13
  §3.2.2.2" for "`vct` is an arbitrary string". In `-13` that rule is §3.2.2.1,
  and it requires a Collision-Resistant Name.
- `libs/server/federation/src/oid4vp/sd-jwt-vc.ts`,
  `libs/server/federation/src/oid4vp/presentation-rejection.ts` and
  `libs/server/federation/src/oid4vp/sd-jwt-vc.test.ts` — comments cite
  §3.2.2.2 with no revision; that is a `-13` section number. They say it names
  six claims that must not be selectively disclosable. In `-13` it names seven,
  `vct#integrity` included. `NON_SELECTIVELY_DISCLOSABLE_CLAIMS` matches
  `-13` exactly, so behaviour is right; only the rationale text is off.
- `libs/server/federation/src/status/status-list-chain.ts` (the module that
  implements the rules),
  `libs/server/federation/src/status/status-list-chain.test.ts`,
  `libs/server/federation/src/attestation/key-attestation.ts`,
  `libs/server/federation/src/x509/anchored-chain.ts`,
  `libs/server/federation/README.md`,
  `libs/server/config/src/lib/schemas/federation.ts` (the
  `OID4VP_STATUS_LIST_TRUST_ANCHORS` docblock) and `.env.example` — cite HAIP
  §6.1.1 for the Status List Token `x5c` rules. Those rules are in §6.1.
  §6.1.1 covers only the `x5c` of the SD-JWT VC issuer. The other §6.1.1
  citations in the repository are about the credential issuer, and they are
  right.
- Twelve comments and test names in `apps/auth-server` and
  `libs/server/config/src/lib/schemas/auth.ts` still name MCP 2025-11-25 for
  behaviour that 2026-07-28 keeps. `registration-attribution.ts` also misquotes
  `README.md`, which now says MCP 2026-07-28.
- `docs/adr/014-agent-authority-tree.md` — its watch list dates rfc7523bis
  `-11` from the stale text header (26 March, expiring 27 September 2026).
  Datatracker says posted 2026-04-28, expiring 2026-10-30.
- `docs/adr/011-enterprise-managed-authorization.md`, "What EMA is" — "currently
  the only" STABLE extension carries no date. It is still true on 2026-09-26.
- `apps/auth-server/src/app/helpers/id-jag.ts` and
  `apps/auth-server/src/app/helpers/id-jag-draft-pin.test.ts` — cite ADR-011
  by a line-number range that has since drifted off the sentence it meant. A
  heading citation would not drift.
- `MVP-PRD.md` — "Composite ML-DSA-65 + Ed25519, following
  `draft-ietf-lamps-pq-composite-sigs` (JOSE WG adoption Jan 2026)". That
  contradicts ADR-005's amendment and mixes up the LAMPS draft with the JOSE
  draft adopted in January 2026.

---

## Triggers

A pass runs when **any** of these fires:

1. **The quarterly calendar pass** asked for in ADR-007's "Process note". Next:
   **2026-11-30**.
2. **A draft expiry.** A `latest` I-D row's `Re-check by` is the earlier of the
   next quarter and its pinned revision's expiry. ID-JAG `-04` expires
   **2026-11-22**, a date recorded nowhere before this file existed;
   rfc7523bis `-11` expires **2026-10-30**.
3. **An ADR moving Proposed → Accepted** re-verifies its own rows first. ADR-011
   is Proposed with merged code, so it triggers on the next pass.
4. **A dictating document changing.** A new HAIP version or a published HAIP
   errata set re-checks both derived rows. An MCP revision after 2026-07-28
   re-checks the CIMD and MCP rows.
5. **A draft in the RFC Editor queue becoming an RFC.** Token Status List,
   rfc7523bis and the LAMPS composite draft were all in the RFC Editor queue on
   2026-09-26.

---

## Method and controls

**Read the pinning document, not just the pinned one.** For a `derived` row the
question is whether HAIP still references that revision. A newer draft is not
by itself drift.

**Use Datatracker for Internet-Drafts, and parse it with code.** Never read
revision numbers or dates from a summary. The current revision, its expiry and
the publication date of every revision come from one `doc.json`:

```bash
curl -s https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/doc.json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["rev"], d["expires"]); print([(r["rev"], r["published"][:10]) for r in d["rev_history"] if r["name"] == d["name"]][-2:])'
# -> 16 2027-03-07 00:22:00
# -> [('15', '2026-03-02'), ('16', '2026-09-03')]
```

The expiry of a superseded revision is not in `doc.json`. Read it from the
`Expires:` line of the archived text:

```bash
curl -s https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt | grep -m1 -o 'Expires: [0-9]* [A-Za-z]* [0-9]*'
# -> Expires: 3 September 2026
```

Replacement and RFC status come from the relations API, asked in both
directions (`source__name=` and `target__name=`), for `replaces` and for
`became_rfc`:

```bash
curl -s 'https://datatracker.ietf.org/api/v1/doc/relateddocument/?source__name=draft-ietf-oauth-v2-1&relationship__slug=became_rfc&format=json' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["meta"]["total_count"])'
# -> 0
```

**Controls applied before believing a result:**

- **Positive control.** Before trusting "no change" on any row, run the same
  query on a draft known to have moved since the last pass, and check that the
  query sees the move. On 2026-09-26 three had moved: OAuth 2.1 (`-16`,
  2026-09-03), SD-JWT VC (`-19`, 2026-08-31) and the JOSE composite draft
  (`-04`, 2026-09-11). A query that reported them unchanged would be broken, and
  so would every "no change" it reported elsewhere.
- **`time` is not a publication date.** In `doc.json`, `time` is the date of the
  last event on the document, such as an RFC Editor status change. Take
  publication dates from `rev_history`. On 2026-09-26, reading `time` would
  date LAMPS `-19` to 2026-09-23 and rfc7523bis `-11` to 2026-09-22. Both were
  published in April (2026-04-21 and 2026-04-28).
- **Cross-check the two expiry sources.** Datatracker sets an I-D's expiry at
  185 days after posting. The archived header's `Expires:` line is written by
  the authors. On 2026-09-26 they agree for every pinned revision except
  rfc7523bis `-11` (see the row notes). Where they disagree, Datatracker wins.
- **Derived pins are checked at the dictating document.** The SD-JWT VC and
  Token Status List rows were verified by reading HAIP 1.0 §9.4 itself, not by
  asking Datatracker what is current, which answers a different question.
- **MCP citations are counted in the specification's source files**, not taken
  from ADR-007's summary of them.
- **The `ext-auth` catalogue is listed through the GitHub contents API**, so
  "the only STABLE extension" is a directory listing and not a claim.
- **OIDF errata are checked by bytes.** Compare the sha256 of each unversioned
  URL with its `-final` copy (or `-errata2` for OIDC Core). A difference beyond
  the one known OID4VP reference entry means an errata set was published.
- **Pin to published revisions only.** ADR-007's 2026-08-06 addendum records
  why: reviewing against a release candidate compounded a stale-claim error.
- **Record the URL, the HTTP status and the date you read it**, not only the
  verdict, so the next pass is a diff rather than a fresh investigation.
- **A negative result still gets written down.** "Confirmed — no change" is the
  most common outcome and the most valuable to record, because it is what makes
  the next pass cheap.

### Sources read on 2026-09-26

All fetched with `curl` (GitHub API calls with `gh api`) and parsed with
`python3`. HTTP status in brackets.

- **Datatracker `doc.json` [200]** for all nine drafts in the table:
  `https://datatracker.ietf.org/doc/<draft>/doc.json`.
- **Datatracker relations [200]**, `replaces` and `became_rfc`, source and
  target side, for all nine drafts (36 queries). Every draft replaces one
  individual draft. None is replaced, and none has become an RFC.
- **Archived texts [200]**, `https://www.ietf.org/archive/id/<draft>-<rev>.txt`:
  sd-jwt-vc `-13`, `-17`, `-18`, `-19`; status-list `-14`, `-21`; identity-assertion-authz-grant
  `-04`; client-id-metadata-document `-00`, `-01`, `-02`; oauth-v2-1 `-13`,
  `-14`, `-15`, `-16`; jose-pq-composite-sigs `-03`, `-04`;
  lamps-pq-composite-sigs `-19`; rfc7523bis `-07`, `-10`, `-11`;
  security-topics-update `-03`.
- **Next revision, not yet published [404]:** sd-jwt-vc `-20`, status-list
  `-22`, identity-assertion-authz-grant `-05`, client-id-metadata-document
  `-03`, oauth-v2-1 `-17`, jose-pq-composite-sigs `-05`,
  lamps-pq-composite-sigs `-20`, rfc7523bis `-12`, security-topics-update `-04`.
- **OpenID Foundation [200]**, all under `https://openid.net/specs/`:
  `openid4vc-high-assurance-interoperability-profile-1_0.html`, `…-1_0-final.html`,
  `openid-4-verifiable-presentations-1_0.html`, `…-1_0-final.html`,
  `openid-4-verifiable-credential-issuance-1_0.html`, `…-1_0-final.html`,
  `openid-connect-core-1_0.html`, `…-errata2.html`, `…-36.html`.
- **OpenID Foundation, not published [404]:** HAIP `…-1_1.html`, OID4VP
  `…-1_1.html`, OID4VCI `…-1_1.html`, OIDC Core `…-37.html` and
  `…-errata3.html`.
- **Editor's drafts [200]:** `raw.githubusercontent.com/openid/OpenID4VC-HAIP/main/1.0/…-1_0.md`
  and `…/1.1/…-1_1.md`;
  `raw.githubusercontent.com/openid/OpenID4VP/main/1.0/…-1_0.md`;
  `openid.github.io/OpenID4VC-HAIP/openid4vc-high-assurance-interoperability-profile-1_1-wg-draft.html`.
- **MCP [200]:** `raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/docs/specification/2026-07-28/basic/authorization/`
  `index.mdx`, `client-registration.mdx`, `security-considerations.mdx`,
  `authorization-server-discovery.mdx`, and `docs/docs.json`; the same four
  files under `docs/specification/draft/basic/authorization/`; `gh api` for the
  `docs/specification` listing, the releases, and pull request #2207
  ("SEP-2207: OIDC-flavored refresh token guidance", merged 2026-03-29).
- **MCP site [307]:** `https://modelcontextprotocol.io/specification/latest`,
  which redirects to `/specification/2026-07-28`.
- **`ext-auth` [200, `gh api`]:** `repos/modelcontextprotocol/ext-auth`, the
  `specification/stable` and `specification/draft` listings, the commit history
  of the EMA file, the file at `e5eef546`, tags, releases and open pull
  requests.

---

## Residual uncertainty

- **(a) The freshness check verifies dates, pin bases and consumer paths.** It does
  **not** verify that a pinned revision still exists upstream, or that a
  `derived` row's basis document still says what the table claims. Those need a
  human, which is what the quarterly pass is for. It also does not check that
  `Re-check by` follows the rule: it never reads `Expires`, so a `latest`
  Internet-Draft row whose re-check date is later than its expiry passes. That
  is how OAuth 2.1 `-15` lapsed unflagged.
- **(b) OIDF errata are invisible between passes.** Four rows cite unversioned
  URLs that absorb errata with no version number to diff (finding 4). A section
  number quoted in QAuth's code can change meaning upstream with no event in
  this repository. The byte comparison in the method catches it only at the
  next pass.
- **(c) An I-D can be replaced between passes** without any signal here. The
  quarterly cadence and the expiry clock bound how long that can go unnoticed;
  nothing shortens it.
- **(d) `ext-auth` is pinned to a branch.** Nothing stops `main` from moving,
  and there is no tag or release to pin to instead.
- **(e) The consumer lists are the load-bearing citations, not an exhaustive
  index.** Each row names the files that must change when its pin changes. A
  citation elsewhere can go stale without failing the check. `git grep` for the
  draft name is the exhaustive answer.
- **(f) Drafts in the RFC Editor queue.** On 2026-09-26, Token Status List,
  rfc7523bis and the LAMPS composite draft were frozen there, and the next
  change is an RFC number. Datatracker showed an expiry for each (LAMPS `-19`:
  2026-10-23), though a draft in the queue does not usually lapse. The rule
  still uses that date for
  rfc7523bis. When Token Status List becomes an RFC, its row stays: HAIP 1.0
  §9.4 would still name `-14`.

---

## Next re-check

Every date in the table, in order:

| Date           | What falls due                                                                    |
| -------------- | --------------------------------------------------------------------------------- |
| **2026-10-30** | rfc7523bis `-11` expires (Datatracker). Its row's `Re-check by`.                  |
| **2026-11-22** | ID-JAG `-04` expires. Its row's `Re-check by`.                                    |
| **2026-11-30** | The quarterly pass. `Re-check by` for the other thirteen rows.                    |
| 2027-01-07     | security-topics-update `-03` expires. Not a fuse: the quarterly pass comes first. |
| 2027-03-07     | OAuth 2.1 `-16` expires. Not a fuse: the quarterly pass comes first.              |

Past dates in the `Expires` column (SD-JWT VC `-13`, Token Status List `-14`,
CIMD `-00`) are recorded, not due: those rows are `derived` or `deliberate`.

Watch specifically for: a new HAIP version or a published HAIP errata set
(either could move the SD-JWT VC and Token Status List pins together), an MCP
revision after `2026-07-28` or a change in what the MCP `draft` tree cites
(either could move the CIMD pin), OIDC Core errata
set 3 being approved (see finding 4), OAuth 2.1 reaching RFC status (which
would retire its row), `ext-auth` pull requests #12 or #30 merging, and ADR-011
moving to Accepted.
