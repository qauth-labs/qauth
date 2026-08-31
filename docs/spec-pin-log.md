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
Internet-Drafts, OpenID Foundation specifications, and the MCP authorization
specification.

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

| Pass         | Trigger                        | Headline outcome                                                                                                      |
| ------------ | ------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `2026-08-31` | #401 — first pass, log created | Rows established from citations already recorded in the ADRs and the code. **No new drift found; nothing re-pinned.** |

The first pass deliberately re-states what ADR-005, ADR-007, ADR-009 and ADR-011
already recorded rather than re-investigating each source. Those records were
themselves written from live checks (ADR-007's `-02` CIMD re-verification on
2026-08-06; the 2026-07-26 EUDI pass's OIDF confirmations), and inventing a
fresh "verified today" date for a source nobody opened would be exactly the
unfalsifiable claim this log exists to stop. Each row's `Last verified` is the
date of the pass that actually looked.

---

## Why `Pin basis` is a column and not prose

The EUDI log implies a pin basis in its narrative; this log makes it a field,
because without it the log has a failure mode with no visible symptom.

**SD-JWT VC is pinned at `draft-13` while `-18` is current.** That is not five
revisions of rot. HAIP 1.0 §9.4 pins `-13`, and QAuth targets HAIP, so `-13` is
the _correct_ revision to cite. A well-meaning "update everything to latest"
pass would break EUDI conformance while making the docs look **more** current —
a regression that reads as an improvement in every diff.

With the column, the re-check question for that row stops being "is there a
newer draft?" and becomes **"did HAIP change what it references?"** — which is
the question that can actually be wrong.

For the same reason: **any automated refresher must only ever open an issue. It
must never commit a revision bump.** A bot that cannot read this column cannot
tell a derived pin from a latest-published one.

### The three bases

| Basis        | Meaning                                                                                                     | Re-check question                |
| ------------ | ----------------------------------------------------------------------------------------------------------- | -------------------------------- |
| `derived`    | The revision is fixed by a **profile or spec we conform to**, not by us. Bumping it is a conformance break. | Did the pinning document change? |
| `latest`     | We track the newest published revision.                                                                     | Is there a newer revision?       |
| `deliberate` | We knowingly cite an older revision, for a recorded reason.                                                 | Does the reason still hold?      |

---

## Pin table

`Re-check by` is the earlier of the next quarterly pass and, for an
Internet-Draft, its expiry. `Consumers` are paths that must exist; the freshness
check fails when one does not, because a pin nothing consumes is a pin nobody
will notice going stale.

| Spec                                                           | Pinned revision            | Pin basis    | Last verified | Re-check by  | Verdict                                                                      | Consumers                                                                                        |
| -------------------------------------------------------------- | -------------------------- | ------------ | ------------- | ------------ | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc`)                       | `-13`                      | `derived`    | `2026-07-26`  | `2026-11-30` | Current for HAIP 1.0 §9.4                                                    | `libs/server/federation/src/oid4vp/sd-jwt-vc.ts`, `docs/adr/009-wallet-account-resolution.md`    |
| Token Status List (`draft-ietf-oauth-status-list`)             | `-14`                      | `derived`    | `2026-07-26`  | `2026-11-30` | Current for HAIP 1.0 §6.1                                                    | `libs/server/federation/src/status/status-list-spec.ts`                                          |
| ID-JAG (`draft-ietf-oauth-identity-assertion-authz-grant`)     | `-04`                      | `latest`     | `2026-08-06`  | `2026-11-22` | Current                                                                      | `apps/auth-server/src/app/helpers/id-jag.ts`, `docs/adr/011-enterprise-managed-authorization.md` |
| CIMD (`draft-ietf-oauth-client-id-metadata-document`)          | `-00` cited, `-02` current | `deliberate` | `2026-08-06`  | `2026-11-30` | Citation lags code, not the reverse                                          | `apps/auth-server/src/app/helpers/cimd.ts`, `apps/auth-server/src/app/helpers/discovery.ts`      |
| OAuth 2.1 (`draft-ietf-oauth-v2-1`)                            | `-15`                      | `latest`     | `2026-08-06`  | `2026-11-30` | Still not an RFC                                                             | `docs/adr/007-mcp-first-positioning.md`                                                          |
| OpenID4VP                                                      | 1.0 Final (2025-07-09)     | `latest`     | `2026-07-26`  | `2026-11-30` | Final; no revision since                                                     | `libs/server/federation/src/oid4vp`, `docs/adr/004-wallet-agnostic-federation.md`                |
| OpenID4VC HAIP                                                 | 1.0 Final (2025-12-24)     | `latest`     | `2026-07-26`  | `2026-11-30` | Final; the pinning document for two rows above                               | `libs/server/federation/src/profiles/verifier-profiles.ts`                                       |
| OpenID4VCI                                                     | 1.0 Final (2025-09-16)     | `latest`     | `2026-07-26`  | `2026-11-30` | Final; Appendix D consumed only                                              | `libs/server/federation/src/attestation/attack-potential.ts`                                     |
| MCP authorization                                              | `2026-07-28`               | `latest`     | `2026-08-06`  | `2026-11-30` | Current published revision                                                   | `docs/adr/007-mcp-first-positioning.md`, `libs/fastify/plugins/mcp-guard`                        |
| PQC composite signatures (`draft-ietf-jose-pq-composite-sigs`) | not implemented            | `deliberate` | `2026-07-18`  | `2026-11-30` | QAuth deviates on purpose — parallel, not composite (ADR-005 amendment #245) | `docs/adr/005-pqc-hybrid-signing.md`                                                             |

### Rows that were considered and deliberately excluded

- **RFC 9964** (ML-DSA for JOSE/COSE) and **RFC 9864** — published RFCs, and the
  reason `draft-ietf-cose-dilithium` has no row: #274 re-pinned QAuth off that
  draft onto its published successor, which is precisely the outcome this log
  wants. `libs/core/crypto/src/lib/hybrid-constants.ts` records it.
- **EUDI ARF, the eIDAS 2 CIRs, ISO/IEC 18013-5, ETSI** — owned by
  [`eudi-regulatory-drift-log.md`](./eudi-regulatory-drift-log.md). Two logs
  tracking one source is how they disagree.
- **RFC 6749, 7636, 8693, 8707, 9700, 7591, 8414, 7523, 9101, 9728** — immutable.

---

## Triggers

A pass runs when **any** of these fires:

1. **The quarterly calendar pass** ADR-007:311-317 mandates.
2. **A draft expiry.** Every I-D row's `Re-check by` is the earlier of the next
   quarter and the draft's own expiry. ID-JAG `-04` expires **2026-11-22**, a
   date recorded nowhere before this file existed.
3. **An ADR moving Proposed → Accepted** re-verifies its own rows first. ADR-011
   is Proposed with merged code, so it triggers on the next pass.

---

## Method and controls

- **Read the pinning document, not just the pinned one.** For a `derived` row
  the question is whether HAIP still references that revision. A newer draft is
  not by itself drift.
- **Record the URL and the date you read it**, in the pass entry, not only the
  verdict — so the next pass is a diff rather than a fresh investigation.
- **Pin to published revisions only.** ADR-007's 2026-08-06 addendum records why:
  reviewing against a release candidate compounded a stale-claim error.
- **A negative result still gets written down.** "Confirmed — no change" is the
  most common outcome and the most valuable to record, because it is what makes
  the next pass cheap.

## Residual uncertainty

- `Last verified` dates are inherited from the ADR passes that did the checking
  (see the ledger note above). They are honest about **when someone last looked**,
  which is the property that matters, but this first pass did not independently
  re-open every source.
- The freshness check verifies dates and consumer paths. It does **not** verify
  that a pinned revision still exists upstream, or that a `derived` row's basis
  document still says what the table claims. Those need a human, which is what
  the quarterly pass is for.

## Next re-check

**2026-11-22** — ID-JAG `-04` expiry, the earliest date in the table. The
quarterly calendar pass for the rest falls due **2026-11-30**.
