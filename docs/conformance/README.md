# Spec conformance matrix

QAuth's requirements are written by the IETF and the OpenID Foundation, not by
us. This directory answers one question: **which normative requirements do we
satisfy, and which do we knowingly not?**

Before it existed, that was unanswerable without reading the whole test suite —
and it is a deliverable for OpenID Foundation OP certification, not overhead
(`docs/oidf-op-certification-runbook.md` anticipates it).

## What is here

| File                       | What it is                                                                                                                                            |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `specs.json`               | Alias registry. Maps every spelling a test title uses (`OIDC Core`, `OpenID Connect Core 1.0`, …) onto one spec id, and carries the `sealed` ratchet. |
| `requirements/<spec>.json` | Hand-authored requirement rows, reviewed like code.                                                                                                   |
| `scripts/spec-matrix.mjs`  | The joiner and the gate. Zero runtime dependencies.                                                                                                   |

Output goes to a gitignored `dist/conformance/` — `matrix.md` for a human or a
certification reviewer, `matrix.json` for machines. **Nothing rendered is checked
in.** The reviewable content is the hand-authored JSON, which is diffed in every
pull request; a committed render would churn on every added test.

## Rows pull tests. Tests never push rows.

The matrix is requirement-driven. You add a row because a specification says
something normative, and the join then finds the tests that prove it.

**The ~3,700 uncited tests are deliberately out of scope, and there is no
backfill to do.** Most of them prove internal behaviour rather than normative
text — that a repository method returns the right shape, that a helper is
fail-closed, that a regression stays fixed. Annotating them with spec references
would be noise, and would invert the direction this document depends on.

## A caveat on the `quote` field

Every increment-1 specification source — `rfc-editor.org`, `datatracker.ietf.org`,
`openid.net` — is unreachable from the environment these rows were authored in
(the egress proxy returns 403). The `quote` field is therefore **transcribed, not
copy-pasted from the source**, and is faithful to the normative requirement
rather than guaranteed byte-exact.

That is fine for the gate — which joins on `(specId, section)` and never reads
the quote — and NOT fine for a certification submission, where a reviewer will
read the quotes. **Re-verify every `quote` against the published specification
before the matrix is used as certification evidence**, and drop this section when
that pass has run.

Recording it here rather than leaving it implicit: a document whose whole purpose
is to be checkable should not have an unmarked soft spot.

## Statuses

Four, and the distinctions carry the whole value:

| Status    | Meaning                                                                  | Gate                                                                                                                                                 |
| --------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `covered` | Proven by at least one **passing** citing test.                          | Unproven fails the build. A row whose only citing tests are **skipped** counts as unproven, and says so distinctly.                                  |
| `manual`  | Settled outside the unit suite.                                          | Requires an `evidenceRef` path (optionally with an anchor) that must resolve.                                                                        |
| `waived`  | **In profile, knowingly not satisfied.**                                 | Requires `reason`, `decision` (issue ref or resolvable path) and `revisit` (ISO date or `never`). Never fails; renders in its own prominent section. |
| `n/a`     | Outside QAuth's profile — implicit/hybrid flow, client-side obligations. | Requires `reason`. Never fails.                                                                                                                      |

**Do not collapse `waived` into `n/a`.** It destroys the document for a
certification reviewer: `n/a` means the requirement never applied; `waived`
means it applied and we chose not to satisfy it. Today's one waiver — RFC 9700
§4.5, token revocation on authorization-code replay — is precisely the kind of
thing a reviewer must be able to find.

## The join

The key is `(specId, section)`, matched **hierarchically**: a test citing §2.4
proves a row declared at §2.4 **or** at §2, never the reverse. Matching is
against Vitest's `fullName`, so a `describe`-level citation propagates to every
leaf beneath it — which is what lifts the joinable base far above the naive
`it`-level count.

A citation with **no** section proves nothing. It names a spec, not a
requirement, and treating it as proof of every row would make the gate
meaningless.

### The corpus, measured on HEAD (2026-08-31)

| Measure                            | Count | Share |
| ---------------------------------- | ----- | ----- |
| Leaf assertions                    | 4,288 | —     |
| Carrying any spec reference        | 550   | 12.8% |
| Using the `RFC NNNN §X.Y` grammar  | 82    | 1.9%  |
| Files with a `RFC NNNN §` citation | 20    | —     |

#400 quoted 26.5% (1,111 of 4,187 across 103 files) and called `RFC NNNN §X.Y`
the overwhelmingly dominant grammar. **Neither holds on HEAD** — re-measured
before the extractor was written, exactly as the issue asked. The practical
consequence is that the extractor could not assume one shape: it accepts a
section with or without `§`, and accepts a **list** of sections after a single
alias (`OIDC Core §3.1.3.6, §3.1.3.7`), which a first draft silently truncated.

## The `sealed` ratchet

Once a spec is `sealed`, a citation naming it with a section that has no
matching row is a **failure**, not a note. That is what stops a spec's coverage
silently regressing after someone has done the work of enumerating it.

Increment 1 seals RFC 9207, RFC 8414 and OIDC Discovery 1.0 — the three that are
enumerated to the depth their tests cite. OIDC Core 1.0 carries the Basic-OP
subset and is deliberately **not** sealed yet; RFC 6749, 7636, 6750, 7591 and
9700 are registered with stubs or a single row.

## Running it

```bash
pnpm exec vitest run --coverage --reporter=json --outputFile=dist/vitest-report.json
node scripts/spec-matrix.mjs --vitest-report dist/vitest-report.json
```

It reads the report the existing coverage step already emits, so the suite is
never run twice.

**Exit codes.** `0` clean · `1` gate failure, emitted as `::error file=…::`
annotations so they land on the pull-request diff · `2` input error.

The `2` class matters most. A missing, empty or shape-changed report exits `2`
rather than rendering as "everything proven": certification evidence that fails
**open** is worse than none.
