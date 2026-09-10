# Spec-conformance matrix

QAuth's requirements are written by the IETF and the OIDF, not by us. This
directory holds the join between those normative requirements and the tests
that prove them, so that **"which normative requirements do we satisfy, and
which do we knowingly not"** is answerable without reading the whole suite.

It doubles as the evidence package for OpenID Foundation OP certification,
which [the certification runbook](../oidf-op-certification-runbook.md) already
anticipates.

## What is here

| Path                          | What it is                                                                                                  |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `specs.json`                  | The alias registry — which strings in a test title mean which spec, and the ratchet                         |
| `requirements/<id>.json`      | The requirement rows, hand-authored and reviewed like code                                                  |
| `scripts/spec-matrix.mjs`     | The joiner and the CI gate (repo root, not an Nx project)                                                   |
| `scripts/spec-matrix.test.ts` | The joiner's own guard — chiefly that a missing, empty or shape-changed report can never render as "proven" |

The joiner writes `dist/conformance/matrix.md` and `dist/conformance/matrix.json`.
Both are gitignored on purpose: the reviewable content is the hand-authored JSON,
which is diffed in every PR, whereas a checked-in render would churn on every
added test. CI uploads the rendered matrix as a build artifact and posts it as a
job summary, so every PR shows the delta without downloading anything.

## Running it

```bash
# One suite run, two reporters — the JSON report is what the gate reads.
pnpm exec vitest run --coverage --reporter=default \
  --reporter=json --outputFile.json=dist/vitest-report.json

pnpm spec-matrix    # node scripts/spec-matrix.mjs --vitest-report dist/vitest-report.json --out-dir dist/conformance
```

Exit codes: `0` clean, `1` gate failure, `2` input error. A missing, empty or
shape-changed report is an **input error**, never a clean matrix — certification
evidence that fails open is worse than no evidence at all.

## The alias registry

`specs.json` maps every spelling a test title uses onto one spec id, so the
citation grammar can drift without touching a single requirement row: `OIDC Core`,
`OIDC Core 1.0` and `OpenID Connect Core 1.0` all resolve to `oidc-core-1_0`.

Each spec carries a `sealed` flag, and that is the ratchet:

- **`sealed: false`** — rows are still being written. A citation that matches no
  row is reported in the matrix's "Citations with no row" section and is the
  backlog.
- **`sealed: true`** — the row list is complete for every section the suite
  cites. A citation that matches no row is a **build failure**, so new citations
  cannot quietly outrun the requirement list.

## The requirement rows

Each row in `requirements/<specId>.json` carries:

- **`section`** — dotted, no `§`. This is the join key.
- **`level`** — the RFC 2119 keyword: `MUST`, `SHOULD`, `REQUIRED`, `OPTIONAL`, …
- **`quote`** — a short **verbatim** quote of the normative sentence, so a
  reviewer never has to trust our paraphrase.
- **`applies`** — optional; which QAuth surface the requirement lands on.
- **`status`** — one of four, below.
- **`evidenceMatch`** — optional, `covered` rows only; see below.

### `evidenceMatch`, and why a section is not a requirement

The join key is `(specId, section)`, and a spec section is routinely far coarser
than a single requirement. OIDC Core §2 declares the **whole** ID Token claim
set; RFC 8414 §2 declares the **whole** metadata document. Section matching
alone would therefore let every test citing §2 stand as proof of every §2 row —
which is how a certification artifact ends up naming an `acr`-value test as its
evidence that the ID Token carries a correct `iss`, and how deleting the test
that actually proves `iss` leaves the gate green.

`evidenceMatch` is the narrowing. It is a regular-expression source string; a
citing test counts as evidence for that row only if its `fullName` **also**
matches it, case-insensitively. It can only ever remove evidence, never add it,
so a row carrying one is strictly harder to prove than a row without one, and a
pattern that fails to compile matches nothing at all.

Write one on every row that shares a section with a row about something else.
When the gate reports such a row as unproven it names the pattern, so the fix —
cite the test that really proves the sentence, or correct the pattern — is
obvious from the annotation alone.

### The four statuses

The distinctions carry the whole value of the document.

- **`covered`** — must be proven by at least one **passing** citing test.
  Unproven fails the build. A row whose only citing tests are skipped counts as
  unproven, because a skipped test proves nothing.
- **`manual`** — settled outside the unit suite: deployment configuration, or
  the external OIDF conformance run. Requires an `evidenceRef` path, optionally
  with a `#anchor`, which the joiner asserts resolves. This is where "there has
  been no external certification run yet" lives — the runbook is the evidence,
  and the row says so.
- **`waived`** — in profile, knowingly not satisfied. Requires `reason`,
  `decision` (an issue reference or a resolvable path) and `revisit` (an ISO
  date or `never`). Never fails the build; renders in its own prominent section.
- **`n/a`** — outside QAuth's profile: the implicit and hybrid flows,
  client-side obligations. Requires `reason`. Never fails the build.

**Do not collapse `waived` into `n/a`.** `n/a` means the requirement never
applied to QAuth. `waived` means it applied and we chose not to satisfy it. For
a certification reviewer, conflating the two destroys the document.

## How the join works

The joiner reads the Vitest JSON report the coverage step already emits — the
suite is never run twice — and extracts `(specId, section)` citations from each
test's `fullName`. Matching `fullName` rather than the leaf title is what makes a
`describe`-level citation carry down to every test inside it.

Sections match **hierarchically**: a test citing `§2.4` proves a row declared at
`§2.4` or at `§2`, but not one at `§2.4.1`. Cited depth in this repo ranges from
`§2` to `§4.2.1.3`, so nothing flatter works.

A bare `§X.Y` is attributed to the nearest spec name to its left in the same
`fullName`, which is how `describe('… (HAIP §4.5.1)') > it('the §5.9.3 prohibition')`
keeps both sections on HAIP. Unregistered spec names still act as anchors
precisely so they can block that mis-attribution; their citations are then
dropped, because only registered specs participate.

The section match is what **answers** a citation — it is why a citation counts
as belonging to this spec rather than showing up under "Citations with no row".
A row's `evidenceMatch` then decides whether that row may lean on it. The two
are kept separate on purpose: narrowing one row must never turn a sibling row's
perfectly good test into an orphan.

## Explicitly out of scope

**The uncited tests are not touched, and nobody should start a backfill.** Only
a small minority of the suite cites a registered spec section in a `describe` or
`it` title, and that ratio is fine.

The exact counts are deliberately **not** written down here. A figure copied
into prose is stale the day after it is copied, and this document exists to be
trusted. Every run of the gate derives them instead and prints them twice: on
stdout (`… N assertions read from …, M of them citing a registered spec across
K file(s)`) and in the header of `dist/conformance/matrix.md`, which CI uploads
and posts as the job summary. If you want the number, run the joiner.

Most uncited tests prove internal behaviour — a helper's edge cases, an error
shape, a repository call — rather than normative text, and annotating them would
be noise that buries the citations that do mean something.

The matrix is **requirement-driven**: rows pull tests, tests never push rows. A
citation is added to a test title when a requirement row needs that test as its
evidence, and for no other reason.

Specs cited in test titles but absent from `specs.json` — ADR references, HAIP,
OID4VP, OID4VCI and the rest — are ignored entirely. Registering one is a
deliberate act that comes with writing its rows.

## Scope of increment 1

Populated: **RFC 9207**, **RFC 8414**, **OpenID Connect Discovery 1.0**, and the
**Basic-OP subset** of **OpenID Connect Core 1.0** (the ID Token, the
authorization endpoint, the token response, UserInfo, and the request-object
obligations the runbook flags). The first three are sealed; OIDC Core is not,
because its row list is deliberately partial.

Stubbed — registered so citations resolve to a stable id, rows to follow:
**RFC 6749**, **RFC 7636**, **RFC 6750**, **RFC 7591**.

Seed rows came from the runbook's Step 7 residual-item checklist and its
Basic-plan Appendix, and from the prose "Known gaps" register that used to sit in
the header comment of `apps/auth-server/src/app/routes/oauth/oidc-conformance.test.ts`.
That comment is now a pointer here, so the gap register has one home.

Two of the runbook's nine Step 7 checkboxes have **no** row yet, and both for the
same reason: **both client-auth methods demonstrated** and **authorization-code
reuse** are RFC 6749 requirements, and RFC 6749 is one of the four stubs above.
They arrive with its rows. Every other Step 7 checkbox is a row here.
