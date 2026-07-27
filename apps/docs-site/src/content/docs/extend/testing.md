---
title: Testing
description: The four tiers — unit, testcontainers integration, the repo-wide coverage gate, and the documentation invariants — what each can and cannot catch, how to run them, and the two caching lessons this repo learned the hard way.
sidebar:
  order: 4
lastVerified: '2026-07-27'
---

QAuth has three test tiers plus a fourth that guards this documentation site. Knowing what each
one **cannot** catch matters more than knowing what it can, because the gaps are where the two
worst incidents in this repo's history came from: a suite that passed while running zero tests,
and a schema change no unit test could see.

| Tier                 | Command                                      | Runs in CI              | Catches                                           |
| -------------------- | -------------------------------------------- | ----------------------- | ------------------------------------------------- |
| Unit                 | `pnpm exec nx run-many -t test --all`        | `nx affected -t … test` | Handler and helper logic, in isolation            |
| Integration          | `pnpm exec nx run infra-db:test-integration` | the `integration` job   | Real Postgres DDL, migrations, repositories       |
| Repo-wide coverage   | `pnpm exec vitest run --coverage`            | a separate step         | Coverage regression across the whole fast suite   |
| Documentation guards | `pnpm exec nx test docs-site`                | part of the unit tier   | Drift between this site and the tree it describes |

## Tier 1 — unit

The fast suite. Vitest, no containers, no network. Every project has an inferred `test` target
(`nx.json:77`), so `pnpm exec nx test auth-server` runs one project's suite and
`pnpm exec nx run-many -t test --all` runs all of them.

Root config: `vitest.config.ts`. Each project's own `vitest.config.ts` merges it, which is why
`nx.json:110` lists the root config under `sharedGlobals` — a change to the exclude globs or the
coverage thresholds must invalidate every project's cached `test` result, and the inferred targets
do not list it themselves.

### The honest limitation

**`apps/auth-server`'s route tests do not boot the app.** Read one before you trust one — take
`apps/auth-server/src/app/routes/auth/login.test.ts`. It mocks the environment module wholesale
(`apps/auth-server/src/app/routes/auth/login.test.ts:10`) and builds a hand-written stand-in for
the Fastify instance (`apps/auth-server/src/app/routes/auth/login.test.ts:59`) whose
`withTypeProvider().post()` simply captures the handler function so the test can call it directly.
Repositories, the password hasher, and the JWT utilities are all `vi.fn()` stubs.

That design is fine for what it targets — it makes handler logic testable without Postgres, Redis,
or a valid environment — but be clear about what it therefore does **not** verify:

- **Nothing about `app.ts`'s composition.** Plugin registration order, content-type parsing, the
  active error handler, whether rate limiting applies to the route — none of it is exercised. This
  is not hypothetical: issue [#365] was a real ordering defect that left the application's error
  handler unreachable from every route, and this tier reported green throughout, because each test
  composes its own instance correctly before testing it. See
  [Request lifecycle](/extend/architecture/#the-error-handler) for the mechanism and for two
  further ordering claims in that file that are not what they appear.
- **Nothing about schema validation.** The stub never runs Fastify's validator, so a route's Zod
  `schema` is not applied to the payload the test passes in.
- **Nothing about the real environment schema.** `vi.mock('../../../config/env')` replaces it with
  an object literal, so a new required variable does not fail these tests.

There are two stronger patterns in the tree, and the difference between them is worth knowing:

- **A real `Fastify()` instance, composed by the test** — for example
  `apps/auth-server/src/app/routes/oauth/signature-verification.test.ts`, which registers `formbody`
  and the JWT plugin so it can exercise the same parsers production wires up. Better than a stub,
  but it still only proves the wiring the test itself built.
- **The real assembled app** — the pattern [#365] introduces as
  `apps/auth-server/src/app/error-handler.wiring.test.ts`. It boots the actual application
  composition, asserts a property of it, and is mutation-checked so it fails if the registration
  order regresses. Check whether it is in your checkout: it lands with that fix, and until it does
  there is no test in this repository of this kind.

When you add a test whose subject is _wiring_ rather than _logic_, the second pattern is the one
that would have caught #365; the first would not have. It is also the pattern that is still missing
for `formbody` and `rateLimitPlugin`, both of which have real ordering requirements and no wiring
test either way.

[#365]: https://github.com/qauth-labs/qauth/issues/365

## Tier 2 — integration (testcontainers)

```bash
pnpm exec nx run infra-db:test-integration
# or, directly:
pnpm test:integration
```

Defined at `libs/infra/db/project.json:8`, running `vitest.integration.config.ts`, which includes
only `**/*.integration.test.ts`, runs files serially (one Postgres container per file), and allows
60s per test for a cold image pull. There are five such suites today, all under
`libs/infra/db/src/lib/` — repositories, identity repositories, OID4VP request state, and two
migration suites.

**This is the only tier that exercises real DDL, and that is not a nice-to-have.** The `ci.yml`
comment at `.github/workflows/ci.yml:56` states the reasoning better than a paraphrase would:

> The `main` job above can never exercise real DDL: every unit suite mocks the repositories, and
> both vitest.config.ts and the coverage gate exclude `*.integration.test.ts`. So the
> testcontainers suites are the ONLY assertion that the generated migrations produce the schema
> the code expects — e.g. that `authorization_codes.state`/`.nonce` are unbounded `text` and not
> the varchar(255) that broke long opaque `state` (#316). Left unwired, a lost migration file or a
> re-narrowed column would sail through a fully green CI.

Both exclusions it names are real and worth seeing for yourself: `vitest.config.ts:23` keeps these
suites out of the fast run, and `vitest.config.ts:35` keeps them out of the coverage report. A
migration that never got committed, or a column quietly re-narrowed by a schema edit, produces no
failure anywhere else.

### It cannot pass vacuously

Locally, an integration suite skips when Docker is not running. On CI it does not: inside
`requireDockerOrSkip` there is a CI branch that throws instead of skipping
(`libs/shared/testing/src/lib/pg-testcontainer.ts:117`), with a message explaining that skipping
"turns the run into a green no-op". The `integration` job at `.github/workflows/ci.yml:66` runs on
a GitHub-hosted runner, which ships a Docker daemon, so the throw is unreachable in practice — it
exists so that a runner _without_ one fails loudly instead of reporting success.

The job is affected-scoped like the main one (`.github/workflows/ci.yml:91`), so a schema,
migration, or repository change runs it and a docs-only pull request pays nothing.

## Tier 3 — the repo-wide coverage gate

```bash
pnpm exec vitest run --coverage
```

Thresholds live in the root config at `vitest.config.ts:42` — statements 70, branches 55,
functions 65, lines 70 — and the comment there is explicit that they sit comfortably below today's
numbers so the gate passes now and fails on a real regression, to be ratcheted up as the
container-backed suite grows.

CI runs this as its **own step** (`.github/workflows/ci.yml:54`), separate from the affected
per-project `test` targets on the line above it (`.github/workflows/ci.yml:45`). The reason, from
that step's comment: the per-project runs write per-project coverage directories, so the threshold
has to be evaluated once across the whole fast unit suite rather than per project. Running
`nx affected -t test` locally therefore tells you nothing about the gate; run the command above
before assuming a large deletion is safe.

## The two caching lessons

Both are about Nx's cache, and both are re-breakable by an edit that looks like tidying.

### #285 — `nx test` passed while running zero tests

`nx.json:112` carries the post-mortem in full:

> #285: this was `["sharedGlobals"]`, dropping Nx's built-in `{projectRoot}/**/*` entry. Every
> `default`-hashed target (test, build) therefore hashed only ci.yml and ignored the project's own
> sources, so a cached green `test` result was replayed even after a failing spec was added. Keep
> `{projectRoot}/**/*` first — it is what makes a source edit invalidate the task.

The fixed value is at `nx.json:118`. The failure mode is the dangerous kind: nothing errors,
nothing warns, and the output says the target succeeded — because it did, once, before your code
existed. If you ever see a suite pass suspiciously fast after a change you expected to break it,
re-run with `--skip-nx-cache` before concluding anything.

### The docs-site target's extra `inputs`

`apps/docs-site/project.json:32` overrides the inferred `inputs` array, and the description at
`apps/docs-site/project.json:46` explains every entry. The short version: several of this
project's guards read files **outside** `apps/docs-site` at runtime — `README.md`, `docs/*.md`,
the auth-server route tree, and (coarsely) every `.ts` file under `apps/` and `libs/`. Nx hashes
only what a target declares, so without those declarations, editing the thing a guard checks left
the hash unchanged and Nx replayed a stale cached pass.

Two things to know before touching that array:

- **Setting `inputs` on an already-inferred target replaces the inferred array rather than merging
  into it.** The first six entries are the inferred defaults re-declared, not additions. Delete one
  and its whole category of input silently stops being hashed.
- **A blanket workspace-wide glob was rejected deliberately.** Hashing every file in the workspace
  would also hash `dist/` and `coverage/`, for no benefit an anchor could ever point at.

## Tier 4 — the documentation invariants

`apps/docs-site/src/invariants/` holds four guards that run as part of the ordinary unit tier
(`pnpm exec nx test docs-site`). They are not documentation _about_ the docs — they are executable
assertions that this site has not drifted from the tree.

| Guard               | Entry point                                              | Fails when                                                                      |
| ------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Link resolution     | `apps/docs-site/src/invariants/link-resolution.ts:177`   | A link points at a route, heading anchor, or repository file that is not there  |
| `path:line` anchors | `apps/docs-site/src/invariants/anchor-validity.ts:81`    | A quoted `path:line` names a missing file, or a symbol quoted beside it is gone |
| Endpoint coverage   | `apps/docs-site/src/invariants/endpoint-coverage.ts:111` | The route tree, `openapi.json`, and the API reference page disagree on paths    |
| Status claims       | `apps/docs-site/src/invariants/status-claims.ts:21`      | Prose calls a feature unbuilt while its evidence path exists on disk            |

### What they protect

Each one closes a specific class of rot:

- **Links** rot when a page is renamed or a heading is reworded. The guard resolves internal links
  against the real content tree, including heading anchors, and resolves repo-relative links
  against the filesystem.
- **`path:line` anchors** rot when a file is renamed or a function is deleted. The guard checks the
  file exists and, when a plain identifier is quoted immediately beside the anchor, that the symbol
  still appears in it.
- **Endpoint coverage** rots in both directions — an endpoint added to the spec but never
  documented, or a documented endpoint removed from the spec.
- **Status claims** rot when a feature ships and the prose describing it as future work does not
  get updated. The guard works from an evidence table (`apps/docs-site/src/invariants/status-claims.ts:21`)
  mapping a feature to paths whose existence proves it shipped — deliberately not a list of
  forbidden sentences, because "a sentence list rots the moment prose is reworded, while a path
  either exists or it doesn't".

### What they do not protect — read this before trusting a green run

These are the limits **by construction**, not gaps waiting to be filled:

- **They only reason about this repository.** Every check bottoms out in "does this path exist in
  the tree" or "does this route exist on this site". A claim about how an **external** tool
  behaves — a client library's defaults, a browser's cookie policy, what a specification requires —
  has nothing in the repo to check it against and is outside their reach entirely. Those claims are
  carried by `lastVerified` and human review, nothing else.
- **Line numbers in anchors are not checked.** `apps/docs-site/src/invariants/anchor-validity.ts:77`
  says so directly: they "drift on every unrelated edit above them, and a guard that fails on
  innocent edits gets disabled". A wrong line number survives a green run silently — so when you
  write one, open the file and count. This has already produced a round of corrections on another
  lane.
- **Endpoint coverage proves path-set equality only.** The guard's own comment at
  `apps/docs-site/src/invariants/endpoint-coverage.ts:128` states that the HTTP method is matched
  only to be skipped and never captured, so `` `GET /oauth/revoke` `` would satisfy the check for a
  POST-only endpoint exactly as well as the correct method. It also "cannot tell a real explanation
  from a passing mention": a path named once in a see-also list counts as documented. What legs 2
  and 3 prove, per `apps/docs-site/src/invariants/endpoint-coverage.ts:136`, is that the **set** of
  path strings on the reference page equals the **set** of path keys in `openapi.json` — real
  anti-rot value, but not a correctness check on what the page says about any one of them.
- **`lastVerified` is recorded, not enforced.** Nothing fails when it goes stale; the Reference
  lane's status page surfaces the oldest date instead. See
  [the frontmatter contract](/extend/frontmatter/).
- **`unbuiltClaims: true` disables the status guard for a whole page.** It is a narrow escape hatch
  for pages that legitimately describe something unbuilt, not a way to silence an inconvenient
  failure.

### If a guard fails on your page

The failure message names the page and the offending link, anchor, or phrase. Fix the **content**,
not the guard. If you genuinely believe the guard is wrong rather than your page, that is worth
raising as its own issue — bending content to satisfy a guard has already produced one real defect
in this site's history, and a guard nobody trusts gets deleted.

## Before you open a pull request

```bash
pnpm exec nx affected -t lint typecheck test build
pnpm exec vitest run --coverage
pnpm exec nx run infra-db:test-integration   # if you touched schema, migrations, or repositories
```

If you changed anything under `apps/docs-site`, add:

```bash
pnpm exec nx run docs-site:typecheck
pnpm exec nx build docs-site
```

On Windows, expect `nx lint` noise unrelated to your change — see the
[CRLF gotcha](/extend/repo-map/#local-development-gotcha-crlf-on-windows).

## See also

- [Request lifecycle](/extend/architecture/) — what the unit tier's stubs stand in for.
- [Repository map](/extend/repo-map/) — the boundary rules `nx lint` enforces.
- [Frontmatter contract](/extend/frontmatter/) — what the docs-site schema requires of a page.
