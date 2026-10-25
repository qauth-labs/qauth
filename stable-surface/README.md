# Stable surface

[ADR-018 §5](../docs/adr/018-1-0-scope-and-stability.md) makes QAuth's promise wire-level: what a
client sees must not change by accident. This directory lists the generated files that carry that
promise, and the breaks someone has decided to ship. CI regenerates each file, compares it with the
committed copy and with the last release, and fails on any change nobody approved.

| Path                                                    | What it is                                                                            |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `surfaces.json`                                         | The registry: one entry per surface                                                   |
| `approved-breaks.json`                                  | The breaks a release will ship on purpose                                             |
| `openapi.json`                                          | The auth server's API under default flags. Generated; never edit it by hand           |
| [`scripts/stable-surface/`](../scripts/stable-surface/) | The check (`check.mjs`), its logic (`lib.mjs`) and the pinned oasdiff (`oasdiff.mjs`) |
| `scripts/stable-surface/__fixtures__/break-rules/`      | The fixtures that pin what oasdiff reports as a break                                 |

## Running it

```bash
pnpm stable-surface --require-baseline                # drift, tags and breaks, as CI runs it
pnpm stable-surface --only drift,tags                 # no oasdiff download
pnpm stable-surface --baseline v0.1.0                 # compare with another ref
node scripts/stable-surface/check.mjs --self-test     # the break-rule fixtures, through oasdiff
```

Exit codes: `0` clean, `1` a gate failure (drift, a missing tag, an unapproved break, a refused
approval), `2` the check could not run (an invalid registry, a failing generator, no oasdiff, a
baseline it cannot read). The report goes to stdout and, in CI, to the job summary.

The check never treats "could not read the baseline" as "nothing to compare". A git error reading
the tag fails the run, and CI passes `--require-baseline`, so a checkout without tags fails too.

## The three checks

**Drift.** Each surface's generator runs once, and the check fails when the file it writes differs
from the committed one. The summary shows the diff. Run the generator and commit its output:

```bash
pnpm exec nx run auth-server:openapi-export
```

**Stability tags.** Every OpenAPI operation carries `x-qauth-stability`, `stable` or
`experimental`. It is a key of the route schema, next to `tags`, and `@fastify/swagger` copies it
onto the operation:

```ts
schema: {
  description: '…',
  tags: ['OAuth', 'Token'],
  'x-qauth-stability': 'stable',
  …
}
```

The auth server exports its API twice: under default flags to `stable-surface/openapi.json`, and with
every switch that registers a route turned on to `apps/docs-site/public/openapi.json`. An operation
only the second has sits behind a switch, so it must be `experimental` (ADR-018 §5). An operation
both have carries the same tag in both. The default export has no `experimental` operation at all:
an experimental route is registered only while its switch is on, and every switch is off there.

The exporter checks its own environment against the experimental-feature registry
(`libs/shared/stability`): it refuses to write a default export with an experimental item on, or a
maximal export that leaves a built item off. So every experimental operation is in the maximal
export, where the check requires its tag.

**Breaks.** Each `stable` surface is compared with the same file at the baseline release: the
latest release tag that is not a pre-release, among the tags reachable from the commit under check
(a patch release tagged on a release branch is not; today that leaves `v0.1.0` for `main`, since
`v0.1.1` to `v0.1.3` were tagged on a release branch). A release candidate (`vX.Y.Z-rc.N`) never becomes
the baseline, because operators upgrade from releases. A break a release candidate shipped is
still measured against the last release until the release that contains it is tagged. Only a
history with no release at all falls back to the latest pre-release. The tag decides, not
`info.version`.

Experimental operations are left out of both sides. A stable operation that turns experimental is
therefore reported as removed, and an experimental one that turns stable as added.

The registry itself is checked against the baseline release's copy. A surface that was stable there
and is missing or `experimental` here is a break (`surface-withdrawn`), approved like any other. A
surface whose `path` changed is still found at the baseline under its old path.

## What counts as a break

The comparison is [oasdiff](https://github.com/oasdiff/oasdiff) `changelog`, at the version pinned in
`scripts/stable-surface/oasdiff.mjs`. A change at oasdiff's error level is a break. That covers its
own error-level checks, and these rules, which oasdiff rates lower and the check raises:

| Change                                               | oasdiff rule                                                                  |
| ---------------------------------------------------- | ----------------------------------------------------------------------------- |
| A removed operation, even one deprecated first       | `api-removed-*`, `api-path-removed-*`                                         |
| A removed or renamed response field, required or not | `response-required-property-removed`, `response-optional-property-removed`    |
| A new required request field or parameter            | `new-required-request-property`, `request-property-became-required`, …        |
| A narrowed request enum                              | `request-property-enum-value-removed`, `request-parameter-enum-value-removed` |
| A changed type                                       | `request-property-type-changed`, `response-property-type-changed`, …          |
| A new required scope, or a credential newly required | `api-security-scope-added`, `api-security-added`                              |

`RAISED_TO_BREAK` in `scripts/stable-surface/lib.mjs` lists the raised rules. The self-test fixtures
pin one case for each row, and the cases that must pass: an added optional response field, an
added optional request field, a widened request enum, and any change to an experimental operation.

A value added to a response enum is a break too, because a client may not handle it. A value set
that is meant to grow, such as error codes or event types, is declared with `x-extensible-enum`
instead of `enum`, and adding to it passes.

Warnings are listed in the summary and do not fail the check. Compatible changes are listed too, so
a reviewer sees everything that changed since the release.

## Registering a surface

A new surface is one entry in `surfaces.json`, and nothing else. The event schemas register this
way, one entry per file (#456), and the Interaction API steps, the realm file schema and the
documented configuration keys will too.

```json
{
  "name": "event-user-signed-in-v1",
  "description": "The urn:qauth:event:user.signed_in:v1-rc.0 event: the envelope with that type's data (ADR-018 §5, #456).",
  "format": "json-schema",
  "role": "both",
  "generator": "pnpm exec nx run shared-events:schema-export --skip-nx-cache",
  "path": "apps/docs-site/public/schemas/events/user.signed_in.v1-rc.0.json",
  "stability": "stable"
}
```

An event schema is `both`: QAuth emits the event, and the events it stored under an earlier
release must still match the schema, so a new required member is a break and a new optional one
is not. The tests of `libs/shared/events` fail when a schema file is missing from the registry.

An event surface's name carries only the major version, and its path carries the whole version.
When a breaking change before 1.0.0 raises a type's release-candidate number, the path changes and
the name does not, so the check compares the new file with the old one at the baseline and reports
the break for approval.

| Key                  | Meaning                                                                                                                     |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `name`               | Kebab-case, unique. Approvals name it                                                                                       |
| `format`             | `openapi` or `json-schema`                                                                                                  |
| `generator`          | The command that writes `path`, run from the repository root. It must write the same bytes on every run                     |
| `path`               | The committed file                                                                                                          |
| `stability`          | `stable`: drift-checked and break-checked. `experimental`: drift-checked only                                               |
| `role`               | `json-schema` only. `input` for documents QAuth accepts, `output` for documents it emits, `both`                            |
| `formerPaths`        | Where the file lived in a release older than this registry. The baseline is read from the first path that exists at the tag |
| `formerExperimental` | `openapi` only. The operations a release older than the stability tags kept behind a switch, as `METHOD /path`              |
| `maximalOf`          | `openapi` only. Names the default-flag export this one is the maximal-flag export of. Such a surface is `experimental`      |
| `description`        | Free text                                                                                                                   |

A JSON Schema file is compared as the request body (`input`), the response body (`output`) or both,
so the rules above apply to it unchanged. Its references must point at its own `$defs`
(`#/$defs/Name`); any other `$ref` is refused.

The OpenAPI entry lists `apps/docs-site/public/openapi.json` under `formerPaths`, because v0.1.0
shipped no `stable-surface/openapi.json`. That file is v0.1.0's maximal export and carries no
stability tags, so `formerExperimental` records the twelve wallet-federation operations v0.1.0
registered only behind `WALLET_FEDERATION_ENABLED`. Every other v0.1.0 operation is stable. Today's
tags are never consulted for an untagged baseline: otherwise tagging a stable operation
`experimental` would exempt it from the comparison. Once a release contains
`stable-surface/openapi.json`, neither key is read again, and both can go.

## Approving a break

A break that a release will ship on purpose needs an entry in `approved-breaks.json`. The check
prints one for each unapproved break; fill in the issue or ADR that decided it and the release that
will ship it:

```json
{
  "approvals": [
    {
      "surface": "openapi",
      "change": {
        "rule": "response-optional-property-removed",
        "operation": "POST /oauth/introspect",
        "fingerprint": "7adc0e316b73",
        "text": "removed the optional property `client_id` from the response with the `200` status"
      },
      "ref": "#123",
      "release": "v0.2.0"
    }
  ]
}
```

- An entry lets exactly one change through: one with that fingerprint, rule, operation and text, on
  that surface. Each entry is spent on one change, so two changes oasdiff reports alike (its
  fingerprint leaves out the media type) need two entries. The approved break stays in the job
  summary, with its release and reference.
- `ref` is an issue (`#123`) or an ADR (`ADR-018`, `ADR-018 §5`).
- `release` must not be tagged yet, and must come after the baseline. Once the release is tagged it
  becomes the baseline, the break is part of it, and the entry is refused: delete it. Release
  candidates do not count, so an entry stays valid across them. After a release tag, empty this file
  in a pull request (`RELEASING.md`).
- An entry that matches no break is refused, so a stale or mistyped entry cannot linger.

Before 1.0 this is how the breaks of a 0.x release are recorded. After 1.0, ADR-018 §5 allows a
break of a stable surface only in a new major release, after a deprecation window.
