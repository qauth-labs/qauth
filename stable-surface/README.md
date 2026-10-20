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
pnpm stable-surface                                   # drift, tags and breaks, as CI runs it
pnpm stable-surface --only drift,tags                 # no oasdiff download
pnpm stable-surface --baseline v0.1.0                 # compare with another ref
node scripts/stable-surface/check.mjs --self-test     # the break-rule fixtures, through oasdiff
```

Exit codes: `0` clean, `1` a gate failure (drift, a missing tag, an unapproved break, a refused
approval), `2` the check could not run (an invalid registry, a failing generator, no oasdiff).
The report goes to stdout and, in CI, to the job summary.

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
both have carries the same tag in both.

**Breaks.** Each `stable` surface is compared with the same file at the baseline release. Until a
1.0 release exists, the baseline is the latest release tag of any kind. From then on it is the
latest release of 1.0 or later that is not a pre-release. The tag decides, not `info.version`.

Experimental operations are left out of both sides. A stable operation that turns experimental is
therefore reported as removed, and an experimental one that turns stable as added.

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

A new surface is one entry in `surfaces.json`, and nothing else. The event schemas, the Interaction
API steps, the realm file schema and the documented configuration keys register this way.

```json
{
  "name": "events",
  "description": "The payload schema of every event type (ADR-018 §5).",
  "format": "json-schema",
  "role": "output",
  "generator": "pnpm exec nx run events:schema-export",
  "path": "stable-surface/events.schema.json",
  "stability": "stable"
}
```

| Key           | Meaning                                                                                                                |
| ------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `name`        | Kebab-case, unique. Approvals name it                                                                                  |
| `format`      | `openapi` or `json-schema`                                                                                             |
| `generator`   | The command that writes `path`, run from the repository root. It must write the same bytes on every run                |
| `path`        | The committed file                                                                                                     |
| `stability`   | `stable`: drift-checked and break-checked. `experimental`: drift-checked only                                          |
| `role`        | `json-schema` only. `input` for documents QAuth accepts, `output` for documents it emits, `both`                       |
| `formerPaths` | Where the file lived in earlier releases. The baseline is read from the first path that exists at the tag              |
| `maximalOf`   | `openapi` only. Names the default-flag export this one is the maximal-flag export of. Such a surface is `experimental` |
| `description` | Free text                                                                                                              |

A JSON Schema file is compared as the request body (`input`), the response body (`output`) or both,
so the rules above apply to it unchanged. Its references must point at its own `$defs`
(`#/$defs/Name`); any other `$ref` is refused.

The OpenAPI entry lists `apps/docs-site/public/openapi.json` under `formerPaths`, because v0.1.0
shipped no `stable-surface/openapi.json`. That baseline carries no stability tags, so each of its
operations takes the tag the same operation carries today, and is stable if no export has it any
more. Once a release contains `stable-surface/openapi.json`, the former path is no longer read.

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

- An entry lets exactly one change through: the one with that fingerprint, rule and operation, on
  that surface. The approved break stays in the job summary, with its release and reference.
- `ref` is an issue (`#123`) or an ADR (`ADR-018`, `ADR-018 §5`).
- `release` must not be tagged yet, and must come after the baseline. Once the release is tagged it
  becomes the baseline, the break is part of it, and the entry is refused: delete it.
- An entry that matches no break is refused, so a stale or mistyped entry cannot linger.

Before 1.0 this is how the breaks of a 0.x release are recorded. After 1.0, ADR-018 §5 allows a
break of a stable surface only in a new major release, after a deprecation window.
