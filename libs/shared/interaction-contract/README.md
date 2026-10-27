# @qauth-labs/shared-interaction-contract

The Interaction API v1 contract (#590, ADR-019 Decision 6, ADR-017 Decision 3, ADR-018 §5): the
operations a sign-in page uses to reach the engine, every step of the step grammar, the brand
block, the results and the errors, written down before any handler. Pure data and schema builders,
with no I/O.

The published reference is the docs page `reference/interaction-api` (generated from this
library), the OpenAPI 3.1 document `apps/docs-site/public/interaction/v1-rc.0/openapi.json` and one
JSON Schema per step under `apps/docs-site/public/interaction/v1-rc.0/steps/`. The auth server
serves the same document at `/interaction/v1-rc.0/openapi.json`, and the typed client in
`libs/shared/interaction-client` is generated from it.

## What it holds

| Module                        | What                                                                                                   |
| ----------------------------- | ------------------------------------------------------------------------------------------------------ |
| `lib/identifiers.ts`          | The version label `v1-rc.0`, the path prefix, the reserved wallet prefix, the flow cookie, step URNs   |
| `lib/schema-kit.ts`           | JSON Schema builders; the display rule (bounded values, no markup, control or format characters)       |
| `lib/step-definition.ts`      | `defineStep`, and what a step holds: params, personal data, answer, errors, `amr`, transports, example |
| `lib/steps/*.ts`              | The 17 steps, by area; `lib/steps/index.ts` lists them in order                                        |
| `lib/envelope.ts`             | The envelope: the step read, the brand block, the client display data, the results, the problem body   |
| `lib/problems.ts`             | The problem codes and the status each is sent with                                                     |
| `lib/rules.ts`                | The API rules and the versioning rules, which the document and the docs page both render               |
| `lib/openapi.ts`              | The bundled OpenAPI 3.1 document, `INTERACTION_OPENAPI`                                                |
| `lib/step-schema.ts`          | One self-contained JSON Schema per step                                                                |
| `lib/docs-page.ts`            | The docs page, rendered from the contract                                                              |
| `lib/artifacts.ts`            | Every published file, with its content                                                                 |
| `scripts/export-contract.ts`  | Writes the published files. The library's only I/O; nothing imports it                                 |
| `testing/schema-validator.ts` | Ajv (draft 2020-12) set up for the tests: strict compile, the official OpenAPI 3.1 schema, components  |

## Changing the contract

Edit the step or envelope module, then regenerate and commit the published files:

```bash
pnpm exec nx run shared-interaction-contract:contract-export
pnpm exec nx run shared-interaction-client:generate
```

The tests fail while a published file differs from what the contract generates, and the
stable-surface check (`stable-surface/README.md`) compares the published files with the last
release. Before 1.0.0 a breaking change raises the release candidate number of the path and of every
step name together (`INTERACTION_API_RC` in `lib/identifiers.ts`).

## The tests

| Test                    | What it holds the contract to                                                                     |
| ----------------------- | ------------------------------------------------------------------------------------------------- |
| `openapi-lint.test.ts`  | A valid OpenAPI 3.1 document; every schema compiles under strict mode; every reference resolves   |
| `display-rules.test.ts` | No response allows HTML or free text: every string is an enum, a constant or a bounded value      |
| `operations.test.ts`    | The four operations, their flow-cookie and CSRF needs, their responses, no navigational parameter |
| `steps.test.ts`         | The step list, names, transports, `amr` and errors; every example validates against its schema    |
| `artifacts.test.ts`     | The committed files equal the generated ones; the registry and the versioning rules               |

## The vendored OpenAPI schemas

`src/lib/oas/` holds the official OpenAPI 3.1 JSON Schemas, byte for byte as the OpenAPI Initiative
publishes them (Apache License 2.0), so the schema lint needs no network. Formatting leaves them
alone (`.oxfmtrc.json`).

| File                          | Source                                                     | SHA-256                                                            |
| ----------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------ |
| `schema-2026-08-03.json`      | `https://spec.openapis.org/oas/3.1/schema/2026-08-03`      | `59f106413cb48c31299f96f024c938d3628aed6cd02cd14bcfb2fcaae7a130b6` |
| `schema-base-2026-08-03.json` | `https://spec.openapis.org/oas/3.1/schema-base/2026-08-03` | `ffdd07e28417bfa89de635d23a7476f7625497b8edd279f18c1424e613966d9a` |
| `dialect-2024-11-10.json`     | `https://spec.openapis.org/oas/3.1/dialect/2024-11-10`     | `647f32dfff64949d5020a28ecd1af4ffeffb1e9c695f861a52255a8004e07460` |
| `meta-2024-11-10.json`        | `https://spec.openapis.org/oas/3.1/meta/2024-11-10`        | `80706a9a404affedbf84ac4dc1328c9ce0d2a00804cdfc4d95c0ddd0053121dd` |

2026-08-03 is the newest iteration of the 3.1 schema as of 2026-10-26. Ajv supports a
`$dynamicAnchor` only at a schema's root, so `testing/schema-validator.ts` replaces the official
schema's `$dynamicRef: "#meta"` with the dialect it resolves to under `schema-base`; the comment
there explains why that is equivalent.
