# @qauth-labs/shared-account-contract

The account API v1 contract (#588, ADR-019 Decision 7, ADR-017 Decision 8, ADR-020 §3, ADR-018 §5):
every operation a signed-in person manages their own account with, written down before the account
console or any handler. Pure data and schema builders, with no I/O.

The published reference is the docs page `reference/account-api` (generated from this library) and
the OpenAPI 3.1 document `apps/docs-site/public/account/v1-rc.0/openapi.json`. The typed client in
`libs/shared/account-client` is generated from that document.

## What it holds

| Module                       | What                                                                                                     |
| ---------------------------- | -------------------------------------------------------------------------------------------------------- |
| `lib/identifiers.ts`         | The version label `v1-rc.0`, the path prefix, the audience, the fresh-authentication and act-chain rules |
| `lib/operations.ts`          | Every operation: path, permission, fresh authentication, act-chain rule, body, codes, one example        |
| `lib/schemas.ts`             | The component schemas, under the display rule of the Interaction API's `schema-kit`                      |
| `lib/problems.ts`            | The problem codes, the status each is sent with, the field-error and password-rejection reasons          |
| `lib/security-log.ts`        | The security log's closed list of kinds, each with the event types it is built from                      |
| `lib/notices.ts`             | The security notices, and which are mandatory                                                            |
| `lib/rules.ts`               | The rules and the versioning rules, which the document and the docs page both render                     |
| `lib/openapi.ts`             | The OpenAPI 3.1 document, `ACCOUNT_OPENAPI`                                                              |
| `lib/docs-page.ts`           | The docs page, rendered from the contract                                                                |
| `lib/artifacts.ts`           | Every published file, with its content                                                                   |
| `scripts/export-contract.ts` | Writes the published files. The library's only I/O; nothing imports it                                   |

## Changing the contract

Edit the module, then regenerate and commit the published files and the client:

```bash
pnpm exec nx run shared-account-contract:contract-export
pnpm exec nx run shared-account-client:generate
```

The tests fail while a published file differs from what the contract generates, and the
stable-surface check (`stable-surface/README.md`) compares the document with the last release.
Before 1.0.0 a breaking change raises the release candidate number of the path and of the audience
together (`ACCOUNT_API_RC` in `lib/identifiers.ts`, and the auth server's
`api-conventions/families.ts`, which a test there keeps equal).

A feature that registers one of the security log's planned event types marks its source
`registered` in `lib/security-log.ts` in the same change; `security-log.test.ts` fails until it does.

## The tests

| Test                    | What it holds the contract to                                                                             |
| ----------------------- | --------------------------------------------------------------------------------------------------------- |
| `openapi-lint.test.ts`  | A valid OpenAPI 3.1 document; every schema compiles under strict mode; every reference resolves           |
| `examples.test.ts`      | Every operation's example request and response, and every problem example, validates against its schema   |
| `display-rules.test.ts` | No schema allows HTML or free text: every string is an enum, a constant or a bounded, patterned value     |
| `operations.test.ts`    | Each operation's audience, fresh authentication and act-chain rule; paging, `If-Match`, the challenge     |
| `security-log.test.ts`  | The kinds are a closed list, matched to the event registry both ways                                      |
| `artifacts.test.ts`     | The committed files equal the generated ones; the registry; the rules appear in the document and the page |

Shared libraries are leaves of the module graph, so this one imports no other workspace library. The
checks that need one run in the auth server's `api-conventions/account-contract.test.ts`: the
document against the official OpenAPI 3.1 schema (the Interaction API contract's vendored copy) and
the API conventions check; the security log's kinds against the event registry, both ways; the
problem codes, the prefix and the audience against the server's tables; the served account
operations against the contract; and the copy of `schema-kit.ts` against the Interaction API
contract's original.
