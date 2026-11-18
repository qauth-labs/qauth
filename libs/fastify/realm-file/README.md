# @qauth-labs/realm-file

The declarative realm file, format `urn:qauth:realm-file:v1-rc.0` (ADR-018 §5, ADR-019 Decision
11, ADR-020 fork G, issue #515): a realm's configuration as one JSON document, with no secret value.
The admin API and the CLI will export and import it; this library fixes the format, parses it and
publishes its JSON Schema. The docs page is
[`reference/realm-file.md`](../../../apps/docs-site/src/content/docs/reference/realm-file.md).

```typescript
import { canonicalRealmFile, parseRealmFile, safeParseRealmFile } from '@qauth-labs/realm-file';

const file = parseRealmFile(JSON.parse(text)); // throws RealmFileError with every issue
const result = safeParseRealmFile(JSON.parse(text)); // { success, file } or { success, issues }
// Each issue: { path: ['clients', 0, 'client_secret'], pointer: '/clients/0/client_secret', message }
const written = canonicalRealmFile(file); // sets and entry lists in canonical order
```

## What it holds

- `src/lib/format.ts`: the format identifier and the paths it is published at.
- `src/lib/sections.ts`: the sections (`policies`, `clients`, `cimd_clients`, `resources`,
  `system_client`), each with its natural key and canonical order. A section is added here, with
  its schema and natural key, and the import plan (#518) adds its diff rules.
- `src/lib/realm-file.ts`: the Zod schema and the parser. `clients`, `cimd_clients`, `resources`
  and `system_client` are the seed manifest's own schemas
  (`@qauth-labs/infra-db/seed-manifest`), so a seed manifest is a realm file as it is, but for
  three mistakes the seed lets pass and the file refuses: a `client_id` listed twice, a member of
  `jwks` beside `keys`, and a URL with a user name or password. `policies` is the realm policy
  registry's `document` view.
- `src/lib/credentials.ts`: the rule that no string of a file is a URL with a user name or
  password, which the parser checks the way a URL parser reads a URL, and the JSON Schema in its
  usual form.
- `src/lib/issues.ts`: the issue of each refused member, with its path and, for a member the
  format leaves out on purpose, the reason (a secret, a section of a later release, a client a
  developer owns, an id the server generates). No message quotes a value that holds a secret.
- `src/lib/json-schema.ts`: the JSON Schema (draft 2020-12), generated from the Zod schema.

## Why the fastify layer

The format needs the seed manifest's client schemas (`infra-db`, `scope:infra`) and the policy
registry (`server-realm-policy`, `scope:server`). The fastify layer is the only one the module
boundaries in `.oxlintrc.json` let reach both, and the one the auth server may import for the admin
API's export and import. Nothing here is a Fastify plugin.

## Published files

`pnpm exec nx run realm-file:schema-export` writes
`apps/docs-site/public/schemas/realm-file-v1-rc.0.json`, registered in
`stable-surface/surfaces.json` as the `input` surface `realm-file-v1`. The tests fail while the
committed file differs from what the schema generates.

## Fixtures

- `fixtures/valid/`: files the format accepts.
- `fixtures/invalid/`: files it refuses; `fixtures/invalid-expected.json` gives the path and
  message of each, and marks the few only the parser refuses (a rule between two values, which
  JSON Schema cannot state) with why.
- `fixtures/seed-manifests/`: seed manifests from the docs, each a valid manifest and a valid realm
  file. The tests also parse the manifests the repository ships
  (`graphs/fixtures/seed-manifest.json`, `apps/wire-suite/seed/clients.json`).

## Tests

```bash
pnpm nx test realm-file      # the format, the fixtures, the JSON Schema against the Zod schema
pnpm nx test docs-checks     # the docs page's example, and every seed manifest example of the docs
```
