# @qauth-labs/server-realm-policy

The realm policies of QAuth as one typed schema with a version
([ADR-019 Decision 10](../../../docs/adr/019-deployment-topology-and-trust-boundaries.md),
[ADR-018 §5](../../../docs/adr/018-1-0-scope-and-stability.md), issue #514). The admin API's realm
representation, the realm file, the diff of two configurations and the rule that decides which
changes need `qauth:admin:security` all come from it, and so does the docs page
[`reference/realm-policies`](../../../apps/docs-site/src/content/docs/reference/realm-policies.md).

It is a plain library over Zod and `@qauth-labs/shared-validation` (for the closed list of security
effects, `SECURITY_EFFECTS`). The policy store below keeps the policies on the realm row (#516),
through a storage port the database library implements; the flows read them from there in the
issues that follow (#527, #528, #529, #534).

## Fields

A field is a Zod type plus its annotations, all of them required:

```typescript
import { policyField } from '@qauth-labs/server-realm-policy';
import { z } from 'zod';

const minScore = policyField(z.number().int().min(0).max(4), {
  seedEnv: 'PASSWORD_MIN_SCORE', // the environment key that seeds a new realm, or null
  default: 2, // the value when that key is not set
  direction: 'higher-is-stricter', // which way is stricter
  securityWhen: 'loosening', // never | loosening | any-change
  effects: ['credential-path'], // what makes a security change one (empty for never)
  secret: false, // write-only, never stored or returned
  environmentBound: false, // left out of a sandbox promotion unless selected
  doc: {
    summary: 'The lowest zxcvbn strength score, from 0 to 4, a new password may have.',
    link: 'https://docs.qauth.dev/reference/realm-policies/#password',
  },
});
```

`policyField` refuses a definition that leaves out an annotation, names an unknown direction, rule
or effect, has a default its type refuses or that is not plain JSON, has a type with no JSON Schema
or, when not secret, one that accepts `undefined`, is `ordered` over a type that accepts a value
outside the order, or is a secret that is not `opaque`, `any-change` and default `null`. The
registry checks every field it registers the same way and keeps a frozen copy (`copyPolicyField`),
so a field from another copy of the library, or a forged one, meets the same rules and cannot
change once registered.

The directions are `lower-is-stricter`, `higher-is-stricter`, `true-is-stricter`,
`false-is-stricter`, `ordered([...])` (from the loosest value to the strictest),
`subset-is-stricter` (allowed values), `superset-is-stricter` (required values) and `opaque`. A
change the schema cannot place, such as a value outside an order or a direction it does not know,
counts as a loosening.

## Groups and the registry

`REALM_POLICY_REGISTRY` holds the built-in groups: `tokens`, `accounts`, `password`, `bruteForce`,
`registration`, `mail`, `posture` and `admin`. Another area adds its own:

```typescript
import { registerPolicyGroup } from '@qauth-labs/server-realm-policy';

registerPolicyGroup('sessions', { maxLifespanSeconds: policyField(/* ... */) });
```

A group name is taken once, in any case. `createPolicyRegistry()` makes an empty registry, for
tests.

## What it builds

```typescript
import {
  defaultsFromEnv,
  diffPolicies,
  parseRealmPolicies,
  toJsonSchema,
  toRealmPoliciesRepresentation,
} from '@qauth-labs/server-realm-policy';

const policies = defaultsFromEnv(env); // a new realm's policies; env as parsed, or raw strings
const {
  changes,
  class: needs,
  effects,
} = diffPolicies(stored, write, {
  setSecrets: ['mail.smtp.password'], // what the secret store holds; no document does
});
// In the write, a secret's value sets it, null clears it, and leaving it out keeps it.
// changes: [{ path: 'password.minScore', before: 2, after: 1, direction: 'loosening',
//             class: 'security', effects: ['credential-path'], ... }]
const stored = parseRealmPolicies(row.policies); // defaults filled, unknown members refused
const representation = toRealmPoliciesRepresentation(stored, ['mail.smtp.password']);
// representation.mail.smtp.passwordSet === true; the value itself is never there
const schema = toJsonSchema('representation'); // or 'document' (the realm file), 'input'
```

The three views:

- `document`: the stored policies and the realm file's `policies`. No secret appears.
- `input`: a write. A secret field may be set here, or cleared with `null`, and is marked
  `writeOnly`. The representation's `<name>Set` is accepted (`readOnly`) and dropped, so a
  representation sent back changes nothing.
- `representation`: what the admin API returns. A secret `<name>` appears as `<name>Set`. Every
  member must be present: its Zod schema never fills a default, so a serialiser built on it cannot
  show a loosened realm as a strict one, and it strips any member it does not name.

## The policy store

`createPolicyStore` reads and writes one realm's policies as one document, over a
`RealmPolicyStorage` port. The realm row keeps four fields in the columns that held them before
(`access_token_lifespan`, `refresh_token_lifespan`, `dynamic_registration_allowed_scopes`,
`max_environment_laxity`) and every other one in `realms.policies`; the port joins and splits the
two forms, so the store sees one document. `@qauth-labs/fastify-plugin-realm-policy` builds it over
the realms table as `fastify.policyStore`.

```typescript
const store = createPolicyStore({ storage, seeds: defaultsFromEnv(env), secrets });

store.ofRealm(row); // the policies of a realm row already loaded: no query
await store.get(realmId); // { version, hasPolicies, schemaVersion, policies }
await store.update(realmId, { password: { minScore: 3 } }, { expectedVersion: 4, tx });
await store.seedRealms(tx); // at boot: fill realms with no policies, complete missing fields
```

- `version` is the realm's `policies_version`: the admin API's `ETag`. `update` takes a JSON Merge
  Patch (RFC 7396) and changes nothing unless the realm still has `expectedVersion`
  (`PolicyVersionConflictError`); a refused merged document throws `PolicyValidationError`.
- A secret field in a patch goes to the `RealmSecretStore` in the same transaction (`put`, `isSet`,
  `getForUse`; implemented by #529), never into the stored document. With no secret store the write
  is refused (`PolicySecretStoreUnavailableError`).
- A realm with no policies yet (`version` 0, created before migration 0046) reads as its fill: the
  seeds, with the values of its row the server read before (the environment ceiling, a non-empty
  dynamic registration allowlist). A field missing from a stored document, which a later release
  added, reads as its seed; `seedRealms` writes both once, reading the row locked (the storage's
  `readLocked`) and writing with `UPDATE ... WHERE policies_version = <read>`, so the first node to
  boot wins and a plain write of the row is never overwritten.
- Members of a stored document this release does not know (a later release's) are skipped on read
  and carried over on write, so a node of the previous release never drops them during a rolling
  upgrade. A document of another schema version is not written: `update` refuses it
  (`PolicySchemaVersionError`) and `seedRealms` leaves it as it is (`skipped`).
- A list a fill keeps from the row loses its repeats, as `defaultsFromEnv` drops them.
- `seedKeysSetIn(process.env)` names the seed keys the environment sets, which a realm with
  policies ignores.

## Versions

`REALM_POLICY_SCHEMA_VERSION` is `1-rc.0`. Before QAuth 1.0.0 a breaking change raises the rc
number; from 1.0.0 it is `1`, and every change inside it is additive: a new field with a default,
never a removal.

## Tests

```bash
pnpm nx test server-realm-policy        # unit and contract tests
pnpm nx test server-realm-policy -- -u  # regenerate reference/realm-policies.md
```

The contract test checks every registered field: all annotations present, every secret write-only,
every security field naming an effect, every docs link resolving, and each seed key agreeing with
the configuration key registry of `@qauth-labs/server-config` (role, path, secrecy and default).
