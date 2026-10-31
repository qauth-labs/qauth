# @qauth-labs/server-realm-policy

The realm policies of QAuth as one typed schema with a version
([ADR-019 Decision 10](../../../docs/adr/019-deployment-topology-and-trust-boundaries.md),
[ADR-018 §5](../../../docs/adr/018-1-0-scope-and-stability.md), issue #514). The admin API's realm
representation, the realm file, the diff of two configurations and the rule that decides which
changes need `qauth:admin:security` all come from it, and so does the docs page
[`reference/realm-policies`](../../../apps/docs-site/src/content/docs/reference/realm-policies.md).

It is a plain library over Zod and `@qauth-labs/shared-validation` (for the closed list of security
effects, `SECURITY_EFFECTS`). Nothing reads the policies from the realm row yet: storing them and
seeding a new realm come next, and the flows read them after that.

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
} = diffPolicies(before, after, {
  setSecrets: ['mail.smtp.password'], // what the secret store holds; no document does
  clearSecrets: [], // secrets this change clears
});
// changes: [{ path: 'password.minScore', before: 2, after: 1, direction: 'loosening',
//             class: 'security', effects: ['credential-path'], ... }]
const stored = parseRealmPolicies(row.policies); // defaults filled, unknown members refused
const representation = toRealmPoliciesRepresentation(stored, ['mail.smtp.password']);
// representation.mail.smtp.passwordSet === true; the value itself is never there
const schema = toJsonSchema('representation'); // or 'document' (the realm file), 'input'
```

The three views:

- `document`: the stored policies and the realm file's `policies`. No secret appears.
- `input`: a write. A secret field may be set here and is marked `writeOnly`.
- `representation`: what the admin API returns. A secret `<name>` appears as `<name>Set`. Every
  member must be present: its Zod schema never fills a default, so a serialiser built on it cannot
  show a loosened realm as a strict one, and it strips any member it does not name.

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
