# @qauth-labs/fastify-plugin-realm-policy

The realm policy store as a Fastify decorator (ADR-019 Decision 10, issue #516). It builds
`@qauth-labs/server-realm-policy`'s `createPolicyStore` over the realms table of
`@qauth-labs/infra-db` and decorates `fastify.policyStore`. The auth server may not import the
policy library itself (`scope:server`), so this package also re-exports what it works with:
`defaultsFromEnv`, `seedKeysSetIn`, the schema version, the store's errors and its types.

```typescript
import { defaultsFromEnv, realmPolicyPlugin } from '@qauth-labs/fastify-plugin-realm-policy';

const seeds = defaultsFromEnv(env);
await fastify.register(databasePlugin, {
  realmPolicySeeds: { policies: { document: seeds, schemaVersion: REALM_POLICY_SCHEMA_VERSION } },
  // ...
});
await fastify.register(realmPolicyPlugin, { seeds });

fastify.policyStore.ofRealm(request.realm); // no query
await fastify.policyStore.update(realmId, patch, { expectedVersion, tx });
await fastify.policyStore.seedRealms(tx); // the default realm's boot step
```

The storage (`createRealmPolicyStorage`) reads a row through `realmPolicyRecord`, which joins the
four policy columns and `realms.policies` into one document, and writes through the realms
repository's `writePolicies`, which splits it again with `UPDATE ... WHERE policies_version =
<expected>`. A write first reads the row locked (`lockPolicyRecord`, `SELECT ... FOR UPDATE`): the
counter of a realm with no policies stays 0 through a plain write of its row, which the fill must
not overwrite.

## Tests

```bash
pnpm nx test fastify-plugin-realm-policy              # unit and contract tests
pnpm nx test-integration fastify-plugin-realm-policy  # against Postgres (Docker)
```

The integration suite holds the four column-backed fields round-tripping, a stale expected version
changing nothing, two nodes filling a realm at once leaving one document, a fill keeping a plain
write of the row it waited on, and a secret staying out of the realm row.
