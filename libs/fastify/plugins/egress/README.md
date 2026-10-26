# @qauth-labs/fastify-plugin-egress

The auth server's way to the SSRF-safe egress client
([`@qauth-labs/server-egress`](../../../server/egress/README.md), ADR-019 Decision 8), issue #481.
The app may not import a `scope:server` library, so this plugin reads the deployment allowlist and
decorates `fastify.egress`.

```typescript
await fastify.register(egressPlugin, { allowlistPath: env.EGRESS_ALLOWLIST_PATH });

const res = await fastify.egress.request({
  method: 'GET',
  url: clientId,
  purpose: 'cimd',
  source: 'client', // who set the destination: operator, admin, client, end_user, remote_document
  realm: realm.name, // the allowlist entries naming it apply to operator and admin destinations
  limits: { maxRedirects: 0 },
});
```

`EGRESS_ALLOWLIST_PATH` names a JSON file the operator writes. The plugin reads it once, at boot; a
file that cannot be read or does not validate fails the boot, naming the variable, the file and the
mistake, and a file that group or others can write gives a warning. The list is not in the
database and no route reads or edits it, so a realm admin cannot widen it. The file format is in
the egress library's README.

The plugin re-exports what the app needs from the egress library: `EgressError`, `isEgressError`,
the request and source types, and `createTestEgressClient`. A test passes that factory as
`createClient` (the app's `egressClientFactory` option) to reach a local fixture server; the plugin
refuses a factory unless `NODE_ENV` is `test`. `src/testing/egress-fixtures.ts` re-exports the
library's fixtures for the auth server's suites.

```bash
pnpm exec nx run fastify-plugin-egress:test
```
