# @qauth-labs/fastify-plugin-signer

The signer's wiring ([ADR-019 Decision 9](../../../../docs/adr/019-deployment-topology-and-trust-boundaries.md)):
it loads the key-encryption key (KEK) provider, reads the realm keys through the database
repositories, and decorates the Fastify instance with the in-process signer of
[`@qauth-labs/server-keys`](../../../server/keys/README.md).

> **Status:** nothing registers this plugin yet. Token signing moves onto it with #491, and the
> first-boot key import (#485) builds on the same wiring.

## Who may import the KEK

ADR-019 provisions the KEK to the signer role alone. In code that is one rule: only this project and
`@qauth-labs/server-keys` itself may import `@qauth-labs/server-keys/custody`, the entry point with
the KEK provider, the envelope API, the key factory and the in-process signer. A
`no-restricted-imports` rule in `eslint.config.mjs` fails `nx lint` for an import from anywhere
else. Every other project signs through `fastify.signer`, typed by the `Signer` interface of
`@qauth-labs/server-keys`.

## Usage

```typescript
import { signerPlugin } from '@qauth-labs/fastify-plugin-signer';

await fastify.register(signerPlugin, {
  db: fastify.db,
  kekEnv: process.env, // KEK_PROVIDER, KEK, KEK_PATH, KEK_PREVIOUS, KEK_PREVIOUS_PATH, NODE_ENV
  enabledSignatureAlgorithms: cryptoEnv.enabledSignatureAlgorithms,
  hybridSigning: cryptoEnv.HYBRID_SIGNING_ENABLED,
});

const token = await fastify.signer.signJws('local', {
  realmId,
  purpose: 'token_signing',
  typ: 'at+jwt',
  claims: { sub, aud, iat, exp },
});
```

- Registering the plugin loads the KEK provider. With `NODE_ENV=production` and no KEK, it refuses
  to start; outside production it falls back to the published development KEK and logs a warning
  that names the variable.
- Nothing is read from the database at registration. The signer reads a realm's keys on the first
  call that needs them.
- `keyCacheSize` and `refreshIntervalMs` tune the signer's key cache (defaults 256 keys and 60
  seconds).

## Storage adapters

- `createRepositorySignerKeyStore(db)`: the `SignerKeyStore` the signer reads, over
  `realms.findById` and the realm keys repository (`listByRealm`, `getWrappedForSigner`,
  `listPublicByRealm`). No upstream provider configuration exists yet, so `findUpstreamClient`
  finds none and `signClientAssertion` signs nothing; the upstream-login work adds that read.
- `createRepositoryKeyStore(db)`: the `RealmKeyStore` the key factory writes through, over the realm
  keys repository (`findByKid`, `listByRealm`, `create`, `updateStatus`, `deleteByScope`). A
  transaction runs on `db`, or as a savepoint inside the caller's transaction, so a subscription or
  provider can be deleted with its keys (`deleteScopedKeys`).

## Testing

```bash
pnpm nx test fastify-plugin-signer
pnpm nx test-integration fastify-plugin-signer # needs Docker
```
