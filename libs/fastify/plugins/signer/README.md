# @qauth-labs/fastify-plugin-signer

The signer's wiring ([ADR-019 Decision 9](../../../../docs/adr/019-deployment-topology-and-trust-boundaries.md)):
it loads the key-encryption key (KEK) provider, reads the realm keys through the database
repositories, and decorates the Fastify instance with the in-process signer of
[`@qauth-labs/server-keys`](../../../server/keys/README.md).

> **Status:** the auth-server registers this plugin for the key boot step, which imports the key
> variables into the default realm's store at first boot (#485). Tokens are signed through it since
> #491, and the session cookie with the realm's cookie key from it since #493.

## Who may import the KEK

ADR-019 provisions the KEK to the signer role alone. In code that is one rule: only this project and
`@qauth-labs/server-keys` itself may import `@qauth-labs/server-keys/custody`, the entry point with
the KEK provider, the envelope API, the key factory and the in-process signer. The key custody
guard in `.oxlintrc.json` fails `nx lint` for an import from anywhere else. Every other project
signs through `fastify.signer`, typed by the `Signer` interface of `@qauth-labs/server-keys`.

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

## The key boot step

With `realmKeysBoot`, the plugin runs the key boot step of `@qauth-labs/server-keys`
(`bootRealmKeys`) for one realm in an `onReady` hook, so before the server listens. Register it
after the default realm's boot step, whose `onReady` hook creates the realm.

```typescript
await fastify.register(signerPlugin, {
  db: fastify.db,
  kekEnv: process.env,
  enabledSignatureAlgorithms: cryptoEnv.enabledSignatureAlgorithms,
  hybridSigning: cryptoEnv.HYBRID_SIGNING_ENABLED,
  realmKeysBoot: {
    realmName: env.DEFAULT_REALM_NAME,
    environmentKeys, // the key variables, with the names of the variables that set them
  },
});
```

- It imports each key variable the realm's store lacks, replacing the active key of its algorithm,
  creates the standard keys still missing, and gives a fresh realm an RS256 signing key, under the
  realm's advisory lock (`lockRealm` of the realm keys repository).
- It logs `realm keys ready` with the `kid`s it imported and generated, one warning per replaced
  key with the retired `kid`s (`keyReplacedWarning`), one per variable that holds a key the store
  retired (`keyInactiveWarning`), and one per key variable still set (`keyVariableWarning`).
  Tokens (#491) and the session cookie (#493) are signed through the store, so a key variable is
  read only here: a new key in a token variable replaces the stored key, and a different secret in
  `SESSION_COOKIE_SECRET` replaces the stored cookie key, found by opening each stored cookie key
  and comparing it with the secret in constant time. The replaced cookie key stays the realm's
  previous cookie key, so cookies it signed keep verifying until the next replacement.
- A refusal rejects `ready()`. The message names the variables, never a value. See the
  [server-keys README](../../../server/keys/README.md#importing-the-key-variables) for the
  refusals.

## Creating a key

`createRealmKey` creates one key for a realm, purpose and algorithm, under the same lock. The
auth-server's operator command `auth-server:keys:create` calls it on a host that holds the KEK:

```console
pnpm nx run auth-server:keys:create --purpose=token_signing --algorithm=RS256
```

It returns the stored keys with their `kid`s and public JWKs, never material. A second active key
of one purpose and algorithm is refused (`ActiveKeyConflictError`); create the replacement with
`status: 'next'`.

`bootRealmKeysWithKekEnv` runs the key boot step for a realm by name, loading the KEK provider
itself, for a caller outside the plugin: the auth-server's test harness runs it again after it
empties the database, and to give a second realm its standard keys.

## Storage adapters

- `createRepositorySignerKeyStore(db)`: the `SignerKeyStore` the signer reads, over
  `realms.findById` and the realm keys repository (`listByRealm`, `getWrappedForSigner`,
  `listPublicByRealm`). No upstream provider configuration exists yet, so `findUpstreamClient`
  finds none and `signClientAssertion` signs nothing; the upstream-login work adds that read.
- `createRepositoryKeyStore(db)`: the `RealmKeyBootStore` the key factory and the key boot step
  write through, over the realm keys repository (`findByKid`, `listByRealm`, `create`,
  `updateStatus`, `deleteByScope`, `lockRealm`, and its public keys). A transaction runs on `db`, or
  as a savepoint inside the caller's transaction, so a subscription or provider can be deleted with
  its keys (`deleteScopedKeys`).

## Testing

```bash
pnpm nx test fastify-plugin-signer
pnpm nx test-integration fastify-plugin-signer # needs Docker
```

`src/testing/memory-signer.ts` (not exported from the entry point) builds the real in-process
signer over keys held in memory, sealed under a test KEK: `createTestSigner()` and
`addRealm({ issuer, rs256? })`. A unit test that signs or verifies tokens without a database
imports it by path, as the JWT plugin's tests do.
