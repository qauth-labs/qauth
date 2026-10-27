import {
  createRealmKeysRepository,
  createRealmsRepository,
  type DbClient,
  type RealmPublicKeysRepository,
} from '@qauth-labs/infra-db';
import { createPublishedKeyReader, type PublishedKeyReader } from '@qauth-labs/server-keys';
import type {
  RealmKeyBootStore,
  SignerKeyStore,
  StoredPublicKey,
} from '@qauth-labs/server-keys/custody';

/**
 * The key library's storage ports over the repositories of
 * `@qauth-labs/infra-db` (ADR-019 Decision 9, issues #461, #463 and #464).
 *
 * `@qauth-labs/server-keys` may not import the database layer, so it names the
 * reads and writes it needs, and this wiring answers them with the realm keys
 * and realms repositories.
 */

/**
 * The store the in-process signer reads: realm issuers, key metadata, wrapped
 * keys for unwrapping, published public keys, and the client id QAuth holds at
 * each upstream provider.
 */
export function createRepositorySignerKeyStore(db: DbClient): SignerKeyStore {
  const realms = createRealmsRepository(db);
  const keys = createRealmKeysRepository(db);
  return Object.freeze({
    async findRealmIssuer(realmId: string) {
      const realm = await realms.findById(realmId);
      return realm === undefined ? undefined : realm.issuer;
    },
    listKeys: (realmId: string, filter: { purpose: string; scopeId: string | null }) =>
      keys.listByRealm(realmId, { purpose: filter.purpose, scopeId: filter.scopeId }),
    getWrappedKey: (realmId: string, kid: string) => keys.getWrappedForSigner(realmId, kid),
    listPublicKeys: (realmId: string) => keys.listPublicByRealm(realmId),
    // No upstream provider is configured anywhere yet: upstream login owns
    // that configuration (ADR-018 §3) and adds this read with it. Until then
    // `signClientAssertion` finds no provider and signs nothing.
    findUpstreamClient: async () => undefined,
  } satisfies SignerKeyStore);
}

/**
 * The realm's verification keys and JWKS, read from `realm_public_keys`
 * alone (#495): the signer's public reads on a process that does not hold the
 * signer role, which has no KEK and must not read `realm_keys`. It reads
 * public material only, the same rows the in-process signer publishes, so a
 * token verifies there exactly as on the signer's process.
 *
 * @param realmPublicKeys - the database plugin's `realmPublicKeys` repository
 */
export function createRepositoryPublishedKeyReader(
  realmPublicKeys: Pick<RealmPublicKeysRepository, 'listByRealm'>
): PublishedKeyReader {
  return createPublishedKeyReader({
    listPublicKeys: (realmId: string) => realmPublicKeys.listByRealm(realmId),
  });
}

/**
 * The store the key factory and the key boot step write through
 * (`createKeyFactory`, `bootRealmKeys`). A transaction runs on `db`, or as a
 * savepoint inside the caller's `outer` transaction, so a realm and its keys
 * can be created together, and a subscription or provider deleted with its
 * keys (`deleteScopedKeys`). `lockRealm` is the repository's advisory lock on
 * a realm's keys.
 */
export function createRepositoryKeyStore(db: DbClient): RealmKeyBootStore<DbClient> {
  const keys = createRealmKeysRepository(db);
  return Object.freeze({
    transaction: <T>(work: (tx: DbClient) => Promise<T>, outer?: DbClient) =>
      (outer ?? db).transaction(work),
    findByKid: keys.findByKid,
    listByRealm: keys.listByRealm,
    create: keys.create,
    updateStatus: keys.updateStatus,
    deleteByScope: keys.deleteByScope,
    lockRealm: keys.lockRealm,
    anotherRealmPublishes: (
      realmId: string,
      identity: Readonly<Record<string, string>>,
      tx: DbClient
    ) => keys.anotherRealmPublishes(realmId, identity, tx),
    async listPublicKeys(realmId: string, tx: DbClient): Promise<readonly StoredPublicKey[]> {
      const rows = await keys.listPublicByRealm(realmId, tx);
      return rows.map(({ kid, purpose, status, publicJwk }) => ({
        kid,
        purpose,
        status,
        publicJwk,
      }));
    },
  } satisfies RealmKeyBootStore<DbClient>);
}
