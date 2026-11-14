import {
  createRealmAuthMethodPluginsRepository,
  createRealmKeysRepository,
  createRealmsRepository,
  createRealmUpstreamProvidersRepository,
  type DbClient,
  type RealmPublicKeysRepository,
} from '@qauth-labs/infra-db';
import { createPublishedKeyReader, type PublishedKeyReader } from '@qauth-labs/server-keys';
import type {
  KekRewrapStore,
  KeyRotationStore,
  RealmKeyBootStore,
  SignerKeyStore,
  StoredPublicKey,
  WrappedDekChange,
} from '@qauth-labs/server-keys/custody';

import type { KekCanaryStore } from './key-custody-check';

/**
 * The key library's storage ports over the repositories of
 * `@qauth-labs/infra-db` (ADR-019 Decision 9, issues #461, #463 and #464).
 *
 * `@qauth-labs/server-keys` may not import the database layer, so it names the
 * reads and writes it needs, and this wiring answers them with the realm keys
 * and realms repositories.
 */

/**
 * The type prefix of the generic upstream OpenID Connect client's providers
 * (`oidc_<alias>`, `UPSTREAM_OIDC_TYPE_PATTERN`): a realm's provider rows hold
 * their config. No plugin may take a type under it (the loader refuses the
 * whole prefix), so a provider id names one source or the other.
 */
const GENERIC_PROVIDER_PREFIX = 'oidc_';

/**
 * The store the in-process signer reads: realm issuers, key metadata, wrapped
 * keys for unwrapping, published public keys, and the client QAuth holds at
 * each upstream provider.
 */
export function createRepositorySignerKeyStore(db: DbClient): SignerKeyStore {
  const realms = createRealmsRepository(db);
  const keys = createRealmKeysRepository(db);
  const plugins = createRealmAuthMethodPluginsRepository(db);
  const providers = createRealmUpstreamProvidersRepository(db);
  return Object.freeze({
    async findRealmIssuer(realmId: string) {
      const realm = await realms.findById(realmId);
      return realm === undefined ? undefined : realm.issuer;
    },
    listKeys: (realmId: string, filter: { purpose: string; scopeId: string | null }) =>
      keys.listByRealm(realmId, { purpose: filter.purpose, scopeId: filter.scopeId }),
    getWrappedKey: (realmId: string, kid: string) => keys.getWrappedForSigner(realmId, kid),
    listPublicKeys: (realmId: string) => keys.listPublicByRealm(realmId),
    // The realm's configuration of the provider (#1073): the client id, and
    // the assertion issuer a preset's signed client secret names. A generic
    // provider's row holds its config; a plugin's is what the admin API
    // derived from the plugin's config at its last configure or enable, as
    // the signer loads no plugin code. Only an enabled provider answers. Two
    // enabled plugin states of one type (another plugin id left behind) are
    // refused rather than picked from.
    async findUpstreamClient(realmId: string, providerId: string) {
      if (providerId.startsWith(GENERIC_PROVIDER_PREFIX)) {
        const found = await providers.findAssertionClient(realmId, providerId);
        return found === undefined ? undefined : { clientId: found.clientId };
      }
      const found = await plugins.listAssertionClients(realmId, providerId);
      if (found.length !== 1) return undefined;
      const [client] = found;
      return client.assertionIssuer === undefined
        ? { clientId: client.clientId }
        : { clientId: client.clientId, assertionIssuer: client.assertionIssuer };
    },
  } satisfies SignerKeyStore);
}

/**
 * What the signer's readiness check reads (#500): the canary keys, one per KEK
 * reference in use, and each one's wrapped row through the one read that
 * returns wrapped material.
 */
export function createRepositoryKekCanaryStore(db: DbClient): KekCanaryStore {
  const keys = createRealmKeysRepository(db);
  return Object.freeze({
    listKekCanaries: (limit: number) => keys.listKekCanaries(limit),
    getWrappedKey: (realmId: string, kid: string) => keys.getWrappedForSigner(realmId, kid),
  } satisfies KekCanaryStore);
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
 * a realm's keys. The key rotation job (#542) writes through it too, and
 * pages through the realms with `listRealmIds`.
 */
export function createRepositoryKeyStore(
  db: DbClient
): RealmKeyBootStore<DbClient> & KeyRotationStore<DbClient> {
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
    listRealmIds: (afterRealmId: string | null, limit: number) =>
      keys.listRealmIds(afterRealmId, limit),
    getWrappedKey: (realmId: string, kid: string, tx: DbClient) =>
      keys.getWrappedForSigner(realmId, kid, tx),
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
  } satisfies RealmKeyBootStore<DbClient> & KeyRotationStore<DbClient>);
}

/**
 * The store the KEK rotation (#545) works through: the keys per KEK
 * reference, a page of one reference's keys, a key's sealed row through the
 * one read that returns wrapped material, and the conditional write of a
 * key's new wrap. The approval is consumed in a transaction on `db`.
 */
export function createRepositoryKekRewrapStore(db: DbClient): KekRewrapStore<DbClient> {
  const keys = createRealmKeysRepository(db);
  return Object.freeze({
    transaction: <T>(work: (tx: DbClient) => Promise<T>) => db.transaction(work),
    countByKekRef: () => keys.countByKekRef(),
    listByKekRef: (kekRef: string, afterId: string | null, limit: number) =>
      keys.listByKekRef(kekRef, afterId, limit),
    getWrappedKey: (realmId: string, kid: string) => keys.getWrappedForSigner(realmId, kid),
    async replaceWrappedDek(realmId: string, kid: string, change: WrappedDekChange) {
      return (await keys.replaceWrappedDek(realmId, kid, change)) !== undefined;
    },
  } satisfies KekRewrapStore<DbClient>);
}
