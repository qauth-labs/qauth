import {
  type Database,
  type DbClient,
  type Realm,
  realmPolicyRecord,
  type RealmsRepository,
} from '@qauth-labs/infra-db';
import type { RealmPolicyStorage } from '@qauth-labs/server-realm-policy';

/**
 * The policy store's storage over the realms table (#516): a realm row is
 * read through `realmPolicyRecord`, which joins the four policy columns and
 * `realms.policies` into one document, and written through the repository's
 * `writePolicies`, which splits it again and compares the counter.
 */
export function createRealmPolicyStorage(
  db: Pick<Database, 'transaction'>,
  realms: Pick<RealmsRepository, 'findById' | 'listPolicyRecords' | 'writePolicies'>
): RealmPolicyStorage<Realm, DbClient> {
  return Object.freeze({
    recordOf: realmPolicyRecord,
    async read(realmId: string, tx?: DbClient) {
      const realm = await realms.findById(realmId, tx);
      return realm === undefined ? undefined : realmPolicyRecord(realm);
    },
    list: (tx?: DbClient) => realms.listPolicyRecords(tx),
    async write(
      realmId: string,
      write: Parameters<RealmsRepository['writePolicies']>[1],
      tx?: DbClient
    ) {
      const realm = await realms.writePolicies(realmId, write, tx);
      return realm === undefined ? undefined : realmPolicyRecord(realm);
    },
    transaction: <T>(work: (tx: DbClient) => Promise<T>, outer?: DbClient): Promise<T> =>
      // A savepoint inside an outer transaction (drizzle nests as SAVEPOINT).
      (outer ?? db).transaction(work),
  });
}
