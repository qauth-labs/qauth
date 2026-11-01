import type { DbClient, RealmSecretsRepository } from '@qauth-labs/infra-db';
import type { RealmSecretStorage } from '@qauth-labs/server-realm-policy';

/**
 * The realm secret store's storage over `realm_secrets` (#529): one row per
 * realm and secret path, holding the signer's ciphertext or nothing. The
 * table's CHECKs refuse any other value, so what reaches it is ciphertext.
 */
export function createRealmSecretStorage(
  repository: Pick<RealmSecretsRepository, 'find' | 'write' | 'insertIfAbsent'>
): RealmSecretStorage<DbClient> {
  return Object.freeze({
    async read(realmId: string, path: string, tx?: DbClient) {
      const row = await repository.find(realmId, path, tx);
      return row === undefined ? undefined : { ciphertext: row.ciphertext };
    },
    write: (
      realmId: string,
      path: string,
      value: Parameters<RealmSecretsRepository['write']>[2],
      tx?: DbClient
    ) => repository.write(realmId, path, value, tx),
    insertIfAbsent: (
      realmId: string,
      path: string,
      value: Parameters<RealmSecretsRepository['insertIfAbsent']>[2],
      tx?: DbClient
    ) => repository.insertIfAbsent(realmId, path, value, tx),
  });
}
