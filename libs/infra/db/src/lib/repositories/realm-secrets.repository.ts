import { and, eq } from 'drizzle-orm';

import type { RealmSecret, RealmSecretsRepository, RealmSecretValue } from '../../types';
import { DbClient } from '../db';
import { realmSecrets } from '../schema/realm-secrets';
import { EPOCH_MS_NOW } from '../schema/sql-helpers';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Refuse a realm id that is not a UUID before it reaches Postgres, where the
 * cast would fail the query (22P02) instead of finding nothing.
 */
function assertRealmId(realmId: string): void {
  if (typeof realmId !== 'string' || !UUID_PATTERN.test(realmId)) {
    throw new TypeError('realmId is not a UUID');
  }
}

const columnsOf = (value: RealmSecretValue | null) => ({
  ciphertext: value?.ciphertext ?? null,
  keyId: value?.keyId ?? null,
});

/**
 * The realms' secret values (`realm_secrets`, #529): ciphertext only. The
 * table's CHECKs refuse anything but the signer's `data_at_rest` format, so a
 * caller that passed a plaintext by mistake fails here and stores nothing.
 */
export function createRealmSecretsRepository(defaultDb: DbClient): RealmSecretsRepository {
  return {
    async find(realmId: string, name: string, tx?: DbClient): Promise<RealmSecret | undefined> {
      assertRealmId(realmId);
      const [row] = await (tx ?? defaultDb)
        .select()
        .from(realmSecrets)
        .where(and(eq(realmSecrets.realmId, realmId), eq(realmSecrets.name, name)))
        .limit(1);
      return row;
    },

    async write(
      realmId: string,
      name: string,
      value: RealmSecretValue | null,
      tx?: DbClient
    ): Promise<void> {
      assertRealmId(realmId);
      const columns = columnsOf(value);
      await (tx ?? defaultDb)
        .insert(realmSecrets)
        .values({ realmId, name, ...columns })
        .onConflictDoUpdate({
          target: [realmSecrets.realmId, realmSecrets.name],
          set: { ...columns, updatedAt: EPOCH_MS_NOW },
        });
    },

    async insertIfAbsent(
      realmId: string,
      name: string,
      value: RealmSecretValue | null,
      tx?: DbClient
    ): Promise<boolean> {
      assertRealmId(realmId);
      const inserted = await (tx ?? defaultDb)
        .insert(realmSecrets)
        .values({ realmId, name, ...columnsOf(value) })
        .onConflictDoNothing({ target: [realmSecrets.realmId, realmSecrets.name] })
        .returning({ name: realmSecrets.name });
      return inserted.length > 0;
    },
  };
}
