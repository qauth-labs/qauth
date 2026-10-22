import type { Pool, PoolClient } from 'pg';

import type {
  NewStoredKey,
  RealmKeyStore,
  StoredKeyFilter,
  StoredKeySummary,
} from '../lib/key-store';

/**
 * A {@link RealmKeyStore} over a node-postgres pool, for this library's
 * integration tests. Never exported from the package entry point.
 *
 * This library may not import `@qauth-labs/infra-db`, so the tests write the
 * two tables with plain SQL against the real migrated schema. The repository
 * the signer's wiring passes in production (#461) writes the same columns.
 */
export function createPgKeyStore(pool: Pool): RealmKeyStore<PoolClient> {
  let savepoints = 0;

  return {
    async transaction<T>(work: (tx: PoolClient) => Promise<T>, outer?: PoolClient): Promise<T> {
      if (outer !== undefined) {
        const savepoint = `key_store_${++savepoints}`;
        await outer.query(`SAVEPOINT ${savepoint}`);
        try {
          const result = await work(outer);
          await outer.query(`RELEASE SAVEPOINT ${savepoint}`);
          return result;
        } catch (error) {
          await outer.query(`ROLLBACK TO SAVEPOINT ${savepoint}`);
          throw error;
        }
      }

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await work(client);
        await client.query('COMMIT');
        return result;
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    },

    async findByKid(realmId: string, kid: string, tx: PoolClient): Promise<object | undefined> {
      const { rows } = await tx.query(
        'SELECT kid FROM realm_keys WHERE realm_id = $1 AND kid = $2',
        [realmId, kid]
      );
      return rows[0];
    },

    async listByRealm(
      realmId: string,
      filter: StoredKeyFilter,
      tx: PoolClient
    ): Promise<readonly StoredKeySummary[]> {
      const conditions = ['realm_id = $1'];
      const values: unknown[] = [realmId];
      if (filter.purpose !== undefined) {
        values.push(filter.purpose);
        conditions.push(`purpose = $${values.length}`);
      }
      if (filter.scopeId === null) {
        conditions.push('scope_id IS NULL');
      } else if (filter.scopeId !== undefined) {
        values.push(filter.scopeId);
        conditions.push(`scope_id = $${values.length}`);
      }
      if (filter.status !== undefined) {
        values.push(filter.status);
        conditions.push(`status = $${values.length}`);
      }
      const { rows } = await tx.query<StoredKeySummary>(
        `SELECT kid, algorithm, status FROM realm_keys WHERE ${conditions.join(' AND ')}`,
        values
      );
      return rows;
    },

    async create({ key, publicJwk }: NewStoredKey, tx: PoolClient): Promise<unknown> {
      await tx.query(
        `INSERT INTO realm_keys (realm_id, purpose, scope_id, algorithm, kid, status, pair_id,
           ciphertext, iv, wrapped_dek, kek_ref, aad_version, publish_at, activate_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
        [
          key.realmId,
          key.purpose,
          key.scopeId,
          key.algorithm,
          key.kid,
          key.status,
          key.pairId,
          key.ciphertext,
          key.iv,
          key.wrappedDek,
          key.kekRef,
          key.aadVersion,
          key.publishAt,
          key.activateAt,
        ]
      );
      if (publicJwk !== undefined) {
        await tx.query(
          `INSERT INTO realm_public_keys (realm_id, kid, purpose, algorithm, status, public_jwk, publish_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            key.realmId,
            key.kid,
            key.purpose,
            key.algorithm,
            key.status,
            JSON.stringify(publicJwk),
            key.publishAt,
          ]
        );
      }
      return key;
    },
  };
}
