import type { Pool, PoolClient } from 'pg';

import type { KekRewrapStore, WrappedDekChange } from '../lib/kek-rewrap';
import type { KeyRotationStore } from '../lib/key-rotation';
import type {
  NewStoredKey,
  StoredKeyFilter,
  StoredKeyStatus,
  StoredKeySummary,
} from '../lib/key-store';
import type { RealmKeyBootStore, StoredPublicKey } from '../lib/realm-key-boot';
import type { WrappedSignerKey } from '../lib/signer-key-store';

/**
 * A {@link RealmKeyBootStore} and {@link KeyRotationStore} over a node-postgres
 * pool, for this library's integration tests. Never exported from the package
 * entry point.
 *
 * This library may not import `@qauth-labs/infra-db`, so the tests write the
 * two tables with plain SQL against the real migrated schema. The repository
 * the signer's wiring passes in production (#461) writes the same columns.
 */
export function createPgKeyStore(
  pool: Pool
): RealmKeyBootStore<PoolClient> & KeyRotationStore<PoolClient> {
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
      const { rows } = await tx.query<{
        kid: string;
        algorithm: string;
        status: StoredKeyStatus;
        pair_id: string | null;
        publish_at: string | null;
        activate_at: string | null;
        retire_at: string | null;
        unpublish_at: string | null;
        created_at: string;
      }>(
        `SELECT kid, algorithm, status, pair_id, publish_at, activate_at, retire_at, unpublish_at,
                created_at FROM realm_keys
         WHERE ${conditions.join(' AND ')} ORDER BY created_at, id`,
        values
      );
      // node-postgres returns `bigint` columns as strings.
      return rows.map((row) => ({
        kid: row.kid,
        algorithm: row.algorithm,
        status: row.status,
        pairId: row.pair_id,
        publishAt: row.publish_at === null ? null : Number(row.publish_at),
        activateAt: row.activate_at === null ? null : Number(row.activate_at),
        retireAt: row.retire_at === null ? null : Number(row.retire_at),
        unpublishAt: row.unpublish_at === null ? null : Number(row.unpublish_at),
        createdAt: Number(row.created_at),
      }));
    },

    async getWrappedKey(
      realmId: string,
      kid: string,
      tx: PoolClient
    ): Promise<WrappedSignerKey | undefined> {
      const { rows } = await tx.query<{
        realm_id: string;
        purpose: string;
        scope_id: string | null;
        kid: string;
        algorithm: string;
        status: StoredKeyStatus;
        ciphertext: Buffer;
        iv: Buffer;
        wrapped_dek: Buffer;
        kek_ref: string;
        aad_version: number;
      }>(
        `SELECT realm_id, purpose, scope_id, kid, algorithm, status, ciphertext, iv, wrapped_dek,
           kek_ref, aad_version FROM realm_keys WHERE realm_id = $1 AND kid = $2`,
        [realmId, kid]
      );
      const row = rows[0];
      if (row === undefined) return undefined;
      return {
        realmId: row.realm_id,
        purpose: row.purpose,
        scopeId: row.scope_id,
        kid: row.kid,
        algorithm: row.algorithm,
        status: row.status,
        ciphertext: row.ciphertext,
        iv: row.iv,
        wrappedDek: row.wrapped_dek,
        kekRef: row.kek_ref,
        aadVersion: row.aad_version,
      };
    },

    async lockRealm(realmId: string, tx: PoolClient): Promise<void> {
      // The lock the realm keys repository takes (`lockRealm`, #485).
      await tx.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
        `qauth:realm-keys:${realmId}`,
      ]);
    },

    async listRealmIds(afterRealmId: string | null, limit: number): Promise<readonly string[]> {
      // The query of the realm keys repository's `listRealmIds` (#542).
      const { rows } = await pool.query<{ realm_id: string }>(
        `SELECT DISTINCT realm_id FROM realm_keys
          WHERE $1::uuid IS NULL OR realm_id > $1::uuid ORDER BY realm_id LIMIT $2`,
        [afterRealmId, limit]
      );
      return rows.map((row) => row.realm_id);
    },

    async anotherRealmPublishes(
      realmId: string,
      identity: Readonly<Record<string, string>>,
      tx: PoolClient
    ): Promise<boolean> {
      const { rows } = await tx.query(
        'SELECT 1 FROM realm_public_keys WHERE realm_id <> $1 AND public_jwk @> $2::jsonb LIMIT 1',
        [realmId, JSON.stringify(identity)]
      );
      return rows.length > 0;
    },

    async listPublicKeys(realmId: string, tx: PoolClient): Promise<readonly StoredPublicKey[]> {
      const { rows } = await tx.query<{
        kid: string;
        purpose: string;
        status: StoredPublicKey['status'];
        public_jwk: Record<string, unknown>;
      }>('SELECT kid, purpose, status, public_jwk FROM realm_public_keys WHERE realm_id = $1', [
        realmId,
      ]);
      return rows.map((row) => ({
        kid: row.kid,
        purpose: row.purpose,
        status: row.status,
        publicJwk: row.public_jwk,
      }));
    },

    async create({ key, publicJwk }: NewStoredKey, tx: PoolClient): Promise<unknown> {
      await tx.query(
        `INSERT INTO realm_keys (realm_id, purpose, scope_id, algorithm, kid, status, pair_id,
           ciphertext, iv, wrapped_dek, kek_ref, aad_version, publish_at, activate_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
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
          key.createdAt,
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

    async updateStatus(realmId, kid, change, tx: PoolClient): Promise<object | undefined> {
      const { rows } =
        change.status === 'active'
          ? await tx.query(
              `UPDATE realm_keys SET status = 'active', activate_at = $3
               WHERE realm_id = $1 AND kid = $2 AND status = 'next' RETURNING kid`,
              [realmId, kid, change.activateAt]
            )
          : await tx.query(
              `UPDATE realm_keys SET status = 'retired', retire_at = $3, unpublish_at = $4
               WHERE realm_id = $1 AND kid = $2 AND status = 'active' RETURNING kid`,
              [realmId, kid, change.retireAt, change.unpublishAt]
            );
      if (rows[0] !== undefined && change.status === 'retired' && change.unpublishAt !== null) {
        await tx.query(
          'UPDATE realm_public_keys SET unpublish_at = $3 WHERE realm_id = $1 AND kid = $2',
          [realmId, kid, change.unpublishAt]
        );
      }
      return rows[0];
    },

    async deleteByScope(realmId, purpose, scopeId, tx: PoolClient): Promise<readonly string[]> {
      const { rows } = await tx.query<{ kid: string }>(
        'DELETE FROM realm_keys WHERE realm_id = $1 AND purpose = $2 AND scope_id = $3 RETURNING kid',
        [realmId, purpose, scopeId]
      );
      return rows.map((row) => row.kid);
    },
  };
}

/**
 * A {@link KekRewrapStore} over a node-postgres pool, for the KEK rotation's
 * integration tests (#545): the statements of the realm keys repository's
 * `countByKekRef`, `listByKekRef` and `replaceWrappedDek`, in plain SQL.
 */
export function createPgKekRewrapStore(pool: Pool): KekRewrapStore<PoolClient> {
  const keys = createPgKeyStore(pool);
  return {
    transaction: (work) => keys.transaction(work),

    async countByKekRef() {
      const { rows } = await pool.query<{ kek_ref: string; rows: string }>(
        'SELECT kek_ref, count(*) AS rows FROM realm_keys GROUP BY kek_ref ORDER BY kek_ref'
      );
      return rows.map((row) => ({ kekRef: row.kek_ref, rows: Number(row.rows) }));
    },

    async listByKekRef(kekRef: string, afterId: string | null, limit: number) {
      const { rows } = await pool.query<{ id: string; realm_id: string; kid: string }>(
        `SELECT id, realm_id, kid FROM realm_keys
          WHERE kek_ref = $1 AND ($2::uuid IS NULL OR id > $2::uuid) ORDER BY id LIMIT $3`,
        [kekRef, afterId, limit]
      );
      return rows.map((row) => ({ id: row.id, realmId: row.realm_id, kid: row.kid }));
    },

    async getWrappedKey(realmId: string, kid: string) {
      const client = await pool.connect();
      try {
        return await keys.getWrappedKey(realmId, kid, client);
      } finally {
        client.release();
      }
    },

    async replaceWrappedDek(realmId: string, kid: string, change: WrappedDekChange) {
      const { rowCount } = await pool.query(
        `UPDATE realm_keys SET wrapped_dek = $5, kek_ref = $6
          WHERE realm_id = $1 AND kid = $2 AND kek_ref = $3 AND wrapped_dek = $4`,
        [realmId, kid, change.fromKekRef, change.fromWrappedDek, change.wrappedDek, change.kekRef]
      );
      return rowCount === 1;
    },
  };
}
