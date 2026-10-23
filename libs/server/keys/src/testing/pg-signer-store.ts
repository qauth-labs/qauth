import type { Pool } from 'pg';

import type {
  PublicKeyRecord,
  SignerKeyRecord,
  SignerKeyStore,
  UpstreamClientRecord,
  WrappedSignerKey,
} from '../lib/signer-key-store';

/**
 * A {@link SignerKeyStore} over a node-postgres pool, for this library's
 * integration tests. Never exported from the package entry point.
 *
 * It reads the migrated `realms`, `realm_keys` and `realm_public_keys` tables
 * with plain SQL, as the repositories the signer's wiring passes in production
 * do (#461, #464), and records every statement it runs in {@link queries}.
 * No table holds upstream provider configuration yet, so those come from
 * {@link PgSignerStore.upstreamClients}.
 */
export interface PgSignerStore extends SignerKeyStore {
  /** Every statement run, in order. */
  readonly queries: string[];
  /** Upstream provider configurations, by `realmId/providerId`. */
  readonly upstreamClients: Map<string, UpstreamClientRecord>;
}

/** node-postgres returns `bigint` columns as strings. */
function epochMs(value: string | null): number | null {
  return value === null ? null : Number(value);
}

export function createPgSignerStore(pool: Pool): PgSignerStore {
  const queries: string[] = [];
  const upstreamClients = new Map<string, UpstreamClientRecord>();

  async function query<R extends object>(text: string, values: unknown[]): Promise<R[]> {
    queries.push(text);
    return (await pool.query<R>(text, values)).rows;
  }

  return {
    queries,
    upstreamClients,

    async findUpstreamClient(realmId, providerId) {
      return upstreamClients.get(`${realmId}/${providerId}`);
    },

    async findRealmIssuer(realmId) {
      const [realm] = await query<{ issuer: string | null }>(
        'SELECT issuer FROM realms WHERE id = $1',
        [realmId]
      );
      return realm === undefined ? undefined : realm.issuer;
    },

    async listKeys(realmId, filter): Promise<readonly SignerKeyRecord[]> {
      const rows = await query<{
        kid: string;
        algorithm: string;
        status: SignerKeyRecord['status'];
        pair_id: string | null;
        retire_at: string | null;
        created_at: string;
      }>(
        `SELECT kid, algorithm, status, pair_id, retire_at, created_at FROM realm_keys
         WHERE realm_id = $1 AND purpose = $2 AND scope_id IS NOT DISTINCT FROM $3
         ORDER BY created_at, id`,
        [realmId, filter.purpose, filter.scopeId]
      );
      return rows.map((row) => ({
        kid: row.kid,
        algorithm: row.algorithm,
        status: row.status,
        pairId: row.pair_id,
        retireAt: epochMs(row.retire_at),
        createdAt: Number(row.created_at),
      }));
    },

    async getWrappedKey(realmId, kid): Promise<WrappedSignerKey | undefined> {
      const [row] = await query<{
        realm_id: string;
        purpose: string;
        scope_id: string | null;
        kid: string;
        algorithm: string;
        status: WrappedSignerKey['status'];
        ciphertext: Buffer;
        iv: Buffer;
        wrapped_dek: Buffer;
        kek_ref: string;
        aad_version: number;
      }>(
        `SELECT realm_id, purpose, scope_id, kid, algorithm, status, ciphertext, iv, wrapped_dek,
           kek_ref, aad_version
         FROM realm_keys WHERE realm_id = $1 AND kid = $2`,
        [realmId, kid]
      );
      return row === undefined
        ? undefined
        : {
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

    async listPublicKeys(realmId): Promise<readonly PublicKeyRecord[]> {
      const rows = await query<{
        kid: string;
        purpose: string;
        algorithm: string;
        status: PublicKeyRecord['status'];
        public_jwk: Record<string, unknown>;
        publish_at: string;
        unpublish_at: string | null;
      }>(
        `SELECT kid, purpose, algorithm, status, public_jwk, publish_at, unpublish_at
         FROM realm_public_keys WHERE realm_id = $1 ORDER BY purpose, publish_at, kid`,
        [realmId]
      );
      return rows.map((row) => ({
        kid: row.kid,
        purpose: row.purpose,
        algorithm: row.algorithm,
        status: row.status,
        publicJwk: row.public_jwk,
        publishAt: Number(row.publish_at),
        unpublishAt: epochMs(row.unpublish_at),
      }));
    },
  };
}
