import type {
  NewStoredKey,
  NewStoredKeyRow,
  StoredKeyFilter,
  StoredKeyStatus,
  StoredKeySummary,
} from '../lib/key-store';
import type { RealmKeyBootStore, StoredPublicKey } from '../lib/realm-key-boot';
import type { WrappedSignerKey } from '../lib/signer-key-store';

/**
 * An in-memory {@link RealmKeyBootStore} for this library's unit tests. Never
 * exported from the package entry point.
 *
 * A transaction keeps everything or nothing: when its work throws, the rows
 * return to what they were when it began, as a database transaction or a
 * savepoint would. Like `realm_keys`, it refuses a second key with the same
 * `kid` in a realm and a second active key for one realm, purpose, scope and
 * algorithm.
 */

/** The transaction handle: which transaction a call ran in. */
export interface MemoryTx {
  readonly id: number;
}

/** A stored key: the row as written, and the lifecycle columns a rotation step sets. */
export interface MemoryStoredKey extends Omit<NewStoredKeyRow, 'status'> {
  readonly status: StoredKeyStatus;
  readonly retireAt?: number | null;
  readonly unpublishAt?: number | null;
}

/** A stored row, with its public JWK when one was written. */
export interface MemoryKeyRow {
  readonly key: MemoryStoredKey;
  readonly publicJwk?: Record<string, unknown>;
}

export interface MemoryKeyStore extends RealmKeyBootStore<MemoryTx> {
  /** The committed rows, oldest first. */
  readonly rows: MemoryKeyRow[];
  /** Every call, in order, with the transaction it ran in. */
  readonly calls: { readonly method: string; readonly tx?: MemoryTx }[];
  /** The `outer` argument of each `transaction` call. */
  readonly outerTransactions: (MemoryTx | undefined)[];
}

/** Options of {@link createMemoryKeyStore}. */
export interface MemoryKeyStoreOptions {
  /** Called before each `create`; throw from it to make that insert fail. */
  readonly beforeCreate?: (input: NewStoredKey, index: number) => void;
  /** Answer every `findByKid` with a hit, as if the realm already held the `kid`. */
  readonly everyKidTaken?: boolean;
}

export function createMemoryKeyStore(options: MemoryKeyStoreOptions = {}): MemoryKeyStore {
  const rows: MemoryKeyRow[] = [];
  const calls: { method: string; tx?: MemoryTx }[] = [];
  const outerTransactions: (MemoryTx | undefined)[] = [];
  let nextTx = 1;
  let creates = 0;

  return {
    rows,
    calls,
    outerTransactions,

    async transaction<T>(work: (tx: MemoryTx) => Promise<T>, outer?: MemoryTx): Promise<T> {
      calls.push({ method: 'transaction', tx: outer });
      outerTransactions.push(outer);
      const snapshot = [...rows];
      try {
        return await work({ id: nextTx++ });
      } catch (error) {
        rows.splice(0, rows.length, ...snapshot);
        throw error;
      }
    },

    async findByKid(realmId: string, kid: string, tx: MemoryTx): Promise<object | undefined> {
      calls.push({ method: 'findByKid', tx });
      if (options.everyKidTaken) return { realmId, kid };
      return rows.find((row) => row.key.realmId === realmId && row.key.kid === kid)?.key;
    },

    async listByRealm(
      realmId: string,
      filter: StoredKeyFilter,
      tx: MemoryTx
    ): Promise<readonly StoredKeySummary[]> {
      calls.push({ method: 'listByRealm', tx });
      return rows
        .map((row) => row.key)
        .filter(
          (key) =>
            key.realmId === realmId &&
            (filter.purpose === undefined || key.purpose === filter.purpose) &&
            (filter.scopeId === undefined || key.scopeId === filter.scopeId) &&
            (filter.status === undefined || key.status === filter.status)
        );
    },

    async getWrappedKey(
      realmId: string,
      kid: string,
      tx: MemoryTx
    ): Promise<WrappedSignerKey | undefined> {
      calls.push({ method: 'getWrappedKey', tx });
      const key = rows.find((row) => row.key.realmId === realmId && row.key.kid === kid)?.key;
      if (key === undefined) return undefined;
      return {
        realmId: key.realmId,
        purpose: key.purpose,
        scopeId: key.scopeId,
        kid: key.kid,
        algorithm: key.algorithm,
        status: key.status,
        ciphertext: key.ciphertext,
        iv: key.iv,
        wrappedDek: key.wrappedDek,
        kekRef: key.kekRef,
        aadVersion: key.aadVersion,
      };
    },

    async lockRealm(_realmId: string, tx: MemoryTx): Promise<void> {
      calls.push({ method: 'lockRealm', tx });
    },

    async listPublicKeys(realmId: string, tx: MemoryTx): Promise<readonly StoredPublicKey[]> {
      calls.push({ method: 'listPublicKeys', tx });
      return rows.flatMap(({ key, publicJwk }) =>
        key.realmId === realmId && publicJwk !== undefined
          ? [{ kid: key.kid, purpose: key.purpose, status: key.status, publicJwk }]
          : []
      );
    },

    async anotherRealmPublishes(
      realmId: string,
      identity: Readonly<Record<string, string>>,
      tx: MemoryTx
    ): Promise<boolean> {
      calls.push({ method: 'anotherRealmPublishes', tx });
      return rows.some(
        ({ key, publicJwk }) =>
          key.realmId !== realmId &&
          publicJwk !== undefined &&
          Object.entries(identity).every(
            ([name, value]) => (publicJwk as Record<string, unknown>)[name] === value
          )
      );
    },

    async create(input: NewStoredKey, tx: MemoryTx): Promise<unknown> {
      calls.push({ method: 'create', tx });
      options.beforeCreate?.(input, creates++);
      const { key } = input;
      if (rows.some((row) => row.key.realmId === key.realmId && row.key.kid === key.kid)) {
        throw new Error('realm_keys_realm_id_kid_unique');
      }
      if (
        key.status === 'active' &&
        rows.some(
          (row) =>
            row.key.status === 'active' &&
            row.key.realmId === key.realmId &&
            row.key.purpose === key.purpose &&
            row.key.scopeId === key.scopeId &&
            row.key.algorithm === key.algorithm
        )
      ) {
        throw new Error('idx_realm_keys_one_active');
      }
      rows.push(input.publicJwk === undefined ? { key } : { key, publicJwk: input.publicJwk });
      return key;
    },

    async updateStatus(realmId, kid, change, tx: MemoryTx): Promise<object | undefined> {
      calls.push({ method: 'updateStatus', tx });
      const from = change.status === 'active' ? 'next' : 'active';
      const index = rows.findIndex(
        (row) => row.key.realmId === realmId && row.key.kid === kid && row.key.status === from
      );
      if (index === -1) return undefined;
      const { key } = rows[index];
      if (
        change.status === 'active' &&
        rows.some(
          (row) =>
            row.key.status === 'active' &&
            row.key.realmId === key.realmId &&
            row.key.purpose === key.purpose &&
            row.key.scopeId === key.scopeId &&
            row.key.algorithm === key.algorithm
        )
      ) {
        throw new Error('idx_realm_keys_one_active');
      }
      const updated: MemoryStoredKey =
        change.status === 'active'
          ? { ...key, status: 'active', activateAt: change.activateAt }
          : {
              ...key,
              status: 'retired',
              retireAt: change.retireAt,
              unpublishAt: change.unpublishAt,
            };
      rows[index] = { ...rows[index], key: updated };
      return updated;
    },

    async deleteByScope(realmId, purpose, scopeId, tx: MemoryTx): Promise<readonly string[]> {
      calls.push({ method: 'deleteByScope', tx });
      const deleted: string[] = [];
      for (let index = rows.length - 1; index >= 0; index--) {
        const { key } = rows[index];
        if (key.realmId === realmId && key.purpose === purpose && key.scopeId === scopeId) {
          deleted.unshift(key.kid);
          rows.splice(index, 1);
        }
      }
      return deleted;
    },
  };
}
