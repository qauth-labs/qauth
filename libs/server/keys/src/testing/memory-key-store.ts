import type {
  NewStoredKey,
  NewStoredKeyRow,
  RealmKeyStore,
  StoredKeyFilter,
  StoredKeySummary,
} from '../lib/key-store';

/**
 * An in-memory {@link RealmKeyStore} for this library's unit tests. Never
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

/** A stored row, with its public JWK when one was written. */
export interface MemoryKeyRow {
  readonly key: NewStoredKeyRow;
  readonly publicJwk?: Record<string, unknown>;
}

export interface MemoryKeyStore extends RealmKeyStore<MemoryTx> {
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
  };
}
