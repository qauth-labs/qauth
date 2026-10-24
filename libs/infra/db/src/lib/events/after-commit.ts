import type { PgTransactionConfig } from 'drizzle-orm/pg-core';

import type { Database, DbTransaction } from '../../types';

/**
 * Work that waits for a transaction to commit (issue #541). The event store
 * hands an event to its telemetry sink only then, so an event whose
 * transaction rolls back is never exported.
 *
 * drizzle has no commit hook, so {@link trackCommits} wraps a database's
 * `transaction`. The callbacks registered on a transaction run after its
 * COMMIT has returned, in the order they were registered, and are dropped
 * when it rolls back, a failed COMMIT included. A nested transaction is a
 * savepoint: its callbacks join its parent's when the savepoint is released
 * and are dropped when it is rolled back, so they still wait for the
 * outermost COMMIT.
 */

/** The callbacks of one transaction or savepoint, while it is open. */
interface CommitScope {
  readonly callbacks: Array<() => void>;
  open: boolean;
}

type TransactionWork<T> = (tx: DbTransaction) => Promise<T>;

const scopes = new WeakMap<DbTransaction, CommitScope>();
const tracked = new WeakSet<Database>();

/** Give `tx` its scope, and make its savepoints report to it. */
function enter<T>(tx: DbTransaction, scope: CommitScope, work: TransactionWork<T>): Promise<T> {
  scopes.set(tx, scope);
  const savepoint = tx.transaction.bind(tx);
  tx.transaction = (async <U>(nested: TransactionWork<U>) => {
    const inner: CommitScope = { callbacks: [], open: true };
    try {
      const result = await savepoint((innerTx) => enter(innerTx, inner, nested));
      // Released: the savepoint's changes are now the parent's, and so is the work.
      if (scope.open) scope.callbacks.push(...inner.callbacks);
      return result;
    } finally {
      inner.open = false;
    }
  }) as DbTransaction['transaction'];
  return work(tx);
}

/**
 * Make the transactions opened on `db` run their {@link afterCommit}
 * callbacks once they commit. Once per database; a second call does nothing.
 *
 * A callback must not throw: the transaction has committed, so its caller
 * must not see a failure. One that throws anyway is ignored, and the
 * callbacks after it still run.
 */
export function trackCommits(db: Database): void {
  if (tracked.has(db)) return;
  tracked.add(db);
  const begin = db.transaction.bind(db);
  db.transaction = (async <T>(work: TransactionWork<T>, config?: PgTransactionConfig) => {
    const scope: CommitScope = { callbacks: [], open: true };
    let result: T;
    try {
      result = await begin((tx) => enter(tx, scope, work), config);
    } finally {
      scope.open = false;
    }
    for (const callback of scope.callbacks) {
      try {
        callback();
      } catch {
        // The commit stands; see above.
      }
    }
    return result;
  }) as Database['transaction'];
}

/**
 * Run `callback` once the transaction `tx` belongs to has committed, or never
 * if it rolls back.
 *
 * @returns `false` when the callback will never run: `tx` was not opened on a
 *   database {@link trackCommits} tracks, or has already ended
 */
export function afterCommit(tx: DbTransaction, callback: () => void): boolean {
  const scope = scopes.get(tx);
  if (scope === undefined || !scope.open) return false;
  scope.callbacks.push(callback);
  return true;
}
