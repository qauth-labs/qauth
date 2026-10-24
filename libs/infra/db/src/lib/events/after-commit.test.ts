import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { Database, DbTransaction } from '../../types';
import { afterCommit, trackCommits } from './after-commit';

/**
 * The commit hook the event store's telemetry waits on (issue #541), against
 * a `pg` client that records statements instead of running them, so each
 * callback can see which statements had run when it was called. The
 * container suite (`events.integration.test.ts`) runs it against Postgres.
 */

/** A recording database; `failOn` makes the statement starting with it fail. */
function createRecordingDb(failOn?: string): { db: Database; statements: string[] } {
  const statements: string[] = [];
  const client = {
    query: (config: { text?: string } | string) => {
      const text = (typeof config === 'string' ? config : (config.text ?? '')).trim().toLowerCase();
      statements.push(text);
      if (failOn !== undefined && text.startsWith(failOn)) {
        return Promise.reject(new Error(`${failOn} failed`));
      }
      return Promise.resolve({ rows: [], rowCount: 0, fields: [], command: '' });
    },
  };
  return { db: drizzle(client as unknown as Pool) as unknown as Database, statements };
}

/** Thrown inside a transaction to roll it back on purpose. */
class Rollback extends Error {}

describe('afterCommit', () => {
  it('runs the callbacks once COMMIT has returned, in the order they were registered', async () => {
    const { db, statements } = createRecordingDb();
    trackCommits(db);
    const seen: Array<{ name: string; statements: string[] }> = [];

    const result = await db.transaction(async (tx) => {
      expect(afterCommit(tx, () => seen.push({ name: 'first', statements: [...statements] }))).toBe(
        true
      );
      afterCommit(tx, () => seen.push({ name: 'second', statements: [...statements] }));
      expect(seen).toEqual([]);
      return 'done';
    });

    expect(result).toBe('done');
    expect(seen.map((entry) => entry.name)).toEqual(['first', 'second']);
    expect(seen[0].statements).toEqual(['begin', 'commit']);
  });

  it('drops the callbacks of a transaction that rolls back', async () => {
    const { db, statements } = createRecordingDb();
    trackCommits(db);
    let called = false;

    await expect(
      db.transaction(async (tx) => {
        afterCommit(tx, () => {
          called = true;
        });
        throw new Rollback();
      })
    ).rejects.toBeInstanceOf(Rollback);

    expect(statements).toEqual(['begin', 'rollback']);
    expect(called).toBe(false);
  });

  it('drops the callbacks when the COMMIT itself fails', async () => {
    const { db } = createRecordingDb('commit');
    trackCommits(db);
    let called = false;

    await expect(
      db.transaction(async (tx) => {
        afterCommit(tx, () => {
          called = true;
        });
      })
    ).rejects.toThrow('Failed query: commit');
    expect(called).toBe(false);
  });

  it("keeps a released savepoint's callbacks for the outer COMMIT, and drops a rolled-back one's", async () => {
    const { db, statements } = createRecordingDb();
    trackCommits(db);
    const called: Array<{ name: string; committed: boolean }> = [];
    const record = (name: string) => () =>
      called.push({ name, committed: statements.includes('commit') });

    await db.transaction(async (tx) => {
      afterCommit(tx, record('outer'));
      await tx.transaction(async (released) => {
        afterCommit(released, record('released'));
        await released.transaction(async (nested) => {
          afterCommit(nested, record('nested'));
        });
      });
      await expect(
        tx.transaction(async (rolledBack) => {
          afterCommit(rolledBack, record('rolled back'));
          throw new Rollback();
        })
      ).rejects.toBeInstanceOf(Rollback);
      expect(called).toEqual([]);
    });

    expect(called).toEqual([
      { name: 'outer', committed: true },
      { name: 'released', committed: true },
      { name: 'nested', committed: true },
    ]);
    expect(statements).toEqual([
      'begin',
      'savepoint sp1',
      'savepoint sp2',
      'release savepoint sp2',
      'release savepoint sp1',
      'savepoint sp1',
      'rollback to savepoint sp1',
      'commit',
    ]);
  });

  it('drops the callbacks of a released savepoint when the outer transaction rolls back', async () => {
    const { db } = createRecordingDb();
    trackCommits(db);
    let called = false;

    await expect(
      db.transaction(async (tx) => {
        await tx.transaction(async (nested) => {
          afterCommit(nested, () => {
            called = true;
          });
        });
        throw new Rollback();
      })
    ).rejects.toBeInstanceOf(Rollback);
    expect(called).toBe(false);
  });

  it('a callback that throws neither fails the committed transaction nor stops the others', async () => {
    const { db } = createRecordingDb();
    trackCommits(db);
    let second = false;

    await expect(
      db.transaction(async (tx) => {
        afterCommit(tx, () => {
          throw new Error('sink broke');
        });
        afterCommit(tx, () => {
          second = true;
        });
        return 'committed';
      })
    ).resolves.toBe('committed');
    expect(second).toBe(true);
  });

  it('refuses a transaction of an untracked database, and one that has ended', async () => {
    const untracked = createRecordingDb().db;
    let untrackedTx: DbTransaction | undefined;
    await untracked.transaction(async (tx) => {
      untrackedTx = tx;
      expect(afterCommit(tx, () => undefined)).toBe(false);
    });

    const { db } = createRecordingDb();
    trackCommits(db);
    let ended: DbTransaction | undefined;
    await db.transaction(async (tx) => {
      ended = tx;
    });
    expect(untrackedTx).toBeDefined();
    expect(afterCommit(ended as DbTransaction, () => undefined)).toBe(false);
  });

  it('tracks a database once however often it is asked to, so a callback runs once', async () => {
    const { db, statements } = createRecordingDb();
    trackCommits(db);
    trackCommits(db);
    let calls = 0;

    await db.transaction(async (tx) => {
      afterCommit(tx, () => {
        calls += 1;
      });
    });
    expect(calls).toBe(1);
    expect(statements).toEqual(['begin', 'commit']);
  });
});
