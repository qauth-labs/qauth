import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { type MigrationEntry, QAUTH_MIGRATIONS_FOLDER, readMigrationJournal } from './journal';
import { describeDatabaseError } from './runner';
import {
  describePending,
  type MigrationQueryable,
  MigrationsPendingError,
  readMigrationStatus,
  waitForMigrations,
} from './status';

/**
 * The migration list and the pending-migration rule (issue #474). The
 * container suites in `apps/migration-runner` and `apps/auth-server` run the
 * same code against a real database.
 */

const ENTRIES: readonly MigrationEntry[] = [
  { tag: '0000_first', when: 1000 },
  { tag: '0001_second', when: 2000 },
  { tag: '0002_third', when: 3000 },
];

/** A database that answers the status queries from fixed values. */
function fakeDatabase(state: {
  present: boolean;
  lastApplied?: string | null;
  unknownApplied?: number;
}): MigrationQueryable & { queries: { text: string; values?: unknown[] }[] } {
  const queries: { text: string; values?: unknown[] }[] = [];
  return {
    queries,
    async query(text: string, values?: unknown[]) {
      queries.push({ text, values });
      if (text.includes('to_regclass')) return { rows: [{ present: state.present }] };
      return {
        rows: [
          { last_applied: state.lastApplied ?? null, unknown_applied: state.unknownApplied ?? 0 },
        ],
      };
    },
  };
}

describe('readMigrationJournal', () => {
  let folder: string | undefined;

  afterEach(() => {
    if (folder) rmSync(folder, { recursive: true, force: true });
    folder = undefined;
  });

  function journalFolder(journal: string): string {
    folder = mkdtempSync(path.join(tmpdir(), 'qauth-journal-'));
    mkdirSync(path.join(folder, 'meta'));
    writeFileSync(path.join(folder, 'meta', '_journal.json'), journal);
    return folder;
  }

  it("reads this source tree's journal, oldest first", () => {
    const entries = readMigrationJournal(QAUTH_MIGRATIONS_FOLDER);
    expect(entries.length).toBeGreaterThan(30);
    expect(entries[0]?.tag).toMatch(/^0000_/);
    const times = entries.map((entry) => entry.when);
    expect([...times].sort((a, b) => a - b)).toEqual(times);
  });

  it('keeps each entry to its tag and time', () => {
    const dir = journalFolder(
      JSON.stringify({
        version: '7',
        entries: [{ idx: 0, version: '7', when: 42, tag: '0000_x', breakpoints: true }],
      })
    );
    expect(readMigrationJournal(dir)).toEqual([{ tag: '0000_x', when: 42 }]);
  });

  it('refuses a folder with no journal, naming the file', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'qauth-journal-'));
    folder = dir;
    expect(() => readMigrationJournal(dir)).toThrow(/meta\/_journal\.json/);
  });

  it('refuses a journal with no entries list or an entry with no tag', () => {
    expect(() => readMigrationJournal(journalFolder('{"version":"7"}'))).toThrow(/no entries/);
    rmSync(folder as string, { recursive: true, force: true });
    expect(() => readMigrationJournal(journalFolder('{"entries":[{"idx":0,"when":1}]}'))).toThrow(
      /Entry 0/
    );
  });
});

describe('readMigrationStatus', () => {
  it('counts every migration pending when the database has no migrations table', async () => {
    const db = fakeDatabase({ present: false });
    await expect(readMigrationStatus(db, ENTRIES)).resolves.toEqual({
      pending: ENTRIES,
      unknownApplied: 0,
    });
    // Only the presence check ran: nothing was created or locked.
    expect(db.queries).toHaveLength(1);
  });

  it('counts the migrations newer than the newest applied, as drizzle does', async () => {
    const status = await readMigrationStatus(
      fakeDatabase({ present: true, lastApplied: '2000' }),
      ENTRIES
    );
    expect(status.pending.map((entry) => entry.tag)).toEqual(['0002_third']);
  });

  it('counts every migration pending on an empty table or a NULL newest row', async () => {
    const status = await readMigrationStatus(
      fakeDatabase({ present: true, lastApplied: null }),
      ENTRIES
    );
    expect(status.pending).toEqual(ENTRIES);
  });

  it('finds nothing pending on a database ahead of the list, and counts what it does not know', async () => {
    const db = fakeDatabase({ present: true, lastApplied: '5000', unknownApplied: 2 });
    await expect(readMigrationStatus(db, ENTRIES)).resolves.toEqual({
      pending: [],
      unknownApplied: 2,
    });
    // "Ahead" means newer than the list's newest migration.
    expect(db.queries[1]?.values).toEqual([3000]);
  });

  it('only reads', async () => {
    const db = fakeDatabase({ present: true, lastApplied: '1000' });
    await readMigrationStatus(db, ENTRIES);
    for (const { text } of db.queries) {
      expect(text.trimStart()).toMatch(/^SELECT/);
    }
  });
});

describe('waitForMigrations', () => {
  /** A database that catches up after `behindFor` looks. */
  function catchingUp(behindFor: number): MigrationQueryable & { looks: () => number } {
    let looks = 0;
    return {
      looks: () => looks,
      async query(text: string) {
        if (text.includes('to_regclass')) {
          looks += 1;
          return { rows: [{ present: true }] };
        }
        return {
          rows: [{ last_applied: looks > behindFor ? '3000' : '1000', unknown_applied: 0 }],
        };
      },
    };
  }

  function manualClock() {
    let time = 0;
    return {
      now: () => time,
      sleep: async (ms: number) => {
        time += ms;
      },
    };
  }

  it('returns at once on a current database, without reporting it behind', async () => {
    const behind: unknown[] = [];
    const db = catchingUp(0);
    await expect(
      waitForMigrations(db, ENTRIES, { waitMs: 60_000, onBehind: (s) => behind.push(s) })
    ).resolves.toEqual({ pending: [], unknownApplied: 0 });
    expect(behind).toEqual([]);
    expect(db.looks()).toBe(1);
  });

  it('waits while the database is behind, reporting it once, and returns when it catches up', async () => {
    const clock = manualClock();
    const behind: string[][] = [];
    const db = catchingUp(3);
    const status = await waitForMigrations(db, ENTRIES, {
      waitMs: 60_000,
      pollMs: 1000,
      onBehind: (s) => behind.push(s.pending.map((entry) => entry.tag)),
      ...clock,
    });
    expect(status.pending).toEqual([]);
    expect(behind).toEqual([['0001_second', '0002_third']]);
    expect(db.looks()).toBe(4);
    expect(clock.now()).toBe(3000);
  });

  it('gives up at the limit, naming every pending migration', async () => {
    const clock = manualClock();
    const db = catchingUp(Number.POSITIVE_INFINITY);
    const error = await waitForMigrations(db, ENTRIES, {
      waitMs: 2500,
      pollMs: 1000,
      ...clock,
    }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(MigrationsPendingError);
    expect((error as MigrationsPendingError).pending.map((entry) => entry.tag)).toEqual([
      '0001_second',
      '0002_third',
    ]);
    expect((error as Error).message).toBe(
      'The database lacks 2 migrations this release needs: 0001_second, 0002_third. ' +
        'Waited 2.5 s for the migration runner. Run it against this database, then start the server again.'
    );
    // The last wait is cut to the limit, then the database is read once more.
    expect(clock.now()).toBe(2500);
    expect(db.looks()).toBe(4);
  });

  it('checks once with no wait', async () => {
    const db = catchingUp(Number.POSITIVE_INFINITY);
    await expect(waitForMigrations(db, ENTRIES, { waitMs: 0 })).rejects.toThrow(
      /lacks 2 migrations/
    );
    expect(db.looks()).toBe(1);
  });

  it('rejects at once when the database cannot be read', async () => {
    const clock = manualClock();
    const db: MigrationQueryable = {
      query: async () => {
        throw new Error('connect ECONNREFUSED 127.0.0.1:5432');
      },
    };
    await expect(waitForMigrations(db, ENTRIES, { waitMs: 60_000, ...clock })).rejects.toThrow(
      /ECONNREFUSED/
    );
    expect(clock.now()).toBe(0);
  });
});

describe('describePending', () => {
  it('names up to ten migrations and counts the rest', () => {
    const many = Array.from({ length: 13 }, (_, i) => ({ tag: `00${10 + i}_m`, when: i }));
    expect(describePending(many)).toBe(
      '0010_m, 0011_m, 0012_m, 0013_m, 0014_m, 0015_m, 0016_m, 0017_m, 0018_m, 0019_m and 3 more'
    );
    expect(describePending(many.slice(0, 1))).toBe('0010_m');
  });
});

describe('describeDatabaseError', () => {
  it('reads the innermost cause, with its code', () => {
    const driver = Object.assign(new Error('relation "realms" already exists'), { code: '42P07' });
    const wrapped = new Error('Failed query: CREATE TABLE "realms" (...)', { cause: driver });
    expect(describeDatabaseError(wrapped)).toBe('relation "realms" already exists (42P07)');
  });

  it('reads the first error of a refused connection to every address', () => {
    const refused = new AggregateError(
      [Object.assign(new Error('connect ECONNREFUSED ::1:5432'), { code: 'ECONNREFUSED' })],
      ''
    );
    expect(describeDatabaseError(refused)).toBe('connect ECONNREFUSED ::1:5432');
  });
});
