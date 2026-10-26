/**
 * Migration 0039 adds the Shared Signals Framework transmitter's tables
 * (#410) and must be expand-only: two new tables and their foreign keys, a
 * column with a default on `realms`, and an index. A release can then apply it
 * while the previous release still runs: that release never names the new
 * column, and the default fills it for every row it inserts.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0039_ssf_transmitter';

interface JournalEntry {
  idx: number;
  tag: string;
}

const journal: { entries: JournalEntry[] } = JSON.parse(
  readFileSync(path.join(DRIZZLE_DIR, 'meta/_journal.json'), 'utf8')
);

/** A migration's statements, split where drizzle-kit splits them, without comments. */
function statementsOf(tag: string): string[] {
  return readFileSync(path.join(DRIZZLE_DIR, `${tag}.sql`), 'utf8')
    .split('--> statement-breakpoint')
    .map((chunk) =>
      chunk
        .split('\n')
        .filter((line) => !line.trim().startsWith('--'))
        .join('\n')
        .trim()
    )
    .filter((statement) => statement !== '');
}

const CREATE_TABLE = /^CREATE TABLE "([a-z0-9_]+)" \(/;
const CREATE_INDEX = /^CREATE (?:UNIQUE )?INDEX "[a-z0-9_]+" ON "([a-z0-9_]+)" USING btree \(/;
const ADD_FOREIGN_KEY = /^ALTER TABLE "([a-z0-9_]+)" ADD CONSTRAINT "[a-z0-9_]+" FOREIGN KEY /;
const ADD_COLUMN_WITH_DEFAULT =
  /^ALTER TABLE "([a-z0-9_]+)" ADD COLUMN "[a-z0-9_]+" [a-z]+ DEFAULT [a-z0-9']+ NOT NULL;$/;

describe('migration 0039 (SSF transmitter)', () => {
  const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal', () => {
    expect(entry?.idx).toBe(39);
  });

  it('holds only new tables, their foreign keys, a column with a default and an index', () => {
    expect(statements.length).toBeGreaterThan(0);
    for (const statement of statements) {
      expect(
        CREATE_TABLE.test(statement) ||
          CREATE_INDEX.test(statement) ||
          ADD_FOREIGN_KEY.test(statement) ||
          ADD_COLUMN_WITH_DEFAULT.test(statement),
        statement
      ).toBe(true);
      expect(statement.replace(/;$/, ''), statement).not.toContain(';');
    }
  });

  it('creates the two stream tables and adds the realm switch, off', () => {
    const created = statements.flatMap((statement) => CREATE_TABLE.exec(statement)?.[1] ?? []);
    expect(created.sort()).toEqual(['ssf_stream_subjects', 'ssf_streams']);
    expect(statements).toContain(
      'ALTER TABLE "realms" ADD COLUMN "ssf_transmitter_enabled" boolean DEFAULT false NOT NULL;'
    );
    for (const statement of statements) {
      const table = ADD_FOREIGN_KEY.exec(statement)?.[1];
      if (table !== undefined) expect(created, statement).toContain(table);
    }
    const indexed = statements.flatMap((statement) => CREATE_INDEX.exec(statement)?.[1] ?? []);
    expect(indexed).toEqual(['event_deliveries']);
  });
});
