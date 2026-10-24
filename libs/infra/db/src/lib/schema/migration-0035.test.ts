/**
 * Migration 0035 adds the delivery role's queue (#460) and must be
 * expand-only: two new tables, a foreign key from one of them, and indexes on
 * them, nothing else. A release can then apply it while the previous release
 * still runs, and no existing table is locked or rewritten.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0035_event_deliveries';

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

describe('migration 0035 (event deliveries)', () => {
  const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal', () => {
    expect(entry?.idx).toBe(35);
  });

  it('holds only CREATE TABLE, CREATE INDEX and a foreign key of a new table', () => {
    expect(statements.length).toBeGreaterThan(0);
    for (const statement of statements) {
      expect(
        CREATE_TABLE.test(statement) ||
          CREATE_INDEX.test(statement) ||
          ADD_FOREIGN_KEY.test(statement),
        statement
      ).toBe(true);
      expect(statement.replace(/;$/, ''), statement).not.toContain(';');
    }
  });

  it('creates two new tables, and touches no other', () => {
    const created = statements.flatMap((statement) => CREATE_TABLE.exec(statement)?.[1] ?? []);
    expect(created).toEqual(['event_deliveries', 'event_delivery_positions']);

    const earlier = journal.entries
      .filter((candidate) => candidate.idx < 35)
      .flatMap((candidate) =>
        statementsOf(candidate.tag).flatMap((statement) => CREATE_TABLE.exec(statement)?.[1] ?? [])
      );
    for (const table of created) expect(earlier).not.toContain(table);

    for (const statement of statements) {
      const table = (CREATE_INDEX.exec(statement) ?? ADD_FOREIGN_KEY.exec(statement))?.[1];
      if (table !== undefined) expect(created, statement).toContain(table);
    }
  });
});
