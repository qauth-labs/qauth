/**
 * Migration 0029 creates the event store (#457) and must be expand-only: a
 * new table and new indexes on it, nothing else. A release can then apply it
 * while the previous release still runs, and no existing table is locked or
 * rewritten.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0029_event_store';

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

describe('migration 0029 (event store)', () => {
  const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal', () => {
    expect(entry?.idx).toBe(29);
  });

  it('holds only CREATE TABLE and CREATE INDEX statements, one per breakpoint', () => {
    expect(statements.length).toBeGreaterThan(0);
    for (const statement of statements) {
      expect(CREATE_TABLE.test(statement) || CREATE_INDEX.test(statement), statement).toBe(true);
      // A second statement hidden behind the first would end in its own `;`.
      expect(statement.replace(/;$/, ''), statement).not.toContain(';');
    }
  });

  it('creates tables no earlier migration created, and indexes only those', () => {
    const created = statements.flatMap((statement) => CREATE_TABLE.exec(statement)?.[1] ?? []);
    expect(created).toEqual(['events']);

    const earlier = journal.entries
      .filter((candidate) => candidate.idx < 29)
      .flatMap((candidate) =>
        statementsOf(candidate.tag).flatMap((statement) => CREATE_TABLE.exec(statement)?.[1] ?? [])
      );
    expect(earlier).not.toEqual(expect.arrayContaining(['events']));

    const indexed = statements.flatMap((statement) => CREATE_INDEX.exec(statement)?.[1] ?? []);
    expect(indexed.length).toBeGreaterThan(0);
    for (const table of indexed) expect(created).toContain(table);
  });
});
