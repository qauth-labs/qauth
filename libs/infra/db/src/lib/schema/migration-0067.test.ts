/**
 * Migration 0067 records on a browser session whether its sign-in took a
 * recovery code in place of a lost factor (ADR-017 Decision 8, #663):
 * `sessions.recovery_code_used`. A code adds no `amr` value, so the account
 * API's fresh-authentication guard reads the column through the access
 * token's `sid`. One column with a constant default: Postgres adds it without
 * rewriting the table, every existing session reads `false` (none of them
 * says it took a code), and an earlier release, which never names the column,
 * keeps inserting sessions during a rolling upgrade.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0067_session_recovery_code';
const MIGRATION_IDX = 67;

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
    .filter((statement) => statement !== '')
    .map((statement) => statement.replace(/\s+/g, ' '));
}

describe('migration 0067 (session recovery code)', () => {
  it('is in the journal, after 0066', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0066_user_recovery_code_lookup');
  });

  it('adds one column with a constant default, and nothing else', () => {
    expect(statementsOf(MIGRATION_TAG)).toEqual([
      'ALTER TABLE "sessions" ADD COLUMN "recovery_code_used" boolean DEFAULT false NOT NULL;',
    ]);
  });
});
