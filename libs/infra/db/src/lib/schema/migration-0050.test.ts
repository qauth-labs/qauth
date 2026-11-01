/**
 * Migration 0050 adds `user_credentials.disabled_at` (#615): the failure
 * ladder's disabled mark (ADR-017 Decision 7). One nullable column with no
 * default, so a node of the previous release keeps inserting credentials
 * during a rolling upgrade, and every existing credential stays usable.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0050_user_credentials_disabled_at';
const MIGRATION_IDX = 50;

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

describe('migration 0050 (user_credentials.disabled_at)', () => {
  it('is in the journal, after 0049', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0049_realm_secrets');
  });

  it('only adds one nullable column, with no default and no backfill', () => {
    expect(statementsOf(MIGRATION_TAG)).toEqual([
      'ALTER TABLE "user_credentials" ADD COLUMN "disabled_at" bigint;',
    ]);
  });
});
