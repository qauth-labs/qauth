/**
 * Migration 0039 records the browser session behind each authorization code
 * (ADR-019 Decisions 3 and 4, #549): one nullable column on
 * `authorization_codes`, its foreign key to `sessions` with ON DELETE SET
 * NULL, and the index that delete reads. Nothing else: no row is rewritten and
 * no other table is touched.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0039_authorization_code_session';

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

describe('migration 0039 (authorization code session)', () => {
  const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);

  it('is in the journal', () => {
    expect(entry?.idx).toBe(39);
  });

  it('holds exactly the nullable column, its set-null foreign key and its index', () => {
    expect(statementsOf(MIGRATION_TAG).map((statement) => statement.replace(/\s+/g, ' '))).toEqual([
      'ALTER TABLE "authorization_codes" ADD COLUMN "session_id" uuid;',
      'ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE set null ON UPDATE no action;',
      'CREATE INDEX "idx_authorization_codes_session_id" ON "authorization_codes" USING btree ("session_id");',
    ]);
  });
});
