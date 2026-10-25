/**
 * Migration 0039 links each refresh-token family to the authorization code
 * whose redemption started it (ADR-017 Decision 10, #627): one nullable column
 * on `refresh_tokens`, its foreign key (`ON DELETE SET NULL`) and a unique
 * partial index. Nothing else: no row is rewritten (the column starts NULL)
 * and no other table is touched.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0039_refresh_token_code_link';

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

describe('migration 0039 (refresh family ↔ authorization code link)', () => {
  const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);

  it('is in the journal', () => {
    expect(entry?.idx).toBe(39);
  });

  it('holds exactly the column, its foreign key and the unique partial index', () => {
    expect(statementsOf(MIGRATION_TAG).map((statement) => statement.replace(/\s+/g, ' '))).toEqual([
      'ALTER TABLE "refresh_tokens" ADD COLUMN "authorization_code_id" uuid;',
      'ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_authorization_code_id_authorization_codes_id_fk" FOREIGN KEY ("authorization_code_id") REFERENCES "public"."authorization_codes"("id") ON DELETE set null ON UPDATE no action;',
      'CREATE UNIQUE INDEX "idx_refresh_tokens_authorization_code_id" ON "refresh_tokens" USING btree ("authorization_code_id") WHERE "refresh_tokens"."authorization_code_id" IS NOT NULL;',
    ]);
  });
});
