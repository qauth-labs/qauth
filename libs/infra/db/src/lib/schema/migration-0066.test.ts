/**
 * Migration 0066 adds the recovery codes' lookup digest (#655; ADR-017
 * Decision 8): `user_recovery_codes.lookup_digest`, which finds an account
 * whose primary identity is a passkey, with no address, by one of its codes
 * alone. One nullable column with no default, its partial index and its CHECK,
 * so every existing row reads NULL and an earlier release, which never names
 * the column, keeps working during a rolling upgrade.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { userRecoveryCodes } from './user-recovery-codes';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0066_user_recovery_code_lookup';
const MIGRATION_IDX = 66;

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

describe('migration 0066 (recovery-code lookup digest)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0065', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0065_token_sign_in_methods');
  });

  it('adds one nullable column with no default, its partial index and its CHECK, and nothing else', () => {
    expect(statements).toEqual([
      'ALTER TABLE "user_recovery_codes" ADD COLUMN "lookup_digest" text;',
      'CREATE INDEX "idx_user_recovery_codes_lookup" ON "user_recovery_codes" USING btree ("realm_id","lookup_digest") WHERE "user_recovery_codes"."lookup_digest" IS NOT NULL AND "user_recovery_codes"."used_at" IS NULL;',
      'ALTER TABLE "user_recovery_codes" ADD CONSTRAINT "user_recovery_codes_lookup_digest_not_empty" CHECK ("user_recovery_codes"."lookup_digest" IS NULL OR length("user_recovery_codes"."lookup_digest") > 0);',
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|RENAME|DEFAULT)\b/);
  });

  it('matches the schema: a nullable text column', () => {
    const column = getTableConfig(userRecoveryCodes).columns.find(
      (candidate) => candidate.name === 'lookup_digest'
    );
    expect(column?.notNull).toBe(false);
    expect(column?.getSQLType()).toBe('text');
  });
});
