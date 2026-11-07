/**
 * Migration 0068 marks each account's primary identity (ADR-015 Decision 8
 * and question 13, #846): `user_credentials.is_primary`, at most one per user,
 * backfilled from the user's oldest credential that is no authenticator app,
 * marked by the database from then on on the credential written with the
 * account, and never moved. The column has a constant default, so Postgres
 * adds it without rewriting the table and a release before this one keeps
 * inserting credentials during a rolling upgrade; the insert trigger marks the
 * one it writes with a new account.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0068_primary_credential';
const MIGRATION_IDX = 68;

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

describe('migration 0068 (primary credential)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0067', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0067_session_recovery_code');
  });

  it('adds the column with a constant default and one primary per user', () => {
    expect(statements.slice(0, 2)).toEqual([
      'ALTER TABLE "user_credentials" ADD COLUMN "is_primary" boolean DEFAULT false NOT NULL;',
      'CREATE UNIQUE INDEX "idx_user_credentials_primary_unique" ON "user_credentials" USING btree ("user_id") WHERE "user_credentials"."is_primary";',
    ]);
  });

  it('backfills before the triggers that refuse a moved mark exist', () => {
    const backfill = statements.findIndex((statement) =>
      statement.startsWith('UPDATE "user_credentials" AS c SET "is_primary" = true')
    );
    const trigger = statements.findIndex((statement) =>
      statement.startsWith('CREATE TRIGGER "user_credentials_primary_update"')
    );
    expect(backfill).toBeGreaterThan(1);
    expect(trigger).toBeGreaterThan(backfill);
    expect(statements[backfill]).toContain(`WHERE "provider_type" <> 'totp'`);
    expect(statements[backfill]).toContain('ORDER BY "user_id", "created_at", "id"');
  });

  it('pins the search path of its function', () => {
    const fn = statements.find((statement) => statement.startsWith('CREATE FUNCTION'));
    expect(fn).toContain('SET search_path = pg_catalog, pg_temp');
    expect(fn).toContain('public."user_credentials"');
    expect(fn).toContain('public."users"');
  });

  it('rewrites no credential data', () => {
    expect(statements.some((statement) => statement.includes('"credential_data" ='))).toBe(false);
  });
});
