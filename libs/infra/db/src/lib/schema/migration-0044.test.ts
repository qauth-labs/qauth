/**
 * Migration 0044 adds `users.not_valid_before` (#748): one nullable column,
 * the time for every account already disabled, the trigger that sets it when
 * an account is disabled and keeps it from moving back, and the deferred one
 * that moves it to the commit of the disabling transaction. Their behaviour is
 * held by `migration-0044.integration.test.ts` against a real Postgres.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0044_users_not_valid_before';
const MIGRATION_IDX = 44;

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

describe('migration 0044 (users.not_valid_before)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0043', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0043_admin_grants');
  });

  it('adds one nullable column with no default, fills it for disabled accounts, and adds the two triggers', () => {
    expect(statements).toHaveLength(6);
    expect(statements[0]).toBe('ALTER TABLE "users" ADD COLUMN "not_valid_before" bigint;');
    // The one row write: accounts disabled before the column existed.
    expect(statements[1]).toBe(
      'UPDATE "users" SET "not_valid_before" = floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint WHERE NOT "enabled";'
    );
    expect(
      statements.filter((statement) => /^(UPDATE|INSERT|DELETE)\b/.test(statement))
    ).toHaveLength(1);
    expect(statements[2]).toMatch(/^CREATE FUNCTION "users_not_valid_before"\(\) RETURNS trigger /);
    expect(statements[3]).toBe(
      'CREATE TRIGGER "users_not_valid_before" BEFORE UPDATE OF "enabled", "not_valid_before" ON "users" FOR EACH ROW EXECUTE FUNCTION "users_not_valid_before"();'
    );
    expect(statements[4]).toMatch(
      /^CREATE FUNCTION "users_not_valid_before_at_commit"\(\) RETURNS trigger /
    );
    expect(statements[5]).toBe(
      'CREATE CONSTRAINT TRIGGER "users_not_valid_before_at_commit" AFTER UPDATE OF "enabled" ON "users" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (OLD."enabled" AND NOT NEW."enabled") EXECUTE FUNCTION "users_not_valid_before_at_commit"();'
    );
  });

  it('sets the time from the clock of the change on disable, and never lets it move back', () => {
    const fn = statements[2];
    expect(fn).toContain('SET search_path = pg_catalog, pg_temp');
    expect(fn).toContain('IF OLD."enabled" AND NOT NEW."enabled" THEN');
    expect(fn).toContain(
      'NEW."not_valid_before" := GREATEST( NEW."not_valid_before", floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint );'
    );
    expect(fn).toContain(
      'IF OLD."not_valid_before" IS NOT NULL AND (NEW."not_valid_before" IS NULL OR NEW."not_valid_before" < OLD."not_valid_before") THEN'
    );
    expect(fn).toContain("CONSTRAINT = 'users_not_valid_before_forward_only'");
  });

  it('moves the time to the commit with an update that names no "enabled", on a still-disabled row only', () => {
    const fn = statements[4];
    expect(fn).toContain('SET search_path = pg_catalog, pg_temp');
    expect(fn).toContain(
      'UPDATE public."users" SET "not_valid_before" = GREATEST( "not_valid_before", floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint ) WHERE "id" = NEW."id" AND NOT "enabled";'
    );
    expect(fn).toContain('RETURN NULL;');
  });
});
