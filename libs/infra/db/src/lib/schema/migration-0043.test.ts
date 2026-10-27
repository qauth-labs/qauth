/**
 * Migration 0043 adds admin roles and grants (ADR-019 Decision 7, #510): two
 * new tables, their triggers, and nothing on a row of another table. It locks
 * `realms` and then `users`, in the order their writers take them, before its
 * foreign keys take them the other way round. Its triggers' behaviour is held
 * by `admin-grants.integration.test.ts` against a real Postgres.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0043_admin_grants';
const MIGRATION_IDX = 43;

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

describe('migration 0043 (admin grants)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0042', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0042_authorization_code_session');
  });

  it('locks realms and then users before anything else', () => {
    expect(statements.slice(0, 2)).toEqual([
      'LOCK TABLE "realms" IN SHARE ROW EXCLUSIVE MODE;',
      'LOCK TABLE "users" IN SHARE ROW EXCLUSIVE MODE;',
    ]);
    expect(statements.filter((statement) => statement.startsWith('LOCK '))).toHaveLength(2);
  });

  it('alters and creates only its own tables', () => {
    for (const statement of statements.slice(2)) {
      expect(statement, statement).toMatch(
        /^(CREATE TABLE "admin_(grants|roles)"|ALTER TABLE "admin_(grants|roles)"|CREATE (UNIQUE )?INDEX "idx_admin_grants_\w+" ON "admin_grants"|CREATE FUNCTION "admin_grants_\w+"|CREATE TRIGGER "admin_grants_\w+")/
      );
    }
  });

  it('writes a grant live and revokes it at or before its last security change', () => {
    const insertLive = statements.find((statement) =>
      statement.startsWith('CREATE FUNCTION "admin_grants_insert_live"')
    );
    expect(insertLive).toContain('IF NEW."revoked_at" IS NOT NULL THEN');
    expect(insertLive).toContain('NEW."last_security_change_at" := NEW."created_at";');
    expect(statements).toContain(
      'CREATE TRIGGER "admin_grants_insert_live" BEFORE INSERT ON "admin_grants" FOR EACH ROW EXECUTE FUNCTION "admin_grants_insert_live"();'
    );
    expect(
      statements.find((statement) =>
        statement.startsWith('CREATE FUNCTION "admin_grants_revoke_only"')
      )
    ).toContain(
      'OR (OLD."revoked_at" IS NULL AND NEW."revoked_at" IS NOT NULL AND NEW."last_security_change_at" < NEW."revoked_at")'
    );
  });
});
