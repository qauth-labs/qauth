/**
 * Migration 0045 adds approval requests for security operations (ADR-019
 * Decision 7, #512): one new table, its indexes, and nothing on a row of
 * another table. It locks `realms` and then `users`, in the order their
 * writers take them, before its foreign keys take them. The table's rules are
 * held by `admin-approvals.integration.test.ts` against a real Postgres.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0045_admin_approvals';
const MIGRATION_IDX = 45;

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

describe('migration 0045 (admin approvals)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0044', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0044_users_not_valid_before');
  });

  it('locks realms and then users before anything else', () => {
    expect(statements.slice(0, 2)).toEqual([
      'LOCK TABLE "realms" IN SHARE ROW EXCLUSIVE MODE;',
      'LOCK TABLE "users" IN SHARE ROW EXCLUSIVE MODE;',
    ]);
    expect(statements.filter((statement) => statement.startsWith('LOCK '))).toHaveLength(2);
  });

  it('creates and alters only its own table', () => {
    for (const statement of statements.slice(2)) {
      expect(statement, statement).toMatch(
        /^(CREATE TABLE "admin_approvals"|ALTER TABLE "admin_approvals" ADD CONSTRAINT|CREATE INDEX "idx_admin_approvals_\w+" ON "admin_approvals")/
      );
    }
  });

  it('draws random ids and keeps a status that matches the approvals held', () => {
    const create = statements.find((statement) =>
      statement.startsWith('CREATE TABLE "admin_approvals"')
    );
    expect(create).toContain('"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL');
    expect(create).toContain('CONSTRAINT "admin_approvals_status_matches_approvals"');
    expect(create).toContain('CONSTRAINT "admin_approvals_used_exactly_when_consumed"');
    expect(create).toContain(
      `CHECK ("admin_approvals"."status" in ('pending', 'approved', 'denied', 'cancelled', 'consumed'))`
    );
  });
});
