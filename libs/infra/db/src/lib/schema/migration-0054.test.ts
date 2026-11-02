/**
 * Migration 0054 takes the request body and the unsalted request hash out of
 * `admin_approvals` (#901): the method, path parameters and query move to
 * columns of their own, `display` holds what an approver is shown, and
 * `canonical_request` and `request_hash` go. An approval filed before it is
 * emptied and its nonce overwritten in the same row version that fills the
 * new columns, and one still open is retired as `expired`, a status stored
 * from here on. What the migration does to rows is held by
 * `migration-0054.integration.test.ts` against a real Postgres.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0054_admin_approvals_no_request_body';
const MIGRATION_IDX = 54;

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

describe('migration 0054 (admin approvals keep no request body)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0053', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0053_oid4vp_response_key_sealing_kid');
  });

  it('touches only admin_approvals', () => {
    for (const statement of statements) {
      expect(statement, statement).toMatch(
        /^(ALTER TABLE "admin_approvals" |UPDATE "admin_approvals" SET |CREATE INDEX "idx_admin_approvals_open_expiry" ON "admin_approvals" )/
      );
    }
  });

  it('empties the stored request and overwrites both hashes before it drops their columns', () => {
    const fill = statements.findIndex((statement) => statement.startsWith('UPDATE '));
    const dropRequest = statements.indexOf(
      'ALTER TABLE "admin_approvals" DROP COLUMN "canonical_request";'
    );
    const dropHash = statements.indexOf(
      'ALTER TABLE "admin_approvals" DROP COLUMN "request_hash";'
    );
    expect(fill).toBeGreaterThan(-1);
    expect(dropRequest).toBeGreaterThan(fill);
    expect(dropHash).toBeGreaterThan(fill);
    expect(statements[fill]).toContain(`"canonical_request" = '{}'::jsonb`);
    expect(statements[fill]).toMatch(/"request_hash" = sha256\(/);
    expect(statements[fill]).toMatch(/"nonce" = sha256\(/);
    // The fill runs before the new columns turn NOT NULL.
    const notNull = statements.findIndex((statement) => statement.includes('SET NOT NULL'));
    expect(notNull).toBeGreaterThan(fill);
  });

  it('stores the status expired, and keeps a display on every open approval', () => {
    expect(statements).toContain(
      `ALTER TABLE "admin_approvals" ADD CONSTRAINT "admin_approvals_status" CHECK ("admin_approvals"."status" in ('pending', 'approved', 'denied', 'cancelled', 'consumed', 'expired'));`
    );
    expect(statements).toContain(
      `ALTER TABLE "admin_approvals" ADD CONSTRAINT "admin_approvals_open_has_display" CHECK ("admin_approvals"."status" not in ('pending', 'approved') or "admin_approvals"."display" is not null);`
    );
  });
});
