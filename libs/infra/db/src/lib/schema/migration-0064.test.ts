/**
 * Migration 0064 adds each account's recovery codes (#649): one new table,
 * `user_recovery_codes`, with its foreign keys, its indexes and the CHECKs that
 * keep the hash non-empty and the times positive. It changes no row of any
 * other table, so an earlier release, which never touches the new table, keeps
 * working during a rolling upgrade. It locks `realms` and then `users`, in the
 * order their writers take them, before its foreign keys take them.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0064_user_recovery_codes';
const MIGRATION_IDX = 64;

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

describe('migration 0064 (user recovery codes)', () => {
  const statements = statementsOf(MIGRATION_TAG);
  const create = statements.find((statement) =>
    statement.startsWith('CREATE TABLE "user_recovery_codes"')
  );

  it('is in the journal, after 0063', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0063_client_registration_challenge');
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
        /^(CREATE TABLE "user_recovery_codes"|ALTER TABLE "user_recovery_codes" ADD CONSTRAINT|CREATE INDEX "idx_user_recovery_codes_\w+" ON "user_recovery_codes")/
      );
    }
  });

  it('keeps a hash and its times, never a code', () => {
    expect(create).toContain('"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL');
    expect(create).toContain('"code_hash" text NOT NULL');
    expect(create).toContain('"created_at" bigint NOT NULL');
    expect(create).toContain('"used_at" bigint,');
    expect(create).not.toMatch(/"code"\s/);
    expect(create).toContain(
      'CONSTRAINT "user_recovery_codes_code_hash_not_empty" CHECK (length("user_recovery_codes"."code_hash") > 0)'
    );
    expect(create).toContain(
      'CONSTRAINT "user_recovery_codes_created_at_positive" CHECK ("user_recovery_codes"."created_at" > 0)'
    );
    expect(create).toContain(
      'CONSTRAINT "user_recovery_codes_used_at_positive" CHECK ("user_recovery_codes"."used_at" IS NULL OR "user_recovery_codes"."used_at" > 0)'
    );
  });

  it('holds the user to its realm, and cascades from both', () => {
    expect(statements).toContain(
      'ALTER TABLE "user_recovery_codes" ADD CONSTRAINT "user_recovery_codes_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade ON UPDATE no action;'
    );
    expect(statements).toContain(
      'ALTER TABLE "user_recovery_codes" ADD CONSTRAINT "user_recovery_codes_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;'
    );
  });

  it("indexes an account's codes and the realm for its cascade", () => {
    expect(statements).toContain(
      'CREATE INDEX "idx_user_recovery_codes_user_realm" ON "user_recovery_codes" USING btree ("user_id","realm_id");'
    );
    expect(statements).toContain(
      'CREATE INDEX "idx_user_recovery_codes_realm_id" ON "user_recovery_codes" USING btree ("realm_id");'
    );
  });
});
