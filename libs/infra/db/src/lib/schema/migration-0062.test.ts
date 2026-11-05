/**
 * Migration 0062 adds each user's session epoch (#642): one new table,
 * `user_session_epochs`, with its foreign keys, its index and the CHECKs that
 * keep the counter and its time positive. It changes no row of any other
 * table, so an earlier release, which never touches the new table, keeps
 * working during a rolling upgrade. It locks `realms` and then `users`, in
 * the order their writers take them, before its foreign keys take them.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0062_user_session_epochs';
const MIGRATION_IDX = 62;

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

describe('migration 0062 (user session epochs)', () => {
  const statements = statementsOf(MIGRATION_TAG);
  const create = statements.find((statement) =>
    statement.startsWith('CREATE TABLE "user_session_epochs"')
  );

  it('is in the journal, after 0061', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0061_client_hosted_flows');
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
        /^(CREATE TABLE "user_session_epochs"|ALTER TABLE "user_session_epochs" ADD CONSTRAINT|CREATE INDEX "idx_user_session_epochs_\w+" ON "user_session_epochs")/
      );
    }
  });

  it('keeps one row per user, with a positive counter and time', () => {
    expect(create).toContain('"user_id" uuid PRIMARY KEY NOT NULL');
    expect(create).toContain('"epoch" integer NOT NULL');
    expect(create).toContain('"advanced_at" bigint NOT NULL');
    expect(create).toContain(
      'CONSTRAINT "user_session_epochs_epoch_positive" CHECK ("user_session_epochs"."epoch" > 0)'
    );
    expect(create).toContain(
      'CONSTRAINT "user_session_epochs_advanced_at_positive" CHECK ("user_session_epochs"."advanced_at" > 0)'
    );
  });

  it('holds the user to its realm, and cascades from both', () => {
    expect(statements).toContain(
      'ALTER TABLE "user_session_epochs" ADD CONSTRAINT "user_session_epochs_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade ON UPDATE no action;'
    );
    expect(statements).toContain(
      'ALTER TABLE "user_session_epochs" ADD CONSTRAINT "user_session_epochs_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;'
    );
  });

  it('indexes the realm for its cascade', () => {
    expect(statements).toContain(
      'CREATE INDEX "idx_user_session_epochs_realm_id" ON "user_session_epochs" USING btree ("realm_id");'
    );
  });
});
