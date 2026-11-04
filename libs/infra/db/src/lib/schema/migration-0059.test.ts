/**
 * Migration 0059 adds the actions a user must take at the next sign-in (#635):
 * one new table, `user_required_actions`, with its foreign keys, its unique
 * index and the CHECKs that close `action` and `source`. It changes no row of
 * any other table, so an earlier release, which never touches the new table,
 * keeps working during a rolling upgrade. It locks `realms` and then `users`,
 * in the order their writers take them, before its foreign keys take them. The
 * table's rules are held by `user-required-actions.integration.test.ts`
 * against a real Postgres.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { USER_REQUIRED_ACTION_SOURCES, USER_REQUIRED_ACTIONS } from './user-required-actions';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0059_user_required_actions';
const MIGRATION_IDX = 59;

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

describe('migration 0059 (user required actions)', () => {
  const statements = statementsOf(MIGRATION_TAG);
  const create = statements.find((statement) =>
    statement.startsWith('CREATE TABLE "user_required_actions"')
  );

  it('is in the journal, after 0058', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0058_client_backchannel_logout');
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
        /^(CREATE TABLE "user_required_actions"|ALTER TABLE "user_required_actions" ADD CONSTRAINT|CREATE (UNIQUE )?INDEX "idx_user_required_actions_\w+" ON "user_required_actions")/
      );
    }
  });

  it('draws time-ordered ids and stamps the creation time in epoch ms', () => {
    expect(create).toContain('"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL');
    expect(create).toContain(
      '"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL'
    );
  });

  it('closes action and source to the lists the code exports', () => {
    const list = (values: readonly string[]) => values.map((value) => `'${value}'`).join(', ');
    expect(create).toContain(
      `CONSTRAINT "user_required_actions_action_known" CHECK ("user_required_actions"."action" in (${list(USER_REQUIRED_ACTIONS)}))`
    );
    expect(create).toContain(
      `CONSTRAINT "user_required_actions_source_known" CHECK ("user_required_actions"."source" in (${list(USER_REQUIRED_ACTION_SOURCES)}))`
    );
  });

  it('holds the user to its realm, and cascades from both', () => {
    expect(statements).toContain(
      'ALTER TABLE "user_required_actions" ADD CONSTRAINT "user_required_actions_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade ON UPDATE no action;'
    );
    expect(statements).toContain(
      'ALTER TABLE "user_required_actions" ADD CONSTRAINT "user_required_actions_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;'
    );
  });

  it('keeps one row per user and action', () => {
    expect(statements).toContain(
      'CREATE UNIQUE INDEX "idx_user_required_actions_user_action_unique" ON "user_required_actions" USING btree ("user_id","action");'
    );
  });
});
