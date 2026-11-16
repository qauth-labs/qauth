/**
 * Migration 0079 adds `admin_enrolments` (#602): the one-time admin
 * enrolments the break-glass command `enrol-admin` issues, each holding the
 * SHA-256 of a token and nothing that recovers it. A new, empty table that a
 * release before this one never names, so nothing is rewritten and a rolling
 * upgrade is safe. Its behaviour against a real Postgres is held by
 * `repositories/admin-enrolments.integration.test.ts` and the auth server's
 * `break-glass.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { TABLE_GRANTS } from '../database-users/grants-map';
import { adminEnrolments } from './admin-enrolments';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0079_admin_enrolments';
const MIGRATION_IDX = 79;

interface JournalEntry {
  idx: number;
  tag: string;
  when: number;
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

describe('migration 0079 (admin enrolments)', () => {
  const statements = statementsOf(MIGRATION_TAG);
  const table = statements.find((statement) => statement.startsWith('CREATE TABLE')) ?? '';

  it('is in the journal, after 0078', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0078_service_accounts');
  });

  it('chains its snapshot from the one before, and comes after it in time', () => {
    const snapshotOf = (idx: number): { id: string; prevId: string } =>
      JSON.parse(
        readFileSync(
          path.join(DRIZZLE_DIR, `meta/${String(idx).padStart(4, '0')}_snapshot.json`),
          'utf8'
        )
      );
    expect(snapshotOf(MIGRATION_IDX).prevId).toBe(snapshotOf(MIGRATION_IDX - 1).id);
    const when = (idx: number) => journal.entries[idx]?.when ?? 0;
    expect(when(MIGRATION_IDX)).toBeGreaterThan(when(MIGRATION_IDX - 1));
  });

  it('creates one new table, its foreign keys and its trigger, and rewrites nothing', () => {
    expect(statements[0]).toMatch(/^CREATE TABLE "admin_enrolments" \(/);
    expect(statements.filter((statement) => statement.startsWith('CREATE TABLE'))).toHaveLength(1);
    for (const statement of statements.slice(1)) {
      expect(statement).toMatch(
        /^(ALTER TABLE "admin_enrolments" ADD CONSTRAINT "admin_enrolments_[a-z_]+" FOREIGN KEY|CREATE FUNCTION "admin_enrolments_use_once"|CREATE TRIGGER "admin_enrolments_use_once")/
      );
    }
    expect(statements.join('\n')).not.toMatch(
      /\b(DROP|DELETE FROM|INSERT INTO|RENAME|TRUNCATE)\b|^UPDATE\b/m
    );
  });

  it('holds a 32-byte hash and no token, one enrolment per account, the account in the row’s realm', () => {
    expect(table).toContain('"token_hash" "bytea" NOT NULL');
    expect(table).not.toMatch(/"token"/);
    for (const constraint of [
      'CONSTRAINT "admin_enrolments_token_hash_unique" UNIQUE("token_hash")',
      'CONSTRAINT "admin_enrolments_user_id_unique" UNIQUE("user_id")',
      'CONSTRAINT "admin_enrolments_token_hash_sha256" CHECK (octet_length("admin_enrolments"."token_hash") = 32)',
      'CONSTRAINT "admin_enrolments_expires_after_created" CHECK ("admin_enrolments"."expires_at" > "admin_enrolments"."created_at")',
    ]) {
      expect(table).toContain(constraint);
    }
    expect(statements.join('\n')).toContain(
      'ADD CONSTRAINT "admin_enrolments_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade'
    );
    expect(
      getTableConfig(adminEnrolments)
        .foreignKeys.map((fk) => getTableConfig(fk.reference().foreignTable).name)
        .sort()
    ).toEqual(['realms', 'users']);
  });

  it('lets a row change only by one redemption before its expiry, whoever writes it', () => {
    const useOnce =
      statements.find((statement) =>
        statement.startsWith('CREATE FUNCTION "admin_enrolments_use_once"')
      ) ?? '';
    expect(useOnce).toContain('SET search_path = pg_catalog, pg_temp');
    for (const guard of [
      'IF OLD."used_at" IS NOT NULL',
      'OR NEW."used_at" IS NULL',
      'OR NEW."used_at" >= OLD."expires_at"',
      'OR (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint >= OLD."expires_at"',
      'OR NEW."user_id" IS DISTINCT FROM OLD."user_id"',
      'OR NEW."token_hash" IS DISTINCT FROM OLD."token_hash"',
      'OR NEW."expires_at" IS DISTINCT FROM OLD."expires_at"',
    ]) {
      expect(useOnce).toContain(guard);
    }
    expect(useOnce).toContain("CONSTRAINT = 'admin_enrolments_use_once'");
    expect(statements).toContain(
      'CREATE TRIGGER "admin_enrolments_use_once"\n  BEFORE UPDATE ON "admin_enrolments"\n  FOR EACH ROW\n  EXECUTE FUNCTION "admin_enrolments_use_once"();'
    );
  });

  it('grants only `web`, which serves the enrolment step (#621), its read and its redemption', () => {
    expect(TABLE_GRANTS['admin_enrolments']).toEqual({ web: ['SELECT', 'UPDATE'] });
  });
});
