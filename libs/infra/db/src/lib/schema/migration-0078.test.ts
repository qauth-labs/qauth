/**
 * Migration 0078 adds `service_accounts` (#522): the service accounts of the
 * admin API, each a user with no credential and the OAuth client it signs in
 * with. A new, empty table that a release before this one never names, so
 * nothing is rewritten and a rolling upgrade is safe. Its behaviour against a
 * real Postgres is held by `repositories/service-accounts.integration.test.ts`
 * and the auth server's `admin-service-accounts.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { FUNCTION_GRANTS } from '../database-users/grants-map';
import { users } from './core';
import { SERVICE_ACCOUNT_NAME_PATTERN, serviceAccounts } from './service-accounts';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0078_service_accounts';
const MIGRATION_IDX = 78;

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

describe('migration 0078 (service accounts)', () => {
  const statements = statementsOf(MIGRATION_TAG);
  const table = statements.find((statement) => statement.startsWith('CREATE TABLE')) ?? '';

  it('is in the journal, after 0077', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0077_deployment_nodes');
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
    // The migrator runs a migration only when it is newer than the last one applied.
    const when = (idx: number) => journal.entries[idx]?.when ?? 0;
    expect(when(MIGRATION_IDX)).toBeGreaterThan(when(MIGRATION_IDX - 1));
  });

  it('creates one new table, one users column with a default, and its functions and trigger', () => {
    expect(statements[0]).toMatch(/^CREATE TABLE "service_accounts" \(/);
    expect(statements.filter((statement) => statement.startsWith('CREATE TABLE'))).toHaveLength(1);
    for (const statement of statements.slice(1)) {
      expect(statement).toMatch(
        /^(ALTER TABLE "service_accounts" ADD CONSTRAINT "service_accounts_[a-z_]+" FOREIGN KEY|CREATE INDEX "idx_service_accounts_|ALTER TABLE "users" ADD COLUMN "is_service_account" boolean DEFAULT false NOT NULL;$|CREATE FUNCTION "(users_service_account_permanent|service_accounts_end_tokens)"|CREATE TRIGGER "users_service_account_permanent"|REVOKE ALL ON FUNCTION "service_accounts_end_tokens"\(uuid, uuid\) FROM PUBLIC;$)/
      );
    }
    // Nothing runs now that rewrites or removes a row: the one UPDATE is the
    // body of a function a caller runs later.
    const runNow = statements.filter((statement) => !statement.startsWith('CREATE FUNCTION'));
    expect(runNow.join('\n')).not.toMatch(
      /\b(DROP|DELETE FROM|INSERT INTO|RENAME|TRUNCATE)\b|^UPDATE\b/m
    );
  });

  it('marks a service account for good, with a constant default no row is rewritten for', () => {
    expect(
      getTableConfig(users).columns.find((column) => column.name === 'is_service_account')
    ).toMatchObject({ notNull: true, default: false });
    const permanent =
      statements.find((statement) =>
        statement.startsWith('CREATE FUNCTION "users_service_account_permanent"')
      ) ?? '';
    expect(permanent).toContain(
      'IF NEW."is_service_account" IS DISTINCT FROM OLD."is_service_account" THEN'
    );
    expect(permanent).toContain("CONSTRAINT = 'users_service_account_permanent'");
    expect(permanent).toContain('SET search_path = pg_catalog, pg_temp');
    expect(statements).toContain(
      'CREATE TRIGGER "users_service_account_permanent"\n  BEFORE UPDATE OF "is_service_account" ON "users"\n  FOR EACH ROW\n  EXECUTE FUNCTION "users_service_account_permanent"();'
    );
  });

  it("moves a bound account's not_valid_before forward only, as a definer the admin role alone runs", () => {
    const end =
      statements.find((statement) =>
        statement.startsWith('CREATE FUNCTION "service_accounts_end_tokens"')
      ) ?? '';
    expect(end).toContain('SECURITY DEFINER');
    expect(end).toContain('SET search_path = pg_catalog, pg_temp');
    expect(end).toContain('coalesce(u."not_valid_before", 0)');
    expect(end).toContain('s."client_id" = p_client_id');
    expect(end).toContain('u."realm_id" = s."realm_id"');
    expect(FUNCTION_GRANTS['"service_accounts_end_tokens"(uuid, uuid)']).toEqual(['admin']);
  });

  it('keeps a bound client from being deleted, and lets the realm cascade pass', () => {
    expect(statements.join('\n')).toContain(
      'ADD CONSTRAINT "service_accounts_client_id_oauth_clients_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."oauth_clients"("id") ON DELETE no action'
    );
  });

  it('binds one user and one client to one service account, the user in the row’s realm', () => {
    for (const constraint of [
      'CONSTRAINT "service_accounts_realm_name_unique" UNIQUE("realm_id","name")',
      'CONSTRAINT "service_accounts_user_id_unique" UNIQUE("user_id")',
      'CONSTRAINT "service_accounts_client_id_unique" UNIQUE("client_id")',
    ]) {
      expect(table).toContain(constraint);
    }
    expect(statements.join('\n')).toContain(
      'ADD CONSTRAINT "service_accounts_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade'
    );
    const config = getTableConfig(serviceAccounts);
    expect(
      config.foreignKeys.map((fk) => getTableConfig(fk.reference().foreignTable).name).sort()
    ).toEqual(['oauth_clients', 'realms', 'users', 'users']);
  });

  it('holds the name grammar in the database, as the repository does', () => {
    expect(table).toContain(
      `CONSTRAINT "service_accounts_name_grammar" CHECK ("service_accounts"."name" ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$')`
    );
    for (const name of ['ci', 'ci-realm-import', 'rp2-account-closing']) {
      expect(SERVICE_ACCOUNT_NAME_PATTERN.test(name), name).toBe(true);
    }
    for (const name of ['CI', '-ci', 'ci-', 'ci--import', '1ci', 'ci import', 'çi']) {
      expect(SERVICE_ACCOUNT_NAME_PATTERN.test(name), name).toBe(false);
    }
  });

  it('starts every service account enabled', () => {
    expect(table).toContain('"enabled" boolean DEFAULT true NOT NULL');
  });
});
