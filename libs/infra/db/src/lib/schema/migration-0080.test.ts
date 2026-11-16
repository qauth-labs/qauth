/**
 * Migration 0080 adds the two functions an admin's deletion of an account
 * runs through (`users.delete`, #681) as the admin role, which holds no
 * `UPDATE` and no `DELETE` on `users`: the lock that holds the account until
 * the deletion commits, and the deletion, which refuses a service account's
 * account and one that holds an admin grant. It only creates them: nothing
 * runs now, nothing is rewritten, and a release before this one never names
 * them. Their behaviour against a real Postgres is held by
 * `repositories/user-deletion.integration.test.ts` and the auth server's
 * `admin-users-delete.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { FUNCTION_GRANTS } from '../database-users/grants-map';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0080_users_delete_account';
const MIGRATION_IDX = 80;

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

describe('migration 0080 (an admin deletes an account)', () => {
  const statements = statementsOf(MIGRATION_TAG);
  const functionNamed = (name: string) =>
    statements.find((statement) => statement.startsWith(`CREATE FUNCTION "${name}"`)) ?? '';

  it('is in the journal, after 0079', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0079_admin_enrolments');
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

  it('only creates two functions and takes EXECUTE on them from PUBLIC', () => {
    expect(statements).toHaveLength(4);
    for (const statement of statements) {
      expect(statement).toMatch(
        /^(CREATE FUNCTION "(users_lock_for_deletion|users_delete_account)"\(p_realm_id uuid, p_user_id uuid\)|REVOKE ALL ON FUNCTION "(users_lock_for_deletion|users_delete_account)"\(uuid, uuid\) FROM PUBLIC;$)/
      );
    }
    // Nothing runs now that rewrites or removes a row: the one DELETE is the
    // body of a function a caller runs later.
    const runNow = statements.filter((statement) => !statement.startsWith('CREATE FUNCTION'));
    expect(runNow.join('\n')).not.toMatch(
      /\b(DROP|DELETE FROM|INSERT INTO|RENAME|TRUNCATE|ALTER)\b|^UPDATE\b/m
    );
  });

  it('runs both as definers with a pinned search path, the admin role alone executing them', () => {
    for (const name of ['users_lock_for_deletion', 'users_delete_account']) {
      const body = functionNamed(name);
      expect(body, name).toContain('SECURITY DEFINER');
      expect(body, name).toContain('VOLATILE');
      expect(body, name).toContain('SET search_path = pg_catalog, pg_temp');
      // Every statement names its schema: the search path holds none of ours.
      expect(body, name).toContain('public."users" u');
      expect(FUNCTION_GRANTS[`"${name}"(uuid, uuid)`], name).toEqual(['admin']);
    }
  });

  it('locks the realm’s account FOR UPDATE, the lock a foreign key’s key-share waits for', () => {
    const lock = functionNamed('users_lock_for_deletion');
    expect(lock).toContain('u."realm_id" = p_realm_id');
    expect(lock).toContain('u."id" = p_user_id');
    expect(lock).toMatch(/FOR UPDATE\s*\$\$;$/);
    expect(lock).not.toMatch(/FOR (NO KEY UPDATE|SHARE|KEY SHARE)/);
  });

  it("deletes only the realm's account that is no service account's and holds no admin grant", () => {
    const remove = functionNamed('users_delete_account');
    expect(remove).toContain('DELETE FROM public."users" u');
    expect(remove).toContain('u."realm_id" = p_realm_id');
    expect(remove).toContain('u."id" = p_user_id');
    expect(remove).toContain('NOT u."is_service_account"');
    expect(remove).toContain(
      'SELECT 1 FROM public."service_accounts" s WHERE s."user_id" = u."id"'
    );
    expect(remove).toContain('g."user_id" = u."id" AND g."revoked_at" IS NULL');
    expect(remove).toContain('RETURNING u."id"');
  });
});
