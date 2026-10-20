import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { DbClient } from '../db';
import { createRefreshTokensRepository } from './refresh-tokens.repository';

/**
 * SQL-shape tests for the refresh-token rotation lock (ANT-2026-2UN56MXQ).
 *
 * A bulk revocation is one `UPDATE ... WHERE revoked = false`. Under READ
 * COMMITTED, one that starts while a rotation is in flight blocks on the
 * parent, finds it revoked once the rotation commits, and never sees the child
 * the rotation inserted. Rotation and the bulk revocations therefore share a
 * per-user advisory lock: shared for rotation, exclusive for revocation, taken
 * before the UPDATE and held to the end of the transaction.
 *
 * These assert the statements the repository emits, without Docker. The
 * container-backed suite (`repositories.integration.test.ts`) runs the actual
 * race against Postgres.
 */

interface CapturedQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

/** A `pg` client that records queries instead of running them. */
function createRecordingDb(): { db: DbClient; queries: CapturedQuery[] } {
  const queries: CapturedQuery[] = [];
  const client = {
    query: (config: { text?: string; values?: unknown[] } | string, values?: unknown[]) => {
      const text = typeof config === 'string' ? config : (config.text ?? '');
      const params = typeof config === 'string' ? (values ?? []) : (config.values ?? values ?? []);
      queries.push({ text, values: params });
      return Promise.resolve({ rows: [], rowCount: 0, fields: [], command: '', oid: 0 });
    },
  };
  return { db: drizzle(client as unknown as Pool) as unknown as DbClient, queries };
}

const texts = (queries: CapturedQuery[]) => queries.map((q) => q.text.toLowerCase());

const USER_ID = '0192f1c4-1111-7000-8000-000000000001';
const CLIENT_ID = '0192f1c4-2222-7000-8000-000000000002';

describe('refresh-token rotation lock', () => {
  it('rotation (revokeIfActive) takes the shared lock on the token owner before its UPDATE', async () => {
    const { db, queries } = createRecordingDb();

    await createRefreshTokensRepository(db).revokeIfActive('token-1', 'rotated', db);

    const sql = texts(queries);
    const lock = sql.findIndex((t) => t.includes('pg_advisory_xact_lock_shared('));
    const update = sql.findIndex((t) => t.startsWith('update "refresh_tokens"'));
    expect(lock).toBeGreaterThanOrEqual(0);
    expect(update).toBeGreaterThan(lock);
    // Keyed on the owner of the token being rotated, read from the row.
    expect(sql[lock]).toContain('"user_id"');
    expect(queries[lock].values).toContain('token-1');
  });

  it.each([
    [
      'revokeFamily',
      (repo: ReturnType<typeof createRefreshTokensRepository>) =>
        repo.revokeFamily('family-1', 'replay_detected'),
    ],
    [
      'revokeAllForUser',
      (repo: ReturnType<typeof createRefreshTokensRepository>) =>
        repo.revokeAllForUser(USER_ID, 'logout'),
    ],
    [
      'revokeAllForUserAndClient',
      (repo: ReturnType<typeof createRefreshTokensRepository>) =>
        repo.revokeAllForUserAndClient(USER_ID, CLIENT_ID, 'consent_revoked'),
    ],
  ] as const)(
    '%s takes the exclusive lock before its UPDATE, inside a transaction',
    async (_name, revoke) => {
      const { db, queries } = createRecordingDb();

      await revoke(createRefreshTokensRepository(db));

      const sql = texts(queries);
      const begin = sql.indexOf('begin');
      const lock = sql.findIndex((t) => /pg_advisory_xact_lock\(/.test(t));
      const update = sql.findIndex((t) => t.startsWith('update "refresh_tokens"'));
      const commit = sql.indexOf('commit');
      // A transaction-scoped lock taken in autocommit would be released before
      // the UPDATE runs, so the repository opens a transaction when the caller
      // passes none.
      expect(begin).toBeGreaterThanOrEqual(0);
      expect(lock).toBeGreaterThan(begin);
      expect(update).toBeGreaterThan(lock);
      expect(commit).toBeGreaterThan(update);
      expect(sql.some((t) => t.includes('pg_advisory_xact_lock_shared('))).toBe(false);
    }
  );

  it("uses the caller's transaction when one is passed", async () => {
    const { db, queries } = createRecordingDb();

    await createRefreshTokensRepository(db).revokeAllForUserAndClient(
      USER_ID,
      CLIENT_ID,
      'consent_revoked',
      db
    );

    const sql = texts(queries);
    expect(sql).not.toContain('begin');
    const lock = sql.findIndex((t) => /pg_advisory_xact_lock\(/.test(t));
    const update = sql.findIndex((t) => t.startsWith('update "refresh_tokens"'));
    expect(lock).toBeGreaterThanOrEqual(0);
    expect(update).toBeGreaterThan(lock);
  });

  it('keys rotation and revocation on the same canonical user id', async () => {
    const { db, queries } = createRecordingDb();
    const repo = createRefreshTokensRepository(db);

    await repo.revokeIfActive('token-1', 'rotated', db);
    await repo.revokeAllForUser(USER_ID, 'logout');

    // Both hash the id as a uuid rendered to text, so an id string spelled
    // differently (upper case) cannot land on a different lock.
    const locks = texts(queries).filter((t) => t.includes('pg_advisory_xact_lock'));
    expect(locks).toHaveLength(2);
    for (const lock of locks) {
      expect(lock).toContain('::uuid::text');
    }
  });
});

describe('refresh-token purge', () => {
  it('deletes an expired token only when no token of its family is live', async () => {
    const { db, queries } = createRecordingDb();

    await createRefreshTokensRepository(db).deleteExpired();

    const sql = texts(queries);
    expect(sql).toHaveLength(1);
    const [statement] = sql;
    expect(statement.startsWith('delete from "refresh_tokens"')).toBe(true);
    // The family test is correlated on family_id and asks for a live row,
    // so a rotated token outlives its own expiry while its family is live.
    expect(statement).toMatch(/not exists \(select 1 from "refresh_tokens" "live"/);
    expect(statement).toContain('"live"."family_id" = "refresh_tokens"."family_id"');
    expect(statement).toContain('"live"."expires_at" >=');
    const [before, after] = queries[0].values;
    expect(before).toBe(after);
  });
});
