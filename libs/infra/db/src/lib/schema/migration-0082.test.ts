/**
 * Migration 0082 adds `admin_act_sessions` (#523): the act-chain tokens
 * issued to admins who act for a user. A new, empty table that a release
 * before this one never names, so nothing is rewritten and a rolling upgrade
 * is safe. Its behaviour against a real Postgres is held by
 * `repositories/admin-act-sessions.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { TABLE_GRANTS } from '../database-users/grants-map';
import { adminActSessions } from './admin-act-sessions';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0082_admin_act_sessions';
const MIGRATION_IDX = 82;

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
    .filter((statement) => statement !== '');
}

describe('migration 0082 (the act-chain tokens issued to admins)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0081', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0081_protected_resources');
  });

  it('creates one new table, its two foreign keys and its index, and touches no other table', () => {
    expect(statements).toHaveLength(4);
    expect(statements[0]).toMatch(/^CREATE TABLE "admin_act_sessions" \(/);
    for (const statement of statements.slice(1, 3)) {
      expect(statement).toMatch(/^ALTER TABLE "admin_act_sessions" ADD CONSTRAINT /);
    }
    expect(statements[3]).toMatch(
      /^CREATE INDEX "idx_admin_act_sessions_user" ON "admin_act_sessions"/
    );
    expect(statements.join('\n')).not.toMatch(
      /\b(DROP|DELETE FROM|INSERT INTO|RENAME)\b|^UPDATE\b/m
    );
  });

  it('keeps the user in the row realm, and references neither the admin nor the approval', () => {
    const config = getTableConfig(adminActSessions);
    const references = config.foreignKeys.map((fk) => {
      const reference = fk.reference();
      return [
        reference.columns.map((column) => column.name).join(','),
        reference.foreignColumns.map((column) => column.name).join(','),
      ];
    });
    expect(references.sort()).toEqual(
      [
        ['realm_id', 'id'],
        ['user_id,realm_id', 'id,realm_id'],
      ].sort()
    );
  });

  it('bounds a token to ten minutes, one row per realm and jti', () => {
    expect(statements[0]).toContain(
      'CONSTRAINT "admin_act_sessions_realm_jti_unique" UNIQUE("realm_id","token_jti")'
    );
    expect(statements[0]).toMatch(
      /CONSTRAINT "admin_act_sessions_lifetime" CHECK \(.*"expires_at" - "admin_act_sessions"\."created_at" <= 600000\)/
    );
  });

  it('lets admin insert and api read, and no role update or delete a row', () => {
    expect(TABLE_GRANTS['admin_act_sessions']).toEqual({
      api: ['SELECT'],
      admin: ['SELECT', 'INSERT'],
    });
  });
});
