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

import { FUNCTION_GRANTS, TABLE_GRANTS } from '../database-users/grants-map';
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
    expect(statements).toHaveLength(8);
    expect(statements[0]).toMatch(/^CREATE TABLE "admin_act_sessions" \(/);
    for (const statement of statements.slice(1, 3)) {
      expect(statement).toMatch(/^ALTER TABLE "admin_act_sessions" ADD CONSTRAINT /);
    }
    expect(statements[3]).toMatch(
      /^CREATE INDEX "idx_admin_act_sessions_user" ON "admin_act_sessions"/
    );
    expect(statements.slice(0, 4).join('\n')).not.toMatch(
      /\b(DROP|DELETE FROM|INSERT INTO|RENAME)\b|^UPDATE\b/m
    );
  });

  it("appends an act-chain call's audit row through two owner functions that PUBLIC cannot run", () => {
    const functions = statements.slice(4);
    expect(functions.map((statement) => statement.split('(', 1)[0])).toEqual([
      'CREATE FUNCTION "admin_audit_act_chain_head"',
      'REVOKE ALL ON FUNCTION "admin_audit_act_chain_head"',
      'CREATE FUNCTION "admin_audit_append_act_chain_call"',
      'REVOKE ALL ON FUNCTION "admin_audit_append_act_chain_call"',
    ]);
    for (const create of [functions[0], functions[2]]) {
      expect(create).toContain('SECURITY DEFINER');
      expect(create).toContain('SET search_path = pg_catalog, pg_temp');
    }
    // The head is read under the chain lock appendAdminAudit takes.
    expect(functions[0]).toContain(
      "pg_advisory_xact_lock(hashtextextended('qauth:admin-audit:' || p_realm_id::text, 0))"
    );
    // The row's actor and act chain come from the token's row, and only an
    // account operation's row, with no effect, diff, approval or digest.
    expect(functions[2]).toContain(`s."admin_user_id"::text, s."admin_realm_id", p_act_chain`);
    expect(functions[2]).toContain(`starts_with(p_operation_id, 'account.')`);
    // The row's time is the database's, and within the token's life.
    expect(functions[0]).toContain(
      'o_now := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;'
    );
    expect(functions[2]).toMatch(
      /p_created_at BETWEEN \(extract\(epoch FROM clock_timestamp\(\)\) \* 1000\)::bigint - 60000\s+AND \(extract\(epoch FROM clock_timestamp\(\)\) \* 1000\)::bigint/
    );
    expect(functions[2]).toContain(
      `p_created_at BETWEEN s."created_at" - 60000 AND s."expires_at" + 60000`
    );
    expect(functions[2]).toMatch(
      /'\[\]'::jsonb,\s+p_outcome::public\."admin_audit_outcome", NULL, '\[\]'::jsonb, NULL/
    );
    // Each a statement of its own, as the grants check looks for.
    expect(statements).toContain(
      'REVOKE ALL ON FUNCTION "admin_audit_act_chain_head"(uuid) FROM PUBLIC;'
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

  it('lets api reach the admin audit log through the two functions alone', () => {
    expect(TABLE_GRANTS['admin_audit_log']).not.toHaveProperty('api');
    expect(TABLE_GRANTS['admin_audit_log_checkpoints']).not.toHaveProperty('api');
    expect(FUNCTION_GRANTS['"admin_audit_act_chain_head"(uuid)']).toEqual(['api']);
    expect(
      FUNCTION_GRANTS[
        '"admin_audit_append_act_chain_call"(uuid, text, bigint, bytea, bytea, text, text, text, jsonb, text, bigint)'
      ]
    ).toEqual(['api']);
  });
});
