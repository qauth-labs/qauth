/**
 * Migration 0070 records an operator's verification of an account (#1052):
 * `users.operator_verified_at` and `users.operator_verified_by`, two nullable
 * columns with no default, so Postgres adds them without rewriting the
 * table, every existing account reads as one no operator verified, and a
 * release before this one keeps writing users during a rolling upgrade; and
 * the two functions `users.verify` runs through as the admin role, which
 * holds no `SELECT` on `user_credentials` and no `UPDATE` on `users`. Its
 * behaviour against a real Postgres is held by
 * `lib/account-verification/verify-account.integration.test.ts` and
 * `lib/repositories/operator-verification.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { OPERATOR_VERIFIED_BY_PATTERN } from '@qauth-labs/shared-validation';
import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { users } from './core';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0070_users_operator_verification';
const MIGRATION_IDX = 70;

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

describe("migration 0070 (an operator's verification of an account)", () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0069', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0069_auth_method_plugin_binding');
  });

  /** The statements that change the table: the columns and their CHECKs. */
  const tableStatements = statements.slice(0, 4);
  /** The functions of the admin role, each with its revoke from PUBLIC. */
  const functionStatements = statements.slice(4);

  it('adds two nullable columns with no default, and touches no row', () => {
    expect(tableStatements.slice(0, 2)).toEqual([
      'ALTER TABLE "users" ADD COLUMN "operator_verified_at" bigint;',
      'ALTER TABLE "users" ADD COLUMN "operator_verified_by" varchar(320);',
    ]);
    expect(tableStatements.join('\n')).not.toMatch(
      /\b(DROP|UPDATE|DELETE|INSERT|RENAME|DEFAULT)\b/
    );
    expect(tableStatements.join('\n')).not.toContain('NOT NULL');
    expect(statements.join('\n')).not.toMatch(/\b(DROP|DELETE|INSERT|RENAME)\b/);
  });

  it('holds both columns set together, the operator in its one form', () => {
    expect(tableStatements.slice(2)).toEqual([
      'ALTER TABLE "users" ADD CONSTRAINT "users_operator_verification_pair" CHECK (("users"."operator_verified_at" IS NULL) = ("users"."operator_verified_by" IS NULL));',
      `ALTER TABLE "users" ADD CONSTRAINT "users_operator_verified_by_form" CHECK ("users"."operator_verified_by" ~ '^(operator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|operator_cli(:[^[:cntrl:]]{1,255})?)$');`,
    ]);
    // The column's CHECK and the shared pattern accept the same forms: the
    // pattern spells [:cntrl:] as \p{Cc}.
    expect(OPERATOR_VERIFIED_BY_PATTERN.source).toBe(
      '^(operator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|operator_cli(:[^\\p{Cc}]{1,255})?)$'
    );
  });

  it('gives users.verify two definer functions, each taken from PUBLIC, that read nothing secret and write the verification alone', () => {
    expect(functionStatements).toHaveLength(4);
    const [proofs, revokeProofs, record, revokeRecord] = functionStatements;
    for (const body of [proofs, record]) {
      expect(body).toContain('SECURITY DEFINER');
      expect(body).toContain('SET search_path = pg_catalog, pg_temp');
    }
    expect(proofs).toMatch(
      /^CREATE FUNCTION "user_credential_proofs"\(p_realm_id uuid, p_user_id uuid\)/
    );
    expect(proofs).toContain('STABLE');
    // Of credential_data, only the keys that say what a credential proves.
    expect(proofs?.match(/"credential_data" -> '([a-z_]+)'/g)).toEqual([
      `"credential_data" -> 'email_verified'`,
      `"credential_data" -> 'user_verified'`,
      `"credential_data" -> 'kind'`,
    ]);
    expect(proofs).not.toMatch(/"credential_data"\s*(,|$|\))/m);
    expect(revokeProofs).toBe(
      'REVOKE ALL ON FUNCTION "user_credential_proofs"(uuid, uuid) FROM PUBLIC;'
    );

    expect(record).toMatch(
      /^CREATE FUNCTION "users_record_operator_verification"\(p_realm_id uuid, p_user_id uuid, p_operator_id uuid, p_at bigint\)/
    );
    // It sets the verification's two columns and updated_at, and only on an
    // enabled account of the realm no operator verified yet.
    const assignments = /\bSET\b([\s\S]*?)\bWHERE\b/.exec(record ?? '')?.[1] ?? '';
    expect([...assignments.matchAll(/"([a-z_]+)" =/g)].map((match) => match[1])).toEqual([
      'operator_verified_at',
      'operator_verified_by',
      'updated_at',
    ]);
    expect(record).toContain(`'operator:' || p_operator_id::text`);
    expect(record).toContain('u."enabled"');
    expect(record).toContain('u."operator_verified_at" IS NULL');
    expect(record).toContain('u."realm_id" = p_realm_id');
    expect(revokeRecord).toBe(
      'REVOKE ALL ON FUNCTION "users_record_operator_verification"(uuid, uuid, uuid, bigint) FROM PUBLIC;'
    );
  });

  it('matches the schema', () => {
    const config = getTableConfig(users);
    const columns = Object.fromEntries(config.columns.map((column) => [column.name, column]));
    expect(columns['operator_verified_at']?.notNull).toBe(false);
    expect(columns['operator_verified_at']?.hasDefault).toBe(false);
    expect(columns['operator_verified_by']?.notNull).toBe(false);
    expect(columns['operator_verified_by']?.hasDefault).toBe(false);
    expect(config.checks.map((check) => check.name).sort()).toEqual([
      'users_operator_verification_pair',
      'users_operator_verified_by_form',
    ]);
  });
});
