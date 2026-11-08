/**
 * Migration 0070 records an operator's verification of an account (#1052):
 * `users.operator_verified_at` and `users.operator_verified_by`, two nullable
 * columns with no default, so Postgres adds them without rewriting the
 * table, every existing account reads as one no operator verified, and a
 * release before this one keeps writing users during a rolling upgrade. Its
 * behaviour against a real Postgres is held by
 * `lib/account-verification/verify-account.integration.test.ts`.
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

  it('adds two nullable columns with no default, and touches no row', () => {
    expect(statements.slice(0, 2)).toEqual([
      'ALTER TABLE "users" ADD COLUMN "operator_verified_at" bigint;',
      'ALTER TABLE "users" ADD COLUMN "operator_verified_by" varchar(320);',
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|RENAME|DEFAULT)\b/);
    expect(statements.join('\n')).not.toContain('NOT NULL');
  });

  it('holds both columns set together, the operator in its one form', () => {
    expect(statements.slice(2)).toEqual([
      'ALTER TABLE "users" ADD CONSTRAINT "users_operator_verification_pair" CHECK (("users"."operator_verified_at" IS NULL) = ("users"."operator_verified_by" IS NULL));',
      `ALTER TABLE "users" ADD CONSTRAINT "users_operator_verified_by_form" CHECK ("users"."operator_verified_by" ~ '^(operator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|operator_cli(:[^[:cntrl:]]{1,255})?)$');`,
    ]);
    // The column's CHECK and the shared pattern accept the same forms: the
    // pattern spells [:cntrl:] as \p{Cc}.
    expect(OPERATOR_VERIFIED_BY_PATTERN.source).toBe(
      '^(operator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|operator_cli(:[^\\p{Cc}]{1,255})?)$'
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
