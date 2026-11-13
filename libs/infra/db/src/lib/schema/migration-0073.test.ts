/**
 * Migration 0073 stores, beside each realm's state of an AuthMethod plugin,
 * whose client the signer signs the plugin's client assertions for (#1073):
 * `realm_auth_method_plugins.assertion_client_id`, `assertion_issuer` and
 * `assertion_algorithm`, three nullable columns with no default, so Postgres
 * adds them without rewriting the table, every existing row has the signer
 * sign nothing (as before), and a release before this one keeps writing rows
 * during a rolling upgrade. Its behaviour against a real Postgres is held by
 * `repositories/realm-auth-method-plugins.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { realmAuthMethodPlugins } from './auth-method-plugins';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0073_auth_method_plugin_assertion_client';
const MIGRATION_IDX = 73;

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

describe('migration 0073 (the assertion client of a realm plugin state)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0072', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0072_new_factor_window');
  });

  it('adds three nullable columns with no default, and touches no row', () => {
    expect(statements.slice(0, 3)).toEqual([
      'ALTER TABLE "realm_auth_method_plugins" ADD COLUMN "assertion_client_id" varchar(255);',
      'ALTER TABLE "realm_auth_method_plugins" ADD COLUMN "assertion_issuer" varchar(255);',
      'ALTER TABLE "realm_auth_method_plugins" ADD COLUMN "assertion_algorithm" varchar(16);',
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|RENAME|DEFAULT)\b/);
    // A NOT NULL column would need a value for every existing row; the CHECKs
    // below name `IS NOT NULL` only as a condition.
    for (const statement of statements.slice(0, 3)) expect(statement).not.toContain('NOT NULL');
  });

  it('adds the CHECKs the schema declares, each of which a NULL row passes', () => {
    const names = statements
      .slice(3)
      .map((statement) => /ADD CONSTRAINT "([a-z_]+)" CHECK/.exec(statement)?.[1]);
    expect(names).toEqual([
      'realm_auth_method_plugins_assertion_client_pair',
      'realm_auth_method_plugins_assertion_issuer_client',
      'realm_auth_method_plugins_assertion_client_id_form',
      'realm_auth_method_plugins_assertion_issuer_form',
      'realm_auth_method_plugins_assertion_algorithm_form',
    ]);
    const declared = getTableConfig(realmAuthMethodPlugins).checks.map((check) => check.name);
    for (const name of names) expect(declared).toContain(name);
  });

  it('declares the columns nullable in the schema', () => {
    const columns = getTableConfig(realmAuthMethodPlugins).columns;
    for (const name of ['assertion_client_id', 'assertion_issuer', 'assertion_algorithm']) {
      const column = columns.find((candidate) => candidate.name === name);
      expect(column?.notNull).toBe(false);
      expect(column?.hasDefault).toBe(false);
    }
  });
});
