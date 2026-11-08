/**
 * Migration 0069 records which plugin wrote each realm's state of an
 * AuthMethod plugin (#949): `realm_auth_method_plugins.plugin_package` and
 * `plugin_type`, two nullable columns with no default, so Postgres adds them
 * without rewriting the table, every existing row reads as written before
 * they were recorded, and a release before this one keeps writing rows during
 * a rolling upgrade. Its behaviour against a real Postgres is held by
 * `repositories/realm-auth-method-plugins.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { realmAuthMethodPlugins } from './auth-method-plugins';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0069_auth_method_plugin_binding';
const MIGRATION_IDX = 69;

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

describe('migration 0069 (the plugin binding of a realm plugin state)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0068', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0068_primary_credential');
  });

  it('adds two nullable columns with no default, and touches no row', () => {
    expect(statements.slice(0, 2)).toEqual([
      'ALTER TABLE "realm_auth_method_plugins" ADD COLUMN "plugin_package" varchar(214);',
      'ALTER TABLE "realm_auth_method_plugins" ADD COLUMN "plugin_type" varchar(63);',
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|RENAME|DEFAULT)\b/);
    expect(statements.join('\n')).not.toContain('NOT NULL');
  });

  it('adds only CHECKs beside them, each one the schema holds', () => {
    const added = statements.slice(2);
    const names = added.map(
      (statement) =>
        /^ALTER TABLE "realm_auth_method_plugins" ADD CONSTRAINT "([a-z_]+)" CHECK \(/.exec(
          statement
        )?.[1]
    );
    expect(names).toEqual([
      'realm_auth_method_plugins_binding_pair',
      'realm_auth_method_plugins_plugin_package_form',
      'realm_auth_method_plugins_plugin_type_form',
    ]);
    const table = getTableConfig(realmAuthMethodPlugins);
    expect(table.checks.map((check) => check.name)).toEqual(expect.arrayContaining(names));
    // Both recorded, or neither: a row written by a release before this one has neither.
    expect(added[0]).toContain(
      'CHECK (("realm_auth_method_plugins"."plugin_package" IS NULL) = ("realm_auth_method_plugins"."plugin_type" IS NULL))'
    );
    // The contract's type rule (`AUTH_METHOD_TYPE_PATTERN`).
    expect(added[2]).toContain(`~ '^[a-z][a-z0-9_]{0,62}$'`);
  });
});
