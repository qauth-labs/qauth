/**
 * Migration 0050 adds `realm_auth_method_plugins` (ADR-019 Decisions 10 and
 * 12, #600): each realm's state of each installed AuthMethod plugin. A new
 * table, so the previous release keeps working on the new schema. Its
 * behaviour against a real Postgres is held by
 * `repositories/realm-auth-method-plugins.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { realmAuthMethodPlugins } from './auth-method-plugins';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0050_realm_auth_method_plugins';
const MIGRATION_IDX = 50;

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

describe('migration 0050 (realm_auth_method_plugins)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0049', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0049_realm_secrets');
  });

  it('only creates the table and its foreign key: no other table is touched', () => {
    expect(statements).toHaveLength(2);
    expect(statements[0].startsWith('CREATE TABLE "realm_auth_method_plugins" (')).toBe(true);
    expect(statements[1]).toBe(
      'ALTER TABLE "realm_auth_method_plugins" ADD CONSTRAINT "realm_auth_method_plugins_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;'
    );
    // The foreign key's own `ON DELETE cascade ON UPDATE no action` aside.
    expect(statements.join('\n').replace('ON DELETE cascade ON UPDATE no action', '')).not.toMatch(
      /\b(DROP|UPDATE|DELETE|INSERT|RENAME)\b/
    );
  });

  it('keys a row by realm and plugin, and holds every stored form in a CHECK', () => {
    const table = getTableConfig(realmAuthMethodPlugins);
    expect(table.primaryKeys.map((key) => key.columns.map((column) => column.name))).toEqual([
      ['realm_id', 'plugin_id'],
    ]);
    expect(table.checks.map((check) => check.name).sort()).toEqual([
      'realm_auth_method_plugins_config_object',
      'realm_auth_method_plugins_plugin_id_form',
      'realm_auth_method_plugins_secrets_ciphertext',
      'realm_auth_method_plugins_secrets_object',
      'realm_auth_method_plugins_version_positive',
    ]);
    for (const name of table.checks.map((check) => check.name)) {
      expect(statements[0]).toContain(`CONSTRAINT "${name}" CHECK (`);
    }
    // No backslash in the jsonpath: its string escapes differ from a regex's.
    expect(statements[0]).toContain(`like_regex "^v1[.][^.]+[.][^.]+[.][^.]+$"`);
  });

  it('starts a plugin off, with an empty config and no secret, at version 1', () => {
    expect(statements[0]).toContain('"enabled" boolean DEFAULT false NOT NULL');
    expect(statements[0]).toContain(`"config" jsonb DEFAULT '{}'::jsonb NOT NULL`);
    expect(statements[0]).toContain(`"secrets" jsonb DEFAULT '{}'::jsonb NOT NULL`);
    expect(statements[0]).toContain('"version" integer DEFAULT 1 NOT NULL');
  });
});
