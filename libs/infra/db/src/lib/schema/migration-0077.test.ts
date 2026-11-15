/**
 * Migration 0077 adds `protected_resources` (#1087): the protected resources
 * a realm registers, the scopes each defines and the clients that may ask
 * for them. A new, empty table that a release before this one never names,
 * so nothing is rewritten and a rolling upgrade is safe. Its behaviour
 * against a real Postgres is held by
 * `repositories/protected-resources.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { protectedResources } from './protected-resources';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0077_protected_resources';
const MIGRATION_IDX = 77;

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

describe('migration 0077 (the protected resources of a realm)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0076', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0076_deployment_nodes');
  });

  it('creates one new table and its realm foreign key, and touches no other table', () => {
    expect(statements).toHaveLength(2);
    expect(statements[0]).toMatch(/^CREATE TABLE "protected_resources" \(/);
    expect(statements[1]).toMatch(
      /^ALTER TABLE "protected_resources" ADD CONSTRAINT "protected_resources_realm_id_realms_id_fk" FOREIGN KEY \("realm_id"\) REFERENCES "public"\."realms"\("id"\) ON DELETE cascade/
    );
    expect(statements.join('\n')).not.toMatch(
      /\b(DROP|DELETE FROM|INSERT INTO|RENAME)\b|^UPDATE\b/m
    );
  });

  it('keeps one resource indicator per realm, and lists clients only when not open to all', () => {
    expect(statements[0]).toContain(
      'CONSTRAINT "protected_resources_realm_resource" UNIQUE("realm_id","resource")'
    );
    expect(statements[0]).toContain('CONSTRAINT "protected_resources_any_client_lists_none"');
    const config = getTableConfig(protectedResources);
    expect(config.foreignKeys.map((fk) => fk.reference().foreignTable)).toHaveLength(1);
  });
});
