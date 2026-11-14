/**
 * Migration 0076 adds `deployment_nodes` (#499): the node list each auth
 * server node registers in and compares its configuration digest with at
 * boot. A new, empty table that a release before this one never names, so
 * nothing is rewritten and a rolling upgrade is safe. Its behaviour against a
 * real Postgres is held by `repositories/deployment-nodes.integration.test.ts`
 * and the auth server's `deployment-nodes.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { deploymentNodes } from './deployment-nodes';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0076_deployment_nodes';
const MIGRATION_IDX = 76;

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

describe('migration 0076 (the node list of the configuration digest)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0075', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0075_key_denylist');
  });

  it('creates one new table and touches no other', () => {
    expect(statements).toHaveLength(1);
    expect(statements[0]).toMatch(/^CREATE TABLE "deployment_nodes" \(/);
    expect(statements.join('\n')).not.toMatch(
      /\b(DROP|DELETE FROM|INSERT INTO|RENAME|ALTER TABLE)\b|^UPDATE\b/m
    );
    expect(getTableConfig(deploymentNodes).foreignKeys).toHaveLength(0);
  });

  it('keys a row by its node id and stores digests, never a value', () => {
    expect(statements[0]).toContain('"node_id" uuid PRIMARY KEY NOT NULL');
    expect(statements[0]).toContain(
      `CONSTRAINT "deployment_nodes_config_digest_hex" CHECK ("deployment_nodes"."config_digest" ~ '^[0-9a-f]{64}$')`
    );
    expect(statements[0]).toContain(
      `CONSTRAINT "deployment_nodes_config_keys_object" CHECK (jsonb_typeof("deployment_nodes"."config_keys") = 'object')`
    );
    expect(statements[0]).toContain(
      'CONSTRAINT "deployment_nodes_roles_not_empty" CHECK (cardinality("deployment_nodes"."roles") > 0)'
    );
    const columns = getTableConfig(deploymentNodes).columns.map((column) => column.name);
    expect(columns.sort()).toEqual(
      [
        'config_digest',
        'config_keys',
        'last_seen_at',
        'node_id',
        'roles',
        'started_at',
        'version',
      ].sort()
    );
  });
});
