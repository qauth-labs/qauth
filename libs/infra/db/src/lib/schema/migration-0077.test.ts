/**
 * Migration 0077 adds `deployment_nodes` (#499): the node list each auth
 * server node registers in and compares its configuration digest with at
 * boot, and the four functions every role reaches it through. A new, empty
 * table that a release before this one never names, so nothing is rewritten
 * and a rolling upgrade is safe. Its behaviour against a
 * real Postgres is held by `repositories/deployment-nodes.integration.test.ts`
 * and the auth server's `deployment-nodes.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { DEPLOYMENT_NODE_FUNCTIONS } from '../database-users/grants-map';
import { deploymentNodes } from './deployment-nodes';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0077_deployment_nodes';
const MIGRATION_IDX = 77;

interface JournalEntry {
  idx: number;
  tag: string;
  when: number;
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

describe('migration 0077 (the node list of the configuration digest)', () => {
  const statements = statementsOf(MIGRATION_TAG);
  const table = statements.find((statement) => statement.startsWith('CREATE TABLE')) ?? '';

  it('is in the journal, after 0076', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0076_key_denylist');
  });

  it('chains its snapshot from the one before, and comes after it in time', () => {
    const snapshotOf = (idx: number): { id: string; prevId: string } =>
      JSON.parse(
        readFileSync(
          path.join(DRIZZLE_DIR, `meta/${String(idx).padStart(4, '0')}_snapshot.json`),
          'utf8'
        )
      );
    expect(snapshotOf(MIGRATION_IDX).prevId).toBe(snapshotOf(MIGRATION_IDX - 1).id);
    // The migrator runs a migration only when it is newer than the last one applied.
    const when = (idx: number) => journal.entries[idx]?.when ?? 0;
    expect(when(MIGRATION_IDX)).toBeGreaterThan(when(MIGRATION_IDX - 1));
  });

  it('creates one new table, its key check first, and touches no other table', () => {
    expect(statements[0]).toMatch(
      /^CREATE FUNCTION "deployment_nodes_config_keys_valid"\(p_keys jsonb\)/
    );
    expect(statements[1]).toMatch(/^CREATE TABLE "deployment_nodes" \(/);
    expect(statements.filter((statement) => statement.startsWith('CREATE TABLE'))).toHaveLength(1);
    // Every statement past the table creates a function or revokes it from PUBLIC.
    for (const statement of statements.slice(2)) {
      expect(statement).toMatch(
        /^(CREATE FUNCTION "deployment_nodes_|REVOKE ALL ON FUNCTION "deployment_nodes_)/
      );
    }
    expect(statements.join('\n')).not.toMatch(/\b(DROP|RENAME|ALTER TABLE|TRUNCATE)\b/);
    expect(getTableConfig(deploymentNodes).foreignKeys).toHaveLength(0);
  });

  it('keys a row by its node id and stores digests, never a value', () => {
    expect(table).toContain('"node_id" uuid PRIMARY KEY NOT NULL');
    expect(table).toContain('"registered_by" text DEFAULT session_user NOT NULL');
    for (const constraint of [
      `CONSTRAINT "deployment_nodes_config_digest_hex" CHECK ("deployment_nodes"."config_digest" ~ '^[0-9a-f]{64}$')`,
      `CONSTRAINT "deployment_nodes_config_keys_valid" CHECK (deployment_nodes_config_keys_valid("deployment_nodes"."config_keys"))`,
      'CONSTRAINT "deployment_nodes_roles_not_empty" CHECK (cardinality("deployment_nodes"."roles") > 0)',
      `CONSTRAINT "deployment_nodes_roles_known" CHECK ("deployment_nodes"."roles" <@ ARRAY['web', 'api', 'admin', 'signer', 'delivery']::text[])`,
    ]) {
      expect(table).toContain(constraint);
    }
    const columns = getTableConfig(deploymentNodes).columns.map((column) => column.name);
    expect(columns.sort()).toEqual(
      [
        'config_digest',
        'config_keys',
        'last_seen_at',
        'node_id',
        'registered_by',
        'roles',
        'started_at',
        'version',
      ].sort()
    );
  });

  it('gives the roles four functions over the table, each a definer with a pinned search_path, taken from PUBLIC', () => {
    const functions = statements.filter((statement) =>
      statement.startsWith('CREATE FUNCTION "deployment_nodes_')
    );
    const definers = functions.filter((statement) => statement.includes('SECURITY DEFINER'));
    expect(
      definers.map((statement) => /^CREATE FUNCTION "([a-z_]+)"/.exec(statement)?.[1])
    ).toEqual([
      'deployment_nodes_live',
      'deployment_nodes_register',
      'deployment_nodes_heartbeat',
      'deployment_nodes_remove',
    ]);
    for (const statement of functions) {
      expect(statement).toContain('SET search_path = pg_catalog, pg_temp');
    }
    const sql = statements.join('\n');
    for (const signature of DEPLOYMENT_NODE_FUNCTIONS) {
      expect(sql, signature).toContain(`REVOKE ALL ON FUNCTION ${signature} FROM PUBLIC`);
    }
  });

  it("marks seen and removes only the rows of the database user that registered them, at the database's time", () => {
    const named = (name: string) =>
      statements.find((statement) => statement.startsWith(`CREATE FUNCTION "${name}"`)) ?? '';
    expect(named('deployment_nodes_heartbeat')).toContain('WHERE n."registered_by" = session_user');
    expect(named('deployment_nodes_remove')).toContain('AND "registered_by" = session_user');
    expect(named('deployment_nodes_register')).toContain('greatest(p_window_ms, 120000)');
    // No function takes a time the caller chose but the start of a row it
    // writes again, and never a later one than now.
    expect(named('deployment_nodes_heartbeat')).toContain(
      'least(greatest(p_started_at, 0), EXTRACT(EPOCH FROM NOW())::bigint * 1000)'
    );
    expect(named('deployment_nodes_register')).not.toContain('"started_at"');
  });

  it("takes the list's advisory lock before a heartbeat writes, as a registration does", () => {
    const named = (name: string) =>
      statements.find((statement) => statement.startsWith(`CREATE FUNCTION "${name}"`)) ?? '';
    const lock = "pg_advisory_xact_lock(hashtextextended('qauth:deployment-nodes', 0))";
    for (const name of ['deployment_nodes_register', 'deployment_nodes_heartbeat']) {
      const body = named(name);
      expect(body, name).toContain(lock);
      expect(body.indexOf(lock), name).toBeLessThan(body.indexOf('INSERT INTO'));
    }
  });
});
