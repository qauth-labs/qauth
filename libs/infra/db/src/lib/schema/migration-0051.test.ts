/**
 * Migration 0051 adds `oauth_clients.client_credentials_scopes` (#891): one
 * nullable column with no default and a CHECK on its stored shape. Its
 * behaviour against a real Postgres is held by
 * `migration-0051.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0051_oauth_client_client_credentials_scopes';
const MIGRATION_IDX = 51;

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

describe('migration 0051 (oauth_clients.client_credentials_scopes)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0050', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0050_realm_auth_method_plugins');
  });

  it('only adds: one nullable column with no default and one CHECK, and rewrites no row', () => {
    expect(statements).toEqual([
      'ALTER TABLE "oauth_clients" ADD COLUMN "client_credentials_scopes" jsonb;',
      `ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_client_credentials_scopes_is_array" CHECK ("oauth_clients"."client_credentials_scopes" IS NULL OR jsonb_typeof("oauth_clients"."client_credentials_scopes") = 'array');`,
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|NOT NULL|DEFAULT)\b/);
  });
});
