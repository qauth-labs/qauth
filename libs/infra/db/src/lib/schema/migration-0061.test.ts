/**
 * Migration 0061 adds `oauth_clients.hosted_flows` (ADR-017 Decision 8, #640):
 * the hosted flows a redirect-flow client may start beyond sign-in. A new
 * nullable column with no default and a CHECK that holds its stored form, so
 * every existing row reads NULL (no hosted flow) and an earlier release, which
 * never names the column, keeps working during a rolling upgrade.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0061_client_hosted_flows';
const MIGRATION_IDX = 61;

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
    .filter((statement) => statement !== '')
    .map((statement) => statement.replace(/\s+/g, ' '));
}

describe('migration 0061 (client hosted flows)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0060', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0060_realm_upstream_providers');
  });

  it('adds a nullable column with no default, and its CHECK, and nothing else', () => {
    expect(statements).toEqual([
      'ALTER TABLE "oauth_clients" ADD COLUMN "hosted_flows" jsonb;',
      `ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_hosted_flows_array" CHECK ("oauth_clients"."hosted_flows" IS NULL OR jsonb_typeof("oauth_clients"."hosted_flows") = 'array');`,
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|RENAME|DEFAULT)\b/);
  });
});
