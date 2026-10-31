/**
 * Migration 0047 adds `oauth_clients.verified_domain` (#593): one nullable
 * column with no default and a CHECK on its stored form. Its behaviour against
 * a real Postgres is held by `migration-0047.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { VERIFIED_DOMAIN_PATTERN } from '@qauth-labs/shared-validation';
import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0047_oauth_client_verified_domain';
const MIGRATION_IDX = 47;

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

describe('migration 0047 (oauth_clients.verified_domain)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0046', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0046_realm_policies');
  });

  it('only adds: one nullable column with no default and one CHECK, and rewrites no row', () => {
    expect(statements).toEqual([
      'ALTER TABLE "oauth_clients" ADD COLUMN "verified_domain" varchar(253);',
      `ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_verified_domain_form" CHECK ("oauth_clients"."verified_domain" IS NULL OR "oauth_clients"."verified_domain" ~ '${VERIFIED_DOMAIN_PATTERN}');`,
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|NOT NULL|DEFAULT)\b/);
  });
});
