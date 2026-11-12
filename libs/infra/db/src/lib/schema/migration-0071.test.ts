/**
 * Migration 0071 gives a client its own token lifetimes (#632, ADR-020 §3):
 * `oauth_clients.access_token_lifespan_seconds` and
 * `refresh_token_lifespan_seconds`, two nullable columns with no default, so
 * Postgres adds them without rewriting the table, every existing client
 * takes the realm's lifetimes, and a release before this one keeps writing
 * clients during a rolling upgrade. The admin API writes them, and the token
 * endpoint takes the shorter of each and the realm's.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { oauthClients } from './core';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0071_client_token_lifetimes';
const MIGRATION_IDX = 71;

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

describe('migration 0071 (a client’s own token lifetimes)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0070', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0070_users_operator_verification');
  });

  it('adds two nullable columns with no default, and touches no row', () => {
    expect(statements.slice(0, 2)).toEqual([
      'ALTER TABLE "oauth_clients" ADD COLUMN "access_token_lifespan_seconds" integer;',
      'ALTER TABLE "oauth_clients" ADD COLUMN "refresh_token_lifespan_seconds" integer;',
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|RENAME|DEFAULT)\b/);
    expect(statements.join('\n')).not.toContain('NOT NULL');
  });

  it('bounds each as the realm’s own lifetime is bounded, with CHECKs the schema holds', () => {
    const added = statements.slice(2);
    const names = added.map(
      (statement) =>
        /^ALTER TABLE "oauth_clients" ADD CONSTRAINT "([a-z_]+)" CHECK \(/.exec(statement)?.[1]
    );
    expect(names).toEqual([
      'oauth_clients_access_token_lifespan_bounds',
      'oauth_clients_refresh_token_lifespan_bounds',
    ]);
    const table = getTableConfig(oauthClients);
    expect(table.checks.map((check) => check.name)).toEqual(expect.arrayContaining(names));
    // A day for an access token, 90 days for a refresh token.
    expect(added[0]).toContain('BETWEEN 1 AND 86400');
    expect(added[1]).toContain('BETWEEN 1 AND 7776000');
    // Not validated against the rows already there, which all read NULL:
    // no scan holds the table's lock.
    for (const statement of added) expect(statement).toMatch(/\) NOT VALID;$/);
  });
});
