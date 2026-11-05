/**
 * Migration 0063 adds `oauth_clients.registration_challenge` (ADR-017
 * Decision 7, #643): whether a registration the client starts must pass the
 * bot challenge first. A new nullable column with no default, so every
 * existing row reads NULL (the realm's policy decides) and an earlier
 * release, which never names the column, keeps working during a rolling
 * upgrade.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0063_client_registration_challenge';
const MIGRATION_IDX = 63;

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

describe('migration 0063 (client registration challenge)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0062', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0062_user_session_epochs');
  });

  it('adds a nullable column with no default, and nothing else', () => {
    expect(statements).toEqual([
      'ALTER TABLE "oauth_clients" ADD COLUMN "registration_challenge" boolean;',
    ]);
    expect(statements.join('\n')).not.toMatch(
      /\b(DROP|UPDATE|DELETE|INSERT|RENAME|DEFAULT|NOT NULL)\b/
    );
  });
});
