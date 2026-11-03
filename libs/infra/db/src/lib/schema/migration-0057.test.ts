/**
 * Migration 0057 adds `oauth_clients.post_logout_redirect_uris` (OpenID
 * Connect RP-Initiated Logout 1.0 §3.1, #675): where the end-session route
 * may send the browser after a logout. The column is NOT NULL with a `[]`
 * default, so an earlier release's INSERT, which does not name it, keeps
 * working during a rolling upgrade, and every existing client gets `[]`:
 * never redirect.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0057_client_post_logout_redirect_uris';
const MIGRATION_IDX = 57;

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

describe('migration 0057 (post-logout redirect URIs)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0056', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0056_realm_sandbox_pairing');
  });

  it('adds one column with an empty-list default an earlier release can insert past, and writes no row', () => {
    expect(statements).toEqual([
      `ALTER TABLE "oauth_clients" ADD COLUMN "post_logout_redirect_uris" jsonb DEFAULT '[]'::jsonb NOT NULL;`,
    ]);
  });
});
