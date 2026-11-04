/**
 * Migration 0058 adds the back-channel logout client metadata (OpenID Connect
 * Back-Channel Logout 1.0 §2.2, #624): `oauth_clients.backchannel_logout_uri`,
 * who set it (`backchannel_logout_uri_source`) and
 * `backchannel_logout_session_required`. Every existing client gets no URI,
 * and so no logout token; the flag defaults to `false`, so an earlier
 * release's INSERT, which names none of the three, keeps working during a
 * rolling upgrade. A CHECK keeps the source set exactly with the URI.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0058_client_backchannel_logout';
const MIGRATION_IDX = 58;

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

describe('migration 0058 (back-channel logout client metadata)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0057', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0057_client_post_logout_redirect_uris');
  });

  it('adds three columns an earlier release can insert past, ties the source to the URI, and writes no row', () => {
    expect(statements).toEqual([
      `ALTER TABLE "oauth_clients" ADD COLUMN "backchannel_logout_uri" text;`,
      `ALTER TABLE "oauth_clients" ADD COLUMN "backchannel_logout_uri_source" varchar(16);`,
      `ALTER TABLE "oauth_clients" ADD COLUMN "backchannel_logout_session_required" boolean DEFAULT false NOT NULL;`,
      `ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_backchannel_logout_source" CHECK (("oauth_clients"."backchannel_logout_uri" IS NULL AND "oauth_clients"."backchannel_logout_uri_source" IS NULL) OR ("oauth_clients"."backchannel_logout_uri" IS NOT NULL AND "oauth_clients"."backchannel_logout_uri_source" IN ('client', 'admin')));`,
    ]);
  });
});
