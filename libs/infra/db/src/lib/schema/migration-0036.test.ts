/**
 * Migration 0036 adds event retention (#536): a table of chain anchors, two
 * realm policy columns with their CHECKs, and the retention index in place
 * of `idx_events_time`, which no query used. Nothing else: no row is
 * rewritten (both columns have a constant default) and no other table is
 * touched.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0036_event_retention';

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

describe('migration 0036 (event retention)', () => {
  const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal', () => {
    expect(entry?.idx).toBe(36);
  });

  it('holds exactly the retention changes', () => {
    expect(statements.map((statement) => statement.replace(/\s+/g, ' '))).toEqual([
      expect.stringMatching(/^CREATE TABLE "event_chain_anchors" \(/),
      'DROP INDEX "idx_events_time";',
      'ALTER TABLE "realms" ADD COLUMN "user_event_retention_days" integer DEFAULT 90 NOT NULL;',
      'ALTER TABLE "realms" ADD COLUMN "admin_event_retention_days" integer DEFAULT 365 NOT NULL;',
      'CREATE INDEX "idx_events_retention" ON "events" USING btree ("realm_id","category","time");',
      'ALTER TABLE "realms" ADD CONSTRAINT "realms_user_event_retention_days_range" CHECK ("realms"."user_event_retention_days" between 1 and 36500);',
      'ALTER TABLE "realms" ADD CONSTRAINT "realms_admin_event_retention_days_range" CHECK ("realms"."admin_event_retention_days" between 90 and 36500);',
    ]);
  });

  it('drops an index no earlier migration gave a second use', () => {
    const earlier = journal.entries
      .filter((candidate) => candidate.idx < 36)
      .flatMap((candidate) => statementsOf(candidate.tag))
      .filter((statement) => statement.includes('idx_events_time'));
    expect(earlier).toEqual(['CREATE INDEX "idx_events_time" ON "events" USING btree ("time");']);
  });
});
