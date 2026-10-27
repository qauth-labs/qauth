/**
 * Migration 0038 records each refresh-token family's start and its browser
 * session's end (ADR-019 Decision 3, #552). It alters both
 * `authorization_codes` and `refresh_tokens`, so it locks them first, in the
 * order a code redemption takes them: otherwise a redemption in flight during
 * the upgrade can deadlock with it (see migration-0038.integration.test.ts).
 * The backfill stays one statement (the decision of 2026-10-25; the upgrade
 * guide measures the pause it causes).
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0038_refresh_family_created_at';

/** The fields of a Drizzle journal entry this test reads. */
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
        .replace(/\s+/g, ' ')
    )
    .filter((statement) => statement !== '');
}

describe('migration 0038 (refresh family start and session end)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal', () => {
    expect(journal.entries.find((entry) => entry.tag === MIGRATION_TAG)?.idx).toBe(38);
  });

  it('locks authorization_codes, then refresh_tokens, before anything else', () => {
    expect(statements.slice(0, 2)).toEqual([
      'LOCK TABLE "authorization_codes" IN ACCESS EXCLUSIVE MODE;',
      'LOCK TABLE "refresh_tokens" IN ACCESS EXCLUSIVE MODE;',
    ]);
  });

  it('keeps its own statements after the locks, the backfill as one statement', () => {
    const touching = (table: string) =>
      statements.slice(2).filter((statement) => statement.includes(`"${table}"`));
    expect(statements[2]).toBe(
      'ALTER TABLE "refresh_tokens" ADD COLUMN "family_created_at" bigint;'
    );
    expect(touching('authorization_codes')).toEqual([
      'ALTER TABLE "authorization_codes" ADD COLUMN "session_expires_at" bigint;',
    ]);
    expect(
      statements.filter((statement) => statement.startsWith('UPDATE "refresh_tokens"'))
    ).toHaveLength(1);
    expect(statements).toHaveLength(13);
  });
});
