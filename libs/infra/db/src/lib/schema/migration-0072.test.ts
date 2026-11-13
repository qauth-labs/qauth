/**
 * Migration 0072 records the window of a factor bound after a sign-in that
 * proved only the account's password (#1064, ADR-017 Decision 8 amended
 * 2026-11-12): `user_credentials.new_until`, a nullable column with no
 * default, and `sessions.new_credential_ids`, the new credentials a session's
 * sign-in bound or proved, with a constant default. Postgres adds both without
 * rewriting either table, every existing credential reads as never new and
 * every existing session as naming none, and a release before this one keeps
 * binding factors and inserting sessions during a rolling upgrade.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { userCredentials } from './identity';
import { sessions } from './sessions';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0072_new_factor_window';
const MIGRATION_IDX = 72;

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

describe('migration 0072 (the new-factor window)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0071', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0071_client_token_lifetimes');
  });

  it('adds two columns that rewrite no table, and touches no row', () => {
    expect(statements.slice(0, 2)).toEqual([
      'ALTER TABLE "user_credentials" ADD COLUMN "new_until" bigint;',
      `ALTER TABLE "sessions" ADD COLUMN "new_credential_ids" jsonb DEFAULT '[]'::jsonb NOT NULL;`,
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|RENAME)\b/);
  });

  it('keeps the session list an array, with a CHECK the schema holds, not validated', () => {
    expect(statements.slice(2)).toEqual([
      `ALTER TABLE "sessions" ADD CONSTRAINT "sessions_new_credential_ids_is_array" CHECK (jsonb_typeof("sessions"."new_credential_ids") = 'array') NOT VALID;`,
    ]);
    expect(getTableConfig(sessions).checks.map((check) => check.name)).toContain(
      'sessions_new_credential_ids_is_array'
    );
  });

  it('is what the schema declares', () => {
    const column = getTableConfig(userCredentials).columns.find(
      (candidate) => candidate.name === 'new_until'
    );
    expect(column?.notNull).toBe(false);
    expect(column?.hasDefault).toBe(false);
  });
});
