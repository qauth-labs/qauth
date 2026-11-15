/**
 * Migration 0075 adds the logout-only sessions of #1144 (ADR-017 Decisions 8
 * and 10, amended 2026-11-15): `sessions.kind`, with a constant default of
 * `browser`, and `refresh_tokens.family_session_id`, a nullable link with no
 * default and no foreign key. Postgres adds both without rewriting either
 * table, every existing session reads as a browser's and every existing token
 * as unlinked, and a release before this one keeps inserting both during a
 * rolling upgrade.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { SESSION_KINDS, sessions } from './sessions';
import { refreshTokens } from './tokens';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0075_logout_only_sessions';
const MIGRATION_IDX = 75;

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

describe('migration 0075 (logout-only sessions)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0074', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0074_admin_grants_security_change');
  });

  it('adds two columns and an index that rewrite no table, and touches no row', () => {
    expect(statements.slice(0, 3)).toEqual([
      'ALTER TABLE "refresh_tokens" ADD COLUMN "family_session_id" uuid;',
      'CREATE INDEX "idx_refresh_tokens_family_session_id" ON "refresh_tokens" USING btree ("family_session_id") WHERE "refresh_tokens"."family_session_id" IS NOT NULL;',
      `ALTER TABLE "sessions" ADD COLUMN "kind" text DEFAULT 'browser' NOT NULL;`,
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|RENAME)\b/);
  });

  it('locks `sessions` last, never while the index build scans `refresh_tokens`', () => {
    const firstSessions = statements.findIndex((statement) =>
      statement.startsWith('ALTER TABLE "sessions"')
    );
    const index = statements.findIndex((statement) => statement.startsWith('CREATE INDEX'));
    expect(index).toBeGreaterThanOrEqual(0);
    expect(firstSessions).toBeGreaterThan(index);
    expect(statements.slice(firstSessions).every((s) => s.includes('"sessions"'))).toBe(true);
  });

  it('keeps the kind to the known ones, with a CHECK the schema holds, not validated', () => {
    expect(statements.slice(3)).toEqual([
      `ALTER TABLE "sessions" ADD CONSTRAINT "sessions_kind_valid" CHECK ("sessions"."kind" IN ('browser', 'registration', 'reset')) NOT VALID;`,
    ]);
    expect(SESSION_KINDS).toEqual(['browser', 'registration', 'reset']);
    expect(getTableConfig(sessions).checks.map((check) => check.name)).toContain(
      'sessions_kind_valid'
    );
  });

  it('is what the schema declares', () => {
    const kind = getTableConfig(sessions).columns.find((column) => column.name === 'kind');
    expect(kind?.notNull).toBe(true);
    expect(kind?.default).toBe('browser');
    const link = getTableConfig(refreshTokens).columns.find(
      (column) => column.name === 'family_session_id'
    );
    expect(link?.notNull).toBe(false);
    expect(link?.hasDefault).toBe(false);
    expect(getTableConfig(refreshTokens).foreignKeys).toHaveLength(3);
  });
});
