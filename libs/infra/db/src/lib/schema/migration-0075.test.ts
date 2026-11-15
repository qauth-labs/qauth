/**
 * Migration 0075 adds the logout-only sessions of #1144 (ADR-017 Decisions 8
 * and 10, amended 2026-11-15): `sessions.kind`, with a constant default of
 * `browser`, and `session_refresh_families`, a new table that links a
 * logout-only session to the refresh families its codes started. Refresh rows
 * name no session (#549). Postgres adds the column without rewriting
 * `sessions`, every existing session reads as a browser's, and a release
 * before this one keeps inserting sessions and refresh tokens during a
 * rolling upgrade.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { SESSION_KINDS, sessionRefreshFamilies, sessions } from './sessions';
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

  it('alters `sessions` first, without rewriting it, and keeps the kind to the known ones', () => {
    expect(statements.slice(0, 2)).toEqual([
      `ALTER TABLE "sessions" ADD COLUMN "kind" text DEFAULT 'browser' NOT NULL;`,
      `ALTER TABLE "sessions" ADD CONSTRAINT "sessions_kind_valid" CHECK ("sessions"."kind" IN ('browser', 'registration', 'reset')) NOT VALID;`,
    ]);
    expect(SESSION_KINDS).toEqual(['browser', 'registration', 'reset']);
    expect(getTableConfig(sessions).checks.map((check) => check.name)).toContain(
      'sessions_kind_valid'
    );
  });

  it('creates the link table, whose session foreign key cascades', () => {
    expect(statements.slice(2)).toEqual([
      'CREATE TABLE "session_refresh_families" ( "session_id" uuid NOT NULL, "family_id" uuid NOT NULL, CONSTRAINT "session_refresh_families_pk" PRIMARY KEY("session_id","family_id") );',
      'ALTER TABLE "session_refresh_families" ADD CONSTRAINT "session_refresh_families_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE cascade ON UPDATE no action;',
    ]);
  });

  it('touches no row and drops nothing', () => {
    // A foreign key's referential actions name DELETE and UPDATE; no statement does.
    const statementsOnly = statements.map((statement) =>
      statement.replace(/ON DELETE \w+ ON UPDATE no action/, '')
    );
    expect(statementsOnly.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|RENAME)\b/);
  });

  it('puts no session link on refresh rows (#549)', () => {
    expect(statements.join('\n')).not.toContain('"refresh_tokens"');
    expect(getTableConfig(refreshTokens).columns.map((column) => column.name)).not.toEqual(
      expect.arrayContaining([expect.stringMatching(/session_id|sid/)])
    );
  });

  it('is what the schema declares', () => {
    const kind = getTableConfig(sessions).columns.find((column) => column.name === 'kind');
    expect(kind?.notNull).toBe(true);
    expect(kind?.default).toBe('browser');
    const links = getTableConfig(sessionRefreshFamilies);
    expect(links.name).toBe('session_refresh_families');
    expect(links.columns.map((column) => [column.name, column.notNull])).toEqual([
      ['session_id', true],
      ['family_id', true],
    ]);
    expect(links.primaryKeys.map((key) => key.getName())).toEqual(['session_refresh_families_pk']);
    expect(links.foreignKeys).toHaveLength(1);
  });
});
