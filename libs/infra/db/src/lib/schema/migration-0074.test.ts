/**
 * Migration 0074 gives the two-admin rule (#521, ADR-019 Decision 7) its one
 * write: `admin_grants_record_security_change`, a definer function that moves
 * `last_security_change_at` of an account's live grants to now when its
 * credentials, identifier or contact address change. No role holds `UPDATE`
 * on `admin_grants`. Its behaviour against a real Postgres is held by
 * `lib/repositories/admin-grants.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0074_admin_grants_security_change';
const MIGRATION_IDX = 74;

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

describe('migration 0074 (the two-admin rule records a security change)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0073', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe(
      '0073_auth_method_plugin_assertion_client'
    );
  });

  it('adds one definer function, taken from PUBLIC, and changes no table', () => {
    expect(statements).toHaveLength(2);
    const [fn, revoke] = statements;
    expect(fn).toMatch(
      /^CREATE FUNCTION "admin_grants_record_security_change"\(p_realm_id uuid, p_user_id uuid\)/
    );
    expect(fn).toContain('SECURITY DEFINER');
    expect(fn).toContain('SET search_path = pg_catalog, pg_temp');
    expect(revoke).toBe(
      'REVOKE ALL ON FUNCTION "admin_grants_record_security_change"(uuid, uuid) FROM PUBLIC;'
    );
    expect(statements.join('\n')).not.toMatch(/\b(ALTER|DROP|DELETE|INSERT|TRUNCATE|GRANT)\b/);
  });

  it("moves last_security_change_at alone, forward only, on the live grants of the realm's account", () => {
    const fn = statements[0] ?? '';
    const assignments = /\bSET\s+("[\s\S]*?)\bWHERE\b/.exec(fn)?.[1] ?? '';
    expect([...assignments.matchAll(/"([a-z_]+)" =/g)].map((match) => match[1])).toEqual([
      'last_security_change_at',
    ]);
    // The database's time, never one the caller names, and never back.
    expect(assignments).toContain(
      'greatest(EXTRACT(EPOCH FROM NOW())::bigint * 1000, g."last_security_change_at")'
    );
    expect(fn).not.toMatch(/p_at\b/);
    expect(fn).toContain('g."user_id" = p_user_id');
    expect(fn).toContain('g."revoked_at" IS NULL');
    expect(fn).toContain('u."realm_id" = p_realm_id');
  });
});
