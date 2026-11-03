/**
 * Migration 0055 gives the SSF subject sweep (#540) the one read it needs
 * from the event store as a `SECURITY DEFINER` function, so the role that
 * runs the sweep (`api`) holds no `SELECT` on `events` once each role has a
 * database user of its own (#498, ADR-019 Decisions 8 and 9). What the
 * function answers is held by the sweep's container suites.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0055_ssf_subject_sweep_reads';
const MIGRATION_IDX = 55;

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

describe('migration 0055 (the SSF subject sweep reads the event store through a function)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0054', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0054_admin_approvals_no_request_body');
  });

  it('creates the function and takes it from PUBLIC, and nothing else', () => {
    expect(statements).toHaveLength(2);
    expect(statements[0]).toMatch(
      /^CREATE FUNCTION "ssf_subject_events_pending"\(p_stream_id uuid, p_subject_id text\) RETURNS boolean /
    );
    expect(statements[1]).toBe(
      'REVOKE ALL ON FUNCTION "ssf_subject_events_pending"(uuid, text) FROM PUBLIC;'
    );
  });

  it('runs as the owner with a pinned search path, and reads every table by its schema', () => {
    const [create = ''] = statements;
    expect(create).toContain(' STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp ');
    const tables = [...create.matchAll(/(?:FROM|JOIN) (\S+)/g)].map((match) => match[1]);
    expect(tables.length).toBeGreaterThan(0);
    for (const table of tables) expect(table, table).toMatch(/^public\."[a-z_]+"$/);
  });

  it('answers only a boolean, about the stream it is given and a user subject', () => {
    const [create = ''] = statements;
    expect(create).toContain('RETURNS boolean');
    expect(create).toContain('AS $$ SELECT EXISTS (');
    expect(create).toContain(`WHERE s."id" = p_stream_id AND e."subject_type" = 'user'`);
    expect(create).toContain(`d."destination_id" = p_stream_id::text`);
    expect(create).toContain(`d."destination_kind" = 'ssf'`);
    expect(create).toContain(`p."destination_kind" = 'ssf'`);
  });
});
