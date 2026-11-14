/**
 * Migration 0075 adds `realm_key_denylist` (#551): the `kid`s an emergency
 * retirement denied, which every role reads. A new, empty table that a
 * release before this one never names, so nothing is rewritten and a rolling
 * upgrade is safe. Its behaviour against a real Postgres is held by
 * `repositories/realm-keys.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { realmKeyDenylist } from './keys';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0075_key_denylist';
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
    .filter((statement) => statement !== '');
}

describe('migration 0075 (the kid denylist of emergency key retirement)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0074', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0074_admin_grants_security_change');
  });

  it('creates one new table and its realm foreign key, and touches no other table', () => {
    expect(statements).toHaveLength(2);
    expect(statements[0]).toMatch(/^CREATE TABLE "realm_key_denylist" \(/);
    expect(statements[1]).toMatch(
      /^ALTER TABLE "realm_key_denylist" ADD CONSTRAINT "realm_key_denylist_realm_id_realms_id_fk" FOREIGN KEY \("realm_id"\) REFERENCES "public"\."realms"\("id"\) ON DELETE cascade/
    );
    expect(statements.join('\n')).not.toMatch(
      /\b(DROP|DELETE FROM|INSERT INTO|RENAME)\b|^UPDATE\b/m
    );
  });

  it('keys a row by realm and kid, with no foreign key to the key row', () => {
    expect(statements[0]).toContain(
      'CONSTRAINT "realm_key_denylist_pk" PRIMARY KEY("realm_id","kid")'
    );
    const config = getTableConfig(realmKeyDenylist);
    expect(config.foreignKeys.map((fk) => fk.reference().foreignTable)).toHaveLength(1);
    expect(statements.join('\n')).not.toContain('"realm_keys"');
  });
});
