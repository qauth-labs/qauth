/**
 * Migration 0053 adds `oid4vp_request_states.response_encryption_sealing_kid`
 * (#546): the `kid` of the realm's `data_at_rest` key that sealed a request's
 * ephemeral response key, in place of the pre-#546 protection marker.
 *
 * One nullable column with no default, and the encrypted-response CHECK
 * widened to accept either way of writing the key, never both. A node of the
 * previous release keeps inserting marker rows during a rolling upgrade, and
 * every row already in flight still satisfies both constraints, so they
 * validate without a backfill.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0053_oid4vp_response_key_sealing_kid';
const MIGRATION_IDX = 53;
const TABLE = '"oid4vp_request_states"';

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

const column = (name: string) => `${TABLE}."${name}"`;
const KID = column('response_encryption_kid');
const JWK = column('response_encryption_private_jwk');
const MARKER = column('response_encryption_key_protection');
const SEALING = column('response_encryption_sealing_kid');

describe('migration 0053 (oid4vp_request_states.response_encryption_sealing_kid)', () => {
  it('is in the journal, after 0052', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0052_user_credentials_disabled_at');
  });

  it('adds one nullable column and widens the completeness CHECK, with no backfill', () => {
    expect(statementsOf(MIGRATION_TAG)).toEqual([
      `ALTER TABLE ${TABLE} DROP CONSTRAINT "oid4vp_request_states_response_encryption_complete";`,
      `ALTER TABLE ${TABLE} ADD COLUMN "response_encryption_sealing_kid" varchar(255);`,
      `ALTER TABLE ${TABLE} ADD CONSTRAINT "oid4vp_request_states_response_encryption_sealed_once" CHECK (${MARKER} is null or ${SEALING} is null);`,
      `ALTER TABLE ${TABLE} ADD CONSTRAINT "oid4vp_request_states_response_encryption_complete" CHECK ((${KID} is null and ${JWK} is null and ${MARKER} is null and ${SEALING} is null) or (${KID} is not null and ${JWK} is not null and (${MARKER} is not null or ${SEALING} is not null)));`,
    ]);
  });

  it('keeps the marker vocabulary as it was', () => {
    expect(statementsOf(MIGRATION_TAG).join('\n')).not.toContain('key_protection_valid');
  });
});
