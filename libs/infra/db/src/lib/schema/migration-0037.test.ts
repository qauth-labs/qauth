/**
 * Migration 0037 binds tokens to a DPoP key (RFC 9449, #480): one operator
 * column on `oauth_clients` and one thumbprint column each on
 * `authorization_codes` and `refresh_tokens`, with a CHECK on the thumbprint's
 * form. Nothing else: no row is rewritten (the flag has a constant default and
 * the thumbprints start NULL) and no other table is touched.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0037_dpop_binding';

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

describe('migration 0037 (DPoP binding)', () => {
  const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);

  it('is in the journal', () => {
    expect(entry?.idx).toBe(37);
  });

  it('holds exactly the three columns and the two thumbprint CHECKs', () => {
    expect(statementsOf(MIGRATION_TAG).map((statement) => statement.replace(/\s+/g, ' '))).toEqual([
      'ALTER TABLE "oauth_clients" ADD COLUMN "dpop_bound_access_tokens" boolean DEFAULT false NOT NULL;',
      'ALTER TABLE "authorization_codes" ADD COLUMN "dpop_jkt" varchar(43);',
      'ALTER TABLE "refresh_tokens" ADD COLUMN "cnf_jkt" varchar(43);',
      `ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_dpop_jkt_format" CHECK ("authorization_codes"."dpop_jkt" IS NULL OR "authorization_codes"."dpop_jkt" ~ '^[A-Za-z0-9_-]{43}$');`,
      `ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_cnf_jkt_format" CHECK ("refresh_tokens"."cnf_jkt" IS NULL OR "refresh_tokens"."cnf_jkt" ~ '^[A-Za-z0-9_-]{43}$');`,
    ]);
  });
});
