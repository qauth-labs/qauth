/**
 * Migration 0065 adds how and when the user signed in to the tokens of a
 * browser sign-in (ADR-017 Decision 10, #662): `authorization_codes.amr`,
 * `refresh_tokens.auth_time` and `refresh_tokens.amr`. Three nullable columns
 * with no default and their CHECKs, after the locks in the writers' order, so
 * every existing row reads NULL and an earlier release, which never names the
 * columns, keeps working during a rolling upgrade.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0065_token_sign_in_methods';
const MIGRATION_IDX = 65;

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

describe('migration 0065 (token sign-in methods)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0064', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0064_user_recovery_codes');
  });

  it('locks authorization_codes before refresh_tokens, as every writer of both does', () => {
    expect(statements.slice(0, 2)).toEqual([
      'LOCK TABLE "authorization_codes" IN ACCESS EXCLUSIVE MODE;',
      'LOCK TABLE "refresh_tokens" IN ACCESS EXCLUSIVE MODE;',
    ]);
  });

  it('adds three nullable columns with no default, and their CHECKs, and nothing else', () => {
    expect(statements.slice(2)).toEqual([
      'ALTER TABLE "authorization_codes" ADD COLUMN "amr" jsonb;',
      'ALTER TABLE "refresh_tokens" ADD COLUMN "auth_time" bigint;',
      'ALTER TABLE "refresh_tokens" ADD COLUMN "amr" jsonb;',
      `ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_amr_valid" CHECK ("authorization_codes"."amr" IS NULL OR ("authorization_codes"."auth_time" IS NOT NULL AND jsonb_typeof("authorization_codes"."amr") = 'array' AND "authorization_codes"."amr" <> '[]'::jsonb));`,
      'ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_auth_time_positive" CHECK ("refresh_tokens"."auth_time" IS NULL OR "refresh_tokens"."auth_time" > 0);',
      `ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_amr_valid" CHECK ("refresh_tokens"."amr" IS NULL OR ("refresh_tokens"."auth_time" IS NOT NULL AND jsonb_typeof("refresh_tokens"."amr") = 'array' AND "refresh_tokens"."amr" <> '[]'::jsonb));`,
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|RENAME|DEFAULT)\b/);
  });
});
