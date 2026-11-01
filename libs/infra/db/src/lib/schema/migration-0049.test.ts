/**
 * Migration 0049 adds `realm_secrets` (#529): the encrypted values of the
 * realms' secret policy fields. One new table, whose CHECKs take only the
 * signer's `data_at_rest` format, and its foreign key to the realm. Its
 * behaviour against a real Postgres is held by
 * `repositories/realm-secrets.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0049_realm_secrets';
const MIGRATION_IDX = 49;

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

describe('migration 0049 (realm_secrets)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0048', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0048_oauth_client_first_party_profile');
  });

  it('only adds: the table, with ciphertext-only CHECKs, and its realm foreign key', () => {
    expect(statements).toHaveLength(2);
    const [create, foreignKey] = statements;
    expect(create).toMatch(/^CREATE TABLE "realm_secrets" \(/);
    expect(create).toContain('"ciphertext" text,');
    expect(create).toContain('"key_id" varchar(255),');
    expect(create).toContain('CONSTRAINT "realm_secrets_pk" PRIMARY KEY("realm_id","name")');
    expect(create).toContain(
      `CONSTRAINT "realm_secrets_ciphertext_form" CHECK ("realm_secrets"."ciphertext" IS NULL OR ("realm_secrets"."ciphertext" ~ '^v1\\.[A-Za-z0-9_-]{1,255}\\.[A-Za-z0-9_-]{16}\\.[A-Za-z0-9_-]{22,}$' AND split_part("realm_secrets"."ciphertext", '.', 2) = "realm_secrets"."key_id"))`
    );
    expect(create).toContain(
      'CONSTRAINT "realm_secrets_value_and_key_together" CHECK (("realm_secrets"."ciphertext" IS NULL) = ("realm_secrets"."key_id" IS NULL))'
    );
    expect(foreignKey).toBe(
      'ALTER TABLE "realm_secrets" ADD CONSTRAINT "realm_secrets_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;'
    );
    expect(create).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT)\b/);
  });
});
