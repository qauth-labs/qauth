/**
 * Migration 0048 adds the operator-set first-party client profile (ADR-017
 * Decision 2, #631): an enum type, then one ALTER TABLE with three nullable
 * columns with no default, the four CHECKs of the decision and two on the
 * stored forms. Its behaviour against a real Postgres is held by
 * `migration-0048.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { FIRST_PARTY_PROFILES } from '@qauth-labs/shared-validation';
import { describe, expect, it } from 'vitest';

import { firstPartyProfileEnum } from './enums';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0048_oauth_client_first_party_profile';
const MIGRATION_IDX = 48;

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

describe('migration 0048 (oauth_clients first-party profile)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0047', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0047_oauth_client_verified_domain');
  });

  it('creates the enum from the shared profile list', () => {
    expect(firstPartyProfileEnum.enumValues).toEqual([...FIRST_PARTY_PROFILES]);
    expect(statements[0]).toBe(
      `CREATE TYPE "public"."first_party_profile" AS ENUM(${FIRST_PARTY_PROFILES.map((p) => `'${p}'`).join(', ')});`
    );
  });

  it('only adds, in one ALTER TABLE (one lock, one scan): three nullable columns with no default and six CHECKs, and rewrites no row', () => {
    expect(statements).toHaveLength(2);
    const [alter] = statements.slice(1);
    expect(alter.startsWith('ALTER TABLE "oauth_clients"\n')).toBe(true);
    expect(alter.endsWith(';')).toBe(true);
    const clauses = alter
      .slice('ALTER TABLE "oauth_clients"\n'.length, -1)
      .split(',\n')
      .map((clause) => clause.trim());
    expect(clauses).toEqual([
      'ADD COLUMN "first_party_profile" "first_party_profile"',
      'ADD COLUMN "first_party_policy" jsonb',
      'ADD COLUMN "first_party_reason" text',
      `ADD CONSTRAINT "oauth_clients_first_party_operator_only" CHECK ("oauth_clients"."first_party_profile" IS NULL OR ("oauth_clients"."dynamic_registered_at" IS NULL AND "oauth_clients"."developer_id" IS NULL AND "oauth_clients"."is_agent" = false AND coalesce("oauth_clients"."metadata"->>'registrationType', '') NOT IN ('dynamic', 'cimd')))`,
      `ADD CONSTRAINT "oauth_clients_first_party_private_key_jwt" CHECK ("oauth_clients"."first_party_profile" IS NULL OR "oauth_clients"."token_endpoint_auth_method" = 'private_key_jwt')`,
      `ADD CONSTRAINT "oauth_clients_first_party_policy_native" CHECK (("oauth_clients"."first_party_profile" IS NOT DISTINCT FROM 'native_backend') = ("oauth_clients"."first_party_policy" IS NOT NULL))`,
      `ADD CONSTRAINT "oauth_clients_first_party_native_authorization_code" CHECK ("oauth_clients"."first_party_profile" IS DISTINCT FROM 'native_backend' OR "oauth_clients"."grant_types" ? 'authorization_code')`,
      `ADD CONSTRAINT "oauth_clients_first_party_reason" CHECK (("oauth_clients"."first_party_profile" IS NULL) = ("oauth_clients"."first_party_reason" IS NULL) AND ("oauth_clients"."first_party_reason" IS NULL OR (char_length("oauth_clients"."first_party_reason") <= 1000 AND "oauth_clients"."first_party_reason" ~ '\\S')))`,
      `ADD CONSTRAINT "oauth_clients_first_party_policy_object" CHECK ("oauth_clients"."first_party_policy" IS NULL OR jsonb_typeof("oauth_clients"."first_party_policy") = 'object')`,
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|RENAME|DEFAULT)\b/);
    for (const clause of clauses.filter((c) => c.startsWith('ADD COLUMN'))) {
      expect(clause).not.toMatch(/\bNOT NULL\b/);
    }
  });
});
