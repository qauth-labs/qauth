/**
 * Migration 0048 adds the operator-set first-party client profile (ADR-017
 * Decision 2, #631): an enum type, three nullable columns with no default and
 * the four CHECKs of the decision. Its behaviour against a real Postgres is
 * held by `migration-0048.integration.test.ts`.
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

  it('only adds: three nullable columns with no default and the four CHECKs, and rewrites no row', () => {
    expect(statements.slice(1)).toEqual([
      'ALTER TABLE "oauth_clients" ADD COLUMN "first_party_profile" "first_party_profile";',
      'ALTER TABLE "oauth_clients" ADD COLUMN "first_party_policy" jsonb;',
      'ALTER TABLE "oauth_clients" ADD COLUMN "first_party_reason" text;',
      `ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_first_party_operator_only" CHECK ("oauth_clients"."first_party_profile" IS NULL OR ("oauth_clients"."dynamic_registered_at" IS NULL AND "oauth_clients"."developer_id" IS NULL AND "oauth_clients"."is_agent" = false AND coalesce("oauth_clients"."metadata"->>'registrationType', '') NOT IN ('dynamic', 'cimd')));`,
      `ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_first_party_private_key_jwt" CHECK ("oauth_clients"."first_party_profile" IS NULL OR "oauth_clients"."token_endpoint_auth_method" = 'private_key_jwt');`,
      `ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_first_party_policy_native" CHECK (("oauth_clients"."first_party_profile" IS NOT DISTINCT FROM 'native_backend') = ("oauth_clients"."first_party_policy" IS NOT NULL));`,
      `ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_first_party_native_authorization_code" CHECK ("oauth_clients"."first_party_profile" IS DISTINCT FROM 'native_backend' OR "oauth_clients"."grant_types" ? 'authorization_code');`,
    ]);
    expect(statements.join('\n')).not.toMatch(/\b(DROP|UPDATE|DELETE|INSERT|RENAME|DEFAULT)\b/);
    for (const statement of statements.filter((s) => s.includes('ADD COLUMN'))) {
      expect(statement).not.toMatch(/\bNOT NULL\b/);
    }
  });
});
