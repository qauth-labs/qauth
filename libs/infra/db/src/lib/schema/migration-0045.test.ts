/**
 * Migration 0045 adds the realm policies to the realm row (#516): the policy
 * document, its schema version and its counter, the CHECKs that keep them
 * consistent, and the trigger that raises the counter whenever the policies
 * change and never lets it move back. It writes no row: the boot step fills
 * a realm's policies from the environment. The behaviour is held by
 * `migration-0045.integration.test.ts` against a real Postgres.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0045_realm_policies';
const MIGRATION_IDX = 45;

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

describe('migration 0045 (realm policies)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0044', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0044_users_not_valid_before');
  });

  it('adds three columns with defaults an earlier release can insert past, and writes no row', () => {
    expect(statements.slice(0, 3)).toEqual([
      `ALTER TABLE "realms" ADD COLUMN "policies" jsonb DEFAULT '{}'::jsonb NOT NULL;`,
      'ALTER TABLE "realms" ADD COLUMN "policy_schema_version" varchar(32);',
      'ALTER TABLE "realms" ADD COLUMN "policies_version" integer DEFAULT 0 NOT NULL;',
    ]);
    expect(
      statements.filter((statement) => /^(UPDATE|INSERT|DELETE|DROP|TRUNCATE)\b/.test(statement))
    ).toEqual([]);
    expect(statements.filter((statement) => /\bDROP\b/.test(statement))).toEqual([]);
  });

  it('adds the four CHECKs', () => {
    expect(statements.slice(3, 7)).toEqual([
      `ALTER TABLE "realms" ADD CONSTRAINT "realms_policies_object" CHECK (jsonb_typeof("realms"."policies") = 'object');`,
      'ALTER TABLE "realms" ADD CONSTRAINT "realms_policies_version_not_negative" CHECK ("realms"."policies_version" >= 0);',
      `ALTER TABLE "realms" ADD CONSTRAINT "realms_policy_schema_version_format" CHECK ("realms"."policy_schema_version" ~ '^[1-9][0-9]*(-rc\\.(0|[1-9][0-9]*))?$');`,
      'ALTER TABLE "realms" ADD CONSTRAINT "realms_policies_complete" CHECK ("realms"."policies_version" = 0 OR ("realms"."policy_schema_version" IS NOT NULL AND "realms"."access_token_lifespan" IS NOT NULL AND "realms"."refresh_token_lifespan" IS NOT NULL));',
    ]);
  });

  it('raises the counter on a change of the document or a policy column, and never lets it move back', () => {
    expect(statements).toHaveLength(9);
    const fn = statements[7];
    expect(fn).toMatch(/^CREATE FUNCTION "realms_policies_version"\(\) RETURNS trigger /);
    expect(fn).toContain('SET search_path = pg_catalog, pg_temp');
    expect(fn).toContain('IF NEW."policies_version" < OLD."policies_version" THEN');
    expect(fn).toContain("CONSTRAINT = 'realms_policies_version_forward_only'");
    expect(fn).toContain(
      'IF OLD."policies_version" > 0 AND NEW."policies_version" = OLD."policies_version" AND'
    );
    for (const column of [
      'policies',
      'policy_schema_version',
      'access_token_lifespan',
      'refresh_token_lifespan',
      'dynamic_registration_allowed_scopes',
      'max_environment_laxity',
    ]) {
      expect(fn).toContain(`NEW."${column}" IS DISTINCT FROM OLD."${column}"`);
    }
    expect(fn).toContain('NEW."policies_version" := OLD."policies_version" + 1;');
    expect(statements[8]).toBe(
      'CREATE TRIGGER "realms_policies_version" BEFORE UPDATE OF "policies", "policy_schema_version", "policies_version", "access_token_lifespan", "refresh_token_lifespan", "dynamic_registration_allowed_scopes", "max_environment_laxity" ON "realms" FOR EACH ROW EXECUTE FUNCTION "realms_policies_version"();'
    );
  });
});
