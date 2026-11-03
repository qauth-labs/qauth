/**
 * Migration 0056 pairs a sandbox realm with its live realm (ADR-019 Decision
 * 11, #554): the nullable `realms.sandbox_of_realm_id`, its foreign key with
 * `ON DELETE RESTRICT`, the unique index that gives a live realm one sandbox,
 * the CHECKs one row can hold, and the trigger for what needs another row.
 * It writes no row. The behaviour is held by
 * `realm-sandbox.integration.test.ts` against a real Postgres.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0056_realm_sandbox_pairing';
const MIGRATION_IDX = 56;

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

describe('migration 0056 (the paired sandbox realm)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0055', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0055_ssf_subject_sweep_reads');
  });

  it('adds a nullable column an earlier release can insert past, and writes no row', () => {
    expect(statements[0]).toBe('ALTER TABLE "realms" ADD COLUMN "sandbox_of_realm_id" uuid;');
    expect(
      statements.filter((statement) => /^(UPDATE|INSERT|DELETE|DROP|TRUNCATE)\b/.test(statement))
    ).toEqual([]);
  });

  it('refuses deleting a live realm while its sandbox exists, and allows it one sandbox', () => {
    expect(statements[1]).toBe(
      'ALTER TABLE "realms" ADD CONSTRAINT "realms_sandbox_of_realm_id_realms_id_fk" FOREIGN KEY ("sandbox_of_realm_id") REFERENCES "public"."realms"("id") ON DELETE restrict ON UPDATE no action;'
    );
    expect(statements[2]).toBe(
      'CREATE UNIQUE INDEX "idx_realms_sandbox_of_realm_id" ON "realms" USING btree ("sandbox_of_realm_id");'
    );
  });

  it('adds the CHECKs one row holds: not itself, not the operator realm, never development', () => {
    expect(statements.slice(3, 6)).toEqual([
      'ALTER TABLE "realms" ADD CONSTRAINT "realms_sandbox_not_self" CHECK ("realms"."sandbox_of_realm_id" IS NULL OR "realms"."sandbox_of_realm_id" <> "realms"."id");',
      'ALTER TABLE "realms" ADD CONSTRAINT "realms_sandbox_not_operator" CHECK ("realms"."sandbox_of_realm_id" IS NULL OR NOT "realms"."is_operator");',
      `ALTER TABLE "realms" ADD CONSTRAINT "realms_sandbox_ceiling" CHECK ("realms"."sandbox_of_realm_id" IS NULL OR "realms"."max_environment_laxity" <> 'development');`,
    ]);
  });

  it('adds the pairing trigger, with a pinned search path and the table named by its schema', () => {
    expect(statements).toHaveLength(9);
    const fn = statements[6];
    expect(fn).toMatch(/^CREATE FUNCTION "realms_sandbox_pairing"\(\) RETURNS trigger /);
    expect(fn).toContain('SET search_path = pg_catalog, pg_temp');
    expect(fn).toContain(
      'FROM public."realms" l WHERE l."id" = NEW."sandbox_of_realm_id" FOR SHARE;'
    );
    for (const constraint of [
      'realms_sandbox_pairing_permanent',
      'realms_sandbox_of_operator',
      'realms_sandbox_of_sandbox',
      // A live realm the trigger cannot read, a later row of the statement
      // included, is refused at once, not at the end of the statement.
      'realms_sandbox_of_realm_id_realms_id_fk',
    ]) {
      expect(fn).toContain(`CONSTRAINT = '${constraint}'`);
    }
    expect(fn).not.toMatch(/SECURITY DEFINER/);
    expect(statements[7]).toBe(
      'CREATE TRIGGER "realms_sandbox_pairing_insert" BEFORE INSERT ON "realms" FOR EACH ROW WHEN (NEW."sandbox_of_realm_id" IS NOT NULL) EXECUTE FUNCTION "realms_sandbox_pairing"();'
    );
    expect(statements[8]).toBe(
      'CREATE TRIGGER "realms_sandbox_pairing_update" BEFORE UPDATE OF "sandbox_of_realm_id", "is_operator" ON "realms" FOR EACH ROW WHEN ( NEW."sandbox_of_realm_id" IS DISTINCT FROM OLD."sandbox_of_realm_id" OR (NEW."is_operator" AND NOT OLD."is_operator") ) EXECUTE FUNCTION "realms_sandbox_pairing"();'
    );
  });
});
