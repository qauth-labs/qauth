/**
 * Migration 0060 adds the generic upstream OpenID Connect providers of each
 * realm (ADR-020, #639): one new table, `realm_upstream_providers`, with its
 * realm foreign key, its unique index and the CHECKs that hold the stored
 * forms. It changes no row of any other table, so an earlier release, which
 * never touches the new table, keeps working during a rolling upgrade. The
 * table's rules are held by
 * `repositories/realm-upstream-providers.integration.test.ts` against a real
 * Postgres.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0060_realm_upstream_providers';
const MIGRATION_IDX = 60;

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

describe('migration 0060 (realm upstream providers)', () => {
  const statements = statementsOf(MIGRATION_TAG);
  const create = statements.find((statement) =>
    statement.startsWith('CREATE TABLE "realm_upstream_providers"')
  );

  it('is in the journal, after 0059', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0059_user_required_actions');
  });

  it('creates and alters only its own table', () => {
    expect(statements).toHaveLength(3);
    for (const statement of statements) {
      expect(statement, statement).toMatch(
        /^(CREATE TABLE "realm_upstream_providers"|ALTER TABLE "realm_upstream_providers" ADD CONSTRAINT|CREATE UNIQUE INDEX "idx_realm_upstream_providers_\w+" ON "realm_upstream_providers")/
      );
    }
    // The foreign key's own `ON DELETE cascade ON UPDATE no action` aside.
    expect(statements.join('\n').replace('ON DELETE cascade ON UPDATE no action', '')).not.toMatch(
      /\b(DROP|UPDATE|DELETE|INSERT|RENAME)\b/
    );
  });

  it('draws time-ordered ids and stamps both times in epoch ms', () => {
    expect(create).toContain('"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL');
    for (const column of ['created_at', 'updated_at']) {
      expect(create).toContain(
        `"${column}" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL`
      );
    }
  });

  it('defaults the listing and verification switches', () => {
    expect(create).toContain('"display_order" integer DEFAULT 0 NOT NULL');
    expect(create).toContain('"hidden" boolean DEFAULT false NOT NULL');
    expect(create).toContain('"enabled" boolean DEFAULT true NOT NULL');
    expect(create).toContain('"marks_verified" boolean DEFAULT true NOT NULL');
    expect(create).toContain('"config" jsonb NOT NULL');
  });

  it('holds the type under the federation contract rule, the name length and the config shape', () => {
    expect(create).toContain(
      `CONSTRAINT "realm_upstream_providers_type_form" CHECK ("realm_upstream_providers"."type" ~ '^oidc_[a-z0-9][a-z0-9_]{0,57}$')`
    );
    expect(create).toContain(
      'CONSTRAINT "realm_upstream_providers_display_name_length" CHECK (char_length("realm_upstream_providers"."display_name") BETWEEN 1 AND 64)'
    );
    expect(create).toContain(
      `CONSTRAINT "realm_upstream_providers_config_object" CHECK (jsonb_typeof("realm_upstream_providers"."config") = 'object')`
    );
  });

  it('deletes the rows of a deleted realm', () => {
    expect(statements).toContain(
      'ALTER TABLE "realm_upstream_providers" ADD CONSTRAINT "realm_upstream_providers_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;'
    );
  });

  it('keeps one provider per type in a realm', () => {
    expect(statements).toContain(
      'CREATE UNIQUE INDEX "idx_realm_upstream_providers_realm_type_unique" ON "realm_upstream_providers" USING btree ("realm_id","type");'
    );
  });
});
