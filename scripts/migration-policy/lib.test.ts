/**
 * Guard for the migration policy rules (#473, ADR-018 §5): which SQL is
 * refused, how the exceptions file and its freeze work, and what the journal
 * and the files of the baseline must keep. The rules are driven on strings
 * here; `check.test.ts` runs the CLI on a git repository.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  applyExceptions,
  checkBaselineFiles,
  checkFreeze,
  checkFrozenMigrations,
  checkJournal,
  EXCEPTIONS_PATH,
  parseExceptions,
  parseJournal,
  PolicyInputError,
  renderSummary,
  scanMigration,
  selectBaselineTag,
  splitStatements,
  STATEMENT_KINDS,
} from './lib.mjs';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

const kindsOf = (sql: string) => scanMigration('0075_example.sql', sql).findings.map((f) => f.kind);
const reviewsOf = (sql: string) => scanMigration('0075_example.sql', sql).reviews;

describe('splitStatements', () => {
  it('splits on top-level semicolons, each statement with its line', () => {
    const statements = splitStatements(
      'CREATE TABLE "a" ("id" uuid);\nCREATE INDEX "i" ON "a" ("id");\n\nSELECT 1'
    );
    expect(statements.map((s) => s.code)).toEqual([
      'CREATE TABLE "_" ("_" UUID)',
      'CREATE INDEX "_" ON "_" ("_")',
      'SELECT 1',
    ]);
    expect(statements.map((s) => s.line)).toEqual([1, 2, 4]);
  });

  it('closes up whitespace around a dot, so a spaced name still parses', () => {
    expect(splitStatements('ALTER TABLE public .users DROP COLUMN email;')[0].code).toBe(
      'ALTER TABLE PUBLIC.USERS DROP COLUMN EMAIL'
    );
  });

  it('masks strings, identifiers and comments, so their words match nothing', () => {
    const [statement] = splitStatements(
      `-- DROP TABLE "users";\n/* TRUNCATE /* nested */ "x" */ COMMENT ON TABLE "drop table" IS 'DELETE FROM x; it''s fine';`
    );
    expect(statement.code).toBe(`COMMENT ON TABLE "_" IS ''`);
    expect(statement.line).toBe(2);
  });

  it('reads an E string with a backslash-escaped quote', () => {
    expect(splitStatements(`SELECT E'a\\'; b';`).map((s) => s.code)).toEqual([`SELECT E''`]);
  });

  it('keeps a dollar-quoted body whole, with its own line', () => {
    const [statement] = splitStatements('DO $body$\nBEGIN\n  PERFORM 1;\nEND $body$;');
    expect(statement.code).toBe('DO $$');
    expect(statement.bodies).toEqual([{ text: '\nBEGIN\n  PERFORM 1;\nEND ', line: 1 }]);
  });
});

describe('scanMigration: refused statements', () => {
  // One fixture per statement kind the policy refuses (#473).
  const REFUSED: [string, string][] = [
    ['drop-table', 'DROP TABLE "legacy_tokens";'],
    ['drop-table', 'DROP TABLE IF EXISTS "legacy_tokens" CASCADE;'],
    ['drop-table', 'DROP SCHEMA "old" CASCADE;'],
    ['drop-column', 'ALTER TABLE "users" DROP COLUMN "email";'],
    ['drop-column', 'ALTER TABLE "users" DROP "email";'],
    ['drop-column', 'ALTER TABLE ONLY "users" ADD COLUMN "x" text, DROP COLUMN IF EXISTS "y";'],
    ['drop-constraint', 'ALTER TABLE "sessions" DROP CONSTRAINT "sessions_user_id_users_id_fk";'],
    ['alter-column-type', 'ALTER TABLE "codes" ALTER COLUMN "state" SET DATA TYPE varchar(64);'],
    ['alter-column-type', 'ALTER TABLE "codes" ALTER "state" TYPE integer USING "state"::integer;'],
    ['rename', 'ALTER TABLE "users" RENAME COLUMN "email" TO "mail";'],
    ['rename', 'ALTER TABLE "users" RENAME TO "accounts";'],
    ['rename', 'ALTER INDEX "idx_a" RENAME TO "idx_b";'],
    ['rename', "ALTER TYPE \"status\" RENAME VALUE 'active' TO 'live';"],
    ['truncate', 'TRUNCATE "sessions";'],
    ['truncate', 'TRUNCATE TABLE ONLY "sessions" RESTART IDENTITY;'],
    ['delete-from', 'DELETE FROM "sessions" WHERE "revoked";'],
    ['delete-from', 'WITH gone AS (DELETE FROM "a" RETURNING 1) SELECT count(*) FROM gone;'],
    ['delete-from', 'MERGE INTO "a" USING "b" ON a.id = b.id WHEN MATCHED THEN DELETE;'],
    ['set-not-null', 'ALTER TABLE "refresh_tokens" ALTER COLUMN "family_created_at" SET NOT NULL;'],
    ['add-column-not-null', 'ALTER TABLE "sessions" ADD COLUMN "realm_id" uuid NOT NULL;'],
    [
      'add-column-not-null',
      'ALTER TABLE "sessions" ADD "realm_id" uuid NOT NULL REFERENCES "realms"("id");',
    ],
    ['add-column-not-null', 'ALTER TABLE "sessions" ADD COLUMN "pk" bigint PRIMARY KEY;'],
    [
      'raise-exception',
      "DO $$ BEGIN IF (SELECT count(*) FROM users) > 0 THEN RAISE EXCEPTION 'run the backfill first'; END IF; END $$;",
    ],
    ['raise-exception', "DO $$ BEGIN RAISE 'level-less RAISE is an EXCEPTION'; END $$;"],
    ['raise-exception', "DO $$ BEGIN RAISE SQLSTATE 'P0001'; END $$;"],
    ['raise-exception', 'DO $$ BEGIN ASSERT (SELECT count(*) FROM users) = 0; END $$;'],
    ['drop-cascade', 'DROP TYPE "status" CASCADE;'],
    ['drop-cascade', 'DROP EXTENSION citext CASCADE;'],
    ['dynamic-sql', "DO $$ BEGIN EXECUTE format('DROP TABLE %I', 'a'); END $$;"],
    ['set-not-null', 'ALTER TABLE "t" ADD CONSTRAINT "t_c_not_null" NOT NULL "c";'],
    ['add-column-not-null', 'ALTER TABLE "t" ADD COLUMN "c" text DEFAULT NULL NOT NULL;'],
    [
      'add-column-not-null',
      'ALTER TABLE "t" ADD COLUMN "c" uuid NOT NULL REFERENCES "u"("id") ON DELETE SET DEFAULT;',
    ],
    ['drop-column', 'ALTER TABLE public .users DROP COLUMN email;'],
    ['drop-table', "DO 'BEGIN DROP TABLE users; END';"],
    ['drop-table', "DO LANGUAGE plpgsql E'BEGIN DROP TABLE users; END';"],
    ['drop-table', "CREATE DOMAIN éE AS text; SELECT éE'\\'; DROP TABLE users; SELECT '';"],
  ];

  it.each(REFUSED)('refuses %s: %s', (kind, sql) => {
    expect(kindsOf(sql)).toEqual([kind]);
  });

  it('has a fixture for every statement kind', () => {
    expect(new Set(REFUSED.map(([kind]) => kind))).toEqual(new Set(STATEMENT_KINDS));
  });

  it('reads the body of a DO block, which runs at migration time', () => {
    const sql = `DO $$
DECLARE orphaned bigint;
BEGIN
  DELETE FROM email_verification_tokens WHERE credential_id IS NULL;
  ALTER TABLE "users" DROP COLUMN "email";
END $$;`;
    const { findings } = scanMigration('0075_example.sql', sql);
    expect(findings.map((f) => [f.kind, f.line])).toEqual([
      ['delete-from', 3],
      ['drop-column', 5],
    ]);
    expect(findings[0].file).toBe('0075_example.sql');
  });

  it('reports each statement with its line', () => {
    const sql =
      'CREATE TABLE "a" ("id" uuid);\n--> statement-breakpoint\n\nALTER TABLE "b" DROP COLUMN "c";';
    expect(scanMigration('0075_example.sql', sql).findings).toEqual([
      {
        file: '0075_example.sql',
        kind: 'drop-column',
        line: 4,
        statement: 'ALTER TABLE "b" DROP COLUMN "c"',
      },
    ]);
  });

  it('cuts the file where drizzle does, even inside a comment', () => {
    // drizzle's migrator splits on the raw marker text: Postgres receives the
    // DROP as a statement of its own.
    expect(kindsOf('SELECT 1; -- note --> statement-breakpoint DROP TABLE users;')).toEqual([
      'drop-table',
    ]);
    const sql = 'DO $$ BEGIN PERFORM 1; END $$\n--> statement-breakpoint\nTRUNCATE "a";';
    expect(scanMigration('0075_example.sql', sql).findings).toEqual([
      expect.objectContaining({ kind: 'truncate', line: 3 }),
    ]);
  });

  it('reads the body of a pg_temp helper, which only this migration runs', () => {
    const sql = `CREATE FUNCTION pg_temp.require_backfill() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM users WHERE email IS NOT NULL) THEN
    RAISE EXCEPTION 'run the backfill first';
  END IF;
  DELETE FROM sessions;
END $$;
--> statement-breakpoint
SELECT pg_temp.require_backfill();`;
    expect(kindsOf(sql)).toEqual(['raise-exception', 'delete-from']);
  });

  it('reads the body of a routine the migration calls itself', () => {
    const sql = `CREATE OR REPLACE FUNCTION "public"."purge"() RETURNS void LANGUAGE sql AS $$ DELETE FROM "x" $$;
SELECT purge();
CREATE PROCEDURE rewrite() LANGUAGE sql AS 'ALTER TABLE "y" DROP COLUMN "z"';
CALL rewrite();`;
    expect(kindsOf(sql)).toEqual(['delete-from', 'drop-column']);
    expect(reviewsOf(sql)).toEqual([]);
  });

  it('does not read a trigger function, which runs on a later write', () => {
    const sql = `CREATE FUNCTION "refuse_update"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'append-only';
END $$;
--> statement-breakpoint
CREATE TRIGGER "t" BEFORE UPDATE ON "events" FOR EACH ROW EXECUTE FUNCTION "refuse_update"();
--> statement-breakpoint
REVOKE ALL ON FUNCTION "refuse_update"() FROM PUBLIC;`;
    expect(kindsOf(sql)).toEqual([]);
  });

  it('finds what migrations 0011 and 0012 did (ADR-002)', () => {
    const scan = (name: string) =>
      new Set(
        scanMigration(
          name,
          readFileSync(join(REPO_ROOT, 'libs/infra/db/drizzle', name), 'utf8')
        ).findings.map((f) => f.kind)
      );
    expect(scan('0011_striped_brother_voodoo.sql')).toEqual(
      new Set(['drop-column', 'drop-constraint', 'delete-from', 'set-not-null', 'raise-exception'])
    );
    expect(scan('0012_flat_morlocks.sql')).toEqual(new Set(['drop-column']));
  });
});

describe('scanMigration: statements that pass', () => {
  const CLEAN: [string, string][] = [
    [
      'a CREATE TABLE with NOT NULL columns',
      'CREATE TABLE "realm_hosts" ("id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL, "host" text NOT NULL, "realm_id" uuid NOT NULL);',
    ],
    ['a nullable ADD COLUMN', 'ALTER TABLE "users" ADD COLUMN "not_valid_before" bigint;'],
    ['a CREATE INDEX', 'CREATE INDEX "idx_users_realm" ON "users" USING btree ("realm_id");'],
    ['a CREATE UNIQUE INDEX', 'CREATE UNIQUE INDEX "idx_a" ON "a" ("b") WHERE "c" IS NOT NULL;'],
    [
      'an ADD COLUMN NOT NULL with a DEFAULT',
      'ALTER TABLE "oauth_clients" ADD COLUMN "suspended" boolean DEFAULT false NOT NULL;',
    ],
    [
      'an ADD COLUMN with IS NOT NULL in its CHECK',
      'ALTER TABLE "a" ADD COLUMN "b" text CHECK ("b" IS NOT NULL OR "c");',
    ],
    [
      'an ADD CONSTRAINT',
      'ALTER TABLE "a" ADD CONSTRAINT "a_b_fk" FOREIGN KEY ("b") REFERENCES "b"("id") ON DELETE cascade;',
    ],
    ['a DROP NOT NULL, which widens', 'ALTER TABLE "a" ALTER COLUMN "b" DROP NOT NULL;'],
    ['a SET DEFAULT', 'ALTER TABLE "a" ALTER COLUMN "b" SET DEFAULT 0;'],
    ['an enum value added', 'ALTER TYPE "status" ADD VALUE \'suspended\';'],
    ['a backfill UPDATE', 'UPDATE "a" SET "b" = 0 WHERE "b" IS NULL;'],
    ['a REVOKE of TRUNCATE and DELETE', 'REVOKE TRUNCATE, DELETE ON "events" FROM "qauth_api";'],
    ['a GRANT of DELETE', 'GRANT SELECT, INSERT, DELETE ON TABLE "a" TO "qauth_web";'],
    [
      'a trigger on TRUNCATE and DELETE',
      'CREATE TRIGGER "t" BEFORE UPDATE OR DELETE OR TRUNCATE ON "events" FOR EACH STATEMENT EXECUTE FUNCTION "refuse"();',
    ],
    [
      'a foreign key ON DELETE',
      'ALTER TABLE "a" ADD CONSTRAINT "f" FOREIGN KEY ("x") REFERENCES "b"("id") ON DELETE RESTRICT;',
    ],
    [
      'a function whose body raises and deletes: it runs when called, not now',
      `CREATE OR REPLACE FUNCTION "refuse"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM "x";
  RAISE EXCEPTION 'events are append-only';
END $$;`,
    ],
    ['a DO block that only notices', "DO $$ BEGIN RAISE NOTICE 'backfilled % rows', 3; END $$;"],
    ['a word in a string', "SELECT 'DROP TABLE users; TRUNCATE x' AS note;"],
    [
      'a word in dollar-quoted text',
      'COMMENT ON TABLE "t" IS $c$ we no longer DELETE FROM it $c$;',
    ],
    [
      'the drop of a temporary table the migration made',
      'CREATE TEMP TABLE "moved" ("id" uuid);\nDROP TABLE "moved";\nDROP TABLE IF EXISTS pg_temp.other;',
    ],
    [
      'a word in a quoted identifier',
      'CREATE TABLE "truncate" ("delete from" text, "rename" text);',
    ],
  ];

  it.each(CLEAN)('passes %s', (_label, sql) => {
    expect(kindsOf(sql)).toEqual([]);
    expect(reviewsOf(sql)).toEqual([]);
  });
});

describe('scanMigration: statements for review', () => {
  it('prints an ALTER form it does not know, and refuses nothing for it', () => {
    const sql = 'ALTER SEQUENCE "s" RESTART WITH 10;';
    expect(kindsOf(sql)).toEqual([]);
    expect(reviewsOf(sql)).toEqual([
      expect.objectContaining({ line: 1, note: 'an ALTER form the check does not know' }),
    ]);
  });

  it('prints an ALTER TABLE action it does not know', () => {
    expect(reviewsOf('ALTER TABLE "a" ALTER COLUMN "b" DROP IDENTITY;')).toEqual([
      expect.objectContaining({
        note: expect.stringMatching(/ALTER TABLE action .* DROP IDENTITY/),
      }),
    ]);
    expect(reviewsOf('ALTER TABLE "a" SET SCHEMA "b";')).toHaveLength(1);
  });

  it('prints a DROP of anything but a table, without CASCADE', () => {
    expect(reviewsOf('DROP INDEX "idx_a";').map((r) => r.note)).toEqual([
      expect.stringMatching(/^DROP INDEX/),
    ]);
    expect(kindsOf('DROP TYPE "status";')).toEqual([]);
  });

  it('does not print the drop of a pg_temp helper', () => {
    expect(reviewsOf('DROP FUNCTION pg_temp.qauth_ip(text);')).toEqual([]);
  });

  it('prints a CALL of a procedure the migration does not define', () => {
    expect(reviewsOf('CALL backfill_sessions();').map((r) => r.note)).toEqual([
      'calls a procedure this migration does not define: the check cannot read it',
    ]);
  });
});

describe('selectBaselineTag', () => {
  it('takes the highest release tag, release candidates included', () => {
    expect(selectBaselineTag(['v0.1.0-rc.2', 'v0.1.0', 'v0.2.0-rc.0', 'v0.1.4-rc.0'])).toBe(
      'v0.2.0-rc.0'
    );
    expect(selectBaselineTag(['v0.2.0-rc.2', 'v0.2.0', 'v0.2.4', 'v0.10.0-rc.1'])).toBe(
      'v0.10.0-rc.1'
    );
  });

  it('ignores names that are not release tags, and finds none in an empty list', () => {
    expect(selectBaselineTag(['latest', 'v1', 'v0.1.0'])).toBe('v0.1.0');
    expect(selectBaselineTag(['latest'])).toBeNull();
    expect(selectBaselineTag([])).toBeNull();
  });
});

const entry = (migration: string, statement = 'drop-column') => ({
  migration,
  statement,
  reason: 'the column has had no reader since #261',
  issue: '#473',
});
const file = (frozen: boolean, exceptions: object[]) => JSON.stringify({ frozen, exceptions });

describe('parseExceptions', () => {
  it('starts empty and open', () => {
    const committed = readFileSync(join(REPO_ROOT, EXCEPTIONS_PATH), 'utf8');
    expect(parseExceptions(committed)).toEqual({ frozen: false, exceptions: [], errors: [] });
  });

  it('reads a missing file (a baseline before #473) as the empty, open list', () => {
    expect(parseExceptions(null)).toEqual({ frozen: false, exceptions: [], errors: [] });
  });

  it('reads valid entries', () => {
    const parsed = parseExceptions(file(true, [entry('0075_example.sql')]));
    expect(parsed).toEqual({ frozen: true, exceptions: [entry('0075_example.sql')], errors: [] });
  });

  it.each([
    [
      'an unknown statement kind',
      { ...entry('0075_example.sql'), statement: 'drop-index' },
      /"statement" must be one of/,
    ],
    ['no reason', { ...entry('0075_example.sql'), reason: '  ' }, /"reason" must say why/],
    [
      'no issue',
      { ...entry('0075_example.sql'), issue: undefined },
      /"issue" must be an issue reference/,
    ],
    ['an issue that is not a reference', { ...entry('0075_example.sql'), issue: '473' }, /"issue"/],
    [
      'a path for the migration',
      { ...entry('0075_example.sql'), migration: 'drizzle/0075_example.sql' },
      /"migration"/,
    ],
    [
      'an unknown field',
      { ...entry('0075_example.sql'), approvedBy: 'x' },
      /unknown field "approvedBy"/,
    ],
  ])('refuses an entry with %s', (_label, bad, message) => {
    const parsed = parseExceptions(file(false, [bad]));
    expect(parsed.exceptions).toEqual([]);
    expect(parsed.errors).toEqual([expect.stringMatching(message)]);
  });

  it('refuses an entry listed twice', () => {
    const parsed = parseExceptions(
      file(false, [entry('0075_example.sql'), entry('0075_example.sql')])
    );
    expect(parsed.errors).toEqual([expect.stringMatching(/listed twice/)]);
  });

  it('refuses a file with no frozen flag or an unknown field', () => {
    expect(parseExceptions(JSON.stringify({ exceptions: [] })).errors).toEqual([
      expect.stringMatching(/"frozen" must be true or false/),
    ]);
    expect(
      parseExceptions(JSON.stringify({ frozen: false, exceptions: [], note: 1 })).errors
    ).toEqual([expect.stringMatching(/unknown field "note"/)]);
  });

  it('throws on a file that is not JSON or not an object', () => {
    expect(() => parseExceptions('{')).toThrow(PolicyInputError);
    expect(() => parseExceptions('[]')).toThrow(PolicyInputError);
  });
});

describe('checkFreeze', () => {
  const open = (exceptions: object[]) => parseExceptions(file(false, exceptions));
  const frozen = (exceptions: object[]) => parseExceptions(file(true, exceptions));

  it('with frozen: true, refuses an exception the reference does not hold', () => {
    const errors = checkFreeze(
      frozen([entry('0075_example.sql'), entry('0076_more.sql')]),
      frozen([entry('0075_example.sql')]),
      'origin/main'
    );
    expect(errors).toEqual([
      'the exception list is frozen: drop-column in 0076_more.sql (#473) is not in the list at origin/main',
    ]);
  });

  it('refuses a new exception in the change that freezes the list', () => {
    expect(checkFreeze(frozen([entry('0075_example.sql')]), open([]), 'origin/main')).toHaveLength(
      1
    );
  });

  it('lets the change that freezes the list keep every exception it had', () => {
    expect(
      checkFreeze(frozen([entry('0075_example.sql')]), open([entry('0075_example.sql')]), 'v0.9.0')
    ).toEqual([]);
  });

  it('counts another statement kind in the same migration as a new exception', () => {
    expect(
      checkFreeze(
        frozen([entry('0075_example.sql', 'rename')]),
        frozen([entry('0075_example.sql')]),
        'origin/main'
      )
    ).toHaveLength(1);
  });

  it('allows a new exception while the list is open', () => {
    expect(checkFreeze(open([entry('0075_example.sql')]), open([]), 'v0.2.4')).toEqual([]);
  });

  it('refuses to lift the freeze', () => {
    expect(checkFreeze(open([]), frozen([]), 'origin/main')).toEqual([
      'the exception list is frozen at origin/main: "frozen" cannot go back to false',
    ]);
  });
});

describe('checkFrozenMigrations', () => {
  const frozen = (exceptions: object[]) => parseExceptions(file(true, exceptions));
  const at = (blob: string) => new Map([['0075_example.sql', blob]]);

  it('with frozen: true, refuses a change to a migration an exception covers', () => {
    expect(
      checkFrozenMigrations(
        frozen([entry('0075_example.sql')]),
        at('aaa'),
        at('bbb'),
        'origin/main'
      )
    ).toEqual([
      '0075_example.sql changed since origin/main, and the frozen exception list covers it: once the list is frozen, a migration an exception covers keeps its contents',
    ]);
  });

  it('accepts it unchanged, and any change while the list is open', () => {
    expect(
      checkFrozenMigrations(
        frozen([entry('0075_example.sql')]),
        at('aaa'),
        at('aaa'),
        'origin/main'
      )
    ).toEqual([]);
    expect(
      checkFrozenMigrations(
        parseExceptions(file(false, [entry('0075_example.sql')])),
        at('aaa'),
        at('bbb'),
        'origin/main'
      )
    ).toEqual([]);
  });
});

describe('applyExceptions', () => {
  const finding = {
    file: '0075_example.sql',
    kind: 'drop-column',
    line: 1,
    statement: 'ALTER TABLE "a" DROP COLUMN "b"',
  };
  const files = {
    checked: ['0075_example.sql'],
    present: ['0011_striped_brother_voodoo.sql', '0075_example.sql'],
  };

  it('refuses a DROP COLUMN no exception lists', () => {
    expect(applyExceptions([finding], [], files)).toEqual({
      refused: [finding],
      excused: [],
      errors: [],
    });
  });

  it('passes it once the exceptions file lists it with a reason', () => {
    expect(applyExceptions([finding], [entry('0075_example.sql')], files)).toEqual({
      refused: [],
      excused: [{ ...finding, issue: '#473' }],
      errors: [],
    });
  });

  it('does not let an exception of one kind excuse another', () => {
    const result = applyExceptions([finding], [entry('0075_example.sql', 'rename')], files);
    expect(result.refused).toEqual([finding]);
    expect(result.errors).toEqual([
      expect.stringMatching(/rename in 0075_example.sql matches no statement/),
    ]);
  });

  it('keeps an exception of a released migration as history', () => {
    expect(applyExceptions([], [entry('0011_striped_brother_voodoo.sql')], files).errors).toEqual(
      []
    );
  });

  it('refuses an exception that names no migration file', () => {
    expect(applyExceptions([], [entry('0099_missing.sql')], files).errors).toEqual([
      'exception for 0099_missing.sql names no migration file',
    ]);
  });
});

const journalOf = (...entries: object[]) => ({ version: '7', dialect: 'postgresql', entries });
const je = (idx: number, when: number) => ({
  idx,
  version: '7',
  when,
  tag: `${String(idx).padStart(4, '0')}_m${idx}`,
  breakpoints: true,
});

describe('checkJournal', () => {
  const baseline = journalOf(je(0, 100), je(1, 200));

  it('accepts entries appended with the next index and a later date', () => {
    expect(checkJournal(baseline, journalOf(je(0, 100), je(1, 200), je(2, 300)), 'v0.2.4')).toEqual(
      []
    );
  });

  it('refuses a changed, removed or reordered entry of the baseline', () => {
    expect(
      checkJournal(baseline, journalOf(je(0, 100), { ...je(1, 200), when: 201 }), 'v0.2.4')
    ).toEqual([expect.stringMatching(/^journal entry 1 changed since v0.2.4/)]);
    expect(checkJournal(baseline, journalOf(je(0, 100)), 'v0.2.4')).toEqual([
      'journal entry 0001_m1 of v0.2.4 is gone',
    ]);
    expect(
      checkJournal(baseline, journalOf(je(1, 200), je(0, 100)), 'v0.2.4').length
    ).toBeGreaterThan(0);
  });

  it('refuses a new entry dated no later than the one before it', () => {
    expect(checkJournal(baseline, journalOf(je(0, 100), je(1, 200), je(2, 150)), 'v0.2.4')).toEqual(
      [expect.stringMatching(/0002_m2 is dated no later than 0001_m1: the migrator would skip it/)]
    );
  });

  it('refuses a new entry out of sequence', () => {
    const errors = checkJournal(
      baseline,
      journalOf(je(0, 100), je(1, 200), { ...je(3, 300) }),
      'v0.2.4'
    );
    expect(errors).toEqual([
      'new journal entry 0003_m3 must have idx 2',
      'new journal entry 0003_m3 must be numbered 0002',
    ]);
  });

  it('refuses a changed header and a tag listed twice', () => {
    expect(
      checkJournal(baseline, { ...journalOf(je(0, 100), je(1, 200)), dialect: 'mysql' }, 'v0.2.4')
    ).toEqual(["the journal's header changed since v0.2.4"]);
    expect(
      checkJournal(
        baseline,
        journalOf(je(0, 100), je(1, 200), { ...je(2, 300), tag: '0001_m1' }),
        'v0.2.4'
      )
    ).toContain('journal entry 0001_m1 appears twice');
  });

  it('throws on a journal with no entries', () => {
    expect(() => parseJournal('{"version":"7"}', 'meta/_journal.json')).toThrow(PolicyInputError);
  });
});

describe('checkBaselineFiles', () => {
  const baseline = new Map([
    ['0000_m0.sql', 'aaa'],
    ['0001_m1.sql', 'bbb'],
  ]);
  const tags = ['0000_m0', '0001_m1', '0002_m2'];

  it('accepts the released files unchanged, beside a new one', () => {
    const current = new Map([...baseline, ['0002_m2.sql', 'ccc']]);
    expect(checkBaselineFiles(baseline, current, tags, 'v0.2.4')).toEqual([]);
  });

  it('refuses an edited released migration', () => {
    const current = new Map([
      ['0000_m0.sql', 'aaa'],
      ['0001_m1.sql', 'edited'],
      ['0002_m2.sql', 'ccc'],
    ]);
    expect(checkBaselineFiles(baseline, current, tags, 'v0.2.4')).toEqual([
      '0001_m1.sql changed since v0.2.4: a released migration never changes; write a new one',
    ]);
  });

  it('refuses a released migration that moved or is gone', () => {
    const moved = new Map([
      ['0000_m0.sql', 'aaa'],
      ['0001_renamed.sql', 'bbb'],
    ]);
    expect(checkBaselineFiles(baseline, moved, ['0000_m0', '0001_renamed'], 'v0.2.4')).toEqual([
      '0001_m1.sql of v0.2.4 moved to 0001_renamed.sql: a released migration keeps its name',
    ]);
    const gone = new Map([['0000_m0.sql', 'aaa']]);
    expect(checkBaselineFiles(baseline, gone, ['0000_m0'], 'v0.2.4')).toEqual([
      '0001_m1.sql of v0.2.4 is gone: a released migration stays',
    ]);
  });

  it('refuses a file the journal does not name, and an entry with no file', () => {
    const current = new Map([...baseline, ['0002_m2.sql', 'ccc']]);
    expect(checkBaselineFiles(baseline, current, ['0000_m0', '0001_m1'], 'v0.2.4')).toEqual([
      '0002_m2.sql is not in the journal: the migrator never runs it',
    ]);
    expect(checkBaselineFiles(baseline, baseline, tags, 'v0.2.4')).toEqual([
      'journal entry 0002_m2 has no 0002_m2.sql',
    ]);
  });
});

describe('renderSummary', () => {
  const base = {
    baseline: 'v0.2.4',
    freezeRef: 'origin/main',
    checked: ['0075_example.sql'],
    errors: [],
    refused: [],
    excused: [],
    reviews: [],
    exceptions: { frozen: false, exceptions: [] },
  };

  it('says the policy passes and that there are no exceptions', () => {
    const summary = renderSummary(base);
    expect(summary).toContain(
      '✅ Passes · baseline `v0.2.4` · 1 migration checked: `0075_example.sql`'
    );
    expect(summary).toContain('### Exceptions (0, open)\n\nNone.');
  });

  it('prints every exception, and whether this change uses it', () => {
    const finding = {
      file: '0075_example.sql',
      kind: 'drop-column',
      line: 3,
      statement: 'ALTER TABLE "a" DROP COLUMN "b"',
    };
    const summary = renderSummary({
      ...base,
      excused: [{ ...finding, issue: '#473' }],
      exceptions: {
        frozen: true,
        exceptions: [entry('0075_example.sql'), entry('0011_striped_brother_voodoo.sql')],
      },
    });
    expect(summary).toContain('### Exceptions (2, frozen)');
    expect(summary).toContain(
      '| 0075_example.sql | drop-column | #473 | the column has had no reader since #261 | yes |'
    );
    expect(summary).toContain(
      '| 0011_striped_brother_voodoo.sql | drop-column | #473 | the column has had no reader since #261 | no |'
    );
    expect(summary).toContain('Frozen: no exception may be added (compared with `origin/main`).');
  });

  it('lists refused statements and errors when it fails', () => {
    const summary = renderSummary({
      ...base,
      errors: ['0001_m1.sql changed since v0.2.4'],
      refused: [{ file: '0075_example.sql', kind: 'truncate', line: 2, statement: 'TRUNCATE "a"' }],
    });
    expect(summary).toContain('❌ Fails');
    expect(summary).toContain('- 0001_m1.sql changed since v0.2.4');
    expect(summary).toContain(
      '| 0075_example.sql | 2 | truncate | deletes every row of a table | `TRUNCATE "a"` |'
    );
  });
});
