/**
 * Guard for `scripts/migration-policy/check.mjs`, the CLI over `lib.mjs`
 * (#473): run as CI runs it, as a child process, against a throwaway git
 * repository with a release tag. It holds the CI acceptance criteria: an
 * edited released migration fails; a new migration with DROP COLUMN fails,
 * and passes once the exceptions file lists it with a reason; a frozen list
 * refuses a new exception.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'check.mjs');
const DIR = 'libs/infra/db/drizzle';

const workspaces: string[] = [];
afterAll(() => {
  for (const dir of workspaces) rmSync(dir, { recursive: true, force: true });
});

function git(root: string, ...args: string[]) {
  const result = spawnSync(
    'git',
    [
      '-c',
      'user.name=Policy Test',
      '-c',
      'user.email=policy-test@example.invalid',
      '-c',
      'commit.gpgsign=false',
      '-c',
      'tag.gpgsign=false',
      ...args,
    ],
    { cwd: root, encoding: 'utf8' }
  );
  expect(result.status, result.stderr).toBe(0);
  return result.stdout;
}

const journalEntry = (idx: number, name: string) => ({
  idx,
  version: '7',
  when: 1_700_000_000_000 + idx * 1000,
  tag: `${String(idx).padStart(4, '0')}_${name}`,
  breakpoints: true,
});

/** A repository whose release `v0.1.0` holds migrations 0000 and 0001. */
function repository() {
  const root = mkdtempSync(join(tmpdir(), 'migration-policy-'));
  workspaces.push(root);
  mkdirSync(join(root, DIR, 'meta'), { recursive: true });
  git(root, 'init', '-q', '-b', 'main');
  const repo = {
    root,
    entries: [] as ReturnType<typeof journalEntry>[],
    write(path: string, text: string) {
      writeFileSync(join(root, DIR, path), text);
    },
    read(path: string) {
      return readFileSync(join(root, DIR, path), 'utf8');
    },
    addMigration(name: string, sql: string) {
      const entry = journalEntry(repo.entries.length, name);
      repo.entries.push(entry);
      repo.write(`${entry.tag}.sql`, sql);
      repo.write(
        'meta/_journal.json',
        JSON.stringify({ version: '7', dialect: 'postgresql', entries: repo.entries }, null, 2)
      );
      return `${entry.tag}.sql`;
    },
    exceptions(frozen: boolean, exceptions: object[]) {
      repo.write('policy-exceptions.json', JSON.stringify({ frozen, exceptions }, null, 2));
    },
    commit(message: string) {
      git(root, 'add', '-A');
      git(root, 'commit', '-q', '-m', message);
    },
  };
  repo.addMigration('init', 'CREATE TABLE "users" ("id" uuid PRIMARY KEY NOT NULL, "email" text);');
  repo.addMigration('drop_email', 'ALTER TABLE "users" DROP COLUMN "email";');
  repo.exceptions(false, []);
  repo.commit('release');
  git(root, 'tag', 'v0.1.0');
  return repo;
}

function check(root: string, ...args: string[]) {
  const summary = join(root, 'summary.md');
  rmSync(summary, { force: true });
  const result = spawnSync('node', [SCRIPT, '--root', root, '--summary', summary, ...args], {
    encoding: 'utf8',
  });
  let written = '';
  try {
    written = readFileSync(summary, 'utf8');
  } catch {
    // No summary: an input error.
  }
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, summary: written };
}

const dropColumnException = {
  migration: '0002_drop_name.sql',
  statement: 'drop-column',
  reason: 'users.name has had no reader since the release before the baseline',
  issue: '#473',
};

describe('migration-policy check CLI', () => {
  it('passes a tree with no migration since the baseline, and checks none of the old ones', () => {
    // 0001 drops a column, but it is released: it is not checked again.
    const { root } = repository();
    const result = check(root);
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('✅ Passes · baseline `v0.1.0` · no migration added since it');
    expect(result.summary).toBe(`${result.stdout}`);
  });

  it('passes a clean new migration: CREATE TABLE, a nullable ADD COLUMN, CREATE INDEX', () => {
    const repo = repository();
    repo.addMigration(
      'expand',
      [
        'CREATE TABLE "sessions" ("id" uuid PRIMARY KEY NOT NULL, "user_id" uuid NOT NULL);',
        'ALTER TABLE "users" ADD COLUMN "display_name" text;',
        'CREATE INDEX "idx_sessions_user_id" ON "sessions" ("user_id");',
      ].join('--> statement-breakpoint\n')
    );
    const result = check(repo.root);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('1 migration checked: `0002_expand.sql`');
  });

  it('fails when a migration file of the baseline tag is edited', () => {
    const repo = repository();
    repo.write('0000_init.sql', `${repo.read('0000_init.sql')}\n-- a comment is an edit too\n`);
    const result = check(repo.root);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain(
      '0000_init.sql changed since v0.1.0: a released migration never changes; write a new one'
    );
  });

  it('fails when a committed edit of a released migration is on the branch', () => {
    const repo = repository();
    repo.write('0001_drop_email.sql', 'SELECT 1;');
    repo.commit('rewrite history');
    expect(check(repo.root).status).toBe(1);
  });

  it('fails when the journal of the baseline changes', () => {
    const repo = repository();
    repo.entries[1] = { ...repo.entries[1], when: repo.entries[1].when + 1 };
    repo.write(
      'meta/_journal.json',
      JSON.stringify({ version: '7', dialect: 'postgresql', entries: repo.entries })
    );
    const result = check(repo.root);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('journal entry 1 changed since v0.1.0');
  });

  it('fails a new migration with DROP COLUMN, and passes it once the exceptions file lists it', () => {
    const repo = repository();
    repo.addMigration('drop_name', 'ALTER TABLE "users" DROP COLUMN "name";');
    const refused = check(repo.root);
    expect(refused.status).toBe(1);
    expect(refused.stdout).toContain(
      '| 0002_drop_name.sql | 1 | drop-column | drops a column and its data | `ALTER TABLE "users" DROP COLUMN "name"` |'
    );

    repo.exceptions(false, [dropColumnException]);
    const excused = check(repo.root);
    expect(excused.status).toBe(0);
    // The exceptions are in the job summary.
    expect(excused.summary).toContain('### Exceptions (1, open)');
    expect(excused.summary).toContain(
      '| 0002_drop_name.sql | drop-column | #473 | users.name has had no reader since the release before the baseline | yes |'
    );
  });

  it('fails an exception with no reason', () => {
    const repo = repository();
    repo.addMigration('drop_name', 'ALTER TABLE "users" DROP COLUMN "name";');
    repo.exceptions(false, [{ ...dropColumnException, reason: '' }]);
    const result = check(repo.root);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('"reason" must say why');
  });

  it('with frozen: true, fails an exception the base ref does not hold', () => {
    const repo = repository();
    repo.exceptions(true, []);
    repo.commit('freeze the exception list');
    repo.addMigration('drop_name', 'ALTER TABLE "users" DROP COLUMN "name";');
    repo.exceptions(true, [dropColumnException]);
    const result = check(repo.root, '--base-ref', 'HEAD');
    expect(result.status).toBe(1);
    expect(result.stdout).toContain(
      'the exception list is frozen: drop-column in 0002_drop_name.sql (#473) is not in the list at HEAD'
    );
    expect(result.stdout).toContain('### Exceptions (1, frozen)');
  });

  it('keeps an exception the base ref already held when the list is frozen', () => {
    const repo = repository();
    repo.addMigration('drop_name', 'ALTER TABLE "users" DROP COLUMN "name";');
    repo.exceptions(false, [dropColumnException]);
    repo.commit('an exception while the list is open');
    repo.exceptions(true, [dropColumnException]);
    expect(check(repo.root, '--base-ref', 'HEAD').status).toBe(0);
    // An empty --base-ref, as CI passes when it has no base, means the baseline.
    expect(check(repo.root, '--base-ref', '').status).toBe(1);
  });

  it('takes the highest release tag, a release candidate included, as the baseline', () => {
    const repo = repository();
    repo.addMigration('drop_name', 'ALTER TABLE "users" DROP COLUMN "name";');
    repo.commit('0.2 work');
    git(repo.root, 'tag', 'v0.2.0-rc.0');
    const result = check(repo.root);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('baseline `v0.2.0-rc.0`');
    expect(check(repo.root, '--baseline', 'v0.1.0').status).toBe(1);
  });

  it('exits 2 without a release tag, rather than checking nothing', () => {
    const repo = repository();
    git(repo.root, 'tag', '-d', 'v0.1.0');
    const result = check(repo.root);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('no release tag (vX.Y.Z) is reachable from HEAD');
    expect(result.summary).toBe('');
  });

  it('exits 2 on a base ref git cannot resolve, and on an unknown argument', () => {
    const { root } = repository();
    expect(check(root, '--base-ref', 'no-such-ref').status).toBe(2);
    expect(check(root, '--frobnicate').status).toBe(2);
  });

  it('exits 2 when the exceptions file is missing or not JSON', () => {
    const repo = repository();
    rmSync(join(repo.root, DIR, 'policy-exceptions.json'));
    expect(check(repo.root).status).toBe(2);
    repo.write('policy-exceptions.json', '{');
    expect(check(repo.root).status).toBe(2);
  });
});
