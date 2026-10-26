/**
 * Nothing writes `audit_logs` any more (#458). The auth server records what a
 * person or a client did as an event (`emitUserEvent` in
 * `helpers/user-events.ts`), and the table stays only so its rows remain
 * readable until a contract migration drops it. A new `auditLogs.create`
 * call, or an insert into the table, would split the record again: this
 * search refuses one anywhere in `apps/`, test files included, and in the
 * libraries' own code outside the repository that defines the table's access.
 *
 * ADR-011 §8 and ADR-017 §11 said to audit through `auditLogs.create`; since
 * #458 that means `emitUserEvent`.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..');

/** The one file that may still name the table's write: its repository. */
const ALLOWED = new Set(['libs/infra/db/src/lib/repositories/audit-logs.repository.ts']);

/** Spelled from parts, so this file does not match its own search. */
const AUDIT = 'auditLogs';
const TABLE = ['audit', 'logs'].join('_');
const WRITES: readonly RegExp[] = [
  new RegExp(`\\b${AUDIT}\\s*\\.\\s*create\\s*\\(`),
  new RegExp(`\\.insert\\(\\s*${AUDIT}\\s*\\)`),
  new RegExp(`\\binsert\\s+into\\s+"?${TABLE}"?`, 'i'),
];

const SKIPPED_DIRS = new Set(['node_modules', 'dist', 'coverage', '.nx', '.astro']);

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (SKIPPED_DIRS.has(entry.name)) return [];
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return /\.(?:[cm]?[jt]sx?)$/.test(entry.name) ? [path] : [];
  });
}

function writesIn(dir: string, { tests }: { tests: boolean }): string[] {
  return sourceFiles(join(REPO_ROOT, dir))
    .map((file) => relative(REPO_ROOT, file))
    .filter((file) => tests || !/\.(?:test|spec)\.[cm]?[jt]sx?$/.test(file))
    .filter((file) => !ALLOWED.has(file))
    .filter((file) => {
      const source = readFileSync(join(REPO_ROOT, file), 'utf8');
      return WRITES.some((pattern) => pattern.test(source));
    });
}

/**
 * The two searches read every source file of a tree synchronously: well under
 * a second alone, but more than Vitest's 5 s default while every project's
 * suite runs at once (`nx run-many -t test --all`).
 */
const TREE_SEARCH_TIMEOUT_MS = 30_000;

describe('audit_logs is read-only (#458)', () => {
  it(
    'finds no write to audit_logs in apps/, test files included',
    () => {
      expect(writesIn('apps', { tests: true })).toEqual([]);
    },
    TREE_SEARCH_TIMEOUT_MS
  );

  it(
    'finds no write to audit_logs in the libraries outside its repository',
    () => {
      // Test files of the libraries may seed old audit rows: the backfill's
      // own suite does, to prove the copy.
      expect(writesIn('libs', { tests: false })).toEqual([]);
    },
    TREE_SEARCH_TIMEOUT_MS
  );

  it('would find one', () => {
    // A guard on the search itself, so a change to the patterns cannot pass
    // the two tests above vacuously.
    const samples = [
      `await fastify.repositories.${AUDIT}.create({ event: 'x' });`,
      `await tx.insert(${AUDIT}).values({});`,
      `INSERT INTO ${TABLE} (event) VALUES ('x')`,
    ];
    for (const sample of samples) {
      expect(
        WRITES.some((pattern) => pattern.test(sample)),
        sample
      ).toBe(true);
    }
  });
});
