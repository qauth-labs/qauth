#!/usr/bin/env node
/**
 * migration-policy — fail CI on a migration that breaks the upgrade promise
 * of ADR-018 §5 (#473): forward-only, expand-then-switch, no destructive
 * statement and no manual step.
 *
 * It compares `libs/infra/db/drizzle` with the baseline, the highest release
 * tag reachable from HEAD (pre-releases included), and checks:
 *
 *   - every migration file of the baseline is still there, under the same
 *     name, with the same git blob id;
 *   - the journal (`meta/_journal.json`) only grew: the baseline's entries
 *     are unchanged and in place, and each new entry has the next index and
 *     a later `when`; the journal and the `.sql` files name each other;
 *   - the SQL of every migration added since the baseline holds no refused
 *     statement (`lib.mjs` lists the kinds), unless
 *     `policy-exceptions.json` lists that kind for that migration with a
 *     reason and an issue. Older migrations are not checked;
 *   - once that file says `frozen: true`, it holds no exception the list at
 *     the reference ref lacks, no migration an exception covers differs from
 *     its copy at the reference, and once the reference is frozen, it stays
 *     frozen. The reference is `--base-ref` when given (CI passes the pull
 *     request's base), else the baseline.
 *
 * It prints a Markdown report, and appends it to the job summary when there
 * is one. The rules live in `lib.mjs` and are unit-tested there; this file
 * is the glue to git and the file system.
 *
 * Exit codes:
 *   0  the policy holds
 *   1  it does not: a refused statement, a changed, moved or missing
 *      released migration, a journal that did not only grow, or a malformed,
 *      stale or (when frozen) new exception
 *   2  input error: no release tag, a ref git cannot resolve, a tree git
 *      cannot read, an unreadable file, bad arguments
 *
 * Usage:
 *   node scripts/migration-policy/check.mjs [--base-ref <ref>] [--baseline <ref>]
 *     [--summary <path> | --no-summary] [--root <dir>]
 */

import { spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  applyExceptions,
  checkBaselineFiles,
  checkFreeze,
  checkFrozenMigrations,
  checkJournal,
  EXCEPTIONS_PATH,
  JOURNAL_PATH,
  MIGRATION_FILE,
  MIGRATIONS_DIR,
  parseExceptions,
  parseJournal,
  PolicyInputError,
  renderSummary,
  scanMigration,
  selectBaselineTag,
} from './lib.mjs';

const EXIT_OK = 0;
const EXIT_POLICY = 1;
const EXIT_INPUT = 2;

const USAGE = `usage: node scripts/migration-policy/check.mjs [options]

  --base-ref <ref>   the ref a frozen exception list is compared with; empty
                     means the baseline (CI passes the pull request's base)
  --baseline <ref>   compare with this ref instead of the latest release tag
  --summary <path>   append the report to this file (default: the job
                     summary file, when the environment names one)
  --no-summary       never write a job summary
  --root <dir>       the repository (default: this checkout)
  --help             print this text`;

function parseArgs(argv) {
  const opts = {
    root: resolve(dirname(fileURLToPath(import.meta.url)), '..', '..'),
    baseline: null,
    baseRef: null,
    summary: process.env.GITHUB_STEP_SUMMARY || null,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = () => {
      const next = argv[++i];
      if (next === undefined) throw new PolicyInputError(`${arg} needs a value\n${USAGE}`);
      return next;
    };
    switch (arg) {
      case '--base-ref':
        opts.baseRef = value() || null;
        break;
      case '--baseline':
        opts.baseline = value() || null;
        break;
      case '--summary':
        opts.summary = resolve(value());
        break;
      case '--no-summary':
        opts.summary = null;
        break;
      case '--root':
        opts.root = resolve(value());
        break;
      case '--help':
        console.log(USAGE);
        process.exit(EXIT_OK);
        break;
      default:
        throw new PolicyInputError(`unknown argument "${arg}"\n${USAGE}`);
    }
  }
  return opts;
}

function createGit(root) {
  const run = (args, input) =>
    spawnSync('git', args, { cwd: root, encoding: 'utf8', input, maxBuffer: 64 * 1024 * 1024 });
  const verified = new Set();
  const verify = (ref) => {
    if (verified.has(ref)) return;
    if (run(['rev-parse', '-q', '--verify', `${ref}^{commit}`]).status !== 0) {
      throw new PolicyInputError(`"${ref}" does not name a commit`);
    }
    verified.add(ref);
  };
  // `ls-tree` answers "absent" with an empty listing and exit 0, and fails
  // only when it cannot read the tree: in a treeless clone, a fetch that did
  // not work. That failure must stop the check, never read as "the file was
  // not in this release", which would pass it.
  const list = (ref, path) => {
    verify(ref);
    const listed = run(['ls-tree', '-z', ref, '--', path]);
    if (listed.status !== 0) {
      throw new PolicyInputError(
        `cannot read the tree of ${ref} at ${path}: ${listed.stderr.trim()}`
      );
    }
    return listed.stdout
      .split('\0')
      .filter(Boolean)
      .map((line) => {
        // `<mode> <type> <object>\t<path>`
        const [meta, file] = line.split('\t');
        const [, type, object] = meta.split(' ');
        return { type, object, path: file };
      });
  };
  return {
    releaseTags() {
      const result = run(['tag', '--list', 'v*', '--merged', 'HEAD']);
      if (result.status !== 0)
        throw new PolicyInputError(`git tag failed: ${result.stderr.trim()}`);
      return result.stdout.split('\n').filter(Boolean);
    },
    verify,
    /** The migration files directly in the directory at `ref`: name → blob id. */
    migrationBlobs(ref) {
      const files = new Map();
      for (const entry of list(ref, `${MIGRATIONS_DIR}/`)) {
        const name = entry.path.slice(MIGRATIONS_DIR.length + 1);
        if (entry.type === 'blob' && MIGRATION_FILE.test(name)) files.set(name, entry.object);
      }
      return files;
    },
    /** A file's contents at `ref`, or null when the ref has no such file. */
    show(ref, path) {
      const [entry] = list(ref, path);
      if (entry === undefined) return null;
      if (entry.type !== 'blob') throw new PolicyInputError(`${ref}:${path} is not a file`);
      const result = run(['show', `${ref}:${path}`]);
      if (result.status !== 0) {
        throw new PolicyInputError(`git show ${ref}:${path} failed: ${result.stderr.trim()}`);
      }
      return result.stdout;
    },
    /** The git blob ids the working copy's files would have: path → id. */
    hashFiles(paths) {
      if (paths.length === 0) return [];
      const result = run(['hash-object', '--stdin-paths'], `${paths.join('\n')}\n`);
      if (result.status !== 0) {
        throw new PolicyInputError(`git hash-object failed: ${result.stderr.trim()}`);
      }
      return result.stdout.split('\n').filter(Boolean);
    },
  };
}

function readWorkingFile(root, path) {
  try {
    return readFileSync(join(root, path), 'utf8');
  } catch (error) {
    throw new PolicyInputError(`cannot read ${path}: ${error.message}`);
  }
}

function run(opts) {
  const git = createGit(opts.root);
  const baseline = opts.baseline ?? selectBaselineTag(git.releaseTags());
  if (baseline === null) {
    throw new PolicyInputError(
      'no release tag (vX.Y.Z) is reachable from HEAD: fetch the tags (git fetch --tags), or pass --baseline <ref>'
    );
  }
  const freezeRef = opts.baseRef ?? baseline;

  // The working copy.
  const dir = join(opts.root, MIGRATIONS_DIR);
  if (!existsSync(dir)) throw new PolicyInputError(`${MIGRATIONS_DIR} does not exist`);
  const present = readdirSync(dir)
    .filter((name) => MIGRATION_FILE.test(name))
    .sort();
  const blobs = git.hashFiles(present.map((name) => `${MIGRATIONS_DIR}/${name}`));
  const currentFiles = new Map(present.map((name, i) => [name, blobs[i]]));
  const journal = parseJournal(readWorkingFile(opts.root, JOURNAL_PATH), JOURNAL_PATH);
  const exceptions = parseExceptions(readWorkingFile(opts.root, EXCEPTIONS_PATH));

  // The baseline and the reference.
  const baselineFiles = git.migrationBlobs(baseline);
  const baselineJournalText = git.show(baseline, JOURNAL_PATH);
  if (baselineJournalText === null) {
    throw new PolicyInputError(`${baseline} has no ${JOURNAL_PATH}`);
  }
  const baselineJournal = parseJournal(baselineJournalText, `${baseline}:${JOURNAL_PATH}`);
  const reference = parseExceptions(
    git.show(freezeRef, EXCEPTIONS_PATH),
    `${freezeRef}:${EXCEPTIONS_PATH}`
  );

  const errors = [...exceptions.errors];
  errors.push(
    ...checkBaselineFiles(
      baselineFiles,
      currentFiles,
      journal.entries.map((e) => e?.tag),
      baseline
    )
  );
  errors.push(...checkJournal(baselineJournal, journal, baseline));
  errors.push(...checkFreeze(exceptions, reference, freezeRef));
  if (exceptions.frozen) {
    const referenceFiles = freezeRef === baseline ? baselineFiles : git.migrationBlobs(freezeRef);
    errors.push(...checkFrozenMigrations(exceptions, referenceFiles, currentFiles, freezeRef));
  }

  const checked = present.filter((name) => !baselineFiles.has(name));
  const findings = [];
  const reviews = [];
  for (const name of checked) {
    const result = scanMigration(name, readWorkingFile(opts.root, `${MIGRATIONS_DIR}/${name}`));
    findings.push(...result.findings);
    reviews.push(...result.reviews);
  }
  const applied = applyExceptions(findings, exceptions.exceptions, { checked, present });
  errors.push(...applied.errors);

  return {
    baseline,
    freezeRef,
    checked,
    errors,
    refused: applied.refused,
    excused: applied.excused,
    reviews,
    exceptions,
  };
}

function main() {
  let opts;
  let report;
  try {
    opts = parseArgs(process.argv.slice(2));
    report = run(opts);
  } catch (error) {
    if (error instanceof PolicyInputError) {
      console.error(`migration-policy: ${error.message}`);
      return EXIT_INPUT;
    }
    throw error;
  }
  const summary = renderSummary(report);
  console.log(summary);
  if (opts.summary) appendFileSync(opts.summary, `${summary}\n`);
  return report.errors.length > 0 || report.refused.length > 0 ? EXIT_POLICY : EXIT_OK;
}

process.exitCode = main();
