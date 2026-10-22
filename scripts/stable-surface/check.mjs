#!/usr/bin/env node
/**
 * stable-surface — fail CI when a stable surface changes by accident (#451,
 * ADR-018 §5).
 *
 * Reads the registry `stable-surface/surfaces.json` and, for every surface in
 * it:
 *
 *   - drift:  runs its generator and fails when the output differs from the
 *             committed file;
 *   - tags:   requires `x-qauth-stability` on every OpenAPI operation, and
 *             `experimental` on every operation only a switch registers;
 *   - breaks: compares a `stable` surface with the same file at the latest
 *             release tag (`git show <tag>:<path>`), through oasdiff, and fails
 *             on a break `stable-surface/approved-breaks.json` does not approve.
 *
 * The logic lives in `lib.mjs` and is unit-tested there; this file is the glue
 * to git, the shell, oasdiff and the job summary. See `stable-surface/README.md`
 * for how to register a surface and how to approve a break.
 *
 * Exit codes:
 *   0  clean
 *   1  gate failure: drift, a missing or wrong stability tag, an unapproved
 *      break, or a refused approval
 *   2  the check could not run: an invalid registry, a generator that failed,
 *      an unreadable surface, oasdiff unavailable
 *
 * Usage:
 *   node scripts/stable-surface/check.mjs [--only drift,tags,breaks] [--baseline <ref>]
 *   node scripts/stable-surface/check.mjs --self-test
 */

import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  annotations,
  exitCodeOf,
  InputError,
  renderSummary,
  runBreakRuleCase,
  runChecks,
} from './lib.mjs';
import { ensureOasdiff, oasdiffDiffer } from './oasdiff.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..', '..');
const FIXTURES = join(HERE, '__fixtures__', 'break-rules');

const STEPS = ['drift', 'tags', 'breaks'];

const USAGE = `Usage: node scripts/stable-surface/check.mjs [options]

Options:
  --only <steps>     comma-separated subset of ${STEPS.join(',')} (default: all)
  --baseline <ref>   compare with this git ref instead of the latest release tag
  --require-baseline exit 2 when no release tag is reachable (CI sets it)
  --self-test        run the break-rule fixtures through oasdiff, then exit
  --root <dir>       repository root (default: this checkout)
  --summary <path>   Markdown job summary sink (default: $GITHUB_STEP_SUMMARY, when set)
  --no-summary       never write a job summary
  --help             print this and exit 0
`;

function parseArgs(argv) {
  const opts = {
    steps: Object.fromEntries(STEPS.map((step) => [step, true])),
    baseline: undefined,
    requireBaseline: false,
    selfTest: false,
    root: REPO_ROOT,
    summary: process.env.GITHUB_STEP_SUMMARY || null,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => {
      const value = argv[++i];
      if (value === undefined) throw new InputError(`${arg} requires a value`);
      return value;
    };
    switch (arg) {
      case '--only': {
        const chosen = next().split(',');
        for (const step of chosen) {
          if (!STEPS.includes(step)) throw new InputError(`--only: unknown step "${step}"`);
        }
        opts.steps = Object.fromEntries(STEPS.map((step) => [step, chosen.includes(step)]));
        break;
      }
      case '--baseline':
        opts.baseline = next();
        break;
      case '--require-baseline':
        opts.requireBaseline = true;
        break;
      case '--self-test':
        opts.selfTest = true;
        break;
      case '--root':
        opts.root = resolve(next());
        break;
      case '--summary':
        opts.summary = resolve(next());
        break;
      case '--no-summary':
        opts.summary = null;
        break;
      case '--help':
      case '-h':
        opts.help = true;
        break;
      default:
        throw new InputError(`unknown argument: ${arg}`);
    }
  }
  return opts;
}

function createGit(root) {
  const run = (args) =>
    spawnSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const verified = new Set();
  return {
    releaseTags() {
      const result = run(['tag', '--list', 'v*', '--merged', 'HEAD']);
      if (result.status !== 0) throw new InputError(`git tag failed: ${result.stderr.trim()}`);
      return result.stdout.split('\n').filter(Boolean);
    },
    tagExists(tag) {
      return run(['rev-parse', '-q', '--verify', `refs/tags/${tag}`]).status === 0;
    },
    show(ref, path) {
      if (!verified.has(ref)) {
        if (run(['rev-parse', '-q', '--verify', `${ref}^{commit}`]).status !== 0) {
          throw new InputError(`baseline ref "${ref}" does not name a commit`);
        }
        verified.add(ref);
      }
      // `ls-tree` answers "absent" with an empty listing and exit 0, and fails
      // only when it cannot read the tree — in a treeless clone, a fetch that
      // did not work. That failure must stop the check, never read as "the
      // file was not in this release", which would pass it.
      const listed = run(['ls-tree', '-z', ref, '--', path]);
      if (listed.status !== 0) {
        throw new InputError(`cannot read the tree of ${ref} at ${path}: ${listed.stderr.trim()}`);
      }
      if (listed.stdout === '') return null;
      // `<mode> <type> <object>\t<path>\0`
      const type = listed.stdout.split('\t')[0].split(' ')[1];
      if (type !== 'blob') throw new InputError(`${ref}:${path} is not a file`);
      const result = run(['show', `${ref}:${path}`]);
      if (result.status !== 0)
        throw new InputError(`git show ${ref}:${path} failed: ${result.stderr.trim()}`);
      return result.stdout;
    },
    diff(before, after, path) {
      const dir = mkdtempSync(join(tmpdir(), 'stable-surface-diff-'));
      try {
        const a = join(dir, 'committed');
        const b = join(dir, 'generated');
        writeFileSync(a, before);
        writeFileSync(b, after);
        const result = run(['diff', '--no-index', '--no-prefix', '--no-color', '-U3', '--', a, b]);
        return result.stdout.split(a).join(`committed/${path}`).split(b).join(`generated/${path}`);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  };
}

function createRunCommand(root) {
  return (command) => {
    console.log(`stable-surface: running ${command}`);
    const result = spawnSync(command, {
      cwd: root,
      shell: true,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    });
    return { status: result.status ?? 1, output: `${result.stdout ?? ''}${result.stderr ?? ''}` };
  };
}

function printAnnotations(report) {
  const inActions = process.env.GITHUB_ACTIONS === 'true';
  for (const { level, file, message } of annotations(report)) {
    if (inActions) {
      const where = file ? ` file=${file}` : '';
      console.log(
        `::${level}${where}::${message.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')}`
      );
    } else {
      console.log(`${level}: ${file ? `${file}: ` : ''}${message}`);
    }
  }
}

async function selfTest(root) {
  const differ = oasdiffDiffer(await ensureOasdiff(root));
  const read = (name) => JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'));
  const bases = { openapi: read('openapi.json'), 'json-schema': read('schema.json') };
  const cases = read('cases.json');
  let failed = 0;
  for (const testCase of cases) {
    const result = await runBreakRuleCase(testCase, bases, differ);
    const verdict =
      result.expected.length === 0 ? 'passes' : `breaks: ${result.expected.join(', ')}`;
    if (result.ok) {
      console.log(`ok    ${result.name} (${verdict})`);
    } else {
      failed++;
      console.log(
        `FAIL  ${result.name}: expected ${result.expected.join(', ') || 'no break'}, got ${result.actual.join(', ') || 'no break'}`
      );
    }
  }
  console.log(
    `stable-surface self-test: ${cases.length - failed}/${cases.length} fixture(s) as expected`
  );
  return failed === 0 ? 0 : 1;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (opts.selfTest) return selfTest(opts.root);

  // Fetched on first use, so `--only drift,tags` needs no network.
  let differ;
  const report = await runChecks({
    root: opts.root,
    steps: opts.steps,
    baselineRef: opts.baseline,
    requireBaseline: opts.requireBaseline,
    git: createGit(opts.root),
    runCommand: createRunCommand(opts.root),
    differ: async (base, revision) => {
      differ ??= oasdiffDiffer(await ensureOasdiff(opts.root));
      return differ(base, revision);
    },
  });

  const summary = renderSummary(report);
  console.log(summary);
  printAnnotations(report);
  if (opts.summary) appendFileSync(opts.summary, `${summary}\n`);
  return exitCodeOf(report);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error) => {
    if (error instanceof InputError) {
      console.error(`stable-surface: ${error.message}`);
      process.exitCode = 2;
    } else {
      console.error(error);
      process.exitCode = 2;
    }
  }
);
