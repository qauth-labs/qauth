#!/usr/bin/env node
/**
 * wire-coverage — fail CI when a stable operation of the OpenAPI document has
 * no wire test (#535, ADR-018 §5).
 *
 * The 1.0 promise is wire-level, and the black-box wire suite
 * (`apps/wire-suite`) guards it. This script makes the suite grow with the
 * API. It reads:
 *
 *   - the committed OpenAPI document, `apps/docs-site/public/openapi.json`,
 *     which lists every operation with its `x-qauth-stability`. The
 *     stable-surface check (`scripts/stable-surface/check.mjs`) keeps it equal
 *     to what the server serves;
 *   - the wire suite's Vitest JSON report. A test that passed, in a
 *     `*.wire.test.ts` file, whose `describe` or `it` title carries
 *     `[METHOD /path]` (`scripts/operation-tag.mjs`) is a wire test of that
 *     operation;
 *   - `apps/wire-suite/exempt-operations.json`, the stable operations that
 *     knowingly have no wire test yet, each with a reason and an issue.
 *
 * A stable operation passes when a passing wire test tags it or the exempt
 * list names it. An operation the document marks `x-qauth-stability:
 * experimental` is exempt by that mark alone: a default deployment does not
 * serve it, and the suite's `suites/experimental/` checks that it does not.
 *
 * The exempt list may only shrink. With `--base-ref`, the script reads the
 * list as it is at that git ref and fails when the working copy names an
 * operation the base does not. An entry also fails when it is stale: its
 * operation is gone from the document or experimental, or (with a report) has
 * a wire test now, so the pull request that adds the test removes the entry.
 *
 * Deliberately NOT an Nx project, like `scripts/spec-matrix.mjs`: it reads a
 * report that a live server run produces, which no project's inputs describe.
 *
 * Zero runtime dependencies — Node's standard library only.
 *
 * Exit codes:
 *   0  clean
 *   1  gate failure: a stable operation with neither a passing wire test nor
 *      an exemption, a tag that names no operation of the document, a
 *      malformed or stale exempt entry, or an entry the base ref does not have
 *   2  input error: a missing, empty or shape-changed report, a report with no
 *      wire test file in it, an unreadable OpenAPI document or exempt list, a
 *      base ref git cannot resolve, bad arguments
 *
 * A missing or empty report MUST exit non-zero and must never read as "every
 * operation tested". `scripts/wire-coverage.test.ts` holds that property down.
 *
 * Usage:
 *   node scripts/wire-coverage.mjs --vitest-report dist/wire-report.json
 *   node scripts/wire-coverage.mjs --base-ref origin/main
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { operationTags, TAG_METHODS } from './operation-tag.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const EXIT_OK = 0;
const EXIT_GATE = 1;
const EXIT_INPUT = 2;

const DEFAULT_OPENAPI = join(REPO_ROOT, 'apps', 'docs-site', 'public', 'openapi.json');
const DEFAULT_EXEMPT = join(REPO_ROOT, 'apps', 'wire-suite', 'exempt-operations.json');

/** The path-item keys that hold an operation (OpenAPI 3.1 §4.8.9). */
const HTTP_METHODS = TAG_METHODS.map((method) => method.toLowerCase());

/** A wire test file of `apps/wire-suite`. */
const WIRE_TEST_FILE = /\.wire\.test\.[cm]?[jt]s$/;

/** `METHOD /path`, as the document lists an operation and a tag names one. */
const OPERATION_SHAPE = new RegExp(`^(?:${TAG_METHODS.join('|')}) /[^\\s\\[\\]]*$`);

/** An issue reference of this repository: `#535`. */
const ISSUE_REFERENCE = /^#[1-9]\d*$/;

/** The members an exempt entry has, and no other. */
const ENTRY_KEYS = ['operation', 'reason', 'issue'];

/** Repo-relative when the path is inside the repo, absolute when it is not. */
function repoPath(absolute) {
  const rel = relative(REPO_ROOT, absolute);
  return rel === '' || rel.startsWith('..') ? absolute : rel;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

class InputError extends Error {}

/** A gate failure: printed, rendered as an `::error` annotation, and exits 1. */
class Finding {
  constructor({ file, line, title, message }) {
    this.file = file;
    this.line = line;
    this.title = title;
    this.message = message;
  }
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

const USAGE = `Usage: node scripts/wire-coverage.mjs [--vitest-report <path>] [--base-ref <ref>] [options]

Options:
  --vitest-report <path>  The wire suite's Vitest JSON report. Every stable
                          operation needs a passing test that tags it, or an
                          exemption
  --base-ref <ref>        A git ref (the pull request's base). Fails when the
                          exempt list names an operation the list at that ref
                          does not: the list may only shrink
  --openapi <path>        default: apps/docs-site/public/openapi.json
  --exempt <path>         default: apps/wire-suite/exempt-operations.json
  --help                  Print this and exit 0

With neither --vitest-report nor --base-ref it checks the exempt list against
the OpenAPI document only.
`;

function parseArgs(argv) {
  const opts = {
    vitestReport: null,
    baseRef: null,
    openapi: DEFAULT_OPENAPI,
    exempt: DEFAULT_EXEMPT,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => {
      const value = argv[++i];
      if (value === undefined || value === '') throw new InputError(`${arg} requires a value`);
      return value;
    };
    switch (arg) {
      case '--vitest-report':
        if (opts.vitestReport) {
          throw new InputError('--vitest-report is given more than once; it reads one wire report');
        }
        opts.vitestReport = resolve(next());
        break;
      case '--base-ref': {
        const ref = next();
        // A ref that starts with `-` would reach git as an option.
        if (ref.startsWith('-')) throw new InputError(`--base-ref ${ref} is not a git ref`);
        opts.baseRef = ref;
        break;
      }
      case '--openapi':
        opts.openapi = resolve(next());
        break;
      case '--exempt':
        opts.exempt = resolve(next());
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

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

function readJson(path, what) {
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    throw new InputError(`cannot read ${what} at ${repoPath(path)}: ${err.message}`);
  }
  if (raw.trim() === '') throw new InputError(`${what} at ${repoPath(path)} is empty`);
  try {
    return { raw, data: JSON.parse(raw) };
  } catch (err) {
    throw new InputError(`${what} at ${repoPath(path)} is not valid JSON: ${err.message}`);
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** The 1-based line of the first line that `matches`, or 1. */
function lineOf(raw, matches) {
  const index = raw.split('\n').findIndex(matches);
  return index === -1 ? 1 : index + 1;
}

/**
 * Every operation of the document, keyed `METHOD /path`, with its stability
 * and the line of its path for the annotation.
 */
function loadDocument(path) {
  const { raw, data } = readJson(path, 'the OpenAPI document');
  if (!isPlainObject(data) || !isPlainObject(data.paths)) {
    throw new InputError(`${repoPath(path)}: expected an OpenAPI document with a "paths" object`);
  }
  const operations = new Map();
  for (const [route, item] of Object.entries(data.paths)) {
    if (!isPlainObject(item)) continue;
    const pathKey = `${JSON.stringify(route)}:`;
    const line = lineOf(raw, (text) => text.trimStart().startsWith(pathKey));
    for (const method of HTTP_METHODS) {
      const operation = item[method];
      if (!isPlainObject(operation)) continue;
      const stability = operation['x-qauth-stability'] ?? item['x-qauth-stability'];
      operations.set(`${method.toUpperCase()} ${route}`, {
        // Anything but an explicit `experimental` is held to the stable rule.
        experimental: stability === 'experimental',
        line,
      });
    }
  }
  if (operations.size === 0) {
    throw new InputError(
      `${repoPath(path)} lists no operation. An empty document cannot be checked, ` +
        `so it is treated as a failure rather than as full coverage.`
    );
  }
  return operations;
}

/** The exempt list: its raw text and its entries, unvalidated. */
function loadExemptList(path) {
  const { raw, data } = readJson(path, 'the exempt list');
  if (!isPlainObject(data) || !Array.isArray(data.exemptions)) {
    throw new InputError(`${repoPath(path)}: expected a JSON object with an "exemptions" array`);
  }
  return { raw, entries: data.exemptions };
}

/** The titles of one assertion, outermost `describe` first. */
function titlesOf(assertion) {
  const { ancestorTitles, title, fullName } = assertion;
  if (
    Array.isArray(ancestorTitles) &&
    ancestorTitles.every((t) => typeof t === 'string') &&
    typeof title === 'string'
  ) {
    return [...ancestorTitles, title];
  }
  return typeof fullName === 'string' ? [fullName] : null;
}

/**
 * The wire tests of a Vitest JSON report. Fails closed: a missing, empty or
 * shape-changed report, or one with no wire test file in it, is an input
 * error, never "no operation is tested" and never "every operation is".
 */
function loadReport(path) {
  if (!existsSync(path)) {
    throw new InputError(
      `no wire-suite report at ${repoPath(path)}. The gate needs the report of a complete run; ` +
        `run the wire suite with \`--reporter=json --outputFile.json=${repoPath(path)}\` first ` +
        `(apps/wire-suite/README.md).`
    );
  }
  const { data } = readJson(path, 'the wire-suite report');
  if (!isPlainObject(data)) {
    throw new InputError(`${repoPath(path)}: expected a JSON object at the top level`);
  }
  if (!Array.isArray(data.testResults)) {
    throw new InputError(
      `${repoPath(path)}: expected a "testResults" array — the reporter shape changed`
    );
  }
  const tests = [];
  let wireFiles = 0;
  for (const suite of data.testResults) {
    if (!isPlainObject(suite) || typeof suite.name !== 'string') continue;
    if (!WIRE_TEST_FILE.test(suite.name)) continue;
    wireFiles += 1;
    if (!Array.isArray(suite.assertionResults)) {
      throw new InputError(
        `${repoPath(path)}: ${suite.name} has no "assertionResults" array — the reporter shape changed`
      );
    }
    for (const assertion of suite.assertionResults) {
      const titles = isPlainObject(assertion) ? titlesOf(assertion) : null;
      if (!titles || typeof assertion.status !== 'string') {
        throw new InputError(
          `${repoPath(path)}: an assertion of ${suite.name} has no string "title" or "fullName" ` +
            `and "status" — the reporter shape changed and the tags are no longer readable.`
        );
      }
      tests.push({ file: suite.name, titles, status: assertion.status });
    }
  }
  if (wireFiles === 0) {
    throw new InputError(
      `${repoPath(path)} holds no *.wire.test.ts file, so it is not the wire suite's report. ` +
        `Give the report of \`pnpm nx run wire-suite:run\`.`
    );
  }
  if (tests.length === 0) {
    throw new InputError(
      `${repoPath(path)} contains no test. An empty report cannot show a wire test, ` +
        `so it is treated as a failure rather than as a clean run.`
    );
  }
  return tests;
}

/** Run git in `cwd`; never through a shell. */
function git(args, cwd) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  if (result.error) throw new InputError(`cannot run git: ${result.error.message}`);
  return result;
}

/**
 * The operations the exempt list names at `ref`, or `null` when the list does
 * not exist there yet (the pull request that adds it).
 */
function loadBaseOperations(ref, exemptPath) {
  const cwd = dirname(exemptPath);
  const resolved = git(['rev-parse', '--verify', '--quiet', `${ref}^{commit}`], cwd);
  if (resolved.status !== 0) {
    throw new InputError(
      `cannot resolve the base ref "${ref}" to a commit in the repository of ` +
        `${repoPath(exemptPath)}. Fetch it, or give --base-ref a ref that exists.`
    );
  }
  // `<rev>:./<name>` is relative to the working directory, the list's own.
  const object = `${ref}:./${basename(exemptPath)}`;
  if (git(['cat-file', '-e', object], cwd).status !== 0) return null;
  const shown = git(['show', object], cwd);
  if (shown.status !== 0) {
    throw new InputError(`cannot read the exempt list at ${ref}: ${shown.stderr.trim()}`);
  }
  let data;
  try {
    data = JSON.parse(shown.stdout);
  } catch (err) {
    throw new InputError(`the exempt list at ${ref} is not valid JSON: ${err.message}`);
  }
  if (!isPlainObject(data) || !Array.isArray(data.exemptions)) {
    throw new InputError(`the exempt list at ${ref} has no "exemptions" array`);
  }
  return new Set(
    data.exemptions
      .map((entry) => (isPlainObject(entry) ? entry.operation : undefined))
      .filter((operation) => typeof operation === 'string')
  );
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/**
 * Validate every exempt entry against its shape and the document. Returns the
 * operations of the well-formed entries with each one's line, and the findings.
 */
function checkExemptList(list, exemptPath, operations) {
  const file = repoPath(exemptPath);
  const findings = [];
  const exempt = new Map();
  const fail = (line, message) =>
    findings.push(new Finding({ file, line, title: 'Exempt operations', message }));

  list.entries.forEach((entry, index) => {
    const label = `exemptions[${index}]`;
    if (!isPlainObject(entry)) {
      fail(1, `${label} is not an object with "operation", "reason" and "issue"`);
      return;
    }
    const operation = typeof entry.operation === 'string' ? entry.operation : null;
    const line = operation
      ? lineOf(list.raw, (text) => text.includes(JSON.stringify(operation)))
      : 1;
    const problems = [];
    if (!operation || !OPERATION_SHAPE.test(operation)) {
      problems.push('"operation" must be "METHOD /path", exactly as the OpenAPI document lists it');
    }
    if (typeof entry.reason !== 'string' || entry.reason.trim() === '') {
      problems.push('"reason" must say why the operation has no wire test yet');
    }
    if (typeof entry.issue !== 'string' || !ISSUE_REFERENCE.test(entry.issue)) {
      problems.push('"issue" must be the issue that brings its wire test, as "#123"');
    }
    const unknownKeys = Object.keys(entry).filter((key) => !ENTRY_KEYS.includes(key));
    if (unknownKeys.length > 0) {
      problems.push(`unknown member(s) ${unknownKeys.map((k) => `"${k}"`).join(', ')}`);
    }
    if (problems.length > 0) {
      fail(line, `${label} (${operation ?? 'no operation'}): ${problems.join('; ')}`);
      return;
    }
    if (exempt.has(operation)) {
      fail(line, `${operation} is listed twice; remove one entry`);
      return;
    }
    const documented = operations.get(operation);
    if (!documented) {
      fail(
        line,
        `${operation} is not an operation of the OpenAPI document, so its exemption is stale; ` +
          `remove the entry`
      );
      return;
    }
    if (documented.experimental) {
      fail(
        line,
        `${operation} is experimental, which already exempts it; remove the entry ` +
          `(the list holds stable operations only)`
      );
      return;
    }
    exempt.set(operation, { line, issue: entry.issue });
  });
  return { exempt, findings };
}

/** Which operations the wire tests tag, with how many passed and the other outcomes. */
function tallyTags(tests) {
  const tagged = new Map();
  for (const test of tests) {
    // A tag in a `describe` and again in its `it` is one claim, not two.
    const operations = new Set(test.titles.flatMap((title) => operationTags(title)));
    for (const operation of operations) {
      const tally = tagged.get(operation) ?? { passed: 0, other: new Map(), files: new Set() };
      if (test.status === 'passed') tally.passed += 1;
      else tally.other.set(test.status, (tally.other.get(test.status) ?? 0) + 1);
      tally.files.add(test.file);
      tagged.set(operation, tally);
    }
  }
  return tagged;
}

/** Where a tag sits in its test file, for the annotation. */
function tagLocation(operation, files) {
  const [file] = [...files];
  let line = 1;
  try {
    line = lineOf(readFileSync(file, 'utf8'), (text) => text.includes(`[${operation}]`));
  } catch {
    // The report came from another checkout; the file name still says where.
  }
  return { file: repoPath(file), line };
}

function describeOutcomes(other) {
  return [...other.entries()].map(([status, count]) => `${count} ${status}`).join(', ');
}

function checkCoverage({ operations, documentPath, exempt, exemptPath, tagged }) {
  const findings = [];
  const covered = [];

  for (const [operation, tally] of tagged) {
    if (operations.has(operation)) continue;
    const { file, line } = tagLocation(operation, tally.files);
    findings.push(
      new Finding({
        file,
        line,
        title: 'Unknown operation tag',
        message:
          `the tag [${operation}] names no operation of the OpenAPI document. ` +
          `Spell it exactly as ${repoPath(documentPath)} lists it: an upper-case method, ` +
          `one space, the path with its {templates}.`,
      })
    );
  }

  for (const [operation, { experimental, line }] of operations) {
    if (experimental) continue;
    const tally = tagged.get(operation);
    if (tally && tally.passed > 0) {
      covered.push(operation);
      continue;
    }
    if (exempt.has(operation)) continue;
    const ran = tally
      ? ` Its tagged tests did not pass (${describeOutcomes(tally.other)}), and a test that ` +
        `did not pass shows nothing.`
      : '';
    findings.push(
      new Finding({
        file: repoPath(documentPath),
        line,
        title: 'Stable operation with no wire test',
        message:
          `${operation} is stable and has no wire test.${ran} Add a test to apps/wire-suite ` +
          `whose describe or it title carries [${operation}] (apps/wire-suite/README.md). ` +
          `The exempt list may only shrink, so a new or changed stable operation cannot join it.`,
      })
    );
  }

  for (const [operation, { line }] of exempt) {
    if ((tagged.get(operation)?.passed ?? 0) === 0) continue;
    findings.push(
      new Finding({
        file: repoPath(exemptPath),
        line,
        title: 'Exempt operations',
        message: `${operation} has a passing wire test now, so its exemption is stale; remove the entry`,
      })
    );
  }

  return { covered, findings };
}

function checkShrink({ exempt, base, baseRef, exemptPath }) {
  const findings = [];
  for (const [operation, { line }] of exempt) {
    if (base.has(operation)) continue;
    findings.push(
      new Finding({
        file: repoPath(exemptPath),
        line,
        title: 'Exempt operations',
        message:
          `${operation} is a new exemption: the list at ${baseRef} does not name it. ` +
          `The exempt list may only shrink; add a wire test for the operation instead.`,
      })
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/** Escape a workflow-command property (`file=…`, `title=…`). */
function escapeProperty(value) {
  return String(value)
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A')
    .replace(/:/g, '%3A')
    .replace(/,/g, '%2C');
}

/** Escape a workflow-command message. */
function escapeData(value) {
  return String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function emitFindings(findings) {
  for (const finding of findings) {
    const props = [
      `file=${escapeProperty(finding.file)}`,
      `line=${finding.line}`,
      `title=${escapeProperty(finding.title)}`,
    ].join(',');
    process.stderr.write(`::error ${props}::${escapeData(finding.message)}\n`);
  }
}

function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`wire-coverage: ${err.message}\n\n${USAGE}`);
    return EXIT_INPUT;
  }
  if (opts.help) {
    process.stdout.write(USAGE);
    return EXIT_OK;
  }

  let operations;
  let list;
  let tests = null;
  let base = null;
  try {
    operations = loadDocument(opts.openapi);
    list = loadExemptList(opts.exempt);
    if (opts.vitestReport) tests = loadReport(opts.vitestReport);
    if (opts.baseRef) base = loadBaseOperations(opts.baseRef, opts.exempt);
  } catch (err) {
    if (!(err instanceof InputError)) throw err;
    process.stderr.write(`wire-coverage: ${err.message}\n`);
    return EXIT_INPUT;
  }

  const { exempt, findings } = checkExemptList(list, opts.exempt, operations);
  const stable = [...operations.values()].filter((op) => !op.experimental).length;
  const experimental = operations.size - stable;
  const out = (line) => process.stdout.write(`wire-coverage: ${line}\n`);

  if (tests) {
    const tagged = tallyTags(tests);
    const coverage = checkCoverage({
      operations,
      documentPath: opts.openapi,
      exempt,
      exemptPath: opts.exempt,
      tagged,
    });
    findings.push(...coverage.findings);
    const taggedTests = tests.filter((test) =>
      test.titles.some((title) => operationTags(title).length > 0)
    ).length;
    out(
      `${stable} stable operations in ${repoPath(opts.openapi)} — ` +
        `${coverage.covered.length} with a passing wire test, ` +
        `${[...exempt.keys()].filter((op) => !coverage.covered.includes(op)).length} exempt by ` +
        `${repoPath(opts.exempt)}; ${experimental} experimental, exempt by their stability`
    );
    out(
      `${tests.length} wire tests read from ${repoPath(opts.vitestReport)}, ` +
        `${taggedTests} of them tagged with an operation`
    );
  } else {
    out(
      `${stable} stable and ${experimental} experimental operations in ${repoPath(opts.openapi)}; ` +
        `${exempt.size} exempt by ${repoPath(opts.exempt)}. Coverage is not checked without ` +
        `--vitest-report.`
    );
  }

  if (opts.baseRef) {
    if (base === null) {
      out(
        `${repoPath(opts.exempt)} does not exist at ${opts.baseRef}, so there is no list to ` +
          `compare with; this change introduces it`
      );
    } else {
      const added = checkShrink({
        exempt,
        base,
        baseRef: opts.baseRef,
        exemptPath: opts.exempt,
      });
      findings.push(...added);
      out(
        `the exempt list names ${exempt.size} operations and named ${base.size} at ` +
          `${opts.baseRef}; ${added.length} added`
      );
    }
  }

  if (findings.length > 0) {
    emitFindings(findings);
    process.stderr.write(`wire-coverage: ${findings.length} gate failure(s)\n`);
    return EXIT_GATE;
  }
  return EXIT_OK;
}

process.exitCode = main();
