/**
 * Guard for `scripts/wire-coverage.mjs`, the gate that fails CI when a stable
 * operation has no wire test (#535, ADR-018 §5), and for the tag grammar it
 * shares with the conformance matrix (`scripts/operation-tag.mjs`).
 *
 * The gate must FAIL CLOSED: a missing, empty or shape-changed wire report
 * exits 2, never 0, because a report the script cannot read would otherwise
 * pass every operation or none without saying which.
 *
 * The script ends in `process.exitCode = main()`, so it cannot be imported
 * without running it. It is exercised the way CI runs it: spawned as a child
 * process, with a fixture OpenAPI document, exempt list and report written to
 * a temporary directory. The `--base-ref` cases commit the exempt list in a
 * throwaway git repository there.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

import { blankOperationTags, operationTags } from './operation-tag.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'wire-coverage.mjs');

const EXIT_OK = 0;
const EXIT_GATE = 1;
const EXIT_INPUT = 2;

const workspaces: string[] = [];

afterAll(() => {
  for (const dir of workspaces) rmSync(dir, { recursive: true, force: true });
});

type Stability = 'stable' | 'experimental';

/** An OpenAPI document with the given operations, `METHOD /path` → stability. */
function openapi(operations: Record<string, Stability>): unknown {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const [operation, stability] of Object.entries(operations)) {
    const [method, path] = operation.split(' ');
    paths[path] ??= {};
    paths[path][method.toLowerCase()] = {
      responses: { 200: { description: 'OK' } },
      'x-qauth-stability': stability,
    };
  }
  return { openapi: '3.1.0', info: { title: 'Fixture', version: '0' }, paths };
}

interface Exemption {
  operation?: unknown;
  reason?: unknown;
  issue?: unknown;
  [key: string]: unknown;
}

function exemption(operation: string, overrides: Partial<Exemption> = {}): Exemption {
  return {
    operation,
    reason: 'No wire test yet: the fixture says why.',
    issue: '#535',
    ...overrides,
  };
}

function exemptList(entries: unknown[]): unknown {
  return { $comment: 'fixture', exemptions: entries };
}

interface FixtureTest {
  /** Outermost `describe` first, the `it` title last. */
  titles: string[];
  status?: string;
}

/** A Vitest JSON report with one wire test file, in the shape the reporter writes. */
function report(tests: FixtureTest[], file = '/fixture/apps/wire-suite/src/suites/a.wire.test.ts') {
  return {
    numTotalTests: tests.length,
    testResults: [
      {
        name: file,
        assertionResults: tests.map(({ titles, status }) => ({
          ancestorTitles: titles.slice(0, -1),
          title: titles[titles.length - 1],
          fullName: titles.join(' '),
          status: status ?? 'passed',
        })),
      },
    ],
  };
}

interface Fixture {
  document?: unknown;
  exempt?: unknown;
  report?: unknown;
}

/** Write the fixture files that are given into a fresh directory. */
function workspace(fixture: Fixture): {
  dir: string;
  openapi: string;
  exempt: string;
  report: string;
} {
  const dir = mkdtempSync(join(tmpdir(), 'wire-coverage-'));
  workspaces.push(dir);
  const paths = {
    dir,
    openapi: join(dir, 'openapi.json'),
    exempt: join(dir, 'exempt-operations.json'),
    report: join(dir, 'wire-report.json'),
  };
  if (fixture.document !== undefined)
    writeFileSync(paths.openapi, JSON.stringify(fixture.document));
  if (fixture.exempt !== undefined) {
    writeFileSync(paths.exempt, `${JSON.stringify(fixture.exempt, null, 2)}\n`);
  }
  if (fixture.report !== undefined) writeFileSync(paths.report, JSON.stringify(fixture.report));
  return paths;
}

function run(args: readonly string[], cwd = HERE) {
  const result = spawnSync(process.execPath, [SCRIPT, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NODE_OPTIONS: '' },
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

/** Run the coverage gate over a full fixture. */
function gate(fixture: Required<Pick<Fixture, 'document' | 'report'>> & Fixture) {
  const paths = workspace({ exempt: exemptList([]), ...fixture });
  return run([
    '--openapi',
    paths.openapi,
    '--exempt',
    paths.exempt,
    '--vitest-report',
    paths.report,
  ]);
}

function git(cwd: string, args: readonly string[]) {
  const result = spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'fixture',
      GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
      GIT_COMMITTER_NAME: 'fixture',
      GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: '/dev/null',
    },
  });
  expect(result.status, result.stderr).toBe(0);
  return result.stdout.trim();
}

/** A git repository whose one commit holds `baseEntries` as the exempt list, if any. */
function repository(document: unknown, baseEntries: unknown[] | null) {
  const paths = workspace({ document });
  git(paths.dir, ['init', '--quiet', '--initial-branch=main']);
  writeFileSync(join(paths.dir, 'README'), 'fixture\n');
  git(paths.dir, ['add', 'README']);
  if (baseEntries) {
    writeFileSync(paths.exempt, `${JSON.stringify(exemptList(baseEntries), null, 2)}\n`);
    git(paths.dir, ['add', 'exempt-operations.json']);
  }
  git(paths.dir, ['commit', '--quiet', '-m', 'base']);
  return paths;
}

describe('operation tags — the title grammar', () => {
  it('reads the [METHOD /path] form, path templates included', () => {
    expect(operationTags('reads one client [GET /a/{id}]')).toEqual(['GET /a/{id}']);
    expect(operationTags('[GET /] the root')).toEqual(['GET /']);
    expect(operationTags('[DELETE /a/{id}/keys/{keyId}] removes a key')).toEqual([
      'DELETE /a/{id}/keys/{keyId}',
    ]);
  });

  it('reads every tag of a title, in order', () => {
    expect(operationTags('[GET /ui/login] [POST /ui/login] signs in')).toEqual([
      'GET /ui/login',
      'POST /ui/login',
    ]);
  });

  it('reads no lower-case method, no missing slash and no space inside the path', () => {
    expect(operationTags('[get /a] [GET a] [GET /a b] [GET  /a] [FETCH /a] GET /a')).toEqual([]);
  });

  it('blanks a tag with as many spaces, so the rest of the title keeps its positions', () => {
    const title = 'RFC 9999 §1 [POST /oauth/token] (§2)';
    const blanked = blankOperationTags(title);
    expect(blanked).toHaveLength(title.length);
    expect(blanked).not.toMatch(/oauth/);
    expect(blanked.indexOf('(§2)')).toBe(title.indexOf('(§2)'));
  });
});

describe('wire-coverage — a stable operation needs a passing wire test', () => {
  it('exits 0 when a passing test tags the operation in its it title, [GET /a/{id}] form', () => {
    const result = gate({
      document: openapi({ 'GET /a/{id}': 'stable' }),
      report: report([{ titles: ['clients', 'reads one [GET /a/{id}]'] }]),
    });
    expect(result.status, result.stderr).toBe(EXIT_OK);
    expect(result.stdout).toMatch(/1 stable operations .* 1 with a passing wire test/);
  });

  it('carries a tag in a describe title down to every test inside it', () => {
    const result = gate({
      document: openapi({ 'POST /oauth/token': 'stable', 'POST /oauth/revoke': 'stable' }),
      report: report([
        { titles: ['[POST /oauth/token] RFC 6749 §4.4', 'issues a token (§4.4.3)'] },
        { titles: ['[POST /oauth/revoke] RFC 7009 §2', 'nested', 'answers 200 (§2.2)'] },
      ]),
    });
    expect(result.status, result.stderr).toBe(EXIT_OK);
  });

  it('exits 1 on an untested stable operation, and names it', () => {
    const result = gate({
      document: openapi({ 'POST /oauth/token': 'stable', 'POST /oauth/revoke': 'stable' }),
      report: report([{ titles: ['[POST /oauth/token] issues a token'] }]),
    });
    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toMatch(/::error file=.*openapi\.json,line=\d+,title=Stable operation/);
    expect(result.stderr).toContain('POST /oauth/revoke is stable and has no wire test');
    expect(result.stderr).not.toContain('POST /oauth/token is stable');
  });

  it('does not count a tag that only names the operation in passing, without the brackets', () => {
    const result = gate({
      document: openapi({ 'POST /oauth/revoke': 'stable' }),
      report: report([{ titles: ['revokes through POST /oauth/revoke'] }]),
    });
    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('POST /oauth/revoke is stable and has no wire test');
  });

  it.each(['skipped', 'failed', 'todo', 'pending'])(
    'exits 1 when the only tagged test is %s — a test that did not pass shows nothing',
    (status) => {
      const result = gate({
        document: openapi({ 'GET /a': 'stable' }),
        report: report([{ titles: ['[GET /a] reads it'], status }]),
      });
      expect(result.status).toBe(EXIT_GATE);
      expect(result.stderr).toContain('GET /a is stable and has no wire test');
      expect(result.stderr).toContain(`1 ${status}`);
    }
  );

  it('counts a tagged test only in a *.wire.test.ts file of the report', () => {
    const tests = report([{ titles: ['[GET /a] reads it'] }]);
    const unit = report([{ titles: ['[GET /b] reads it'] }], '/fixture/apps/x/src/b.test.ts');
    const result = gate({
      document: openapi({ 'GET /a': 'stable', 'GET /b': 'stable' }),
      report: { testResults: [...tests.testResults, ...unit.testResults] },
    });
    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('GET /b is stable and has no wire test');
    expect(result.stderr).not.toContain('GET /a is stable');
  });

  it('exempts an experimental operation by its stability alone', () => {
    const result = gate({
      document: openapi({ 'GET /a': 'stable', 'POST /ssf/stream': 'experimental' }),
      report: report([{ titles: ['[GET /a] reads it'] }]),
    });
    expect(result.status, result.stderr).toBe(EXIT_OK);
    expect(result.stdout).toContain('1 experimental, exempt by their stability');
  });

  it('holds an operation with no x-qauth-stability to the stable rule', () => {
    const document = openapi({ 'GET /a': 'stable' }) as { paths: Record<string, unknown> };
    document.paths['/b'] = { get: { responses: {} } };
    const result = gate({ document, report: report([{ titles: ['[GET /a] reads it'] }]) });
    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('GET /b is stable and has no wire test');
  });

  it('exits 1 on a tag that names no operation of the document', () => {
    const result = gate({
      document: openapi({ 'GET /a': 'stable' }),
      report: report([{ titles: ['[GET /a] reads it'] }, { titles: ['[GET /a/{ID}] typo'] }]),
    });
    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('the tag [GET /a/{ID}] names no operation');
  });
});

describe('wire-coverage — the exempt list', () => {
  it('exits 0 when the exempt list names the untested stable operation', () => {
    const result = gate({
      document: openapi({ 'GET /a': 'stable', 'GET /b': 'stable' }),
      exempt: exemptList([exemption('GET /b')]),
      report: report([{ titles: ['[GET /a] reads it'] }]),
    });
    expect(result.status, result.stderr).toBe(EXIT_OK);
    expect(result.stdout).toContain('1 with a passing wire test, 1 exempt');
  });

  it('exits 1 on a stale entry: its operation has a passing wire test now', () => {
    const result = gate({
      document: openapi({ 'GET /a': 'stable' }),
      exempt: exemptList([exemption('GET /a')]),
      report: report([{ titles: ['[GET /a] reads it'] }]),
    });
    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('GET /a has a passing wire test now');
  });

  it('exits 1 on a stale entry: its operation left the document', () => {
    const result = gate({
      document: openapi({ 'GET /a': 'stable' }),
      exempt: exemptList([exemption('GET /gone')]),
      report: report([{ titles: ['[GET /a] reads it'] }]),
    });
    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('GET /gone is not an operation of the OpenAPI document');
  });

  it('exits 1 on an entry for an experimental operation, which its stability already exempts', () => {
    const result = gate({
      document: openapi({ 'GET /a': 'stable', 'GET /x': 'experimental' }),
      exempt: exemptList([exemption('GET /x')]),
      report: report([{ titles: ['[GET /a] reads it'] }]),
    });
    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('GET /x is experimental');
  });

  it('exits 1 on an operation listed twice', () => {
    const result = gate({
      document: openapi({ 'GET /a': 'stable' }),
      exempt: exemptList([exemption('GET /a'), exemption('GET /a')]),
      report: report([{ titles: ['other'] }]),
    });
    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('GET /a is listed twice');
  });

  it.each([
    ['no reason', exemption('GET /a', { reason: '  ' }), '"reason"'],
    ['an issue that is not a reference', exemption('GET /a', { issue: '535' }), '"issue"'],
    ['an operation not in METHOD /path form', exemption('get /a'), '"operation"'],
    ['an unknown member', exemption('GET /a', { until: '2027' }), 'unknown member(s) "until"'],
    ['an entry that is not an object', 'GET /a', 'is not an object'],
  ])('exits 1 on an entry with %s', (_name, entry, expected) => {
    const result = gate({
      document: openapi({ 'GET /a': 'stable' }),
      exempt: exemptList([entry]),
      report: report([{ titles: ['other'] }]),
    });
    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain(expected);
  });

  it('checks the list against the document without a report, and says it checked no coverage', () => {
    const paths = workspace({
      document: openapi({ 'GET /a': 'stable', 'GET /b': 'stable' }),
      exempt: exemptList([exemption('GET /b')]),
    });
    const result = run(['--openapi', paths.openapi, '--exempt', paths.exempt]);
    expect(result.status, result.stderr).toBe(EXIT_OK);
    expect(result.stdout).toContain('Coverage is not checked without --vitest-report');
  });
});

describe('wire-coverage — the exempt list may only shrink (--base-ref)', () => {
  const document = openapi({ 'GET /a': 'stable', 'GET /b': 'stable', 'GET /c': 'stable' });

  function compare(paths: { openapi: string; exempt: string }, ref = 'main') {
    return run(['--openapi', paths.openapi, '--exempt', paths.exempt, '--base-ref', ref]);
  }

  it('exits 1 when the working copy adds an entry the base does not have, and names it', () => {
    const paths = repository(document, [exemption('GET /a')]);
    writeFileSync(
      paths.exempt,
      JSON.stringify(exemptList([exemption('GET /a'), exemption('GET /c')]), null, 2)
    );
    const result = compare(paths);
    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('GET /c is a new exemption: the list at main does not name it');
    expect(result.stderr).not.toContain('GET /a is a new exemption');
  });

  it('exits 0 when the working copy removes an entry', () => {
    const paths = repository(document, [exemption('GET /a'), exemption('GET /b')]);
    writeFileSync(paths.exempt, JSON.stringify(exemptList([exemption('GET /b')]), null, 2));
    const result = compare(paths);
    expect(result.status, result.stderr).toBe(EXIT_OK);
    expect(result.stdout).toContain('names 1 operations and named 2 at main; 0 added');
  });

  it('accepts a changed reason or issue for an entry the base has', () => {
    const paths = repository(document, [exemption('GET /a')]);
    writeFileSync(
      paths.exempt,
      JSON.stringify(exemptList([exemption('GET /a', { reason: 'Reworded.', issue: '#1' })]))
    );
    expect(compare(paths).status).toBe(EXIT_OK);
  });

  it('exits 0 and says so when the base has no list yet: the change that introduces it', () => {
    const paths = repository(document, null);
    writeFileSync(paths.exempt, JSON.stringify(exemptList([exemption('GET /a')])));
    const result = compare(paths);
    expect(result.status, result.stderr).toBe(EXIT_OK);
    expect(result.stdout).toContain('does not exist at main');
  });

  it('exits 2 when git cannot resolve the base ref', () => {
    const paths = repository(document, [exemption('GET /a')]);
    const result = compare(paths, 'no-such-branch');
    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stderr).toContain('cannot resolve the base ref "no-such-branch"');
  });

  it('exits 2 when git cannot read the base commit’s tree — a failed read never passes as "no list yet"', () => {
    const paths = repository(document, [exemption('GET /a')]);
    writeFileSync(
      paths.exempt,
      JSON.stringify(exemptList([exemption('GET /a'), exemption('GET /c')]), null, 2)
    );
    // The commit stays resolvable while its tree is gone, as in a partial
    // clone whose on-demand fetch fails.
    const tree = git(paths.dir, ['rev-parse', 'main^{tree}']);
    rmSync(join(paths.dir, '.git', 'objects', tree.slice(0, 2), tree.slice(2)));
    const result = compare(paths);
    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stderr).toContain('cannot read the tree of the base ref "main"');
    expect(result.stdout).not.toContain('does not exist at main');
  });

  it('exits 2 on a base ref that git would read as an option', () => {
    const paths = repository(document, [exemption('GET /a')]);
    const result = compare(paths, '--output=/tmp/x');
    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stderr).toContain('is not a git ref');
  });
});

describe('wire-coverage — fail-closed on its inputs', () => {
  const document = openapi({ 'GET /a': 'stable' });

  it('exits 2 when the report does not exist, and writes no verdict', () => {
    const paths = workspace({ document, exempt: exemptList([]) });
    const result = run([
      '--openapi',
      paths.openapi,
      '--exempt',
      paths.exempt,
      '--vitest-report',
      join(paths.dir, 'missing.json'),
    ]);
    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stderr).toContain('no wire-suite report at');
    expect(result.stdout).toBe('');
  });

  it.each([
    ['an empty file', ''],
    ['invalid JSON', '{"testResults": ['],
    ['no testResults array', '{"numTotalTests": 3}'],
    ['a top-level array', '[]'],
  ])('exits 2 on a report that is %s', (_name, raw) => {
    const paths = workspace({ document, exempt: exemptList([]) });
    writeFileSync(paths.report, raw);
    const result = run([
      '--openapi',
      paths.openapi,
      '--exempt',
      paths.exempt,
      '--vitest-report',
      paths.report,
    ]);
    expect(result.status).toBe(EXIT_INPUT);
  });

  it('exits 2 on a report with no wire test file: not the wire suite’s report', () => {
    const result = gate({
      document,
      report: report([{ titles: ['[GET /a] reads it'] }], '/fixture/apps/x/src/a.test.ts'),
    });
    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stderr).toContain('not the wire suite');
  });

  it('exits 2 on a wire report with no test in it', () => {
    const result = gate({ document, report: report([]) });
    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stderr).toContain('contains no test');
  });

  it('exits 2 when an assertion lost its status — the reporter shape changed', () => {
    const shape = report([{ titles: ['[GET /a] reads it'] }]);
    delete (shape.testResults[0].assertionResults[0] as { status?: string }).status;
    const result = gate({ document, report: shape });
    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stderr).toContain('the reporter shape changed');
  });

  it('exits 2 when the exempt list is missing or has no exemptions array', () => {
    const missing = workspace({ document, report: report([{ titles: ['[GET /a] x'] }]) });
    expect(
      run([
        '--openapi',
        missing.openapi,
        '--exempt',
        missing.exempt,
        '--vitest-report',
        missing.report,
      ]).status
    ).toBe(EXIT_INPUT);

    const result = gate({ document, exempt: ['GET /a'], report: report([{ titles: ['x'] }]) });
    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stderr).toContain('"exemptions" array');
  });

  it('exits 2 on a document that lists no operation', () => {
    const result = gate({ document: { openapi: '3.1.0', paths: {} }, report: report([]) });
    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stderr).toContain('lists no operation');
  });

  it('exits 2 on an unknown argument and on --vitest-report given twice', () => {
    expect(run(['--nope']).status).toBe(EXIT_INPUT);
    expect(run(['--vitest-report', 'a.json', '--vitest-report', 'b.json']).status).toBe(EXIT_INPUT);
  });
});

describe('wire-coverage — the committed files', () => {
  it('passes the repository’s exempt list against the committed OpenAPI document', () => {
    const result = run([]);
    expect(result.status, result.stderr).toBe(EXIT_OK);
  });
});
