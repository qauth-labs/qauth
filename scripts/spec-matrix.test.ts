/**
 * Guard for `scripts/spec-matrix.mjs`, the spec-conformance gate (issue #400).
 *
 * The gate's single most important property is that it FAILS CLOSED. A missing,
 * empty or shape-changed Vitest report must exit non-zero and must not render a
 * matrix at all — because a matrix rendered from an empty report says every
 * requirement is unproven, and a matrix rendered from a report the joiner can
 * no longer parse says nothing while looking like evidence. Certification
 * evidence that fails open is worse than no evidence.
 *
 * That property was protected by nothing until this file existed.
 *
 * The joiner is a CLI whose module body ends in `process.exitCode = main()`, so
 * it cannot be imported without running it. It is therefore exercised the way
 * CI runs it: spawned as a child process, with fixture conformance data and
 * fixture reports written to a temp directory. That also means v8 records no
 * coverage for it — the assertions here are on exit codes, on the `::error`
 * annotations, and on which files the run did or did not write.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'spec-matrix.mjs');

const EXIT_OK = 0;
const EXIT_GATE = 1;
const EXIT_INPUT = 2;

const workspaces: string[] = [];

afterAll(() => {
  for (const dir of workspaces) rmSync(dir, { recursive: true, force: true });
});

/** A registry with exactly one unsealed fixture spec. */
const SPECS = {
  version: 1,
  specs: [
    {
      id: 'rfc9999',
      name: 'RFC 9999 — Fixture Spec',
      url: 'https://example.invalid/rfc9999',
      aliases: ['RFC 9999'],
      sealed: false,
    },
  ],
};

type Row = Record<string, unknown>;

/** A `covered` row at §2 unless the caller overrides it. */
function row(overrides: Row = {}): Row {
  return {
    id: 'fixture-row',
    section: '2',
    level: 'MUST',
    quote: 'The fixture server MUST do the fixture thing.',
    status: 'covered',
    ...overrides,
  };
}

interface FixtureTest {
  fullName: string;
  status?: string;
}

/** A Vitest JSON report in the shape the joiner reads. */
function report(tests: FixtureTest[]): unknown {
  return {
    numTotalTests: tests.length,
    testResults: [
      {
        name: '/fixture/repo/fixture.test.ts',
        assertionResults: tests.map((test) => ({
          ancestorTitles: [],
          title: test.fullName,
          fullName: test.fullName,
          status: test.status ?? 'passed',
        })),
      },
    ],
  };
}

interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
  outDir: string;
  rendered: boolean;
}

/**
 * Write a fixture workspace and run the joiner against it.
 *
 * `reportBody` is written verbatim when it is a string, so a test can hand the
 * joiner something that is not JSON at all; pass `null` to write no report file
 * and exercise the missing-report path.
 */
function run(options: {
  rows?: Row[];
  reportBody?: unknown;
  specs?: unknown;
  omitReportArg?: boolean;
}): RunResult {
  const dir = mkdtempSync(join(tmpdir(), 'spec-matrix-'));
  workspaces.push(dir);

  const conformanceDir = join(dir, 'conformance');
  mkdirSync(join(conformanceDir, 'requirements'), { recursive: true });
  writeFileSync(join(conformanceDir, 'specs.json'), JSON.stringify(options.specs ?? SPECS));
  writeFileSync(
    join(conformanceDir, 'requirements', 'rfc9999.json'),
    JSON.stringify({ specId: 'rfc9999', requirements: options.rows ?? [row()] })
  );

  const reportPath = join(dir, 'report.json');
  if (options.reportBody !== null && options.reportBody !== undefined) {
    writeFileSync(
      reportPath,
      typeof options.reportBody === 'string'
        ? options.reportBody
        : JSON.stringify(options.reportBody)
    );
  }

  const outDir = join(dir, 'out');
  const args = ['--conformance-dir', conformanceDir, '--out-dir', outDir, '--no-summary'];
  if (!options.omitReportArg) args.unshift('--vitest-report', reportPath);

  const proc = spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: 'utf8',
    // GITHUB_STEP_SUMMARY would otherwise be honoured from the ambient env.
    env: { ...process.env, GITHUB_STEP_SUMMARY: '' },
  });

  return {
    status: proc.status ?? -1,
    stdout: proc.stdout ?? '',
    stderr: proc.stderr ?? '',
    outDir,
    rendered: existsSync(join(outDir, 'matrix.md')),
  };
}

/** The citation grammar the joiner extracts, for a row declared at §2. */
const CITING = 'the fixture server does the fixture thing (RFC 9999 §2)';

describe('spec-matrix — fail-closed on the Vitest report', () => {
  // Each of these must exit 2 (input error, distinct from a gate failure) AND
  // must not render a matrix, because a rendered matrix is read as evidence.
  const cases: Array<[string, { reportBody?: unknown; omitReportArg?: boolean }]> = [
    ['no report file at the given path', { reportBody: null }],
    ['an empty file', { reportBody: '' }],
    ['whitespace only', { reportBody: '   \n  ' }],
    ['a file that is not JSON', { reportBody: 'not json at all' }],
    ['a JSON array at the top level', { reportBody: [] }],
    ['JSON null', { reportBody: 'null' }],
    ['an object with no testResults', { reportBody: {} }],
    ['testResults present but empty', { reportBody: { testResults: [] } }],
    [
      'every suite carrying a null assertionResults',
      { reportBody: { testResults: [{ name: 'a.test.ts', assertionResults: null }] } },
    ],
    [
      'suites present but zero assertions between them',
      { reportBody: { testResults: [{ name: 'a.test.ts', assertionResults: [] }] } },
    ],
    [
      'a first assertion with no fullName',
      {
        reportBody: {
          testResults: [{ name: 'a.test.ts', assertionResults: [{ status: 'passed' }] }],
        },
      },
    ],
    [
      'a first assertion with no status',
      {
        reportBody: {
          testResults: [{ name: 'a.test.ts', assertionResults: [{ fullName: CITING }] }],
        },
      },
    ],
    ['no --vitest-report argument at all', { omitReportArg: true }],
  ];

  it.each(cases)('exits 2 and renders nothing on %s', (_label, options) => {
    const result = run(options);

    expect(result.status).toBe(EXIT_INPUT);
    expect(result.rendered).toBe(false);
    expect(result.stderr).toMatch(/spec-matrix:/);
  });

  it('never reports a row as proven when the report is empty', () => {
    // The regression this whole file exists for: an empty report must not be
    // read as "no citations found, nothing to complain about".
    const result = run({ reportBody: { testResults: [] } });

    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stdout).not.toMatch(/covered/);
    expect(existsSync(join(result.outDir, 'matrix.json'))).toBe(false);
  });

  it('separates an input error from a gate failure by exit code', () => {
    const input = run({ reportBody: '{}' });
    const gate = run({ reportBody: report([{ fullName: 'an uncited test' }]) });

    expect(input.status).toBe(EXIT_INPUT);
    expect(gate.status).toBe(EXIT_GATE);
  });
});

describe('spec-matrix — the gate on `covered` rows', () => {
  it('exits 0 and renders the matrix when a passing test cites the row', () => {
    const result = run({ reportBody: report([{ fullName: CITING }]) });

    expect(result.status).toBe(EXIT_OK);
    expect(result.rendered).toBe(true);
    const markdown = readFileSync(join(result.outDir, 'matrix.md'), 'utf8');
    expect(markdown).toContain('The fixture server MUST do the fixture thing.');
    expect(markdown).toContain(CITING);
  });

  it('exits 1 naming the row file and section when no test cites the row', () => {
    const result = run({ reportBody: report([{ fullName: 'an unrelated test' }]) });

    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toMatch(/::error file=.*requirements\/rfc9999\.json,line=\d+/);
    expect(result.stderr).toContain('unproven: rfc9999 §2');
    expect(result.stderr).toContain('no passing test in the report cites it');
  });

  it('exits 1 when the only citing test is skipped — a skipped test proves nothing', () => {
    const result = run({ reportBody: report([{ fullName: CITING, status: 'skipped' }]) });

    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('its only citing tests did not pass');
    expect(result.stderr).toContain('skipped: ' + CITING);
  });

  it('exits 1 when the only citing test failed', () => {
    const result = run({ reportBody: report([{ fullName: CITING, status: 'failed' }]) });

    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('its only citing tests did not pass');
  });

  it('matches sections hierarchically — §2.4 proves a row at §2, §2.4.1 does not', () => {
    const deeper = run({
      reportBody: report([{ fullName: 'a deeper citation (RFC 9999 §2.4)' }]),
    });
    const shallower = run({
      rows: [row({ section: '2.4.1' })],
      reportBody: report([{ fullName: 'a shallower citation (RFC 9999 §2.4)' }]),
    });

    expect(deeper.status).toBe(EXIT_OK);
    expect(shallower.status).toBe(EXIT_GATE);
  });
});

describe('spec-matrix — evidenceMatch narrows what counts as proof', () => {
  it('exits 1 when the citing test matches the section but not the pattern', () => {
    // The #400 defect in miniature: a test that cites §2 for an unrelated
    // requirement in the same section must not stand in as this row's proof.
    const result = run({
      rows: [row({ evidenceMatch: 'does the fixture thing' })],
      reportBody: report([{ fullName: 'something else entirely (RFC 9999 §2)' }]),
    });

    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('matches its evidenceMatch `does the fixture thing`');
  });

  it('exits 0 when a citing test matches both the section and the pattern', () => {
    const result = run({
      rows: [row({ evidenceMatch: 'does the fixture thing' })],
      reportBody: report([
        { fullName: 'something else entirely (RFC 9999 §2)' },
        { fullName: CITING },
      ]),
    });

    expect(result.status).toBe(EXIT_OK);
    const markdown = readFileSync(join(result.outDir, 'matrix.md'), 'utf8');
    // The Evidence column must name the test that actually proves the row.
    expect(markdown).toContain(CITING);
    expect(markdown).not.toContain('something else entirely');
  });

  it('can only remove evidence, never add it — a pattern cannot cross sections', () => {
    const result = run({
      rows: [row({ section: '3', evidenceMatch: 'fixture' })],
      reportBody: report([{ fullName: CITING }]),
    });

    expect(result.status).toBe(EXIT_GATE);
  });

  it('exits 1 on an evidenceMatch that will not compile, and proves nothing with it', () => {
    const result = run({
      rows: [row({ evidenceMatch: '([unterminated' })],
      reportBody: report([{ fullName: CITING }]),
    });

    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('not a valid regular expression');
    // Fail-closed: a broken pattern must not fall back to "everything matches".
    expect(result.stderr).toContain('unproven: rfc9999 §2');
  });

  it('exits 1 when evidenceMatch is put on a row that is not `covered`', () => {
    const result = run({
      rows: [row({ status: 'n/a', reason: 'never applied', evidenceMatch: 'anything' })],
      reportBody: report([{ fullName: CITING }]),
    });

    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('only means anything on a "covered" row');
  });
});

describe('spec-matrix — waived and n/a rows must carry their justification', () => {
  const waived = {
    status: 'waived',
    reason: 'in profile, knowingly not satisfied',
    decision: '#400',
    revisit: '2027-02-28',
  };

  it('accepts a complete waiver without any citing test', () => {
    const result = run({
      rows: [row(waived)],
      reportBody: report([{ fullName: 'an unrelated test' }]),
    });

    expect(result.status).toBe(EXIT_OK);
    const markdown = readFileSync(join(result.outDir, 'matrix.md'), 'utf8');
    expect(markdown).toContain('### Waived');
    expect(markdown).toContain('in profile, knowingly not satisfied');
  });

  it.each([
    ['reason', 'must carry a "reason"'],
    ['decision', 'must carry a "decision"'],
    ['revisit', 'must carry a "revisit"'],
  ])('exits 1 when a waived row omits %s', (field, message) => {
    const incomplete: Record<string, unknown> = { ...waived };
    delete incomplete[field];
    const result = run({
      rows: [row(incomplete)],
      reportBody: report([{ fullName: 'an unrelated test' }]),
    });

    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain(message);
  });

  it('exits 1 on a revisit that is not an ISO date or "never"', () => {
    const result = run({
      rows: [row({ ...waived, revisit: 'soon' })],
      reportBody: report([{ fullName: 'an unrelated test' }]),
    });

    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('must carry a "revisit"');
  });

  it('exits 1 on a decision that is neither an issue reference nor a resolvable path', () => {
    const result = run({
      rows: [row({ ...waived, decision: 'docs/does-not-exist.md' })],
      reportBody: report([{ fullName: 'an unrelated test' }]),
    });

    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('"decision" is neither an issue reference nor a resolvable');
  });

  it('exits 1 when an n/a row carries no reason, and 0 when it does', () => {
    const bare = run({
      rows: [row({ status: 'n/a' })],
      reportBody: report([{ fullName: 'an unrelated test' }]),
    });
    const justified = run({
      rows: [row({ status: 'n/a', reason: 'a client-side obligation' })],
      reportBody: report([{ fullName: 'an unrelated test' }]),
    });

    expect(bare.status).toBe(EXIT_GATE);
    expect(bare.stderr).toContain('must carry a "reason"');
    expect(justified.status).toBe(EXIT_OK);
    expect(readFileSync(join(justified.outDir, 'matrix.md'), 'utf8')).toContain(
      '### Not applicable'
    );
  });

  it('keeps waived and n/a in separate sections — collapsing them destroys the document', () => {
    const result = run({
      rows: [row(waived), row({ id: 'fixture-na', status: 'n/a', reason: 'outside the profile' })],
      reportBody: report([{ fullName: 'an unrelated test' }]),
    });

    expect(result.status).toBe(EXIT_OK);
    const markdown = readFileSync(join(result.outDir, 'matrix.md'), 'utf8');
    expect(markdown.indexOf('### Waived')).toBeLessThan(markdown.indexOf('### Not applicable'));
  });
});

describe('spec-matrix — the sealed ratchet', () => {
  it('reports an orphan citation without failing while the spec is unsealed', () => {
    const result = run({
      reportBody: report([{ fullName: CITING }, { fullName: 'an orphan (RFC 9999 §7)' }]),
    });

    expect(result.status).toBe(EXIT_OK);
    expect(readFileSync(join(result.outDir, 'matrix.md'), 'utf8')).toContain(
      '## Citations with no row'
    );
  });

  it('fails on the same orphan once the spec is sealed', () => {
    const sealed = { ...SPECS, specs: [{ ...SPECS.specs[0], sealed: true }] };
    const result = run({
      specs: sealed,
      reportBody: report([{ fullName: CITING }, { fullName: 'an orphan (RFC 9999 §7)' }]),
    });

    expect(result.status).toBe(EXIT_GATE);
    expect(result.stderr).toContain('orphan citation: rfc9999 §7');
  });
});

describe('spec-matrix — the citation-coverage figures it derives', () => {
  it('reports how much of the report carries a registered citation, so no document has to', () => {
    const result = run({
      reportBody: report([
        { fullName: CITING },
        { fullName: 'uncited' },
        { fullName: 'cites an unregistered spec (HAIP §4.5.1)' },
      ]),
    });

    expect(result.status).toBe(EXIT_OK);
    expect(result.stdout).toContain('3 assertions read from');
    expect(result.stdout).toContain('1 of them citing a registered spec across 1 file(s)');
    expect(readFileSync(join(result.outDir, 'matrix.md'), 'utf8')).toContain('Joinable corpus');
  });
});
