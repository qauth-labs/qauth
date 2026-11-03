/**
 * Guard for the dependency audit summary (#795): the report `pnpm audit
 * --json` prints, read and rendered as the job summary. Driven on objects
 * here; `summary.test.ts` runs the CLI the way CI does.
 */
import { describe, expect, it } from 'vitest';

import { parseReport, renderSummary, ReportError } from './lib.mjs';

/**
 * The pipes that separate cells in a table row, as Markdown tables read them: a
 * pipe is escaped only by an odd number of backslashes before it. Six cells
 * have seven.
 */
function cellBoundaries(row: string | undefined): number {
  return row?.match(/(?<!\\)(?:\\\\)*\|/g)?.length ?? 0;
}

type Finding = { version: string; paths: string[] };

/** One advisory in the shape pnpm 12 prints it, with `overrides` on top. */
function advisory(overrides: Record<string, unknown> = {}) {
  return {
    findings: [
      {
        version: '1.16.1',
        paths: ['.>@nx/web>http-server>http-proxy>follow-redirects'],
        dev: false,
        optional: false,
        bundled: false,
      },
    ] as Finding[],
    id: 1243600,
    title: 'follow-redirects: custom credentials can follow redirects',
    module_name: 'follow-redirects',
    vulnerable_versions: '>=1.16.0 <=1.16.1',
    patched_versions: '>=1.16.2',
    patched_versions_unpublished: false,
    severity: 'high',
    cwe: 'CWE-200',
    github_advisory_id: 'GHSA-mrwp-f3q8-3g9p',
    url: 'https://example.test/advisories/GHSA-mrwp-f3q8-3g9p',
    ...overrides,
  };
}

function report(...advisories: Record<string, unknown>[]) {
  return JSON.stringify({
    advisories: Object.fromEntries(advisories.map((a, index) => [String(1000 + index), a])),
    metadata: { vulnerabilities: {}, dependencies: 1, devDependencies: 1 },
  });
}

describe('parseReport', () => {
  it('reads an advisory, its installed versions and every path', () => {
    const [read] = parseReport(
      report(
        advisory({
          findings: [
            { version: '10.5.0', paths: ['a>glob', 'b>glob'] },
            { version: '13.0.6', paths: ['c>glob'] },
            { version: '10.5.0', paths: ['d>glob'] },
          ],
        })
      )
    );

    expect(read).toEqual({
      id: 'GHSA-mrwp-f3q8-3g9p',
      severity: 'high',
      packageName: 'follow-redirects',
      title: 'follow-redirects: custom credentials can follow redirects',
      url: 'https://example.test/advisories/GHSA-mrwp-f3q8-3g9p',
      vulnerableVersions: '>=1.16.0 <=1.16.1',
      patchedVersions: '>=1.16.2',
      installedVersions: ['10.5.0', '13.0.6'],
      paths: ['a>glob', 'b>glob', 'c>glob', 'd>glob'],
    });
  });

  it('reads an advisory no release fixes', () => {
    const [read] = parseReport(report(advisory({ patched_versions: null })));

    expect(read.patchedVersions).toBeNull();
  });

  it('reads a report with no advisory', () => {
    expect(parseReport(report())).toEqual([]);
  });

  it('orders by severity, most severe first, then by package and advisory', () => {
    const read = parseReport(
      report(
        advisory({ severity: 'low', module_name: 'deepmerge', github_advisory_id: 'GHSA-l' }),
        advisory({ severity: 'moderate', module_name: 'seroval', github_advisory_id: 'GHSA-b' }),
        advisory({ severity: 'critical', module_name: 'zod', github_advisory_id: 'GHSA-c' }),
        advisory({ severity: 'moderate', module_name: 'seroval', github_advisory_id: 'GHSA-a' }),
        advisory({ severity: 'moderate', module_name: 'glob', github_advisory_id: 'GHSA-g' }),
        advisory({ severity: 'high', module_name: 'qs', github_advisory_id: 'GHSA-h' })
      )
    );

    expect(read.map((a) => a.id)).toEqual([
      'GHSA-c',
      'GHSA-h',
      'GHSA-g',
      'GHSA-a',
      'GHSA-b',
      'GHSA-l',
    ]);
  });

  // A change in pnpm's output must fail the summary step, not render a
  // summary that quietly lists nothing.
  it.each([
    ['text that is not JSON', 'npm ERR! audit endpoint returned an error', /is not JSON/],
    ['a JSON array', '[]', /is not a JSON object/],
    [
      'a registry error',
      JSON.stringify({ error: { code: 'ERR_PNPM_AUDIT_BAD_RESPONSE' } }),
      /is an error/,
    ],
    ['a report with no advisories', JSON.stringify({ metadata: {} }), /no "advisories" object/],
    ['an advisories list', JSON.stringify({ advisories: [] }), /no "advisories" object/],
    ['an advisory that is not an object', report('high' as never), /is not an object/],
    ['an unknown severity', report(advisory({ severity: 'severe' })), /unknown severity/],
    ['no advisory id', report(advisory({ github_advisory_id: undefined })), /"github_advisory_id"/],
    ['no package name', report(advisory({ module_name: '' })), /"module_name"/],
    ['no title', report(advisory({ title: 7 })), /"title"/],
    ['no url', report(advisory({ url: undefined })), /"url"/],
    [
      'no vulnerable range',
      report(advisory({ vulnerable_versions: null })),
      /"vulnerable_versions"/,
    ],
    [
      'a patched range that is not a string',
      report(advisory({ patched_versions: 2 })),
      /"patched_versions"/,
    ],
    ['no findings', report(advisory({ findings: [] })), /no findings/],
    [
      'a finding with no version',
      report(advisory({ findings: [{ paths: ['a'] }] })),
      /version and its paths/,
    ],
    [
      'a finding with no paths',
      report(advisory({ findings: [{ version: '1.0.0' }] })),
      /version and its paths/,
    ],
    [
      'a path that is not a string',
      report(advisory({ findings: [{ version: '1.0.0', paths: [1] }] })),
      /path that is not a string/,
    ],
  ])('refuses %s', (_label, text, message) => {
    expect(() => parseReport(text)).toThrow(ReportError);
    expect(() => parseReport(text)).toThrow(message);
  });
});

describe('renderSummary', () => {
  it('says so when the report holds no advisory', () => {
    const summary = renderSummary(parseReport(report()));

    expect(summary).toBe(
      [
        '## Dependency audit',
        '',
        '`pnpm audit` reports no advisory.',
        '',
        'Advisories accepted in `pnpm-workspace.yaml` (`auditConfig.ignoreGhsas`) are left out; each entry there says why and until when.',
        '',
      ].join('\n')
    );
  });

  // The fourth task of #795: moderate and low findings reach the summary, and
  // the summary says they do not fail the job.
  it('lists moderate and low advisories and says they do not fail the job', () => {
    const summary = renderSummary(
      parseReport(
        report(
          advisory({
            severity: 'moderate',
            module_name: 'glob',
            github_advisory_id: 'GHSA-3g3m-2fjr-6pw4',
            url: 'https://example.test/advisories/GHSA-3g3m-2fjr-6pw4',
            title: 'Glob: AbortSignal cancellation bypass',
            patched_versions: '>=14.0.2',
            findings: [
              { version: '13.0.6', paths: ['apps__auth-server>@fastify/static>glob'] },
              { version: '10.5.0', paths: ['.>archiver>archiver-utils>glob'] },
            ],
          }),
          advisory({
            severity: 'low',
            module_name: 'deepmerge',
            github_advisory_id: 'GHSA-gcqx-w48m-w2h4',
            url: 'https://example.test/advisories/GHSA-gcqx-w48m-w2h4',
            title: 'deepmerge prototype poisoning',
            patched_versions: null,
            findings: [{ version: '4.3.1', paths: ['.>html-to-text>deepmerge'] }],
          })
        )
      )
    );

    expect(summary.split('\n')).toEqual([
      '## Dependency audit',
      '',
      '`pnpm audit` reports 2 advisories: 1 moderate, 1 low.',
      '',
      'None is high or critical, so none fails this job: they are listed here until they are fixed.',
      '',
      '| Severity | Package | Installed | Fixed in | Advisory | Paths |',
      '| --- | --- | --- | --- | --- | --- |',
      '| moderate | `glob` | `10.5.0`, `13.0.6` | `>=14.0.2` | [GHSA-3g3m-2fjr-6pw4](https://example.test/advisories/GHSA-3g3m-2fjr-6pw4) Glob: AbortSignal cancellation bypass | 2, e.g. `apps__auth-server>@fastify/static>glob` |',
      '| low | `deepmerge` | `4.3.1` | no release | [GHSA-gcqx-w48m-w2h4](https://example.test/advisories/GHSA-gcqx-w48m-w2h4) deepmerge prototype poisoning | 1, e.g. `.>html-to-text>deepmerge` |',
      '',
      'Advisories accepted in `pnpm-workspace.yaml` (`auditConfig.ignoreGhsas`) are left out; each entry there says why and until when.',
      '',
    ]);
  });

  it('says how many advisories fail the job, and where one is accepted', () => {
    const summary = renderSummary(
      parseReport(
        report(
          advisory(),
          advisory({
            severity: 'critical',
            module_name: 'x',
            github_advisory_id: 'GHSA-xxxx-xxxx-xxxx',
          }),
          advisory({
            severity: 'moderate',
            module_name: 'y',
            github_advisory_id: 'GHSA-yyyy-yyyy-yyyy',
          })
        )
      )
    );

    expect(summary).toContain('`pnpm audit` reports 3 advisories: 1 critical, 1 high, 1 moderate.');
    expect(summary).toContain(
      '2 high or critical: this job fails until each is fixed, or accepted with a reason in `pnpm-workspace.yaml` under `auditConfig.ignoreGhsas`. Moderate and low ones are listed and do not fail it.'
    );
    expect(summary).toContain('| high | `follow-redirects` | `1.16.1` | `>=1.16.2` |');
  });

  it('uses the singular for one advisory', () => {
    expect(renderSummary(parseReport(report(advisory())))).toContain(
      '`pnpm audit` reports 1 advisory: 1 high.'
    );
  });

  // The registry's text lands in Markdown the job summary renders as HTML: none of
  // it may end a row, end a cell, open a link or inject markup.
  it('keeps text from the report inside its cell', () => {
    const summary = renderSummary(
      parseReport(
        report(
          advisory({
            title:
              'a | b\n| x | <img src=x onerror=alert(1)> [link](https://evil.test) *bold* `tick`',
            module_name: 'pkg|name`',
            patched_versions: '>=1 | <2',
            findings: [{ version: '1.0.0', paths: ['.>a|b>`c`'] }],
          })
        )
      )
    );
    const row = summary.split('\n').find((line) => line.startsWith('| high '));

    expect(summary.split('\n').filter((line) => line.startsWith('| high ')).length).toBe(1);
    expect(row).toBe(
      "| high | `pkg\\|name'` | `1.0.0` | `>=1 \\| <2` | [GHSA-mrwp-f3q8-3g9p](https://example.test/advisories/GHSA-mrwp-f3q8-3g9p) a \\| b \\| x \\| \\<img src=x onerror=alert\\(1\\)\\> \\[link\\]\\(https://evil.test\\) \\*bold\\* \\`tick\\` | 1, e.g. `.>a\\|b>'c'` |"
    );
    expect(cellBoundaries(row)).toBe(7);
  });

  // `\\|` is an escaped backslash and then a pipe that ends the cell: the backslash
  // must be escaped before the pipe is.
  it('keeps a backslash before a pipe from ending the cell', () => {
    const summary = renderSummary(
      parseReport(
        report(
          advisory({
            module_name: 'pkg\\|name',
            findings: [{ version: '1.0.0\\', paths: ['.>a\\|b'] }],
          })
        )
      )
    );
    const row = summary.split('\n').find((line) => line.startsWith('| high '));

    expect(row).toContain("| `pkg\\\\\\|name` | `1.0.0\\\\` |");
    expect(row).toContain('| 1, e.g. `.>a\\\\\\|b` |');
    expect(cellBoundaries(row)).toBe(7);
  });

  it.each([
    ['a URL that is not https', 'http://example.test/advisories/GHSA-mrwp-f3q8-3g9p'],
    ['a javascript: URL', 'javascript:alert(1)'],
    ['text that is not a URL', 'see the advisory database'],
  ])('does not link %s', (_label, url) => {
    const summary = renderSummary(parseReport(report(advisory({ url }))));

    expect(summary).toContain('| GHSA-mrwp-f3q8-3g9p follow-redirects');
    expect(summary).not.toContain('](');
  });

  it('keeps a pipe in a URL from ending the cell', () => {
    const summary = renderSummary(
      parseReport(report(advisory({ url: 'https://example.test/a|b?q=c|d' })))
    );
    const row = summary.split('\n').find((line) => line.startsWith('| high '));

    expect(row).toContain('[GHSA-mrwp-f3q8-3g9p](https://example.test/a%7Cb?q=c%7Cd)');
    expect(cellBoundaries(row)).toBe(7);
  });

  it('keeps a parenthesis in a URL from closing the link', () => {
    const summary = renderSummary(
      parseReport(report(advisory({ url: 'https://example.test/a(b)c' })))
    );

    expect(summary).toContain('[GHSA-mrwp-f3q8-3g9p](https://example.test/a%28b%29c)');
  });

  it('escapes an advisory id that is not a GHSA id', () => {
    const summary = renderSummary(
      parseReport(report(advisory({ github_advisory_id: '[x](https://evil.test)', url: 'nope' })))
    );

    expect(summary).toContain('| \\[x\\]\\(https://evil.test\\) follow-redirects');
  });
});
