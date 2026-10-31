/**
 * Guard for the pinned-reference rule (#796): every `uses:` in a workflow
 * names a major tag or a full commit SHA, never a branch or `latest`. The
 * rule is driven on strings here; the `actionlint` CI job runs it on the
 * committed workflows through `check.mjs`.
 */
import { describe, expect, it } from 'vitest';

import { referenceProblem, workflowReferences } from './lib.mjs';

const SHA = '3d3c42e5aac5ba805825da76410c181273ba90b1';
const DIGEST = `sha256:${'0123456789abcdef'.repeat(4)}`;

describe('referenceProblem', () => {
  it.each([
    ['a major tag', 'actions/checkout@v7'],
    ['major tag zero', 'some-org/some-action@v0'],
    ['a major tag of an action in a subdirectory', 'actions/cache/restore@v6'],
    ['a full commit SHA', `actions/checkout@${SHA}`],
    ['a local action', './tools/local-action'],
    ['an image at a version tag', 'docker://rhysd/actionlint:1.7.7'],
    ['an image at a v-prefixed version tag', 'docker://koalaman/shellcheck:v0.10.0'],
    ['an image from a registry with a port', 'docker://registry.example:5000/team/tool:2.1'],
    ['an image at a digest', `docker://alpine@${DIGEST}`],
  ])('accepts %s', (_label, reference) => {
    expect(referenceProblem(reference)).toBeNull();
  });

  it.each([
    ['a branch', 'actions/checkout@main', /"main", which is neither a major tag nor/],
    ['a branch with a slash', 'some-org/some-action@release/v1', /"release\/v1"/],
    ['latest', 'some-org/some-action@latest', /names "latest"/],
    ['no ref', 'actions/checkout', /names no ref/],
    ['an empty ref', 'actions/checkout@', /names no ref/],
    ['a patch tag', 'actions/checkout@v7.0.1', /version tag v7\.0\.1; pin its major tag \(@v7\)/],
    ['a minor tag', 'actions/checkout@v7.1', /version tag v7\.1; pin its major tag \(@v7\)/],
    ['an abbreviated SHA', 'actions/checkout@3d3c42e', /full 40-character lower-case SHA/],
    ['an upper-case SHA', `actions/checkout@${SHA.toUpperCase()}`, /full 40-character/],
    ['an image with no tag', 'docker://rhysd/actionlint', /no image tag/],
    ['an image at latest', 'docker://rhysd/actionlint:latest', /image tag "latest"/],
    ['an image at a named tag', 'docker://node:lts-alpine', /image tag "lts-alpine"/],
    ['an image at a rolling version tag', 'docker://some/tool:1-nightly', /image tag "1-nightly"/],
    ['an image whose only colon is a port', 'docker://registry.example:5000/tool', /no image tag/],
  ])('refuses %s', (_label, reference, message) => {
    expect(referenceProblem(reference)).toMatch(message);
  });
});

describe('workflowReferences', () => {
  it('reads every uses: line with its line number, past quotes and comments', () => {
    const text = [
      'jobs:',
      '  build:',
      '    steps:',
      `      - uses: actions/checkout@${SHA} # v7.0.1`,
      '      - name: Set up Node',
      "        uses: 'actions/setup-node@v7'",
      '      - uses: "pnpm/action-setup@v6"   # pinned',
      '  shared:',
      '    uses: ./workflows/shared.yml',
    ].join('\n');

    expect(workflowReferences(text)).toEqual([
      { line: 4, uses: `actions/checkout@${SHA}`, problem: null },
      { line: 6, uses: 'actions/setup-node@v7', problem: null },
      { line: 7, uses: 'pnpm/action-setup@v6', problem: null },
      { line: 9, uses: './workflows/shared.yml', problem: null },
    ]);
  });

  it('refuses a reference at a branch, on its own line', () => {
    const text = [
      'steps:',
      '  - uses: actions/checkout@v7',
      '  - uses: some-org/some-action@main',
    ].join('\n');

    expect(workflowReferences(text)).toEqual([
      { line: 2, uses: 'actions/checkout@v7', problem: null },
      {
        line: 3,
        uses: 'some-org/some-action@main',
        problem: expect.stringMatching(/neither a major tag nor a full commit SHA/),
      },
    ]);
  });

  it('reads a file with CRLF line endings', () => {
    expect(workflowReferences('steps:\r\n  - uses: some-org/some-action@main\r\n')).toEqual([
      { line: 2, uses: 'some-org/some-action@main', problem: expect.any(String) },
    ]);
  });

  it('skips keys that only end in uses, and comments', () => {
    const text = ['reuses: some-org/some-action@main', 'upload-artifact: false', '# uses: x@main'];

    expect(workflowReferences(text.join('\n'))).toEqual([]);
  });

  it.each([
    ['a value on the next line', '  - uses:'],
    ['a comment and no value', '  - uses: # later'],
    ['an unclosed quote', "  - uses: 'actions/checkout@v7"],
    ['text after a quoted value', "  - uses: 'actions/checkout@v7' extra"],
    ['a flow mapping', '  - { uses: actions/checkout@main }'],
    ['a quoted key', '  - "uses": actions/checkout@main'],
    ['a single-quoted key', "    'uses': actions/checkout@main"],
    ['an anchor before the key', '  - &step uses: actions/checkout@main'],
  ])('refuses a uses: line it cannot read: %s', (_label, line) => {
    expect(workflowReferences(line)).toEqual([
      { line: 1, uses: line.trim(), problem: expect.stringMatching(/cannot be read/) },
    ]);
  });
});
