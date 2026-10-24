import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { headingAnchor, markdownHeadingAnchors, RESERVED_ANCHORS } from './anchor';

const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');

describe('headingAnchor', () => {
  // The values the docs site renders, checked against its built HTML for this
  // change: `id="oid4vp-10-base"` and the others.
  it.each([
    ['oid4vp-1.0-base', 'oid4vp-10-base'],
    ['plugin-api', 'plugin-api'],
    ['8. Assurance before 1.0', '8-assurance-before-10'],
    ['What experimental means', 'what-experimental-means'],
    ['The `/first-party` subpath', 'the-first-party-subpath'],
  ])('turns %s into %s', (text, anchor) => {
    expect(headingAnchor(text)).toBe(anchor);
  });
});

describe('markdownHeadingAnchors', () => {
  it('reads every heading level, a link as its text, and numbers a repeated heading', () => {
    const anchors = markdownHeadingAnchors(
      [
        '# Title',
        '## A [linked](https://example.com) heading',
        '### Notes',
        '### Notes',
        '#### Closed heading ##',
      ].join('\n')
    );
    expect([...anchors]).toEqual([
      'title',
      'a-linked-heading',
      'notes',
      'notes-1',
      'closed-heading',
    ]);
  });

  it('skips fenced code and lines that are not headings', () => {
    const anchors = markdownHeadingAnchors(
      ['Some text', '```bash', '# a shell comment', '```', '#not-a-heading', '## Real'].join('\n')
    );
    expect([...anchors]).toEqual(['real']);
  });

  it('reads a long line of spaces or brackets in linear time', () => {
    const anchors = markdownHeadingAnchors(
      [`# a${' '.repeat(100_000)}b`, `## ${'[\\'.repeat(50_000)}`].join('\n')
    );
    expect(anchors.size).toBe(2);
  });

  it('finds the section a fixture names in ADR-018', () => {
    const adr = readFileSync(join(REPO_ROOT, 'docs/adr/018-1-0-scope-and-stability.md'), 'utf8');
    expect(markdownHeadingAnchors(adr).has('8-assurance-before-10')).toBe(true);
  });
});

describe('RESERVED_ANCHORS', () => {
  it('holds the anchors of the page headings above the items', () => {
    expect([...RESERVED_ANCHORS]).toEqual(['what-experimental-means', 'becoming-stable', 'items']);
  });
});
