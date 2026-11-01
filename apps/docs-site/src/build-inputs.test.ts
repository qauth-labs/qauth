/**
 * The `build` target's declared inputs cover what the build reads (#960).
 *
 * `build` is cacheable: CI restores an unchanged site from the remote cache
 * instead of building it. Its hash covers this project's own files, its
 * dependencies, `docs/**` and the root-level `*.md` files (project.json). The
 * records collection reads docs/adr and docs/security, and the remark plugin
 * (src/plugins/remark-rewrite-record-links.ts) rewrites a record's relative
 * link only when the target EXISTS, so every file a record links to is an
 * input too. A link to a file outside those globs would be rewritten from a
 * file the hash does not see: creating, moving or deleting it would leave a
 * cached build replaying the old page.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { resolveRepoRoot } from './lib/repo-root';

const repoRoot = resolveRepoRoot();
const RECORD_DIRS = ['docs/adr', 'docs/security'];
const DECLARED = ['{workspaceRoot}/docs/**/*', '{workspaceRoot}/*.md'];

/**
 * The text with every fenced code block blanked, line for line. A link inside a
 * fence is an example, never a link the remark plugin rewrites. A fence closes
 * only on the opener's character, at least as many of them, and nothing else on
 * the line (CommonMark).
 */
function withoutFences(text: string): string {
  let fence: { char: string; length: number } | null = null;
  return text
    .split('\n')
    .map((line) => {
      const marker = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line);
      if (fence === null) {
        // A backtick fence's info string may not contain a backtick.
        if (marker && !(marker[1][0] === '`' && marker[2].includes('`'))) {
          fence = { char: marker[1][0], length: marker[1].length };
          return '';
        }
        return line;
      }
      if (
        marker &&
        marker[1][0] === fence.char &&
        marker[1].length >= fence.length &&
        marker[2].trim() === ''
      ) {
        fence = null;
      }
      return '';
    })
    .join('\n');
}

/** The relative link targets in a record's text, fragments dropped. */
function linkTargets(text: string): string[] {
  const live = withoutFences(text);
  const urls = [
    ...[...live.matchAll(/\]\(\s*<?([^)\s>]+)>?/g)].map((m) => m[1]),
    ...[...live.matchAll(/^\s*\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)/gm)].map((m) => m[1]),
  ];
  return urls
    .filter((url) => !/^(?:[a-z][a-z0-9+.-]*:|#|\/)/i.test(url))
    .map((url) => url.split('#')[0])
    .filter((path) => path.length > 0);
}

/** The repo-relative targets of a record file's relative links. */
function relativeTargets(file: string): string[] {
  return linkTargets(readFileSync(file, 'utf8')).map((path) =>
    relative(repoRoot, resolve(dirname(file), path)).replace(/\\/g, '/')
  );
}

function covered(repoRelative: string): boolean {
  return repoRelative.startsWith('docs/') || /^[^/]+\.md$/.test(repoRelative);
}

describe('link scan', () => {
  it('skips links inside fenced code, closed only by a matching fence', () => {
    const text = [
      'See [ADR](./001-x.md).',
      '````md',
      '[example](../../examples/a.md)',
      '```',
      '[still inside](../../examples/b.md)',
      '````',
      '~~~',
      '[tilde](../../examples/c.md)',
      '~~~',
      '[ref]: ../security/threat-model.md',
    ].join('\n');
    expect(linkTargets(text)).toEqual(['./001-x.md', '../security/threat-model.md']);
  });

  it('drops fragments, absolute paths and URLs', () => {
    const text = '[a](./x.md#y) [b](/docs/z.md) [c](https://e.com/x.md) [d](#top)';
    expect(linkTargets(text)).toEqual(['./x.md']);
  });
});

describe('docs-site build inputs', () => {
  it('declares the globs this guard checks against', () => {
    const project = JSON.parse(readFileSync(join(repoRoot, 'apps/docs-site/project.json'), 'utf8'));
    expect(project.targets.build.cache).toBe(true);
    expect(project.targets.build.inputs).toEqual(expect.arrayContaining(DECLARED));
  });

  it('every relative link in a record points inside them', () => {
    const outside: string[] = [];
    let links = 0;
    for (const dir of RECORD_DIRS) {
      for (const name of readdirSync(join(repoRoot, dir)).filter((n) => n.endsWith('.md'))) {
        const file = join(repoRoot, dir, name);
        for (const target of relativeTargets(file)) {
          links += 1;
          if (!covered(target)) outside.push(`${dir}/${name} -> ${target}`);
        }
      }
    }
    expect(links, 'the scan found no relative links at all').toBeGreaterThan(0);
    expect(
      outside,
      'a record links outside the build inputs: add the target to the build target inputs in apps/docs-site/project.json, and to `covered()` here'
    ).toEqual([]);
  });
});
