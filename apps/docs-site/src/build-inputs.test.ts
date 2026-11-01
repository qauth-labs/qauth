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

/** The repo-relative targets of a record's relative links, fragments dropped. */
function relativeTargets(file: string): string[] {
  const text = readFileSync(file, 'utf8');
  const urls = [
    ...[...text.matchAll(/\]\(\s*<?([^)\s>]+)>?/g)].map((m) => m[1]),
    ...[...text.matchAll(/^\s*\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)/gm)].map((m) => m[1]),
  ];
  return urls
    .filter((url) => !/^(?:[a-z][a-z0-9+.-]*:|#|\/)/i.test(url))
    .map((url) => url.split('#')[0])
    .filter((path) => path.length > 0)
    .map((path) => relative(repoRoot, resolve(dirname(file), path)).replace(/\\/g, '/'));
}

function covered(repoRelative: string): boolean {
  return repoRelative.startsWith('docs/') || /^[^/]+\.md$/.test(repoRelative);
}

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
