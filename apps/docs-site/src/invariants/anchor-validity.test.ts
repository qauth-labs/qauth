import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { type AnchorablePage, findInvalidAnchors } from './anchor-validity';
import { loadContentTree } from './content-tree';
import { resolveWorkspaceRoot } from './workspace-root';

/**
 * Guard 2: every `path:line`-shaped anchor in the content names a file that
 * really exists, and where a symbol is quoted beside it, that symbol still
 * appears in the file. Line numbers are deliberately NOT checked — they
 * drift on every unrelated edit above them. If this test is deleted, prose
 * can point at a file (or a renamed symbol) that no longer exists and
 * nothing will notice.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '__fixtures__', 'anchor-validity');
const REPO_ROOT = resolveWorkspaceRoot();

function loadFixturePage(name: string): AnchorablePage {
  return { id: name, content: readFileSync(join(FIXTURES, name), 'utf8') };
}

describe('findInvalidAnchors — fixtures', () => {
  it('passes an anchor whose file exists and whose quoted symbol is present', () => {
    expect(findInvalidAnchors([loadFixturePage('ok.md')], REPO_ROOT)).toEqual([]);
  });

  it('does not assert the line number — a stale line number alone must not fail', () => {
    expect(findInvalidAnchors([loadFixturePage('ok-stale-line.md')], REPO_ROOT)).toEqual([]);
  });

  it('MUTATION: fails an anchor whose file does not exist', () => {
    const violations = findInvalidAnchors([loadFixturePage('broken-file.md')], REPO_ROOT);
    expect(violations).toEqual([
      expect.objectContaining({
        anchor: 'apps/docs-site/src/invariants/__fixtures__/anchor-validity/does-not-exist.ts:5',
      }),
    ]);
  });

  it('MUTATION: fails an anchor whose quoted symbol is not in the file', () => {
    const violations = findInvalidAnchors([loadFixturePage('broken-symbol.md')], REPO_ROOT);
    expect(violations).toEqual([expect.objectContaining({ symbol: 'totallyMissingSymbol' })]);
  });
});

describe('findInvalidAnchors — real content tree', () => {
  it('every anchor in the shipped docs-site content is valid', () => {
    const contentDir = join(REPO_ROOT, 'apps', 'docs-site', 'src', 'content', 'docs');
    const contentPages = loadContentTree(contentDir);

    // Non-vacuity: the content tree may genuinely carry zero path:line
    // anchors today (Task 5 is what adds anchor-heavy reference content), so
    // "found at least N anchors" would be a lie that only later becomes
    // true — not a real assertion. Assert instead that the scan actually
    // VISITED a non-trivial, known set of content files: a lower bound that
    // survives the tree growing, plus a specific file (the frontmatter
    // contract this whole guard suite depends on) that must always be
    // present. A wrong glob or a broken walker fails these even though the
    // anchor count alone would stay silently at zero either way.
    expect(contentPages.length).toBeGreaterThanOrEqual(5);
    expect(contentPages.map((page) => page.slug)).toContain('extend/frontmatter');

    const pages = contentPages.map((page): AnchorablePage => ({
      id: page.slug,
      content: page.body,
    }));
    expect(findInvalidAnchors(pages, REPO_ROOT)).toEqual([]);
  });
});
