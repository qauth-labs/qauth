import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { loadContentTree } from './content-tree';
import { extractLinkTargets, findBrokenLinks, type LinkablePage } from './link-resolution';
import { resolveWorkspaceRoot } from './workspace-root';

/**
 * Guard 1: every internal link in the docs-site content tree resolves — to
 * another content page, to a real repository file, or to a heading anchor
 * that actually exists on the target. It also runs in reverse: a `docs/*.md`
 * pointer stub (left behind once a guide moves into the site) linking at a
 * route that no longer exists is exactly the drift README.md/docs/README.md
 * already show for status claims (see status-claims.test.ts) — this is the
 * same failure mode for links. If this test is deleted, a page or a stub can
 * link into the void and nothing will notice until a reader does.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '__fixtures__', 'link-resolution');
const REPO_ROOT = resolveWorkspaceRoot();

function loadFixturePage(relativePath: string, route?: string): LinkablePage {
  const filePath = join(FIXTURES, relativePath);
  return { id: relativePath, filePath, content: readFileSync(filePath, 'utf8'), route };
}

describe('findBrokenLinks — fixtures', () => {
  const home = loadFixturePage('content/index.md', '/');
  const guide = loadFixturePage('content/guide.md', '/guide/');
  const routedPages = [home, guide];

  it('passes when every link resolves to a route, a repo file, and a real heading', () => {
    const okScan = loadFixturePage('ok-scan.md');
    const violations = findBrokenLinks([home, guide, okScan], {
      repoRoot: REPO_ROOT,
      routedPages,
    });
    expect(violations).toEqual([]);
  });

  it('MUTATION: fails a link to a route and a file that do not exist', () => {
    const brokenScan = loadFixturePage('broken-scan.md');
    const violations = findBrokenLinks([home, guide, brokenScan], {
      repoRoot: REPO_ROOT,
      routedPages,
    });
    expect(violations).toHaveLength(2);
    expect(violations.map((v) => v.link).sort()).toEqual(['./nope.md', '/does-not-exist/']);
  });

  it('MUTATION: fails a link whose anchor fragment does not exist on the target page', () => {
    const brokenAnchor = loadFixturePage('broken-anchor.md');
    const violations = findBrokenLinks([home, guide, brokenAnchor], {
      repoRoot: REPO_ROOT,
      routedPages,
    });
    expect(violations).toEqual([expect.objectContaining({ link: '/guide/#missing-heading' })]);
  });

  it('passes a pointer stub whose link resolves to a real route', () => {
    const stubOk = loadFixturePage('stub-ok.md');
    const violations = findBrokenLinks([home, guide, stubOk], { repoRoot: REPO_ROOT, routedPages });
    expect(violations).toEqual([]);
  });

  it('MUTATION: fails a pointer stub aiming at a route that no longer exists (the opposite direction)', () => {
    const stubBroken = loadFixturePage('stub-broken.md');
    const violations = findBrokenLinks([home, guide, stubBroken], {
      repoRoot: REPO_ROOT,
      routedPages,
    });
    expect(violations).toEqual([
      expect.objectContaining({ page: 'stub-broken.md', link: '/gone/' }),
    ]);
  });

  it('leaves external links alone — the suite must not depend on the network', () => {
    const external: LinkablePage = {
      id: 'external.md',
      filePath: join(FIXTURES, 'external.md'),
      content: '[spec](https://example.com/rfc) and [mail](mailto:a@example.com)',
    };
    const violations = findBrokenLinks([external], { repoRoot: REPO_ROOT, routedPages });
    expect(violations).toEqual([]);
  });
});

describe('findBrokenLinks — real content tree', () => {
  it('every link in the shipped docs-site content resolves', () => {
    const contentDir = join(REPO_ROOT, 'apps', 'docs-site', 'src', 'content', 'docs');
    const pages = loadContentTree(contentDir).map((page): LinkablePage => ({
      id: page.slug,
      filePath: page.filePath,
      content: page.body,
      route: page.route,
    }));

    // Non-vacuity: "zero violations" looks identical whether this scanned
    // every page on the site or nothing at all — a wrong glob, a renamed
    // directory, or a workspace-root resolution that lands somewhere
    // unexpected would still leave the assertion below green. Lower bounds,
    // not an exact count, so this survives the content tree growing (the
    // whole point of every later docs task). Today there are 7 pages and
    // `index.mdx` alone carries 4 `LinkCard` links.
    expect(pages.length).toBeGreaterThanOrEqual(5);
    const totalLinks = pages.reduce(
      (sum, page) => sum + extractLinkTargets(page.content).length,
      0
    );
    expect(totalLinks).toBeGreaterThan(0);

    const violations = findBrokenLinks(pages, { repoRoot: REPO_ROOT, routedPages: pages });
    expect(violations).toEqual([]);
  });
});
