import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { RECORDS } from '../lib/records';
import { loadContentTree } from './content-tree';
import {
  extractLinkTargets,
  findBrokenLinks,
  type LinkablePage,
  resolveSiteOrigin,
} from './link-resolution';
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
const SITE_ORIGIN = resolveSiteOrigin(REPO_ROOT);

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
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([]);
  });

  it('MUTATION: fails a link to a route and a file that do not exist', () => {
    const brokenScan = loadFixturePage('broken-scan.md');
    const violations = findBrokenLinks([home, guide, brokenScan], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toHaveLength(2);
    expect(violations.map((v) => v.link).sort()).toEqual(['./nope.md', '/does-not-exist/']);
  });

  it('MUTATION: fails a link whose anchor fragment does not exist on the target page', () => {
    const brokenAnchor = loadFixturePage('broken-anchor.md');
    const violations = findBrokenLinks([home, guide, brokenAnchor], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([expect.objectContaining({ link: '/guide/#missing-heading' })]);
  });

  it('resolves an anchor whose heading has punctuation glued to a word, using the real github-slugger slug (qauth-labs/qauth#351 fix round 1)', () => {
    // guide.md's "## Redirect to `/oauth/authorize`" heading really renders
    // to id="redirect-to-oauthauthorize" (github-slugger deletes the `/`
    // characters with nothing in their place) — a shape the old hand-rolled
    // slugifyHeading approximation got wrong (see the next test).
    const gluedReal = loadFixturePage('glued-punctuation-real-slug.md');
    const violations = findBrokenLinks([home, guide, gluedReal], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([]);
  });

  it("MUTATION: rejects the old approximation's wrong guess at the same anchor", () => {
    // The hand-rolled approximation this guard used before #351 fix round 1
    // would have computed "redirect-to-oauth-authorize" (an extra hyphen)
    // for the same heading. That string is not a real anchor, so a link
    // using it must still be reported broken.
    const gluedApproximated = loadFixturePage('glued-punctuation-approximated-slug.md');
    const violations = findBrokenLinks([home, guide, gluedApproximated], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([
      expect.objectContaining({ link: '/guide/#redirect-to-oauth-authorize' }),
    ]);
  });

  it('passes a pointer stub whose link resolves to a real route', () => {
    const stubOk = loadFixturePage('stub-ok.md');
    const violations = findBrokenLinks([home, guide, stubOk], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([]);
  });

  it('MUTATION: fails a pointer stub aiming at a route that no longer exists (the opposite direction)', () => {
    const stubBroken = loadFixturePage('stub-broken.md');
    const violations = findBrokenLinks([home, guide, stubBroken], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([
      expect.objectContaining({ page: 'stub-broken.md', link: '/gone/' }),
    ]);
  });

  it("resolves a link written as the site's own absolute production URL — the pointer-stub style (qauth-labs/qauth#351 fix round 2)", () => {
    // Real docs/*.md stubs link with `https://docs.qauth.dev/...` rather
    // than a site-relative path, because they're read on GitHub, where a
    // site-relative link resolves against github.com and breaks for a
    // human reader. That absolute form must still be checked, not skipped
    // as an external link.
    const siteOriginOk = loadFixturePage('site-origin-ok.md');
    const violations = findBrokenLinks([home, guide, siteOriginOk], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([]);
  });

  it('MUTATION: fails a site-origin-absolute link aiming at a route that does not exist', () => {
    // Before this fix, `isOutOfScope` matched ANY `https?:` link — including
    // one on the site's own origin — and skipped it unconditionally. This
    // is the exact bug qauth-labs/qauth#351 fix round 2 found: all four
    // `docs/*.md` pointer stubs use this absolute form, so this guard was
    // silently checking none of their forward links.
    const siteOriginBroken = loadFixturePage('site-origin-broken.md');
    const violations = findBrokenLinks([home, guide, siteOriginBroken], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([
      expect.objectContaining({ link: `${SITE_ORIGIN}/does-not-exist/` }),
    ]);
  });

  it('leaves external links alone — the suite must not depend on the network', () => {
    const external: LinkablePage = {
      id: 'external.md',
      filePath: join(FIXTURES, 'external.md'),
      content: '[spec](https://example.com/rfc) and [mail](mailto:a@example.com)',
    };
    const violations = findBrokenLinks([external], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([]);
  });
});

/**
 * Guard 1's blind spot (qauth-labs/qauth#[docs-astro-docs-site], the third
 * time this exact shape of defect has hit this project): a repo-root-absolute
 * link with a file extension (`/docs/adr/001-jwt-key-management.md`) used to
 * fall straight to a plain "does this file exist in the repository" check —
 * true, since the file is real — not "does the BUILT SITE serve this literal
 * path" — false, always, for anything outside `apps/docs-site/public/`,
 * since `astro.config.mjs` (`output: 'static'`, `outDir:
 * dist/apps/docs-site`) never copies the repository itself into what gets
 * deployed. The rule was first taught only about `/docs/*` (Task 14); it is
 * now general — ANY repo-root-absolute path is only valid if it is a known
 * site route or sits under `apps/docs-site/public/`, so `/libs/...`,
 * `/package.json`, and any future unpublished prefix are caught the same
 * way, with no per-prefix special case. These fixtures use REAL files under
 * the repo's `docs/adr`, `docs/` root, and `libs/fastify/plugins/mcp-guard`
 * (not fixture-local stand-ins) so the "the file genuinely exists" half of
 * the defect is reproduced exactly, not merely simulated.
 */
describe('findBrokenLinks — repo-root-absolute paths the deployed site never serves', () => {
  const home = loadFixturePage('content/index.md', '/');
  const guide = loadFixturePage('content/guide.md', '/guide/');
  const routedPages = [home, guide];

  it('MUTATION: fails a link to a real repo file under docs/adr, naming the rendered route it should use instead', () => {
    const page = loadFixturePage('docs-path-record.md');
    const violations = findBrokenLinks([home, guide, page], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([
      expect.objectContaining({
        link: '/docs/adr/001-jwt-key-management.md',
        reason: expect.stringContaining('/reference/records/adr/001-jwt-key-management/'),
      }),
    ]);
  });

  it('MUTATION: fails a link to a real docs/ file the records collection does not load, suggesting a GitHub blob link instead', () => {
    const page = loadFixturePage('docs-path-non-record.md');
    const violations = findBrokenLinks([home, guide, page], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([
      expect.objectContaining({
        link: '/docs/oidf-op-certification-runbook.md',
        reason: expect.stringContaining('GitHub blob URL'),
      }),
    ]);
  });

  it('MUTATION: fails a link to a real repo file with NO docs/ or libs/ prefix at all, proving the rule is general', () => {
    // package.json — no special-cased prefix — is exactly the "next
    // unserved prefix someone invents" the generalized rule must catch
    // without a third special case being added.
    const page = loadFixturePage('repo-root-file-not-served.md');
    const violations = findBrokenLinks([home, guide, page], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([
      expect.objectContaining({
        link: '/package.json',
        reason: expect.stringContaining('GitHub blob URL'),
      }),
    ]);
  });

  it('MUTATION: fails a link to a real repo file under libs/, the family this rule was deliberately not generalized to cover until now', () => {
    const page = loadFixturePage('repo-root-libs-not-served.md');
    const violations = findBrokenLinks([home, guide, page], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([
      expect.objectContaining({
        link: '/libs/fastify/plugins/mcp-guard/README.md',
        reason: expect.stringContaining('GitHub blob URL'),
      }),
    ]);
  });

  it('passes a legitimate repo-root-absolute file link the site actually serves (under apps/docs-site/public/)', () => {
    const page = loadFixturePage('docs-path-public-ok.md');
    const violations = findBrokenLinks([home, guide, page], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([]);
  });

  it('passes an external URL that merely looks like a /docs/*.md path', () => {
    const page = loadFixturePage('docs-path-external-ok.md');
    const violations = findBrokenLinks([home, guide, page], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([]);
  });

  it('passes a bare same-page anchor, unaffected by the new /docs/ rule', () => {
    const page = loadFixturePage('docs-path-anchor-ok.md');
    const violations = findBrokenLinks([home, guide, page], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([]);
  });
});

describe('findBrokenLinks — real content tree', () => {
  /** The repo-root pointer stubs Task 5 left behind — scan-only, own no route. */
  function loadStub(fileName: string): LinkablePage {
    const filePath = join(REPO_ROOT, 'docs', fileName);
    return { id: `docs/${fileName}`, filePath, content: readFileSync(filePath, 'utf8') };
  }

  /**
   * The `records` collection (`docs/adr/**`, `docs/security/**`) is loaded
   * by Astro from OUTSIDE `apps/docs-site/src/content/docs` (see
   * `content.config.ts`'s own comment: the physical-directory walk this
   * guard's real-tree scan uses "therefore never appears in that walk"), so
   * `loadContentTree` alone never contributes their routes. Built from
   * `RECORDS` (`src/lib/records.ts`) — the SAME data `records.mdx` and the
   * remark link rewriter use — rather than re-deriving the route shape here,
   * so a rename in `records.ts` can't silently desynchronise this guard from
   * what the site actually serves. Only added to `routedPages` (valid link
   * TARGETS): scanning the records' own outgoing links is
   * `remark-rewrite-record-links.test.ts`'s job, not this guard's.
   */
  function loadRecordPages(): LinkablePage[] {
    return [...RECORDS.adr, ...RECORDS.security].map((record) => {
      const filePath = join(REPO_ROOT, record.sourcePath);
      return {
        id: record.sourcePath,
        filePath,
        content: readFileSync(filePath, 'utf8'),
        route: record.route,
      };
    });
  }

  it('every link in the shipped docs-site content resolves, INCLUDING the repo-root pointer stubs', () => {
    const contentDir = join(REPO_ROOT, 'apps', 'docs-site', 'src', 'content', 'docs');
    const pages = loadContentTree(contentDir).map((page): LinkablePage => ({
      id: page.slug,
      filePath: page.filePath,
      content: page.body,
      route: page.route,
    }));
    const recordPages = loadRecordPages();
    // Non-vacuity: guards against `RECORDS` (or the `docs/adr` /
    // `docs/security` directories it reads) coming back empty and this
    // silently degrading to the old, records-blind route index.
    expect(recordPages.length).toBeGreaterThanOrEqual(10);

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

    // The four Task 5 pointer stubs — scanned here too (previously they
    // were not: they link with the site's absolute production URL, which
    // `isOutOfScope` treated as unconditionally external and skipped
    // before qauth-labs/qauth#351 fix round 2). `routedPages` stays
    // `pages` + `recordPages` only: a stub owns no route of its own, so
    // nothing should be able to link INTO one.
    const stubs = [
      loadStub('mcp-quickstart.md'),
      loadStub('oauth-flow.md'),
      loadStub('api-reference.md'),
      loadStub('code-examples.md'),
    ];
    // Non-vacuity for the stub scan specifically: each stub must carry at
    // least one link, or a broken stub loader would silently contribute
    // nothing to the scan below.
    for (const stub of stubs) {
      expect(extractLinkTargets(stub.content).length).toBeGreaterThan(0);
    }

    const routedPages = [...pages, ...recordPages];
    const violations = findBrokenLinks([...pages, ...stubs], {
      repoRoot: REPO_ROOT,
      routedPages,
      siteOrigin: SITE_ORIGIN,
    });
    expect(violations).toEqual([]);
  });
});
