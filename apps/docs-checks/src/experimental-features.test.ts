import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import {
  DOCS_CONTENT_PATH,
  docsFlagProblems,
  type DocsPage,
  EXPERIMENTAL_FEATURES_PAGE_PATH,
  EXPERIMENTAL_ITEMS,
  markdownHeadingAnchors,
  missingEvidencePaths,
  readDocsPage,
  renderExperimentalFeaturesPage,
  repositoryPathCheck,
} from '@qauth-labs/shared-stability';
import { describe, expect, it } from 'vitest';

import { formatAs, REPO_ROOT } from './workspace';

/**
 * The experimental-feature registry of `@qauth-labs/shared-stability` against
 * the repository: the generated docs page, the pages flagged experimental
 * (#477), the decision records and the evidence paths (#476). The library's
 * own tests check the registry and the rules these checks apply.
 */

const PAGE_PATH = join(REPO_ROOT, EXPERIMENTAL_FEATURES_PAGE_PATH);

/** Every page of the docs collection on disk. */
function loadDocsPages(): DocsPage[] {
  const root = join(REPO_ROOT, DOCS_CONTENT_PATH);
  const files = readdirSync(root, { recursive: true, encoding: 'utf8' }).filter((path) =>
    /\.mdx?$/.test(path)
  );
  return files.map((path) => readDocsPage(path, readFileSync(join(root, path), 'utf8')));
}

describe('the experimental features page', () => {
  // This test is the generator: when the registry changes,
  // `pnpm nx test docs-checks -- -u` rewrites the page, and without `-u` the
  // test fails until the committed page matches.
  it('is what the registry renders (regenerate with `pnpm nx test docs-checks -- -u`)', async () => {
    const page = formatAs(PAGE_PATH, renderExperimentalFeaturesPage(EXPERIMENTAL_ITEMS));
    await expect(page).toMatchFileSnapshot(PAGE_PATH);
  });
});

describe('the docs site', () => {
  const pages = loadDocsPages();

  it('reads every page of the docs collection', () => {
    expect(pages.map((candidate) => candidate.route)).toContain('/integrate/wallet-login/');
    expect(pages.length).toBeGreaterThan(20);
  });

  // The acceptance criterion of #477: flagged pages and registry items match
  // one to one.
  it('has flagged pages and registry items that match one to one', () => {
    expect(docsFlagProblems(pages, EXPERIMENTAL_ITEMS)).toEqual([]);
    expect(
      pages
        .filter((candidate) => candidate.experimental)
        .map((candidate) => candidate.route)
        .sort()
    ).toEqual(
      EXPERIMENTAL_ITEMS.flatMap((item) => (item.docsPage === null ? [] : [item.docsPage])).sort()
    );
  });

  it('flags the page of every built item', () => {
    for (const item of EXPERIMENTAL_ITEMS.filter((candidate) => candidate.built)) {
      expect(
        pages.find((candidate) => candidate.route === item.docsPage)?.experimental,
        item.id
      ).toBe(true);
    }
  });
});

describe('the experimental-feature registry against the repository', () => {
  it('documents the pilot on the wallet sign-in page', () => {
    const pilot = EXPERIMENTAL_ITEMS.find((item) => item.id === 'oid4vp-1.0-base');
    expect(pilot?.docsPage).toBe('/integrate/wallet-login/');
    expect(
      existsSync(join(REPO_ROOT, 'apps/docs-site/src/content/docs/integrate/wallet-login.md'))
    ).toBe(true);
  });

  // Where a decision record already names an item's switch, the registry uses
  // that name, so the area that builds the item does not invent another.
  it.each([
    ['fipa-challenge-endpoint', 'docs/adr/017-first-party-login.md', 'FIRST_PARTY_LOGIN_ENABLED'],
    ['pass-through-leg', 'docs/adr/016-agent-platform-bindings.md', 'PASS_THROUGH_LEG_ENABLED'],
  ])('names the switch of %s as its record does', (id, adr, key) => {
    const item = EXPERIMENTAL_ITEMS.find((candidate) => candidate.id === id);
    expect(item?.adr).toBe(adr);
    expect(item?.switchKey).toBe(key);
    expect(readFileSync(join(REPO_ROOT, adr), 'utf8')).toContain(`\`${key}\``);
  });

  it.each(EXPERIMENTAL_ITEMS.map((item) => [item.id, item.adr] as const))(
    '%s links a decision record that exists (%s)',
    (_id, adr) => {
      expect(existsSync(join(REPO_ROOT, adr))).toBe(true);
    }
  );

  it('names, in ADR-018 §4, every record the items link', () => {
    const adr018 = readFileSync(join(REPO_ROOT, 'docs/adr/018-1-0-scope-and-stability.md'), 'utf8');
    const section = adr018.slice(
      adr018.indexOf('### 4. Experimental in 1.0'),
      adr018.indexOf('### 5. The stability contract')
    );
    expect(section).toContain('ADR-017');
    expect(section).toContain('ADR-016 §4');
    expect(section).toContain('`oid4vp-1.0-base`');
    expect(section).toContain('`/first-party` subpath of `@qauth-labs/node`');
    expect(section).toContain('draft-ietf-oauth-attestation-based-client-auth');
    expect(section).toContain('The plugin API');
  });

  // The anchor a fixture of the library's tests names.
  it('finds the section a fixture names in ADR-018', () => {
    const adr = readFileSync(join(REPO_ROOT, 'docs/adr/018-1-0-scope-and-stability.md'), 'utf8');
    expect(markdownHeadingAnchors(adr).has('8-assurance-before-10')).toBe(true);
  });

  // Evidence is a link or a path that must exist (#476): a file, and a
  // section of it when one is named. The same check the script runs.
  it('names only files and sections that exist as evidence', () => {
    const pathExists = repositoryPathCheck({
      isFile: (path) =>
        existsSync(join(REPO_ROOT, path)) && statSync(join(REPO_ROOT, path)).isFile(),
      readText: (path) => readFileSync(join(REPO_ROOT, path), 'utf8'),
    });
    expect(
      EXPERIMENTAL_ITEMS.flatMap((item) =>
        missingEvidencePaths(item, pathExists).map((missing) => `${item.id} ${missing}`)
      )
    ).toEqual([]);
  });
});
