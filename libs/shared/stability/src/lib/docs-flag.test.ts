import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  DOCS_CONTENT_PATH,
  docsFlagProblems,
  type DocsPage,
  docsPageRoute,
  readDocsPage,
} from './docs-flag';
import { EXPERIMENTAL_ITEMS } from './items';

const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');

/** Every page of the docs collection on disk. */
function loadDocsPages(): DocsPage[] {
  const root = join(REPO_ROOT, DOCS_CONTENT_PATH);
  const files = readdirSync(root, { recursive: true, encoding: 'utf8' }).filter((path) =>
    /\.mdx?$/.test(path)
  );
  return files.map((path) => readDocsPage(path, readFileSync(join(root, path), 'utf8')));
}

const page = (overrides: Partial<DocsPage> = {}): DocsPage => ({
  route: '/integrate/sample-feature/',
  experimental: true,
  body: 'How to use sample-feature.',
  ...overrides,
});

const ITEM = { id: 'sample-feature', docsPage: '/integrate/sample-feature/' };

describe('docsPageRoute', () => {
  it.each([
    ['integrate/wallet-login.md', '/integrate/wallet-login/'],
    ['reference/records.mdx', '/reference/records/'],
    ['integrate/index.md', '/integrate/'],
    ['index.mdx', '/'],
    ['integrate\\wallet-login.md', '/integrate/wallet-login/'],
  ])('serves %s at %s', (path, route) => {
    expect(docsPageRoute(path)).toBe(route);
  });
});

describe('readDocsPage', () => {
  it('reads the flag from the frontmatter', () => {
    const source = "---\ntitle: A\nlastVerified: '2026-10-25'\nexperimental: true\n---\n\nText.\n";
    expect(readDocsPage('integrate/a.md', source)).toEqual({
      route: '/integrate/a/',
      experimental: true,
      body: '\nText.\n',
    });
  });

  it.each([
    ['set to false', '---\ntitle: A\nexperimental: false\n---\nText.'],
    ['missing', '---\ntitle: A\n---\nText.'],
    ['indented under another key', '---\ntitle: A\nsidebar:\n  experimental: true\n---\nText.'],
    ['in the text, not the frontmatter', '---\ntitle: A\n---\nexperimental: true\n'],
    ['without frontmatter', 'experimental: true\n'],
  ])('is not flagged with the flag %s', (_label, source) => {
    expect(readDocsPage('integrate/a.md', source).experimental).toBe(false);
  });
});

describe('docsFlagProblems', () => {
  it('passes a flagged page that names its item', () => {
    expect(docsFlagProblems([page()], [ITEM])).toEqual([]);
  });

  it('passes an item with no docs page and no flagged page', () => {
    expect(
      docsFlagProblems([page({ experimental: false })], [{ id: 'later', docsPage: null }])
    ).toEqual([]);
  });

  // "A page that documents a registry item must carry the flag" (#477).
  it('fails on an item whose page does not carry the flag', () => {
    expect(docsFlagProblems([page({ experimental: false })], [ITEM])).toEqual([
      'sample-feature: its docs page /integrate/sample-feature/ does not set experimental: true in its frontmatter',
    ]);
  });

  it('fails on an item whose page does not exist', () => {
    expect(docsFlagProblems([], [ITEM])).toEqual([
      'sample-feature: its docs page /integrate/sample-feature/ does not exist',
    ]);
  });

  // "A flagged page must name a registry item" (#477).
  it('fails on a flagged page that no item names', () => {
    expect(docsFlagProblems([page({ route: '/integrate/other/' })], [])).toEqual([
      '/integrate/other/: sets experimental: true, but no item of the registry names it as its docs page',
    ]);
  });

  it('fails on a flagged page that does not name its item', () => {
    expect(docsFlagProblems([page({ body: 'How to use it.' })], [ITEM])).toEqual([
      '/integrate/sample-feature/: documents sample-feature, but does not name it',
    ]);
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
