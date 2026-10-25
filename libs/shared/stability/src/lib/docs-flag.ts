import type { ExperimentalItem } from './item';

/**
 * The docs pages flagged `experimental: true` against the registry (ADR-018
 * §5, #477). The docs label an experimental item: the page that documents it
 * carries the flag, and the docs site shows an "Experimental" banner there.
 * Flagged pages and registry items match one to one.
 *
 * Pure: the caller reads the pages.
 */

/** The docs collection, from the repository root. */
export const DOCS_CONTENT_PATH = 'apps/docs-site/src/content/docs';

/** One page of the docs collection, as the flag check reads it. */
export interface DocsPage {
  /** Its site route: `/integrate/wallet-login/`. */
  readonly route: string;
  /** Its frontmatter sets `experimental: true`. */
  readonly experimental: boolean;
  /** Its text, without the frontmatter. */
  readonly body: string;
}

/**
 * The site route of a page of the docs collection, from its path inside the
 * collection: `integrate/wallet-login.md` is served at
 * `/integrate/wallet-login/`, and an `index` page at its folder's route.
 */
export function docsPageRoute(pathInCollection: string): string {
  const segments = pathInCollection
    .replace(/\\/g, '/')
    .replace(/\.mdx?$/, '')
    .split('/')
    .filter((segment) => segment !== '');
  if (segments.at(-1) === 'index') segments.pop();
  return segments.length === 0 ? '/' : `/${segments.join('/')}/`;
}

/**
 * A top-level `experimental` key set to true, in each spelling YAML reads as
 * true and the docs schema then accepts, with an optional comment after it.
 */
const FLAG_LINE = /^experimental:[ \t]*(?:true|True|TRUE)[ \t]*(?:#.*)?\r?$/m;

/**
 * Read one page: its route, whether its frontmatter sets `experimental: true`
 * at the top level, and its text. A file without frontmatter is not flagged.
 */
export function readDocsPage(pathInCollection: string, source: string): DocsPage {
  const route = docsPageRoute(pathInCollection);
  const match = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(source);
  if (match === null) return { route, experimental: false, body: source };
  return {
    route,
    experimental: FLAG_LINE.test(match[1]),
    body: source.slice(match[0].length),
  };
}

/**
 * Whether `text` names the item `id` as a whole: not as part of a longer id
 * or word, so `oid4vp-1.0` does not name `oid4vp-1.0-base`.
 */
export function namesItem(text: string, id: string): boolean {
  const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?<![\\w.-])${escaped}(?![\\w-]|\\.\\w)`).test(text);
}

/**
 * Check flagged pages against registry items, one to one. Returns one line
 * per problem, `[]` when there is none:
 *
 * - an item that names a docs page whose page does not exist, or does not
 *   carry the flag;
 * - a flagged page that no item names as its docs page, or that does not name
 *   its item's id in its text.
 *
 * That a built item names a page, and that no two items name the same one,
 * is the registry's own rule (`validateExperimentalRegistry`).
 */
export function docsFlagProblems(
  pages: readonly DocsPage[],
  items: readonly Pick<ExperimentalItem, 'id' | 'docsPage'>[]
): string[] {
  const problems: string[] = [];
  const byRoute = new Map(pages.map((page) => [page.route, page]));
  const itemOf = new Map<string, string>();

  for (const item of items) {
    if (item.docsPage === null) continue;
    itemOf.set(item.docsPage, item.id);
    const page = byRoute.get(item.docsPage);
    if (page === undefined) {
      problems.push(`${item.id}: its docs page ${item.docsPage} does not exist`);
    } else if (!page.experimental) {
      problems.push(
        `${item.id}: its docs page ${item.docsPage} does not set experimental: true in its frontmatter`
      );
    }
  }

  for (const page of pages) {
    if (!page.experimental) continue;
    const id = itemOf.get(page.route);
    if (id === undefined) {
      problems.push(
        `${page.route}: sets experimental: true, but no item of the registry names it as its docs page`
      );
    } else if (!namesItem(page.body, id)) {
      problems.push(`${page.route}: documents ${id}, but does not name it`);
    }
  }

  return problems;
}
