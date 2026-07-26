import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

// Aliased to avoid shadowing `ContentPage.slug` / `loadContentTree`'s local
// `slug` variable (the content-collection slug, e.g. `extend/frontmatter`) —
// an unrelated concept that happens to share the name.
import GithubSlugger, { slug as githubSlug } from 'github-slugger';

/** A single page loaded from the Starlight `docs` content collection. */
export interface ContentPage {
  /** Absolute filesystem path to the source `.md`/`.mdx` file. */
  filePath: string;
  /** Path relative to the content collection root, extension stripped, e.g. `extend/frontmatter`. */
  slug: string;
  /** The site route this page resolves to, e.g. `/extend/frontmatter/`. Always trailing-slashed. */
  route: string;
  /** Parsed top-level frontmatter fields (see {@link parseFrontmatter}). */
  frontmatter: Record<string, string | boolean>;
  /** The Markdown/MDX body, frontmatter stripped. */
  body: string;
  /** The full file contents, frontmatter included. */
  raw: string;
}

/**
 * A deliberately narrow frontmatter reader — NOT a general YAML parser.
 *
 * Adding a real YAML dependency for this is the kind of thing the brief asks
 * to be raised rather than silently `pnpm add`ed, and every field these
 * guards need (`unbuiltClaims`, `lastVerified`, `title`) is a scalar at the
 * top level of the block. This reads exactly that: un-indented `key: value`
 * lines. Indented lines (e.g. `sidebar:\n  order: 0`) are skipped rather
 * than mis-parsed — nothing here currently needs them.
 */
export function parseFrontmatter(raw: string): {
  frontmatter: Record<string, string | boolean>;
  body: string;
} {
  const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) {
    return { frontmatter: {}, body: raw };
  }
  const [, block, body] = match;
  const frontmatter: Record<string, string | boolean> = {};
  for (const line of block.split(/\r?\n/)) {
    const fieldMatch = line.match(/^([A-Za-z0-9_]+):\s*(.*)$/);
    if (!fieldMatch) continue; // indented / nested line — not a top-level scalar
    const [, key, rawValue] = fieldMatch;
    const value = rawValue.trim();
    if (value === 'true') frontmatter[key] = true;
    else if (value === 'false') frontmatter[key] = false;
    else frontmatter[key] = value.replace(/^['"]|['"]$/g, '');
  }
  return { frontmatter, body };
}

/**
 * Map a content-collection slug to the site route Starlight serves it at.
 * `index` segments collapse (Starlight's own behaviour), and every route is
 * trailing-slashed to match how the existing pages link each other
 * (`href="/integrate/"` in `index.mdx`).
 */
export function slugToRoute(slug: string): string {
  const segments = slug.split('/').filter(Boolean);
  if (segments[segments.length - 1] === 'index') segments.pop();
  const route = '/' + segments.join('/');
  return route.endsWith('/') ? route : route + '/';
}

function walkContentFiles(dir: string, root: string, out: string[]): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walkContentFiles(full, root, out);
    } else if (/\.(md|mdx)$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

/** Load every page under a Starlight `docs` content collection directory. */
export function loadContentTree(contentDocsDir: string): ContentPage[] {
  const files = walkContentFiles(contentDocsDir, contentDocsDir, []);
  return files.map((filePath) => {
    const raw = readFileSync(filePath, 'utf8');
    const { frontmatter, body } = parseFrontmatter(raw);
    const slug = relative(contentDocsDir, filePath)
      .replace(/\\/g, '/')
      .replace(/\.(md|mdx)$/, '');
    return { filePath, slug, route: slugToRoute(slug), frontmatter, body, raw };
  });
}

const HEADING_RE = /^#{1,6}\s+(.+)$/gm;

/**
 * The anchor slug Starlight's rendering pipeline actually gives a heading —
 * via `github-slugger`, the SAME package `@astrojs/markdown-remark` (Astro's
 * own markdown pipeline) depends on, not an approximation of it. An earlier
 * hand-rolled approximation here (replace every run of non-`[a-z0-9]`
 * characters with one hyphen) LOOKED plausible and passed this guard's own
 * fixtures, but diverged from the real, rendered anchor whenever punctuation
 * sat directly against a word with no space — e.g. a heading containing
 * `` `/oauth/authorize` `` really renders to the id
 * `...-oauthauthorize` (github-slugger deletes the `/` with nothing in its
 * place), not `...-oauth-authorize` (what the hand-rolled version computed).
 * Confirmed by diffing the guard's output against real `id="..."` attributes
 * in a built `dist/apps/docs-site` — see the `punctuation-glued-to-word`
 * fixture below and qauth-labs/qauth#351 fix round 1.
 *
 * Markdown code-span backticks are syntax, not content, so they're stripped
 * before slugifying; the text INSIDE a code span (e.g. a path in
 * `` `/oauth/authorize` ``) is real heading text and stays.
 */
export function slugifyHeading(text: string): string {
  return githubSlug(text.replace(/`/g, ''));
}

/**
 * Extract the set of heading anchors a page's body would render, including
 * `github-slugger`'s own duplicate-heading suffixing (`heading`, `heading-1`,
 * `heading-2`, ...). Astro's markdown pipeline uses one slugger instance per
 * file so repeated heading text gets distinct anchors within that file but
 * not across files; a fresh `GithubSlugger` per call reproduces that.
 */
export function extractHeadingAnchors(body: string): Set<string> {
  const anchors = new Set<string>();
  const slugger = new GithubSlugger();
  let match: RegExpExecArray | null;
  const re = new RegExp(HEADING_RE);
  while ((match = re.exec(body))) {
    anchors.add(slugger.slug(match[1].replace(/`/g, '')));
  }
  return anchors;
}
