import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

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

/** Approximate the anchor slug rehype-slug/Starlight would give a heading. */
export function slugifyHeading(text: string): string {
  return text
    .replace(/`/g, '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

/** Extract the set of heading anchors a page's body would render. */
export function extractHeadingAnchors(body: string): Set<string> {
  const anchors = new Set<string>();
  let match: RegExpExecArray | null;
  const re = new RegExp(HEADING_RE);
  while ((match = re.exec(body))) {
    anchors.add(slugifyHeading(match[1]));
  }
  return anchors;
}
