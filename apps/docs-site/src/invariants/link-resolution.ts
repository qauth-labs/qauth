import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { extractHeadingAnchors, slugifyHeading } from './content-tree';

/**
 * Read the site's own production origin straight from `astro.config.mjs`'s
 * `site:` field — single-sourced, so a domain change there is picked up here
 * automatically rather than drifting against a second hardcoded copy of the
 * same string (qauth-labs/qauth#351 fix round 2).
 *
 * A deliberately narrow regex read, not a real ESM import of the config:
 * `astro.config.mjs` pulls in `@astrojs/starlight`'s TS source via
 * `astro/config`, which Node's native type-stripping refuses to load from
 * inside `node_modules` — confirmed by trying it. `site` is one quoted
 * string literal; that is all this needs to extract, matching this
 * project's existing preference for a narrow reader over a heavier
 * dependency (see `content-tree.ts`'s `parseFrontmatter`).
 */
export function resolveSiteOrigin(repoRoot: string): string {
  const configPath = join(repoRoot, 'apps', 'docs-site', 'astro.config.mjs');
  const configText = readFileSync(configPath, 'utf8');
  const match = configText.match(/\bsite:\s*['"]([^'"]+)['"]/);
  if (!match) {
    throw new Error(`Could not find a "site:" field in ${configPath}`);
  }
  // Trailing slash trimmed so `${siteOrigin}/` (below) never doubles up.
  return match[1].replace(/\/+$/, '');
}

/**
 * A page (or page-shaped stub) whose outgoing links this guard scans.
 *
 * Two kinds feed this: real content-collection pages (which have a `route`
 * other pages can link to) and old-path pointer stubs — files that will
 * live at `docs/*.md` and exist only to redirect a reader into the new site.
 * A stub has no `route` of its own; it only ever appears as a scan target,
 * never as a link destination.
 */
export interface LinkablePage {
  /** Identifier used in violation reports — a repo-relative path is ideal. */
  id: string;
  /** Absolute filesystem path. Used to resolve the page's own relative links. */
  filePath: string;
  /** Markdown/MDX body to scan for links. */
  content: string;
  /** The site route this page is served at, if any. Stubs omit this. */
  route?: string;
}

export interface LinkViolation {
  page: string;
  link: string;
  reason: string;
}

const MD_LINK_RE = /\[[^\]]*\]\(([^)]+)\)/g;
const HREF_RE = /\bhref\s*=\s*["']([^"']+)["']/g;

/**
 * Exported only so the real-tree test can assert it actually found a
 * non-trivial number of links — a "no violations" verdict looks identical
 * whether the scan examined every link on the site or none at all.
 */
export function extractLinkTargets(content: string): string[] {
  const targets: string[] = [];
  for (const re of [MD_LINK_RE, HREF_RE]) {
    const pattern = new RegExp(re.source, re.flags);
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content))) {
      targets.push(match[1].trim());
    }
  }
  return targets;
}

/**
 * A link starting with the site's OWN production origin (`siteOrigin`,
 * e.g. `https://docs.qauth.dev`) is an internal link written as an absolute
 * URL, not an external one — the `docs/*.md` pointer stubs use this form
 * deliberately (they're read on GitHub, where a site-relative link like
 * `/integrate/api-reference/` would resolve against github.com and break
 * for a human reader), so it must be resolved like any other internal link,
 * not skipped.
 */
function isOutOfScope(link: string, siteOrigin: string): boolean {
  if (link === siteOrigin || link.startsWith(`${siteOrigin}/`)) return false;
  return /^(https?:|mailto:|tel:)/i.test(link);
}

/** Strip a leading site-origin prefix so the rest of the resolver sees the same site-relative path it already knows how to check. Links NOT on the site origin pass through unchanged. */
function stripSiteOrigin(link: string, siteOrigin: string): string {
  if (link === siteOrigin) return '/';
  if (link.startsWith(`${siteOrigin}/`)) return link.slice(siteOrigin.length);
  return link;
}

function splitFragment(link: string): { pathPart: string; fragment?: string } {
  const hashIndex = link.indexOf('#');
  if (hashIndex === -1) return { pathPart: link };
  return { pathPart: link.slice(0, hashIndex), fragment: link.slice(hashIndex + 1) };
}

function normalizeRoute(route: string): string {
  return route.endsWith('/') ? route : route + '/';
}

/** Everything a link needs resolved against, built once per guard run. */
export interface LinkResolutionContext {
  /** Absolute path to the repository root, for resolving repo-relative file links. */
  repoRoot: string;
  /** Every page that owns a site route — the routes stubs and pages are allowed to point at. */
  routedPages: LinkablePage[];
  /**
   * The site's own production origin (e.g. `https://docs.qauth.dev`, no
   * trailing slash) — see {@link resolveSiteOrigin}. A link written against
   * this origin is resolved as an internal link rather than skipped as
   * external.
   */
  siteOrigin: string;
}

function buildRouteIndex(routedPages: LinkablePage[]): Map<string, LinkablePage> {
  const index = new Map<string, LinkablePage>();
  for (const page of routedPages) {
    if (page.route) index.set(normalizeRoute(page.route), page);
  }
  return index;
}

function hasFileExtension(pathPart: string): boolean {
  const lastSegment = pathPart.split('/').pop() ?? '';
  return /\.[A-Za-z0-9]+$/.test(lastSegment);
}

/**
 * Whether an absolute, non-route path resolves to a real file — either a
 * repo-root-relative reference (`/docs/agent-authorization.md`), or a file
 * under `apps/docs-site/public/`, which Astro serves at the SITE ROOT
 * (`public/openapi.json` → `/openapi.json`). The site-origin fix
 * (qauth-labs/qauth#351 fix round 2) started resolving links like
 * `https://docs.qauth.dev/openapi.json` instead of skipping them as
 * external, which surfaced this gap: that link is real and correctly
 * served, but nothing in the repository tree sits at a path matching it
 * literally, so the plain repo-root check alone would flag it broken.
 */
function existsAsRepoOrPublicFile(pathPart: string, repoRoot: string): boolean {
  if (existsSync(join(repoRoot, pathPart))) return true;
  return existsSync(join(repoRoot, 'apps', 'docs-site', 'public', pathPart));
}

function checkFragment(
  fragment: string | undefined,
  targetContent: string | undefined,
  targetId: string
): string | undefined {
  if (!fragment || targetContent === undefined) return undefined;
  const anchors = extractHeadingAnchors(targetContent);
  if (!anchors.has(slugifyHeading(fragment)) && !anchors.has(fragment)) {
    return `anchor "#${fragment}" does not exist in ${targetId}`;
  }
  return undefined;
}

/**
 * Resolve every link on every scanned page against:
 *   1. another page's site route (± a heading anchor that must actually exist there),
 *   2. a real file in the repository, or
 *   3. an anchor on the scanning page itself.
 *
 * `scanPages` and `context.routedPages` are deliberately separate: running
 * this with `scanPages = [...sitePages, ...oldPathStubs]` while
 * `context.routedPages = sitePages` checks BOTH directions in one pass — a
 * site page linking out, and a `docs/*.md` stub pointing back in — without
 * the guard needing to know which kind of file it is looking at.
 */
export function findBrokenLinks(
  scanPages: LinkablePage[],
  context: LinkResolutionContext
): LinkViolation[] {
  const routeIndex = buildRouteIndex(context.routedPages);
  const violations: LinkViolation[] = [];

  for (const page of scanPages) {
    for (const link of extractLinkTargets(page.content)) {
      if (isOutOfScope(link, context.siteOrigin)) continue;

      // Violations still report the link AS WRITTEN (below); only the
      // resolution logic works against the site-relative form.
      const { pathPart, fragment } = splitFragment(stripSiteOrigin(link, context.siteOrigin));

      if (pathPart === '') {
        const reason = checkFragment(fragment, page.content, page.id);
        if (reason) violations.push({ page: page.id, link, reason });
        continue;
      }

      if (pathPart.startsWith('/')) {
        if (!hasFileExtension(pathPart)) {
          const target = routeIndex.get(normalizeRoute(pathPart));
          if (target) {
            const reason = checkFragment(fragment, target.content, target.id);
            if (reason) violations.push({ page: page.id, link, reason });
            continue;
          }
        }
        // Not a known route (or it looks like a file) — fall back to a real
        // file, either repo-root-relative or under docs-site's `public/`.
        if (existsAsRepoOrPublicFile(pathPart, context.repoRoot)) continue;
        violations.push({
          page: page.id,
          link,
          reason: `"${pathPart}" is not a known site route and does not exist as a file in the repository`,
        });
        continue;
      }

      // Relative link — resolve against the scanning page's own directory.
      const absolute = resolve(dirname(page.filePath), pathPart);
      if (!existsSync(absolute)) {
        violations.push({
          page: page.id,
          link,
          reason: `"${pathPart}" does not resolve to a file relative to ${page.id}`,
        });
        continue;
      }
      const target = context.routedPages.find((p) => p.filePath === absolute);
      const reason = checkFragment(fragment, target?.content, target?.id ?? pathPart);
      if (reason) violations.push({ page: page.id, link, reason });
    }
  }

  return violations;
}
