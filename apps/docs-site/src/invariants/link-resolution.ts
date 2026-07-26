import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { extractHeadingAnchors, slugifyHeading } from './content-tree';

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

function extractLinkTargets(content: string): string[] {
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

function isOutOfScope(link: string): boolean {
  return /^(https?:|mailto:|tel:)/i.test(link);
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
      if (isOutOfScope(link)) continue;

      const { pathPart, fragment } = splitFragment(link);

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
        // Not a known route (or it looks like a file) — fall back to a
        // repo-root-relative file reference.
        if (existsSync(join(context.repoRoot, pathPart))) continue;
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
