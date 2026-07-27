import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { recordRouteForRepoPath } from '../lib/records';
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
 * Whether an absolute path resolves to a file under `apps/docs-site/public/`,
 * which Astro serves at the SITE ROOT (`public/openapi.json` →
 * `/openapi.json`). This is one of exactly two ways a repo-root-absolute
 * link can be valid — the other is a known site route, checked in
 * `findBrokenLinks` via `routeIndex` — so it is checked ahead of treating
 * the path as unserved: a file placed under `public/` really is served at
 * its literal path even if it happens to start with `/docs/` or `/libs/` —
 * nothing does today, but the rule should be true for the right reason, not
 * by accident of check ordering.
 */
function existsUnderPublic(pathPart: string, repoRoot: string): boolean {
  return existsSync(join(repoRoot, 'apps', 'docs-site', 'public', pathPart));
}

/**
 * The violation reason for a repo-root-absolute path the deployed site does
 * not serve — tailored to what the author should do instead, and to whether
 * the path even names a real file.
 *
 * File existence is used ONLY to pick the wording, never to decide whether
 * there is a violation (see `findBrokenLinks`'s absolute-path branch — a
 * real file that the site doesn't serve is exactly as broken a link as one
 * that names nothing at all; the reader gets a 404 either way):
 *
 *   - the path doesn't correspond to any real repository file: the old
 *     generic "not a known site route" message — most likely a typo or a
 *     route that was renamed/removed.
 *   - the path IS a real repository file: computed from
 *     `recordRouteForRepoPath` (the SAME function that decides which
 *     `docs/` files actually render, reused here rather than re-deriving the
 *     rule) so the message can never name a route that disagrees with what
 *     the site actually builds — its rendered route if the `records`
 *     collection loads it, otherwise a GitHub blob URL, matching this
 *     project's one established convention for linking to un-rendered repo
 *     files (see `remark-rewrite-record-links.ts`'s bucket 3).
 */
function unservedAbsolutePathReason(pathPart: string, repoRoot: string): string {
  const repoRelative = pathPart.replace(/^\/+/, '');
  if (!existsSync(join(repoRoot, repoRelative))) {
    return `"${pathPart}" is not a known site route and does not exist as a file in the repository`;
  }
  const recordRoute = recordRouteForRepoPath(repoRelative);
  const instead = recordRoute
    ? `its rendered route ${recordRoute} instead`
    : 'a GitHub blob URL instead (the site does not render this file at all)';
  return (
    `"${pathPart}" is a real repository file, but the deployed site (astro.config.mjs: ` +
    `output: 'static', outDir dist/apps/docs-site) only serves its own routes and files under ` +
    `apps/docs-site/public/ — it never publishes the rest of the repository at that literal ` +
    `path, regardless of the file existing — link to ${instead}`
  );
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
 *   2. for a repo-root-absolute path, a file the deployed site actually
 *      serves at that literal path — which is ONLY a file under
 *      `apps/docs-site/public/`, since that route match already happened in
 *      (1); a repo file existing on disk elsewhere (`docs/...`, `libs/...`,
 *      `package.json`, ...) is never enough on its own — see
 *      `unservedAbsolutePathReason`,
 *   3. for a relative path, a real file on disk next to the scanning page
 *      (relative links are read on GitHub, not resolved by the deployed
 *      site, so a plain filesystem check is the right question there), or
 *   4. an anchor on the scanning page itself.
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
        // Not a known route (or it looks like a file): the ONLY other way a
        // repo-root-absolute path is genuinely served is a file under
        // `apps/docs-site/public/` — checked here, ahead of treating the
        // path as unserved, so a deliberately public-served file still
        // passes for the right reason. A file merely existing SOMEWHERE ELSE
        // in the repository (`docs/...`, `libs/...`, `package.json`, ...) is
        // deliberately NOT enough on its own: the deployed site never
        // publishes the rest of the repository at its literal path, and that
        // gap between "exists in the repo" and "is served by the site" is
        // exactly the fact that made this whole class of defect invisible to
        // begin with (qauth-labs/qauth#351, and the `/docs/*` and
        // `/libs/mcp-guard/*` families this rule generalizes over).
        if (existsUnderPublic(pathPart, context.repoRoot)) continue;
        violations.push({
          page: page.id,
          link,
          reason: unservedAbsolutePathReason(pathPart, context.repoRoot),
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
