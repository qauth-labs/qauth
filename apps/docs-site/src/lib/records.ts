import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { resolveRepoRoot } from './repo-root';

/**
 * The subdirectories of the repository's `docs/` directory that are loaded
 * into the `records` content collection (see `content.config.ts`) and
 * rendered at `/reference/records/**`. Any other file under `docs/` —
 * `docs/eudi-regulatory-drift-log.md`, `docs/oidf-op-certification-runbook.md`,
 * `docs/README.md`, the four Task 5 pointer stubs, etc. — is a repo file
 * only; see `records.mdx` for why those are linked out rather than rendered.
 */
export const RECORD_SUBDIRS = ['adr', 'security'] as const;
export type RecordSubdir = (typeof RECORD_SUBDIRS)[number];

function isRecordSubdir(value: string): value is RecordSubdir {
  return (RECORD_SUBDIRS as readonly string[]).includes(value);
}

export const RECORDS_ROUTE_BASE = '/reference/records';

/**
 * Base URL for a GitHub blob view of a repo-relative path (append the path,
 * no leading slash). Matches `package.json`'s `repository.url`
 * (`qauth-labs/qauth`) and the `main` default branch. Used by the remark
 * link rewriter for links to real repo files the `records` collection does
 * not render (see `remark-rewrite-record-links.ts`), and by the record page
 * template for its "view source" link.
 */
export const GITHUB_REPO_BLOB_BASE = 'https://github.com/qauth-labs/qauth/blob/main';

/** Site route for a `records` collection entry, given its collection id (e.g. `adr/001-jwt-key-management`). */
export function routeForRecordId(id: string): string {
  return `${RECORDS_ROUTE_BASE}/${id}/`;
}

/**
 * The site route a repo-relative path resolves to if — and only if — it is
 * one of the files the `records` collection actually loads (an in-tree
 * `.md` link's ultimate purpose: does THIS target get rendered on the
 * site?). Returns `undefined` for every other path, including files
 * elsewhere under `docs/` that are not rendered — the remark link rewriter
 * (`src/plugins/remark-rewrite-record-links.ts`) uses that `undefined` to
 * decide a link needs a different treatment, not a route.
 *
 * Mirrors `content.config.ts`'s `generateId` exactly (strip the `docs/`
 * prefix, strip the `.md` suffix, no case transformation) so a collection
 * entry's `id` and the route this function computes for its own source
 * path always agree.
 */
export function recordRouteForRepoPath(repoRelativePath: string): string | undefined {
  const posixPath = repoRelativePath.replace(/\\/g, '/');
  if (!posixPath.startsWith('docs/') || !posixPath.endsWith('.md')) return undefined;
  const withoutDocsPrefix = posixPath.slice('docs/'.length, -'.md'.length);
  const subdir = withoutDocsPrefix.split('/')[0];
  if (!subdir || !isRecordSubdir(subdir)) return undefined;
  return routeForRecordId(withoutDocsPrefix);
}

/**
 * The first H1 heading in a record's body, used as its page title since
 * these files carry no frontmatter (and, per the Task 10 brief, never
 * will). Every ADR and the security review opens with `# Title` as its
 * literal first line — verified by opening each file — so this is a
 * mechanical read of real content, not an invented title.
 */
export function extractRecordTitle(body: string, fallbackId: string): string {
  const match = body.match(/^#\s+(.+)$/m);
  return match ? match[1].trim() : fallbackId;
}

export interface RecordSummary {
  /** Collection id, e.g. `adr/001-jwt-key-management`. */
  id: string;
  title: string;
  /** Site route, e.g. `/reference/records/adr/001-jwt-key-management/`. */
  route: string;
  /** Repo-relative source path, e.g. `docs/adr/001-jwt-key-management.md`. */
  sourcePath: string;
}

/**
 * Reads `docs/adr` and `docs/security` directly off disk — the SAME source
 * files the `records` content collection loads — to build the summary list
 * `records.mdx` renders. A second, independent read rather than an import
 * of the collection itself: `records.mdx` is a plain MDX page in the same
 * style as `reference/status.mdx` (which is fed by this file's sibling,
 * `lib/status.ts`), and Astro's content-collection API (`getCollection`) is
 * async, which would require top-level `await` in MDX. Reading the
 * filesystem synchronously here keeps that same, already-established
 * "lib/*.ts feeds a Reference-lane page" pattern instead of introducing a
 * second one.
 */
function listRecords(subdir: RecordSubdir): RecordSummary[] {
  const repoRoot = resolveRepoRoot();
  const dir = join(repoRoot, 'docs', subdir);
  return readdirSync(dir)
    .filter((file) => file.endsWith('.md'))
    .sort()
    .map((file) => {
      const id = `${subdir}/${file.slice(0, -'.md'.length)}`;
      const sourcePath = `docs/${subdir}/${file}`;
      const body = readFileSync(join(dir, file), 'utf8');
      return {
        id,
        title: extractRecordTitle(body, id),
        route: routeForRecordId(id),
        sourcePath,
      };
    });
}

/** `RECORDS.adr` and `RECORDS.security` — what `records.mdx` iterates to build its index. */
export const RECORDS: Record<RecordSubdir, RecordSummary[]> = {
  adr: listRecords('adr'),
  security: listRecords('security'),
};

/**
 * Look up one record by id (e.g. `adr/009-wallet-account-resolution`),
 * throwing at build time rather than silently rendering `undefined` into a
 * link if the id is wrong — for the handful of places `records.mdx` needs
 * to deep-link a SPECIFIC record (not just iterate all of them), such as
 * the ADR-009 drift re-check anchor.
 */
export function findRecord(id: string): RecordSummary {
  const found = [...RECORDS.adr, ...RECORDS.security].find((record) => record.id === id);
  if (!found) throw new Error(`records: no entry with id "${id}"`);
  return found;
}
