#!/usr/bin/env node --experimental-strip-types
/**
 * Fail CI when checked-in prose presents a CLOSED issue as open work (#399).
 *
 * WHY THIS IS A SCRIPT AND NOT A VITEST CASE. Everything except the single
 * `fetch` below is unit-tested: the extraction in
 * `apps/docs-site/src/invariants/issue-state-claims.test.ts`, the response
 * parsing in `issue-state-resolution.test.ts`. Only the network call needs a
 * token. Putting that in the unit suite would mean either a suite that cannot
 * run offline, or one that skips the check whenever the network is unavailable
 * — and a guard that silently no-ops reports green while checking nothing,
 * which is worse than no guard, because it looks maintained.
 *
 * So: fail loudly, never skip. Every non-zero exit below is deliberate.
 *
 *   0  clean
 *   1  a closed issue is presented as open work, or a reference could not be
 *      resolved — emitted as `::error file=…,line=…::` so it lands on the PR diff
 *   2  input error: no token, an unreachable API, an unparseable response
 *
 * Run through Node's own type stripping (`--experimental-strip-types`, the
 * default from Node 23) so it can IMPORT the extraction rather than carry a
 * second copy of it, WITHOUT adding a script runner to the root
 * devDependencies. A duplicated regex would drift from the one the fixtures
 * test, and the check would then verify something other than what CI runs.
 *
 * Cadence: this belongs in the per-PR job, not on the spec pin log's quarterly
 * pass. `#379` closed and `MVP-PRD.md` was wrong within 24 hours; a quarterly
 * check would have found it up to 90 days later.
 *
 * Usage: node --experimental-strip-types scripts/check-issue-state-claims.mts
 * Env:   GITHUB_TOKEN (or GH_TOKEN) — issue reads on a public repo need only
 *        the default `GITHUB_TOKEN` a workflow already has.
 */
import { readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadContentTree } from '../apps/docs-site/src/invariants/content-tree.ts';
import {
  buildIssueStatesQuery,
  type IssueState,
  parseIssueStatesResponse,
} from '../apps/docs-site/src/invariants/issue-state-resolution.ts';
import {
  findClosedIssuesNamedAsOpen,
  findOpenWorkIssueRefs,
  type ScannablePage,
} from '../apps/docs-site/src/invariants/status-claims.ts';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OWNER = 'qauth-labs';
const REPO = 'qauth';

/**
 * The repo-root status surfaces, on top of the site content tree.
 *
 * `MVP-PRD.md` is IN here and OUT of the evidence-path guard's scan set, and
 * that split is the decision #399 asked for. The evidence-path check excludes
 * it because a PRD's status column calls shipped work "in progress" by design;
 * this check only ever flags an issue that is CLOSED while listed as
 * outstanding, and a planning record naming finished work as remaining is
 * simply wrong. `MVP-PRD.md` carried two of #396's six defects.
 */
const REPO_ROOT_PAGES = ['README.md', 'docs/README.md', 'MVP-PRD.md', 'AGENTS.md'];

function fail(code: number, message: string): never {
  process.stderr.write(`check-issue-state-claims: ${message}\n`);
  process.exit(code);
}

function buildScanSet(): ScannablePage[] {
  const contentDir = join(REPO_ROOT, 'apps', 'docs-site', 'src', 'content', 'docs');
  const sitePages: ScannablePage[] = loadContentTree(contentDir).map((page) => ({
    id: relative(REPO_ROOT, page.filePath),
    content: page.body,
    unbuiltClaims: page.frontmatter.unbuiltClaims === true,
  }));

  const rootPages: ScannablePage[] = REPO_ROOT_PAGES.map((rel) => ({
    id: rel,
    content: readFileSync(join(REPO_ROOT, rel), 'utf8'),
  }));

  return [...sitePages, ...rootPages];
}

async function resolveIssueStates(numbers: number[]): Promise<Map<number, IssueState>> {
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (!token) {
    fail(
      2,
      'GITHUB_TOKEN (or GH_TOKEN) is required. Refusing to skip the check: a guard that ' +
        'no-ops when it cannot reach the API reports green while checking nothing.'
    );
  }

  let response: Response;
  try {
    response = await fetch('https://api.github.com/graphql', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'qauth-issue-state-claims',
      },
      body: JSON.stringify({ query: buildIssueStatesQuery(OWNER, REPO, numbers) }),
    });
  } catch (err) {
    fail(2, `GitHub API unreachable: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (!response.ok) {
    fail(2, `GitHub API returned HTTP ${response.status} ${response.statusText}`);
  }

  return parseIssueStatesResponse(await response.json(), fail);
}

async function main(): Promise<void> {
  const pages = buildScanSet();
  if (pages.length === 0) {
    fail(2, 'scan set is empty — the content tree or the repo-root page list is wrong');
  }

  const refs = findOpenWorkIssueRefs(pages);
  if (refs.length === 0) {
    // Not an error, but said out loud: a regex that stopped matching would
    // otherwise look exactly like a clean tree.
    process.stdout.write(
      `check-issue-state-claims: scanned ${pages.length} pages, found no open-work issue references.\n`
    );
    return;
  }

  const numbers = [...new Set(refs.map((ref) => ref.issue))].sort((a, b) => a - b);
  const states = await resolveIssueStates(numbers);
  const violations = findClosedIssuesNamedAsOpen(refs, states);

  process.stdout.write(
    `check-issue-state-claims: ${pages.length} pages, ${refs.length} references, ` +
      `${numbers.length} distinct issues resolved.\n`
  );

  if (violations.length === 0) return;

  for (const violation of violations) {
    // GitHub Actions annotation — lands on the PR diff at the offending line.
    process.stdout.write(
      `::error file=${violation.file},line=${violation.line}::${violation.reason}: ${violation.excerpt}\n`
    );
  }
  process.stderr.write(
    `\ncheck-issue-state-claims: ${violations.length} issue-state claim(s) are stale.\n` +
      'Remove the closed issue from the open-work list, or reword the sentence so it ' +
      'attributes the work to that issue rather than listing it as outstanding.\n'
  );
  process.exit(1);
}

await main();
