import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { loadContentTree } from './content-tree';
import {
  findClosedIssuesNamedAsOpen,
  findOpenWorkIssueRefs,
  type ScannablePage,
} from './status-claims';
import { resolveWorkspaceRoot } from './workspace-root';

/**
 * The issue-state half of the drift guard (#399).
 *
 * Every defect in #396 landed on a repo that already ran a prose-drift guard in
 * CI, and it caught none of them. The reason is structural, not a bug: the
 * existing check resolves "shipped" by looking for evidence paths on disk, so a
 * sentence reading "Open: … key-storage assurance (#379) …" stays green forever
 * after `#379` closes. Nothing about it is falsifiable from the filesystem.
 *
 * These tests cover the extraction — which is pure, offline, and where all the
 * judgement lives. Resolving the numbers is `scripts/check-issue-state-claims.mjs`'s
 * job, and it is deliberately NOT exercised here: a unit suite that needed a
 * network and a token would be skipped in exactly the situations it matters.
 */

const REPO_ROOT = resolveWorkspaceRoot();
const FIXTURES = join(
  REPO_ROOT,
  'apps',
  'docs-site',
  'src',
  'invariants',
  '__fixtures__',
  'issue-state'
);

function fixture(name: string): ScannablePage {
  return { id: name, content: readFileSync(join(FIXTURES, name), 'utf8') };
}

/** The real states of the issues the fixtures name, as of 2026-08-31. */
const STATES = new Map<number, 'open' | 'closed'>([
  [224, 'closed'],
  [230, 'closed'],
  [231, 'open'],
  [237, 'closed'],
  [238, 'closed'],
  [300, 'closed'],
  [308, 'closed'],
  [376, 'open'],
  [377, 'open'],
  [379, 'closed'],
]);

describe('findOpenWorkIssueRefs — what counts as a claim about an issue', () => {
  it('picks up every issue named after an "Open:" trigger', () => {
    const refs = findOpenWorkIssueRefs([fixture('closed-listed-as-open.md')]);
    expect(refs.map((r) => r.issue).sort((a, b) => a - b)).toEqual([231, 376, 377, 379]);
  });

  it('ignores issue numbers used as ATTRIBUTION, not as open work', () => {
    // This is the case that decides whether the check is usable at all. The
    // repository cites issue numbers constantly to say where something CAME
    // FROM — "added in #226", "the #308 gate", "(#379 review, finding 3)" — and
    // every one of those is correct precisely because the issue is closed.
    const refs = findOpenWorkIssueRefs([fixture('attribution-only.md')]);
    expect(refs).toEqual([]);
  });

  it('does not let a trigger reach past its own sentence', () => {
    // The trailing paragraph of this fixture names #237, #308 and #379 as
    // history. A scope that ran to the end of the page would flag all three.
    const refs = findOpenWorkIssueRefs([fixture('closed-listed-as-open.md')]);
    const excerpts = refs.map((r) => r.excerpt).join(' ');
    expect(excerpts).not.toContain('acr` propagation');
  });

  it('scopes a bullet trigger to its own bullet', () => {
    // "Shipped: key-storage assurance (#379)" sits between two "Remaining:"
    // bullets. A scope that crossed newlines would flag #379 from the bullet
    // above it.
    const refs = findOpenWorkIssueRefs([fixture('bullet-scoped.md')]);
    expect(refs.map((r) => r.issue).sort((a, b) => a - b)).toEqual([376, 377]);
  });

  it('reports the file and the line the reference sits on', () => {
    const refs = findOpenWorkIssueRefs([fixture('closed-listed-as-open.md')]);
    const ref = refs.find((r) => r.issue === 379);
    expect(ref?.file).toBe('closed-listed-as-open.md');
    // The `#379` in the fixture's "Open:" list is on line 6.
    expect(ref?.line).toBe(6);
  });

  it('honours the page-scoped unbuiltClaims escape hatch', () => {
    const page = { ...fixture('closed-listed-as-open.md'), unbuiltClaims: true };
    expect(findOpenWorkIssueRefs([page])).toEqual([]);
  });
});

describe('findClosedIssuesNamedAsOpen — the gate', () => {
  it('FAILS on a fixture where a closed issue is named in an open-work list', () => {
    const refs = findOpenWorkIssueRefs([fixture('closed-listed-as-open.md')]);
    const violations = findClosedIssuesNamedAsOpen(refs, STATES);

    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({
      file: 'closed-listed-as-open.md',
      line: 6,
      issue: 379,
    });
    // The failure has to name the file, the line and the issue — an operator
    // reading CI output should not have to go looking.
    expect(violations[0].reason).toContain('#379');
    expect(violations[0].reason).toContain('closed');
  });

  it('PASSES once the closed issue is removed from the list', () => {
    // Same page, same triggers, same still-open issues — the ONLY difference is
    // that `#379` is gone from the "Open:" list. This pair is the proof the
    // gate is load-bearing rather than incidentally green.
    const refs = findOpenWorkIssueRefs([fixture('open-only.md')]);
    expect(refs.map((r) => r.issue).sort((a, b) => a - b)).toEqual([231, 376, 377]);
    expect(findClosedIssuesNamedAsOpen(refs, STATES)).toEqual([]);
  });

  it('treats an UNRESOLVED issue as a violation, never as a pass', () => {
    // A guard that silently skips what it could not check reports green while
    // checking nothing, which is worse than no guard at all.
    const refs = findOpenWorkIssueRefs([fixture('open-only.md')]);
    const partial = new Map(STATES);
    partial.delete(377);

    const violations = findClosedIssuesNamedAsOpen(refs, partial);
    expect(violations).toHaveLength(1);
    expect(violations[0].issue).toBe(377);
    expect(violations[0].reason).toContain('could not be resolved');
  });
});

describe('REGRESSION: the real #396 defect this check exists for', () => {
  /**
   * These two fixtures are the ACTUAL prose from `README.md:186` and
   * `MVP-PRD.md:10` as they stood before #398 corrected them — copied out of
   * git, not paraphrased. `#379` closed 2026-08-26 and both files named it as
   * remaining T4 work; the existing evidence-path guard was green throughout,
   * because nothing about an issue's state is falsifiable from the filesystem.
   *
   * Written from the real defect rather than from a minimal repro so that a
   * future rewrite of the trigger list has to keep working on the sentence
   * shapes this repository actually writes, not just on ones convenient to
   * match.
   */
  it('flags #379 in the README line that carried the defect', () => {
    const refs = findOpenWorkIssueRefs([fixture('regression-379-readme.md')]);
    const violations = findClosedIssuesNamedAsOpen(refs, STATES);

    expect(violations.map((v) => v.issue)).toEqual([379]);
    // The still-open siblings in the same sentence must NOT be flagged.
    expect(refs.map((r) => r.issue).sort((a, b) => a - b)).toEqual([231, 376, 377, 379]);
  });

  it('flags #379 in MVP-PRD.md — the file the evidence-path scan set excludes', () => {
    // This is the case that decides the scan-set split. `status-claims.test.ts`
    // leaves `MVP-PRD.md` out for a good reason that does not transfer here, and
    // `MVP-PRD.md` carried two of #396's six defects.
    const refs = findOpenWorkIssueRefs([fixture('regression-379-mvp-prd.md')]);
    const violations = findClosedIssuesNamedAsOpen(refs, STATES);

    expect(violations.map((v) => v.issue)).toEqual([379]);
  });

  it('does not flag the surrounding prose that merely CITES closed issues', () => {
    // The README fixture's neighbouring lines name #232 as the reason
    // `WalletProvider.verify()` throws. That is attribution and it is correct.
    const refs = findOpenWorkIssueRefs([fixture('regression-379-readme.md')]);
    expect(refs.map((r) => r.issue)).not.toContain(232);
  });
});

/**
 * The scan set for THIS check, and why it differs from the evidence-path one.
 *
 * `status-claims.test.ts` deliberately excludes `MVP-PRD.md`, because a PRD's
 * status column calls already-shipped work "in progress" by design and would
 * make the evidence-path guard permanently red for a reason unrelated to drift.
 *
 * That reasoning does not transfer. This check flags only issues that are
 * CLOSED while being listed as outstanding, and a planning record naming
 * finished work as remaining is simply wrong — `MVP-PRD.md` carried two of
 * #396's six defects. So it joins the scan set here and stays out there. The
 * decision #399 asked for is that split, not a single answer for both checks.
 */
function buildIssueStateScanSet(): ScannablePage[] {
  const contentDir = join(REPO_ROOT, 'apps', 'docs-site', 'src', 'content', 'docs');
  const sitePages: ScannablePage[] = loadContentTree(contentDir).map((page) => ({
    id: page.slug,
    content: page.body,
    unbuiltClaims: page.frontmatter.unbuiltClaims === true,
  }));

  const repoFiles = ['README.md', 'docs/README.md', 'MVP-PRD.md', 'AGENTS.md'].map((rel) => ({
    id: rel,
    content: readFileSync(join(REPO_ROOT, rel), 'utf8'),
  }));

  return [...sitePages, ...repoFiles];
}

describe('issue-state claims — real tree', () => {
  it('scans the site content plus the four repo-root status surfaces', () => {
    const ids = buildIssueStateScanSet().map((page) => page.id);
    // Non-vacuity: zero violations looks identical whether this scanned
    // everything or nothing.
    expect(ids).toEqual(
      expect.arrayContaining(['README.md', 'docs/README.md', 'MVP-PRD.md', 'AGENTS.md'])
    );
    expect(ids.length).toBeGreaterThanOrEqual(10);
  });

  it('every issue the tree presents as open work is one the check can see', () => {
    // Offline half of the real-tree assertion: the numbers are resolved against
    // GitHub by `scripts/check-issue-state-claims.mjs` in CI. What is asserted
    // here is that extraction over the real tree produces a sane, non-empty,
    // deduplicated set — a regex that silently stopped matching would otherwise
    // leave the CI script checking nothing and reporting success.
    const refs = findOpenWorkIssueRefs(buildIssueStateScanSet());
    expect(refs.length).toBeGreaterThan(0);
    for (const ref of refs) {
      expect(ref.issue).toBeGreaterThan(0);
      expect(ref.line).toBeGreaterThan(0);
      expect(ref.file).toBeTruthy();
    }
  });
});
