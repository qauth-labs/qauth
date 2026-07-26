import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { loadContentTree } from './content-tree';
import {
  type EvidenceEntry,
  FEATURE_EVIDENCE,
  findStaleStatusClaims,
  type ScannablePage,
} from './status-claims';
import { resolveWorkspaceRoot } from './workspace-root';

/**
 * Guard 4: content may not call a shipped feature "deferred", "not yet
 * implemented", "coming soon" or equivalent. This is what actually failed
 * in the repo already — README.md still lists the ADR-002 migration, PQC
 * hybrid signing and wallet federation as undelivered, unnoticed across
 * three merge waves because nothing mechanical checked it. If this test is
 * deleted, that regression is silent again.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '__fixtures__', 'status-claims');
const REPO_ROOT = resolveWorkspaceRoot();

function loadFixturePage(name: string, unbuiltClaims?: boolean): ScannablePage {
  return { id: name, content: readFileSync(join(FIXTURES, name), 'utf8'), unbuiltClaims };
}

describe('FEATURE_EVIDENCE table', () => {
  it('every evidence path exists in the repository — an invented path would silently disable its row', () => {
    for (const entry of FEATURE_EVIDENCE) {
      for (const evidencePath of entry.evidencePaths) {
        expect(
          existsSync(join(REPO_ROOT, evidencePath)),
          `${entry.feature}: expected "${evidencePath}" to exist`
        ).toBe(true);
      }
    }
  });
});

describe('findStaleStatusClaims — fixtures', () => {
  it('passes prose that describes a shipped feature as shipped', () => {
    const violations = findStaleStatusClaims(
      [loadFixturePage('ok-shipped.md')],
      FEATURE_EVIDENCE,
      REPO_ROOT
    );
    expect(violations).toEqual([]);
  });

  it('MUTATION: fails prose that calls a shipped feature deferred / not yet implemented', () => {
    const violations = findStaleStatusClaims(
      [loadFixturePage('broken-deferred.md')],
      FEATURE_EVIDENCE,
      REPO_ROOT
    );
    expect(violations).toEqual([
      expect.objectContaining({ file: 'broken-deferred.md', feature: 'PQC / hybrid signing' }),
    ]);
  });

  it('the escape hatch is page-scoped: unbuiltClaims: true silences the exact same prose', () => {
    const violations = findStaleStatusClaims(
      [loadFixturePage('broken-deferred.md', true)],
      FEATURE_EVIDENCE,
      REPO_ROOT
    );
    expect(violations).toEqual([]);
  });

  it('does not flag "not deferred" as a violation (negative-lookbehind on the status phrase)', () => {
    const violations = findStaleStatusClaims(
      [loadFixturePage('not-deferred.md')],
      FEATURE_EVIDENCE,
      REPO_ROOT
    );
    expect(violations).toEqual([]);
  });

  it('does not trust evidence that does not exist on disk', () => {
    const fakeEvidence: EvidenceEntry[] = [
      { feature: 'Ghost Feature', aliases: ['ghost feature'], evidencePaths: ['does/not/exist'] },
    ];
    const violations = findStaleStatusClaims(
      [loadFixturePage('fake-evidence.md')],
      fakeEvidence,
      REPO_ROOT
    );
    expect(violations).toEqual([]);
  });

  it('README.md and docs/README.md have no frontmatter and must not crash the guard', () => {
    const page: ScannablePage = {
      id: 'no-frontmatter.md',
      content: 'plain text, no unbuiltClaims field',
    };
    expect(() => findStaleStatusClaims([page], FEATURE_EVIDENCE, REPO_ROOT)).not.toThrow();
  });
});

/**
 * Real-tree scan set: the site content tree plus README.md and
 * docs/README.md (per the brief). `MVP-PRD.md` is deliberately excluded —
 * owner decision, not an oversight: it is a planning record that calls
 * already-shipped work "in progress" by design (that's what a PRD's status
 * column is for), so scanning it would make this guard permanently red for
 * a reason unrelated to documentation drift. See vitest.config.ts / nx.json
 * for this repo's existing convention of commenting exclusions like this
 * one rather than leaving them unexplained.
 */
function buildRealScanSet(): ScannablePage[] {
  const contentDir = join(REPO_ROOT, 'apps', 'docs-site', 'src', 'content', 'docs');
  const sitePages: ScannablePage[] = loadContentTree(contentDir).map((page) => ({
    id: page.slug,
    content: page.body,
    unbuiltClaims: page.frontmatter.unbuiltClaims === true,
  }));

  // No frontmatter on either file, so `unbuiltClaims` is left `undefined` —
  // never exempt. That absence must not throw (asserted above).
  const readme: ScannablePage = {
    id: 'README.md',
    content: readFileSync(join(REPO_ROOT, 'README.md'), 'utf8'),
  };
  const docsReadme: ScannablePage = {
    id: 'docs/README.md',
    content: readFileSync(join(REPO_ROOT, 'docs', 'README.md'), 'utf8'),
  };

  return [...sitePages, readme, docsReadme];
}

describe('findStaleStatusClaims — real tree', () => {
  /**
   * EXPECTED TO FAIL until Task 4 (#350) lands. README.md and docs/README.md
   * currently call the ADR-002 migration, PQC hybrid signing and wallet
   * federation "deferred" / "not yet implemented" while all three have
   * shipped — the exact rot this guard exists to catch. Per the task brief:
   * do not skip this, do not narrow the scan set, do not soften the
   * assertion. Its failure output IS Task 4's work order.
   */
  it('the site content tree, README.md, and docs/README.md make no stale status claims', () => {
    const violations = findStaleStatusClaims(buildRealScanSet(), FEATURE_EVIDENCE, REPO_ROOT);
    expect(violations).toEqual([]);
  });
});
