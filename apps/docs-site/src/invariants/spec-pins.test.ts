import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { findStaleSpecPins, parseSpecPinTable } from './spec-pins';
import { resolveWorkspaceRoot } from './workspace-root';

/**
 * The freshness check for `docs/spec-pin-log.md` (#401).
 *
 * The log's main risk is that it becomes another decaying document — a table of
 * dates is itself a status surface, and one that looks maintained and is not is
 * worse than none, because a reader trusts it. That risk is only managed if this
 * check fails HARD. Every case below therefore asserts a failure, not a warning,
 * and the real-tree case at the end is a plain `toEqual([])`.
 */

const REPO_ROOT = resolveWorkspaceRoot();
const LOG_PATH = join(REPO_ROOT, 'docs', 'spec-pin-log.md');

/**
 * A pinned "today" for the FIXTURE cases below, so their behaviour does not
 * drift with the wall clock.
 *
 * The real-tree case deliberately does NOT use it — see `realToday()`.
 */
const TODAY = '2026-08-31';

/**
 * The actual date, used only by the real-tree case.
 *
 * This is the whole point of the gate and it must not be pinned: a freshness
 * check frozen at a fixed date passes forever and enforces nothing. When
 * ID-JAG `-04` expires on 2026-11-22, this test goes red and someone runs the
 * quarterly pass — which is the mechanism ADR-007 asked for and has never had.
 *
 * Yes, that means the suite can fail on a day nobody changed any code. That is
 * the design, not a flake: the tree really has become stale on that day, and a
 * check that only fires when someone happens to touch the log would be exactly
 * the warn-only version the log's own header says to delete it over.
 */
function realToday(): string {
  return new Date().toISOString().slice(0, 10);
}

function table(rows: string): string {
  return [
    '| Spec | Pinned revision | Pin basis | Last verified | Re-check by | Verdict | Consumers |',
    '| --- | --- | --- | --- | --- | --- | --- |',
    rows,
  ].join('\n');
}

describe('parseSpecPinTable', () => {
  it('reads the pin table and nothing else', () => {
    // The document also contains a "three bases" explainer table and a pass
    // ledger. Only the table whose header names both `Pin basis` and
    // `Re-check by` is the pin table.
    const rows = parseSpecPinTable(readFileSync(LOG_PATH, 'utf8'));
    expect(rows.length).toBeGreaterThanOrEqual(8);
    expect(rows.map((r) => r.spec).join(' ')).toContain('SD-JWT VC');
    for (const row of rows) {
      expect(row.basis, `${row.spec} has no basis`).toBeTruthy();
      expect(row.recheckBy, `${row.spec} has no re-check date`).toMatch(/\d{4}-\d{2}-\d{2}/);
    }
  });

  it('returns nothing when there is no pin table', () => {
    // The caller must treat an empty parse as a failure rather than a clean
    // bill — see the real-tree non-vacuity assertion below.
    expect(parseSpecPinTable('# Just prose\n\nNo table here.')).toEqual([]);
  });
});

describe('findStaleSpecPins — the gate', () => {
  it('FAILS on a past Re-check by date', () => {
    const rows = parseSpecPinTable(
      table(
        '| ID-JAG | `-04` | `latest` | `2026-08-06` | `2026-08-30` | Current | `package.json` |'
      )
    );
    const violations = findStaleSpecPins(rows, REPO_ROOT, TODAY);

    expect(violations).toHaveLength(1);
    expect(violations[0].reason).toContain('re-check was due 2026-08-30');
  });

  it('PASSES on a future Re-check by date — the mutation pair', () => {
    const rows = parseSpecPinTable(
      table(
        '| ID-JAG | `-04` | `latest` | `2026-08-06` | `2026-11-22` | Current | `package.json` |'
      )
    );
    expect(findStaleSpecPins(rows, REPO_ROOT, TODAY)).toEqual([]);
  });

  it('treats the due date itself as still in date, not overdue', () => {
    const rows = parseSpecPinTable(
      table(
        `| ID-JAG | \`-04\` | \`latest\` | \`2026-08-06\` | \`${TODAY}\` | Current | \`package.json\` |`
      )
    );
    expect(findStaleSpecPins(rows, REPO_ROOT, TODAY)).toEqual([]);
  });

  it('FAILS on a consumer path that no longer exists', () => {
    const rows = parseSpecPinTable(
      table(
        '| ID-JAG | `-04` | `latest` | `2026-08-06` | `2026-11-22` | Current | `libs/gone/away.ts` |'
      )
    );
    const violations = findStaleSpecPins(rows, REPO_ROOT, TODAY);

    expect(violations).toHaveLength(1);
    expect(violations[0].reason).toContain('libs/gone/away.ts');
    expect(violations[0].reason).toContain('no longer exists');
  });

  it('FAILS on a row with no consumers at all', () => {
    const rows = parseSpecPinTable(
      table('| Orphan | `-01` | `latest` | `2026-08-06` | `2026-11-22` | Current |  |')
    );
    expect(findStaleSpecPins(rows, REPO_ROOT, TODAY)[0].reason).toContain('no consumers');
  });

  it('FAILS on a pin basis outside the three the log defines', () => {
    // The column is load-bearing: without a basis, an "update to latest" pass
    // cannot tell a derived pin (bumping it breaks conformance) from a tracked
    // one. A row that opts out of the vocabulary opts out of that protection.
    const rows = parseSpecPinTable(
      table(
        '| ID-JAG | `-04` | `current-ish` | `2026-08-06` | `2026-11-22` | Current | `package.json` |'
      )
    );
    expect(findStaleSpecPins(rows, REPO_ROOT, TODAY)[0].reason).toContain('pin basis');
  });

  it('FAILS on a malformed date rather than reading it as "not yet due"', () => {
    const rows = parseSpecPinTable(
      table('| ID-JAG | `-04` | `latest` | `soon` | `whenever` | Current | `package.json` |')
    );
    const reasons = findStaleSpecPins(rows, REPO_ROOT, TODAY).map((v) => v.reason);

    expect(reasons.some((r) => r.includes('"Re-check by" is not an ISO date'))).toBe(true);
    expect(reasons.some((r) => r.includes('"Last verified" is not an ISO date'))).toBe(true);
  });

  it('names the line, so a failure points at the row to edit', () => {
    const rows = parseSpecPinTable(
      table(
        '| ID-JAG | `-04` | `latest` | `2026-08-06` | `2026-08-01` | Current | `package.json` |'
      )
    );
    expect(findStaleSpecPins(rows, REPO_ROOT, TODAY)[0].line).toBe(3);
  });
});

describe('docs/spec-pin-log.md — real tree', () => {
  it('every pin is in date TODAY and every consumer path exists', () => {
    const rows = parseSpecPinTable(readFileSync(LOG_PATH, 'utf8'));

    // Non-vacuity, asserted first: zero violations looks identical whether this
    // parsed ten rows or none. A reformatted table that stopped parsing would
    // otherwise report a clean bill forever.
    expect(rows.length).toBeGreaterThanOrEqual(8);
    expect(rows.flatMap((row) => row.consumers).length).toBeGreaterThanOrEqual(10);

    // `realToday()`, not the pinned TODAY — this assertion is the gate.
    expect(findStaleSpecPins(rows, REPO_ROOT, realToday())).toEqual([]);
  });

  it('records the ID-JAG draft expiry the issue says is written down nowhere', () => {
    const rows = parseSpecPinTable(readFileSync(LOG_PATH, 'utf8'));
    const idJag = rows.find((row) => row.spec.includes('ID-JAG'));
    expect(idJag?.recheckBy).toBe('2026-11-22');
  });

  it('pins SD-JWT VC at draft-13 on a DERIVED basis, not as a latest-published pin', () => {
    // The row the Pin basis column exists for. `-18` is current; HAIP 1.0 §9.4
    // requires `-13`. An "update to latest" pass that bumped this would break
    // EUDI conformance while making the docs look more current.
    const rows = parseSpecPinTable(readFileSync(LOG_PATH, 'utf8'));
    const sdJwt = rows.find((row) => row.spec.includes('SD-JWT VC'));
    expect(sdJwt?.revision).toBe('-13');
    expect(sdJwt?.basis).toBe('derived');
  });
});
