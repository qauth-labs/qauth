import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

// `id-jag.ts` transitively imports `config/env`, which validates `process.env`
// at module load. This test is about one exported constant, so stub the env
// rather than construct a full valid environment for it.
vi.mock('../../config/env', () => ({
  env: {
    ID_JAG_ENABLED: false,
    ID_JAG_TRUSTED_ISSUERS: {},
  },
}));

import { ID_JAG_DRAFT } from './id-jag';

/**
 * The in-code ID-JAG draft pin, tied to the row that tracks it (#401).
 *
 * ADR-011:420-422 requires the implementation to pin the revision it targets
 * **in code**, not only in prose. `ID_JAG_DRAFT` is that pin. `docs/spec-pin-log.md`
 * is what makes it re-checkable — it carries the revision, the basis, the
 * draft's 2026-11-22 expiry and the row's `Re-check by` date, and its freshness
 * check fails the build once the `Re-check by` date passes. The basis is
 * `derived` (#466): the MCP `ext-auth` EMA extension names the revision, so the
 * re-check date is the quarterly pass, not the expiry.
 *
 * Two artefacts stating the same fact drift unless something compares them.
 * This is that something.
 */

function resolveWorkspaceRoot(): string {
  let dir = process.cwd();
  for (let depth = 0; depth < 10; depth += 1) {
    if (existsSync(join(dir, 'pnpm-workspace.yaml')) && existsSync(join(dir, 'nx.json')))
      return dir;
    const parent = resolve(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(`Could not locate the workspace root walking up from ${process.cwd()}`);
}

const PIN_LOG = readFileSync(join(resolveWorkspaceRoot(), 'docs', 'spec-pin-log.md'), 'utf8');

/**
 * The ID-JAG row of the pin table. Matched by the row's own first cell, not by "the first
 * line that names ID-JAG": the pass ledger and the prose above the table mention it too,
 * and a pin test must read the row that carries the pin.
 */
function pinTableRow(): string | undefined {
  return PIN_LOG.split('\n').find((line) => line.startsWith('| ID-JAG ('));
}

/** The ID-JAG row's cells, keyed by the pin table's own column names. */
function pinTableCells(): Record<string, string> {
  const lines = PIN_LOG.split('\n');
  const header = lines.find((line) => line.startsWith('| Spec ') && line.includes('Re-check by'));
  const row = pinTableRow();
  if (!header || !row) return {};

  const cells = (line: string) =>
    line
      .split('|')
      .slice(1, -1)
      .map((cell) => cell.trim());
  const values = cells(row);
  return Object.fromEntries(cells(header).map((name, i) => [name, values[i]]));
}

describe('ID_JAG_DRAFT — the in-code pin ADR-011 requires', () => {
  it('names a concrete revision, not a floating draft reference', () => {
    // `draft-ietf-oauth-identity-assertion-authz-grant` without a revision is
    // exactly the unfalsifiable citation ADR-011:26 used to carry ("currently
    // -04"). A pin that does not name a revision pins nothing.
    expect(ID_JAG_DRAFT).toMatch(/^draft-ietf-oauth-identity-assertion-authz-grant-\d{2}$/);
  });

  it('agrees with the revision docs/spec-pin-log.md tracks', () => {
    const revision = ID_JAG_DRAFT.slice(-3); // `-04`
    const row = pinTableRow();

    expect(row, 'no ID-JAG row in the pin log').toBeDefined();
    expect(row, `pin log does not track ${revision}`).toContain(`\`${revision}\``);
  });

  it('is covered by a pin-log row carrying the draft expiry', () => {
    // Before #401 the expiry was recorded nowhere. Since #466 it no longer sets
    // the re-check date, but it stays in the row: anyone citing `-04` after
    // 2026-11-22 cites an expired draft, and should be able to see that.
    expect(pinTableCells()['Expires']).toBe('2026-11-22');
  });

  it('is derived from the MCP EMA extension, so it is re-checked at the quarterly pass', () => {
    // A newer IETF revision alone does not move this constant. It moves when
    // the EMA file at the commit the log pins names a newer revision, and the
    // code here implements it.
    const cells = pinTableCells();
    expect(cells['Pin basis']).toBe('`derived`');
    expect(cells['Re-check by']).toBe('`2026-11-30`');
  });
});
