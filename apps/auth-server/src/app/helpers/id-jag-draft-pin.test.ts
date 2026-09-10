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
 * is what makes it re-checkable — it carries the revision, the basis, and the
 * draft's 2026-11-22 expiry, and its freshness check fails the build once that
 * date passes.
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

describe('ID_JAG_DRAFT — the in-code pin ADR-011 requires', () => {
  it('names a concrete revision, not a floating draft reference', () => {
    // `draft-ietf-oauth-identity-assertion-authz-grant` without a revision is
    // exactly the unfalsifiable citation ADR-011:26 used to carry ("currently
    // -04"). A pin that does not name a revision pins nothing.
    expect(ID_JAG_DRAFT).toMatch(/^draft-ietf-oauth-identity-assertion-authz-grant-\d{2}$/);
  });

  it('agrees with the revision docs/spec-pin-log.md tracks', () => {
    const revision = ID_JAG_DRAFT.slice(-3); // `-04`
    const row = PIN_LOG.split('\n').find((line) => line.includes('ID-JAG') && line.includes('|'));

    expect(row, 'no ID-JAG row in the pin log').toBeDefined();
    expect(row, `pin log does not track ${revision}`).toContain(`\`${revision}\``);
  });

  it('is covered by a pin-log row carrying the draft expiry', () => {
    // The expiry is what turns the pin into something that expires loudly
    // rather than silently. Before #401 it was recorded nowhere.
    const row = PIN_LOG.split('\n').find((line) => line.includes('ID-JAG') && line.includes('|'));
    expect(row).toContain('2026-11-22');
  });
});
