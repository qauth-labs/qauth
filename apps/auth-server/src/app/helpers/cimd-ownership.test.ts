import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

/**
 * The argument that makes a CIMD client NOT OWNABLE (ADR-012 §3), locked so it
 * cannot quietly stop being true.
 *
 * ADR-012 rejects the CIMD claim flow #374 floats on a mechanical ground, not a
 * philosophical one: `upsertCimdClient`'s `ON CONFLICT` set refreshes every
 * field `PATCH /api/clients/{id}` can edit except `scopes`, so an adopted CIMD
 * client would accept a developer's edits and silently revert them on the next
 * resolution of its `client_id` URL. Ownership without editability is a worse
 * lie than no ownership.
 *
 * That argument rests on an OVERLAP between two field lists in two different
 * projects, and nothing else in the suite compares them. If someone narrows the
 * upsert set — or widens the PATCH schema — the ADR's reasoning could become
 * false while every other test stayed green, and the next person to read it
 * would be reasoning from a premise the code no longer supports.
 *
 * This is a source-level assertion because that is what the claim is about: the
 * shape of two declarations, not the behaviour of one call. Behavioural tests
 * for the upsert itself live in the Docker-backed repository suite.
 */

/**
 * The workspace root, located from whichever cwd the runner used.
 *
 * `nx run auth-server:test` starts in `apps/auth-server`; a bare `vitest run`
 * from the repository root starts there. `import.meta.url` would settle it
 * without guessing, but this project typechecks under a module setting that
 * rejects it (TS1343), so walk up to the marker pair instead — the same pair
 * `apps/docs-site/src/invariants/workspace-root.ts` uses.
 */
function resolveWorkspaceRoot(): string {
  let dir = process.cwd();
  for (let depth = 0; depth < 10; depth += 1) {
    if (existsSync(join(dir, 'pnpm-workspace.yaml')) && existsSync(join(dir, 'nx.json'))) {
      return dir;
    }
    const parent = resolve(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(`Could not locate the workspace root walking up from ${process.cwd()}`);
}

const REPO_ROOT = resolveWorkspaceRoot();

/** Field names in the `set:` block of `upsertCimdClient`'s `onConflictDoUpdate`. */
function upsertOverwrittenFields(): Set<string> {
  const source = readFileSync(
    join(REPO_ROOT, 'libs/infra/db/src/lib/repositories/oauth-clients.repository.ts'),
    'utf8'
  );
  const fnStart = source.indexOf('async upsertCimdClient');
  expect(fnStart, 'upsertCimdClient not found — has it been renamed?').toBeGreaterThan(-1);

  const setStart = source.indexOf('set: {', fnStart);
  expect(setStart, 'onConflictDoUpdate set block not found').toBeGreaterThan(-1);
  const setEnd = source.indexOf('\n          },', setStart);
  const block = source.slice(setStart, setEnd);

  return new Set(
    [...block.matchAll(/^\s{12}(\w+):/gm)].map((match) => match[1]).filter((f) => f !== 'updatedAt')
  );
}

/** Field names a developer may PATCH on their own client. */
function patchableFields(): Set<string> {
  const source = readFileSync(
    join(REPO_ROOT, 'apps/auth-server/src/app/schemas/clients.ts'),
    'utf8'
  );
  const start = source.indexOf('export const updateClientRequestSchema');
  expect(start, 'updateClientRequestSchema not found').toBeGreaterThan(-1);
  const end = source.indexOf('.partial()', start);
  const block = source.slice(start, end);

  return new Set([...block.matchAll(/^\s{4}(\w+):/gm)].map((match) => match[1]));
}

describe('ADR-012 §3 — a CIMD client is not ownable because its edits would be reverted', () => {
  it('reads both field lists non-vacuously', () => {
    // Zero violations means nothing if either regex silently stopped matching.
    expect(upsertOverwrittenFields().size).toBeGreaterThanOrEqual(8);
    expect(patchableFields().size).toBeGreaterThanOrEqual(6);
  });

  it('the CIMD upsert overwrites every PATCH-able field except `scopes`', () => {
    const overwritten = upsertOverwrittenFields();
    const patchable = patchableFields();

    const survives = [...patchable].filter((field) => !overwritten.has(field)).sort();

    // If this list ever grows, ADR-012 §3's reasoning has weakened and the
    // decision deserves a fresh look — a CIMD client whose edits mostly stick
    // is a different animal from one whose edits are reverted within the cache
    // TTL. If it shrinks to nothing, the argument only got stronger.
    expect(survives).toEqual(['scopes']);
  });

  it('names the fields the argument depends on, so a rename is visible here', () => {
    const overwritten = upsertOverwrittenFields();
    for (const field of [
      'name',
      'description',
      'redirectUris',
      'grantTypes',
      'responseTypes',
      'tokenEndpointAuthMethod',
      'enabled',
    ]) {
      expect(overwritten, `${field} is no longer refreshed on CIMD re-resolution`).toContain(field);
    }
  });

  it('CIMD materialisation still pins developerId to null', () => {
    // The decision itself, at the site that implements it.
    const source = readFileSync(
      join(REPO_ROOT, 'apps/auth-server/src/app/helpers/cimd.ts'),
      'utf8'
    );
    expect(source).toContain('developerId: null');
    expect(source).toContain('ADR-012');
  });
});
