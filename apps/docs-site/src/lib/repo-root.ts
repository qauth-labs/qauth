import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Resolve the monorepo root by walking up from THIS FILE's own location,
 * not `process.cwd()` — so it agrees regardless of how the Astro/Vitest
 * process was launched (mirrors the reasoning in
 * `src/invariants/workspace-root.ts`'s `resolveWorkspaceRoot`).
 *
 * Deliberately a SEPARATE resolver, not an import of that guard module:
 * Task 10's brief asks that nothing under `src/invariants/` be touched, and
 * this project's convention (see that file's own comments) is to prefer a
 * small duplicated reader over a cross-module dependency for something this
 * narrow. The two share the same marker-pair strategy — `pnpm-workspace.yaml`
 * + `nx.json` together are unlikely to exist at any level below the real
 * workspace root — but stay independent so records-rendering code never
 * depends on drift-guard code, or vice versa.
 */
export function resolveRepoRoot(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 10; depth += 1) {
    if (existsSync(join(dir, 'pnpm-workspace.yaml')) && existsSync(join(dir, 'nx.json'))) {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(`Could not locate the workspace root by walking up from ${import.meta.url}`);
}
