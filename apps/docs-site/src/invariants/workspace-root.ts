import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Resolve the monorepo root by walking up from THIS FILE's own location,
 * not `process.cwd()`.
 *
 * The four drift guards read files across the whole repository — route
 * sources under `apps/auth-server`, `README.md`, `apps/docs-site/public/
 * openapi.json` — so their result must not depend on how the test process
 * was launched. `nx test docs-site` and a bare `vitest` invoked from
 * `apps/docs-site` start with different working directories; anchoring on
 * `import.meta.url` instead makes both agree on the same tree.
 *
 * `pnpm-workspace.yaml` + `nx.json` together are a marker pair unlikely to
 * exist at any level below the real workspace root.
 */
export function resolveWorkspaceRoot(): string {
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
