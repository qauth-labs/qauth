import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { describe, expect, it } from 'vitest';

/**
 * Guards the two conditional security invariants recorded in `main.ts` (#323).
 *
 * Both Dependabot findings below were floored in `pnpm-workspace.yaml` rather than
 * fixed upstream, and both are inert only because of a design choice made in `main.ts`.
 * These assertions are source-level on purpose: `main.ts` calls `start()` at module
 * scope, so it cannot be imported and inspected as a value without booting a listener.
 */
/**
 * Locate `main.ts` without `import.meta` — `tsconfig.app.json` compiles this project
 * (tests included) as `module: commonjs`, under which `import.meta` is a syntax error.
 * Walk up from the cwd so the lookup works whether the runner was launched from the
 * project directory or the workspace root.
 */
function resolveMainPath(): string {
  let dir = process.cwd();
  for (let depth = 0; depth < 8; depth += 1) {
    for (const candidate of [
      join(dir, 'src', 'main.ts'),
      join(dir, 'apps', 'auth-server', 'src', 'main.ts'),
    ]) {
      if (existsSync(candidate)) return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('Could not locate apps/auth-server/src/main.ts from cwd ' + process.cwd());
}

const mainSource = readFileSync(resolveMainPath(), 'utf8');

/** Strip line and block comments so the assertions read code, not the comments about it. */
const mainCode = mainSource.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

describe('main.ts security invariants', () => {
  it('installs a global Zod validator compiler so ajv (and thus fast-uri) never validates a request', () => {
    // fast-uri host confusion (CVE-2026-13676, CVE-2026-16221) reaches the tree via ajv.
    // Fastify only loads ajv when a route has no non-ajv validator compiler.
    expect(mainCode).toMatch(/server\.setValidatorCompiler\(\s*validatorCompiler\s*\)/);
  });

  it('serves HTTP/1.1, keeping the find-my-way HTTP/2 DoS (CVE-2026-47219) unreachable', () => {
    expect(mainCode).not.toMatch(/\bhttp2\b/);
    expect(mainCode).not.toMatch(/\bserverFactory\b/);
  });
});
