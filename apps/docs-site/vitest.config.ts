import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig, mergeConfig } from 'vitest/config';

import baseConfig from '../../vitest.config';

const projectRoot = dirname(fileURLToPath(import.meta.url));

// #285: a bare `export default baseConfig` leaves `root` unset, so Vitest
// resolves it from `process.cwd()` — a target invoked from the workspace
// root would then collect every spec in the monorepo instead of this
// project's own. Pinning `root` here (mirrors apps/auth-server/vitest.config.ts)
// makes discovery independent of where the process was launched.
export default mergeConfig(
  baseConfig,
  defineConfig({
    root: projectRoot,
    test: {
      // Scope collection to this project's guard sources. The base config's
      // `exclude` (node_modules, dist, `*.integration.test.ts`, worktrees)
      // still applies on top.
      include: ['src/**/*.{test,spec}.?(c|m)[jt]s?(x)'],
    },
  })
);
