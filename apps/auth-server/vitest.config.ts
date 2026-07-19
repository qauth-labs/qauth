import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig, mergeConfig } from 'vitest/config';

import baseConfig from '../../vitest.config';

const projectRoot = dirname(fileURLToPath(import.meta.url));

// #285: this file used to be `export default baseConfig` — a verbatim re-export
// of the workspace-root config, which declares neither `root` nor `include`.
// Vitest then resolved `root` from the *current working directory*, so
// `vitest --config apps/auth-server/vitest.config.ts` from the workspace root
// collected every spec in the monorepo (116 files) instead of this project's
// 48. Pinning `root` to this file's directory makes discovery independent of
// where the process was launched, which is what lets the Nx target, a bare
// `npx vitest --config …` and an IDE runner all agree on the same file set.
export default mergeConfig(
  baseConfig,
  defineConfig({
    root: projectRoot,
    test: {
      // Scope collection to the app sources. The base config's `exclude`
      // (node_modules, dist, `*.integration.test.ts`) still applies on top.
      include: ['src/**/*.{test,spec}.?(c|m)[jt]s?(x)'],
    },
  })
);
