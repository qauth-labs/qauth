import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig, mergeConfig } from 'vitest/config';

import baseConfig from '../../vitest.config';

const projectRoot = dirname(fileURLToPath(import.meta.url));

// #285: see apps/auth-server/vitest.config.ts. This file was the same verbatim
// re-export of the root config, so `root` fell back to the launching cwd and
// project-scoped runs collected the whole monorepo. Note this config is
// deliberately independent of vite.config.mts — the portal's component tests
// rely on esbuild's built-in JSX transform plus per-file
// `// @vitest-environment jsdom` docblocks, not on the TanStack Start / React
// plugin pipeline used for building the app.
export default mergeConfig(
  baseConfig,
  defineConfig({
    root: projectRoot,
    test: {
      include: ['src/**/*.{test,spec}.?(c|m)[jt]s?(x)'],
    },
  })
);
