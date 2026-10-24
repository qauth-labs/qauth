import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig, mergeConfig } from 'vitest/config';

import baseConfig from '../../vitest.config';

const projectRoot = dirname(fileURLToPath(import.meta.url));

// The test's OWN unit tests: its configuration guard, its state file and its
// HTML helpers. They run with the rest of the fast suite and need no server.
// The upgrade steps (`*.upgrade.test.ts`) are excluded by the root config and
// run only through `vitest.upgrade.config.ts`, i.e. the `populate`, `verify`
// and `smoke` targets.
export default mergeConfig(
  baseConfig,
  defineConfig({
    root: projectRoot,
    test: {
      include: ['src/**/*.test.ts'],
    },
  })
);
