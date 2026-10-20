import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig, mergeConfig } from 'vitest/config';

import baseConfig from '../../vitest.config';

const projectRoot = dirname(fileURLToPath(import.meta.url));

// The suite's OWN unit tests: its configuration guard and its helpers. They run
// with the rest of the fast suite and need no server. The wire tests
// (`*.wire.test.ts`) are excluded by the root config and run only through
// `vitest.wire.config.ts`, i.e. the `wire-suite:run` target.
export default mergeConfig(
  baseConfig,
  defineConfig({
    root: projectRoot,
    test: {
      include: ['src/**/*.test.ts'],
    },
  })
);
