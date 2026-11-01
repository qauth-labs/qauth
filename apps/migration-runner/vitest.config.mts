import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig, mergeConfig } from 'vitest/config';

import baseConfig from '../../vitest.config.mts';

const projectRoot = dirname(fileURLToPath(import.meta.url));

// Root pinned to this directory, as in apps/auth-server (#285), so the Nx
// target and a bare `vitest --config` collect the same files.
export default mergeConfig(
  baseConfig,
  defineConfig({
    root: projectRoot,
    test: {
      include: ['src/**/*.{test,spec}.?(c|m)[jt]s?(x)'],
    },
  })
);
