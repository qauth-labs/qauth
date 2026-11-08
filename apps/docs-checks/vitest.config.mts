import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig, mergeConfig } from 'vitest/config';

import baseConfig from '../../vitest.config.mts';

const projectRoot = dirname(fileURLToPath(import.meta.url));

// The checks that compare the docs with the code of the libraries (#1044).
// They read the docs collection, the decision records and the repository's
// files, so they live in this project, which nothing depends on, instead of
// in the libraries, whose dependents a docs edit would otherwise mark affected.
export default mergeConfig(
  baseConfig,
  defineConfig({
    root: projectRoot,
    test: {
      include: ['src/**/*.test.ts'],
    },
  })
);
