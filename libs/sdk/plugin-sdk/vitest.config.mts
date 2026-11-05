import { fileURLToPath } from 'node:url';

import { defineConfig, mergeConfig } from 'vitest/config';

import baseConfig from '../../../vitest.config.mts';

/**
 * The example plugin (`examples/minimal-plugin`) imports this package by its
 * npm name, as a plugin in its own repository does; inside the workspace each
 * entry point resolves to its source. Its own test runs under Node's test
 * runner, not this one: `src/example-plugin.test.ts` runs the same check here.
 */
const source = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default mergeConfig(
  baseConfig,
  defineConfig({
    test: {
      exclude: ['examples/**'],
    },
    resolve: {
      alias: [
        { find: /^@qauth-labs\/plugin-sdk$/, replacement: source('./src/index.ts') },
        { find: /^@qauth-labs\/plugin-sdk\/host$/, replacement: source('./src/host.ts') },
        {
          find: /^@qauth-labs\/plugin-sdk\/testing$/,
          replacement: source('./src/testing/index.ts'),
        },
      ],
    },
  })
);
