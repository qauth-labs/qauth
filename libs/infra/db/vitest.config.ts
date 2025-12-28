// import { resolve } from 'path';
import { defineConfig, mergeConfig } from 'vitest/config';

import baseConfig from '../../../vitest.config';

export default mergeConfig(
  baseConfig,
  defineConfig({
    test: {
      // globalSetup: resolve(__dirname, 'vitest.setup.ts'),
      hookTimeout: 60000, // 60 seconds for Docker containers and migrations
    },
  })
);
