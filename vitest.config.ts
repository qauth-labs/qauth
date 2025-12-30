import { resolve } from 'path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/coverage/**',
      '**/.{idea,git,cache,output,temp}/**',
      '**/{karma,rollup,webpack,vite,vitest,jest,ava,babel,nyc,cypress,tsup,build,eslint,prettier}.config.*',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      exclude: [
        '**/node_modules/**',
        '**/dist/**',
        '**/coverage/**',
        '**/*.config.{js,ts}',
        '**/*.d.ts',
        '**/*.e2e.test.{js,ts}',
        '**/__tests__/**',
        '**/test/**',
      ],
    },
  },
  resolve: {
    conditions: ['source', 'default'],
    alias: {
      '@qauth/cache': resolve(__dirname, 'libs/infra/cache/src/index.ts'),
      '@qauth/db': resolve(__dirname, 'libs/infra/db/src/index.ts'),
      '@qauth/fastify-plugin-db': resolve(__dirname, 'libs/fastify/plugins/db/src/index.ts'),
      '@qauth/fastify-plugin-cache': resolve(__dirname, 'libs/fastify/plugins/cache/src/index.ts'),
      '@qauth/fastify-plugin-password': resolve(
        __dirname,
        'libs/fastify/plugins/password/src/index.ts'
      ),
      '@qauth/errors': resolve(__dirname, 'libs/shared/errors/src/index.ts'),
      '@qauth/validation': resolve(__dirname, 'libs/shared/validation/src/index.ts'),
      '@qauth/password': resolve(__dirname, 'libs/server/password/src/index.ts'),
      '@qauth/config': resolve(__dirname, 'libs/server/config/src/index.ts'),
      '@qauth/testing': resolve(__dirname, 'libs/shared/testing/src/index.ts'),
    },
  },
});
