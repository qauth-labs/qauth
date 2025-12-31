import { resolve } from 'path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/coverage/**',
      '**/.{idea,git,cache,output,temp,nx}/**',
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
      '@qauth/infra-cache': resolve(__dirname, 'libs/infra/cache/src/index.ts'),
      '@qauth/infra-db': resolve(__dirname, 'libs/infra/db/src/index.ts'),
      '@qauth/fastify-plugin-db': resolve(__dirname, 'libs/fastify/plugins/db/src/index.ts'),
      '@qauth/fastify-plugin-cache': resolve(__dirname, 'libs/fastify/plugins/cache/src/index.ts'),
      '@qauth/fastify-plugin-password': resolve(
        __dirname,
        'libs/fastify/plugins/password/src/index.ts'
      ),
      '@qauth/fastify-plugin-email': resolve(__dirname, 'libs/fastify/plugins/email/src/index.ts'),
      '@qauth/shared-errors': resolve(__dirname, 'libs/shared/errors/src/index.ts'),
      '@qauth/shared-validation': resolve(__dirname, 'libs/shared/validation/src/index.ts'),
      '@qauth/shared-testing': resolve(__dirname, 'libs/shared/testing/src/index.ts'),
      '@qauth/server-password': resolve(__dirname, 'libs/server/password/src/index.ts'),
      '@qauth/server-email': resolve(__dirname, 'libs/server/email/src/index.ts'),
      '@qauth/server-config': resolve(__dirname, 'libs/server/config/src/index.ts'),
    },
  },
});
