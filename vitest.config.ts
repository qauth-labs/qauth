import path from 'node:path';
import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

const root = path.join(__dirname);

export default defineConfig({
  plugins: [tsconfigPaths()],
  resolve: {
    alias: {
      '@qauth/shared-errors': path.join(root, 'libs/shared/errors/src/index.ts'),
      '@qauth/shared-testing': path.join(root, 'libs/shared/testing/src/index.ts'),
      '@qauth/shared-validation': path.join(root, 'libs/shared/validation/src/index.ts'),
      '@qauth/server-jwt': path.join(root, 'libs/server/jwt/src/index.ts'),
      '@qauth/server-password': path.join(root, 'libs/server/password/src/index.ts'),
      '@qauth/server-email': path.join(root, 'libs/server/email/src/index.ts'),
      '@qauth/server-config': path.join(root, 'libs/server/config/src/index.ts'),
      '@qauth/server-pkce': path.join(root, 'libs/server/pkce/src/index.ts'),
      '@qauth/infra-db': path.join(root, 'libs/infra/db/src/index.ts'),
      '@qauth/infra-cache': path.join(root, 'libs/infra/cache/src/index.ts'),
      '@qauth/fastify-plugin-jwt': path.join(root, 'libs/fastify/plugins/jwt/src/index.ts'),
      '@qauth/fastify-plugin-db': path.join(root, 'libs/fastify/plugins/db/src/index.ts'),
      '@qauth/fastify-plugin-cache': path.join(root, 'libs/fastify/plugins/cache/src/index.ts'),
      '@qauth/fastify-plugin-password': path.join(
        root,
        'libs/fastify/plugins/password/src/index.ts'
      ),
      '@qauth/fastify-plugin-email': path.join(root, 'libs/fastify/plugins/email/src/index.ts'),
      '@qauth/fastify-plugin-pkce': path.join(root, 'libs/fastify/plugins/pkce/src/index.ts'),
    },
    conditions: ['source', 'default'],
  },
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
});
