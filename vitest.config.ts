import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    watch: false,
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/coverage/**',
      '**/.{idea,git,cache,output,temp,nx}/**',
      '**/{karma,rollup,webpack,vite,vitest,jest,ava,babel,nyc,cypress,tsup,build,eslint,prettier}.config.*',
      // Git worktrees are created under `.claude/worktrees/<id>/`, i.e. INSIDE
      // the repo, so each one is a second full copy of the tree. Without this
      // the root project globs every worktree's tests in alongside its own and
      // registers duplicate Fastify routes ("Method 'POST' already declared for
      // route '/register'"), failing a run that has nothing wrong with it.
      '**/.claude/**',
      // Docker-backed repository integration suite (#167). Kept out of the
      // fast unit run so CI needs no Postgres/Redis; run it via the dedicated
      // `test-integration` target instead.
      '**/*.integration.test.ts',
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
        '**/*.integration.test.ts',
        '**/__tests__/**',
        '**/test/**',
      ],
      // Modest global gate: comfortably below today's numbers (statements
      // ~80%, branches ~66%) so it passes now and fails CI on a real
      // regression. Ratchet up as the testcontainers suite (#167) lands.
      thresholds: {
        statements: 70,
        branches: 55,
        functions: 65,
        lines: 70,
      },
    },
  },
});
