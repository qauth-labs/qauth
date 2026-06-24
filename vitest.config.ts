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
