import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    watch: false,
    // Vitest 5 clears every mock before each test by default. Kept off so a
    // call recorded in beforeAll or at module scope still counts, as in v4.
    clearMocks: false,
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
      // The gitignored scratch directory. The upgrade test (#475) unpacks the
      // baseline release's whole tree into `tmp/upgrade-test/baseline-src/`,
      // tests included, which this run would otherwise glob in after a local
      // `scripts/upgrade-test/upgrade-test.sh` run, against packages the
      // workspace no longer has.
      'tmp/**',
      // Docker-backed repository integration suite (#167). Kept out of the
      // fast unit run so CI needs no Postgres/Redis; run it via the dedicated
      // `test-integration` target instead.
      '**/*.integration.test.ts',
      // The black-box wire suite (#450) talks to a RUNNING server over HTTP,
      // so it cannot run here. `apps/wire-suite/vitest.wire.config.mts` runs it,
      // through the `wire-suite:run` target and the `wire-suite` CI job.
      '**/*.wire.test.ts',
      // The upgrade test (#475) talks to a RUNNING baseline release and then to
      // the new build. `apps/upgrade-test/vitest.upgrade.config.mts` runs it,
      // through the `upgrade-test:populate`, `:verify` and `:smoke` targets and
      // the `upgrade-test` CI job.
      '**/*.upgrade.test.ts',
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
