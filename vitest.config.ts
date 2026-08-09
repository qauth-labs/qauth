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
    server: {
      deps: {
        // #365: `apps/auth-server/src/app/error-handler-wiring.test.ts` boots
        // the REAL `app` plugin — the only way to assert that the global error
        // handler is actually REACHABLE from a route, which is the property
        // that regressed. `@fastify/autoload` discovers route modules at
        // RUNTIME and imports them by absolute path; left externalized, those
        // `import()` calls go to Node's own loader, which cannot resolve the
        // extensionless relative imports TypeScript sources use, so the boot
        // dies on the first route file. Inlining puts autoload inside Vite's
        // module graph, so its dynamic imports resolve through the same
        // transform pipeline as everything else.
        //
        // Declared HERE rather than in `apps/auth-server/vitest.config.ts`
        // because that file `mergeConfig`s this one (so it inherits the
        // setting) while the workspace-root `qauth:test` target runs a bare
        // `vitest run` against THIS config and globs every project's specs,
        // auth-server's included — a project-local declaration would leave that
        // run failing. Same reason, same setting, as
        // `vitest.integration.config.ts`.
        inline: ['@fastify/autoload'],
      },
    },
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
