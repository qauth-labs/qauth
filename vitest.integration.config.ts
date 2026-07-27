import { defineConfig } from 'vitest/config';

/**
 * Integration test config (#167).
 *
 * Runs ONLY the Docker-backed `*.integration.test.ts` suites (testcontainers
 * Postgres) that the fast unit config (vitest.config.ts) deliberately
 * excludes. Kept separate so the unit suite + coverage gate stay free of
 * Postgres/Redis, and so the slow container suite is opt-in (`test-integration`
 * target / `pnpm test:integration`).
 *
 * Container startup dominates; a generous testTimeout covers image pull on a
 * cold cache.
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    watch: false,
    include: ['**/*.integration.test.ts'],
    server: {
      deps: {
        // `@fastify/autoload` discovers route modules at RUNTIME and imports
        // them by absolute path. Left externalized, those `import()` calls go
        // to Node's loader, which cannot resolve the extensionless relative
        // imports TypeScript sources use — so booting the real auth-server
        // (issue #240's E2E) fails on the first route file. Inlining puts
        // autoload inside Vite's module graph, so its dynamic imports resolve
        // through the same transform pipeline as everything else, and
        // `vi.resetModules()` actually clears the routes between the several
        // differently-configured deployments that suite boots.
        inline: ['@fastify/autoload'],
      },
    },
    // Container-backed suites share a single Postgres per file; run files
    // serially to avoid N containers at once on constrained machines.
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 180_000,
  },
});
