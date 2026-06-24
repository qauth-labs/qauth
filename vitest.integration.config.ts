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
    // Container-backed suites share a single Postgres per file; run files
    // serially to avoid N containers at once on constrained machines.
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 180_000,
  },
});
