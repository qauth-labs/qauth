import { configDefaults, defineConfig } from 'vitest/config';

/**
 * Integration test config (#167).
 *
 * Runs ONLY the Docker-backed `*.integration.test.ts` suites (testcontainers
 * Postgres) that the fast unit config (vitest.config.mts) deliberately
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
    // Vitest 5 clears every mock before each test by default. Kept off so a
    // call recorded in beforeAll or at module scope still counts, as in v4.
    clearMocks: false,
    include: ['**/*.integration.test.ts'],
    // Not the gitignored scratch directory, where the upgrade test (#475)
    // unpacks the baseline release's tree, its integration suites included
    // (see vitest.config.mts).
    exclude: [...configDefaults.exclude, 'tmp/**'],
    // Container-backed suites share a single Postgres per file; run files
    // serially to avoid N containers at once on constrained machines.
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 180_000,
  },
});
