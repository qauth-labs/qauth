import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

const projectRoot = dirname(fileURLToPath(import.meta.url));

/**
 * The wire suite (ADR-018 §5): black-box tests against a RUNNING QAuth.
 *
 * Deliberately standalone rather than merged with the root `vitest.config.ts`:
 * that config excludes `*.wire.test.ts` from the fast suite, carries coverage
 * thresholds for code this suite never loads, and inlines server-side modules
 * this suite must never import.
 *
 * The global setup refuses to start unless `QAUTH_WIRE_ALLOW_WRITES=1`, before
 * any test file is collected (see `src/global-setup.ts`).
 *
 * Two projects, run one after the other. `suites/rate-limit/**` spends a
 * per-address rate-limit budget on purpose, so it runs in a later group
 * (`sequence.groupOrder`) and cannot starve a test that needs that budget.
 */
export default defineConfig({
  root: projectRoot,
  test: {
    environment: 'node',
    watch: false,
    // Vitest 5 clears every mock before each test by default. Kept off so a
    // call recorded in beforeAll or at module scope still counts, as in v4.
    clearMocks: false,
    globalSetup: ['./src/global-setup.ts'],
    // Every request crosses a real network and the registration path hashes
    // a password with Argon2id.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    projects: [
      {
        extends: true,
        test: {
          name: 'wire',
          include: ['src/suites/**/*.wire.test.ts'],
          exclude: ['src/suites/rate-limit/**'],
        },
      },
      {
        extends: true,
        test: {
          name: 'wire-budget',
          include: ['src/suites/rate-limit/**/*.wire.test.ts'],
          sequence: { groupOrder: 1 },
        },
      },
    ],
  },
});
