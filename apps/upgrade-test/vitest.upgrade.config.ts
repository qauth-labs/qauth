import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

const projectRoot = dirname(fileURLToPath(import.meta.url));

/**
 * The upgrade test (#475, ADR-018 §5): runs against a RUNNING QAuth, one
 * project per step of the CI job, chosen with `--project`:
 *
 * - `populate` writes data through the baseline release and saves the state file;
 * - `verify` checks that data on the new build after the upgrade;
 * - `smoke` runs a fresh scenario on whichever server is up: the new build
 *   after the upgrade, and the baseline on the migrated database (the
 *   rolling-upgrade leg).
 *
 * Standalone rather than merged with the root `vitest.config.ts`, like the wire
 * suite's: that config excludes `*.upgrade.test.ts` from the fast suite and
 * carries coverage thresholds for code this test never loads.
 *
 * The global setup refuses to start unless `QAUTH_UPGRADE_ALLOW_WRITES=1`,
 * before any test file is collected (see `src/global-setup.ts`).
 */
export default defineConfig({
  root: projectRoot,
  test: {
    environment: 'node',
    watch: false,
    clearMocks: false,
    globalSetup: ['./src/global-setup.ts'],
    // Every request crosses a real network, and registration, sign-in, client
    // creation and API-key minting each hash with Argon2id.
    testTimeout: 60_000,
    hookTimeout: 60_000,
    projects: [
      {
        extends: true,
        test: { name: 'populate', include: ['src/suites/populate.upgrade.test.ts'] },
      },
      { extends: true, test: { name: 'verify', include: ['src/suites/verify.upgrade.test.ts'] } },
      { extends: true, test: { name: 'smoke', include: ['src/suites/smoke.upgrade.test.ts'] } },
    ],
  },
});
