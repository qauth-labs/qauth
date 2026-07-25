/**
 * Unit tests for the Docker gate that gates every container-backed suite.
 *
 * This gate is load-bearing for CI honesty: the `*.integration.test.ts` suites
 * are the ONLY place the real generated DDL is ever executed (every unit suite
 * mocks the repositories), so if the gate skipped on a daemon-less CI runner
 * the integration lane would report green while asserting nothing — the exact
 * shape of failure that let qauth-labs/qauth#316 reach production.
 *
 * The daemon probe is mocked so both branches are provable without Docker;
 * these cases run in the fast unit lane.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// `vi.hoisted` because the `vi.mock` factory below is hoisted above ordinary
// top-level consts and would otherwise read the binding before initialization.
const { getContainerRuntimeClient } = vi.hoisted(() => ({
  getContainerRuntimeClient: vi.fn(),
}));

// `pg-testcontainer` imports `testcontainers` statically (GenericContainer,
// Wait) and dynamically (getContainerRuntimeClient); the mock must cover both
// or the module under test fails to load.
vi.mock('testcontainers', () => ({
  getContainerRuntimeClient,
  GenericContainer: class {},
  Wait: { forLogMessage: vi.fn() },
}));

import { isDockerAvailable, requireDockerOrSkip } from './pg-testcontainer';

const NO_DAEMON = new Error('connect ENOENT /var/run/docker.sock');

describe('isDockerAvailable', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('is true when the container runtime answers', async () => {
    getContainerRuntimeClient.mockResolvedValue({});
    await expect(isDockerAvailable()).resolves.toBe(true);
  });

  it('is false — never throws — when no daemon is reachable', async () => {
    getContainerRuntimeClient.mockRejectedValue(NO_DAEMON);
    await expect(isDockerAvailable()).resolves.toBe(false);
  });
});

describe('requireDockerOrSkip', () => {
  const originalCi = process.env['CI'];

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env['CI'];
  });

  afterEach(() => {
    if (originalCi === undefined) delete process.env['CI'];
    else process.env['CI'] = originalCi;
  });

  it('returns true when Docker is reachable, on CI or not', async () => {
    getContainerRuntimeClient.mockResolvedValue({});
    await expect(requireDockerOrSkip()).resolves.toBe(true);
    process.env['CI'] = 'true';
    await expect(requireDockerOrSkip()).resolves.toBe(true);
  });

  it('returns false (suite skips) when Docker is absent off CI', async () => {
    // A contributor without Docker must still get a green local run.
    getContainerRuntimeClient.mockRejectedValue(NO_DAEMON);
    await expect(requireDockerOrSkip()).resolves.toBe(false);
  });

  it('THROWS when Docker is absent on CI, so the lane cannot pass vacuously', async () => {
    getContainerRuntimeClient.mockRejectedValue(NO_DAEMON);
    process.env['CI'] = 'true';
    await expect(requireDockerOrSkip()).rejects.toThrow(/must never skip on CI/i);
  });

  it.each(['false', '0', ''])(
    'treats CI=%o as not-CI so a CI-ish local shell still skips',
    async (ci) => {
      getContainerRuntimeClient.mockRejectedValue(NO_DAEMON);
      process.env['CI'] = ci;
      await expect(requireDockerOrSkip()).resolves.toBe(false);
    }
  );

  it('treats any other CI value (e.g. "1") as CI', async () => {
    getContainerRuntimeClient.mockRejectedValue(NO_DAEMON);
    process.env['CI'] = '1';
    await expect(requireDockerOrSkip()).rejects.toThrow();
  });
});
