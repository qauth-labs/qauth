/**
 * Unit tests for the integration global setup: what it starts, what it hands
 * the suites, and that it starts nothing, and fails nothing, without Docker.
 *
 * The servers are mocked, so these cases run in the fast unit lane.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { isDockerAvailable, startSharedPostgres, startSharedRedis } = vi.hoisted(() => ({
  isDockerAvailable: vi.fn(),
  startSharedPostgres: vi.fn(),
  startSharedRedis: vi.fn(),
}));

vi.mock('./lib/pg-testcontainer', () => ({ isDockerAvailable, startSharedPostgres }));
vi.mock('./lib/redis-testcontainer', () => ({ startSharedRedis }));

import setup from './integration-global-setup';

const POSTGRES_ENV = { QAUTH_TEST_SHARED_POSTGRES_URLS: 'postgresql://a,postgresql://b' };
const REDIS_ENV = { QAUTH_TEST_SHARED_REDIS_URL: 'redis://c' };
const project = (maxWorkers: number) => ({ config: { maxWorkers } });

function server(env: Record<string, string>) {
  return { env, stop: vi.fn(async () => undefined) };
}

describe('the integration global setup', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    for (const key of [...Object.keys(POSTGRES_ENV), ...Object.keys(REDIS_ENV)]) {
      delete process.env[key];
    }
  });

  it('starts nothing and fails nothing without Docker, so the suites skip as before', async () => {
    isDockerAvailable.mockResolvedValue(false);

    await expect(setup(project(3))).resolves.toBeUndefined();

    expect(startSharedPostgres).not.toHaveBeenCalled();
    expect(startSharedRedis).not.toHaveBeenCalled();
    expect(process.env['QAUTH_TEST_SHARED_POSTGRES_URLS']).toBeUndefined();
  });

  it('starts a Postgres server per worker slot and one Redis, and points the workers at them', async () => {
    isDockerAvailable.mockResolvedValue(true);
    const postgres = server(POSTGRES_ENV);
    const redis = server(REDIS_ENV);
    startSharedPostgres.mockResolvedValue(postgres);
    startSharedRedis.mockResolvedValue(redis);

    const teardown = await setup(project(3));

    expect(startSharedPostgres).toHaveBeenCalledWith(3);
    expect(process.env['QAUTH_TEST_SHARED_POSTGRES_URLS']).toBe(
      POSTGRES_ENV.QAUTH_TEST_SHARED_POSTGRES_URLS
    );
    expect(process.env['QAUTH_TEST_SHARED_REDIS_URL']).toBe(REDIS_ENV.QAUTH_TEST_SHARED_REDIS_URL);

    await teardown?.();
    expect(postgres.stop).toHaveBeenCalledOnce();
    expect(redis.stop).toHaveBeenCalledOnce();
    expect(process.env['QAUTH_TEST_SHARED_POSTGRES_URLS']).toBeUndefined();
    expect(process.env['QAUTH_TEST_SHARED_REDIS_URL']).toBeUndefined();
  });

  it('stops the server that started when the other one fails, and fails the run', async () => {
    isDockerAvailable.mockResolvedValue(true);
    const redis = server(REDIS_ENV);
    startSharedPostgres.mockRejectedValue(new Error('no image'));
    startSharedRedis.mockResolvedValue(redis);

    await expect(setup(project(2))).rejects.toThrow('no image');

    expect(redis.stop).toHaveBeenCalledOnce();
    expect(process.env['QAUTH_TEST_SHARED_REDIS_URL']).toBeUndefined();
  });
});
