import { afterEach, describe, expect, it, vi } from 'vitest';

import type { DatabaseInstance, Logger } from '../types';
import { createDatabase } from './db';

function createSpyLogger(): Logger {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  };
}

describe('createDatabase logger injection (F-13)', () => {
  let database: DatabaseInstance | undefined;

  afterEach(async () => {
    await database?.close().catch(() => undefined);
    database = undefined;
  });

  it('routes connection-failure diagnostics through the injected logger', async () => {
    const logger = createSpyLogger();
    // Point at a closed port with a tiny connect timeout so testConnection
    // fails fast without needing a real database.
    database = createDatabase({
      connectionString: 'postgresql://user:pass@127.0.0.1:1/db',
      pool: { connectionTimeoutMillis: 200, min: 0 },
      logger,
    });

    await expect(database.testConnection()).resolves.toBe(false);
    expect(logger.error).toHaveBeenCalledWith(
      'Database connection test failed:',
      expect.anything()
    );
  });
});
