import { afterEach, describe, expect, it, vi } from 'vitest';

import type { CacheClient, Logger } from '../types';
import { createRedisConnection } from './redis';

function createSpyLogger(): Logger {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  };
}

describe('createRedisConnection logger injection (F-13)', () => {
  let client: CacheClient | undefined;

  afterEach(() => {
    // lazyConnect keeps the socket closed, but disconnect() is safe regardless
    // and prevents background reconnect timers from leaking between tests.
    client?.disconnect();
    client = undefined;
  });

  it('routes connection-event diagnostics through the injected logger', () => {
    const logger = createSpyLogger();
    // lazyConnect (default) means no socket is opened by construction.
    client = createRedisConnection({ host: '127.0.0.1', port: 6379, logger });

    client.emit('connect');
    client.emit('ready');
    client.emit('reconnecting');
    client.emit('close');
    client.emit('end');
    client.emit('error', new Error('boom'));

    expect(logger.info).toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalledWith('Redis: Connection error:', expect.any(Error));
  });
});
