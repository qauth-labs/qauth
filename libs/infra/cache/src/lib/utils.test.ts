import { beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import type { CacheClient, Logger } from '../types';
import { createCacheUtils, createSessionUtils, createUserUtils, KEY_PREFIXES } from './utils';

/**
 * Minimal in-memory fake of the bits of the Redis client these utilities use.
 * Only `get`/`setex` are exercised by the validation paths under test.
 */
function createFakeClient(initial: Record<string, string> = {}): {
  client: CacheClient;
  store: Map<string, string>;
} {
  const store = new Map<string, string>(Object.entries(initial));
  const client = {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    setex: vi.fn(async (key: string, _ttl: number, value: string) => {
      store.set(key, value);
      return 'OK' as const;
    }),
  } as unknown as CacheClient;
  return { client, store };
}

function createSpyLogger(): Logger {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  };
}

describe('cache deserialization validation (F-11)', () => {
  let logger: Logger;

  beforeEach(() => {
    logger = createSpyLogger();
  });

  describe('createCacheUtils.getCache', () => {
    it('returns the parsed value without a schema (backward compatible)', async () => {
      const { client } = createFakeClient({
        [`${KEY_PREFIXES.CACHE}k`]: JSON.stringify({ a: 1 }),
      });
      const utils = createCacheUtils(client, logger);

      await expect(utils.getCache('k')).resolves.toEqual({ a: 1 });
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it('returns the validated value when the schema matches', async () => {
      const schema = z.object({ a: z.number() });
      const { client } = createFakeClient({
        [`${KEY_PREFIXES.CACHE}k`]: JSON.stringify({ a: 1 }),
      });
      const utils = createCacheUtils(client, logger);

      await expect(utils.getCache('k', schema)).resolves.toEqual({ a: 1 });
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it('treats a schema-validation failure as a cache miss and warns', async () => {
      const schema = z.object({ a: z.number() });
      const { client } = createFakeClient({
        [`${KEY_PREFIXES.CACHE}k`]: JSON.stringify({ a: 'not-a-number' }),
      });
      const utils = createCacheUtils(client, logger);

      await expect(utils.getCache('k', schema)).resolves.toBeNull();
      expect(logger.warn).toHaveBeenCalledTimes(1);
    });

    it('treats malformed JSON as a cache miss and warns', async () => {
      const { client } = createFakeClient({
        [`${KEY_PREFIXES.CACHE}k`]: '{not valid json',
      });
      const utils = createCacheUtils(client, logger);

      await expect(utils.getCache('k')).resolves.toBeNull();
      expect(logger.warn).toHaveBeenCalledTimes(1);
    });

    it('returns null on a genuine miss without warning', async () => {
      const { client } = createFakeClient();
      const utils = createCacheUtils(client, logger);

      await expect(utils.getCache('missing')).resolves.toBeNull();
      expect(logger.warn).not.toHaveBeenCalled();
    });
  });

  describe('createCacheUtils.getOrSetCache', () => {
    it('recomputes via fallback when the cached value fails validation', async () => {
      const schema = z.object({ a: z.number() });
      const { client, store } = createFakeClient({
        [`${KEY_PREFIXES.CACHE}k`]: JSON.stringify({ a: 'bad' }),
      });
      const utils = createCacheUtils(client, logger);
      const fallback = vi.fn(async () => ({ a: 42 }));

      await expect(utils.getOrSetCache('k', fallback, 60, schema)).resolves.toEqual({ a: 42 });
      expect(fallback).toHaveBeenCalledTimes(1);
      expect(logger.warn).toHaveBeenCalledTimes(1);
      // The recomputed value should have been written back to the cache.
      expect(store.get(`${KEY_PREFIXES.CACHE}k`)).toBe(JSON.stringify({ a: 42 }));
    });
  });

  describe('createSessionUtils.getSession', () => {
    it('treats a schema-validation failure as a miss and warns', async () => {
      const schema = z.object({ userId: z.string() });
      const { client } = createFakeClient({
        [`${KEY_PREFIXES.SESSION}s`]: JSON.stringify({ userId: 123 }),
      });
      const utils = createSessionUtils(client, logger);

      await expect(utils.getSession('s', schema)).resolves.toBeNull();
      expect(logger.warn).toHaveBeenCalledTimes(1);
    });
  });

  describe('createUserUtils.getUserData', () => {
    it('returns the validated value when the schema matches', async () => {
      const schema = z.object({ email: z.email() });
      const { client } = createFakeClient({
        [`${KEY_PREFIXES.USER}u`]: JSON.stringify({ email: 'a@b.com' }),
      });
      const utils = createUserUtils(client, logger);

      await expect(utils.getUserData('u', schema)).resolves.toEqual({ email: 'a@b.com' });
      expect(logger.warn).not.toHaveBeenCalled();
    });
  });
});
