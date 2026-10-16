import { beforeEach, describe, expect, it } from 'vitest';

import {
  createPasswordHasher,
  DEFAULT_PASSWORD_CONFIG,
  type PasswordHasher,
} from './password-hash';

describe('createPasswordHasher', () => {
  it('should create a hasher with default config', () => {
    const hasher = createPasswordHasher();
    expect(hasher).toHaveProperty('hashPassword');
    expect(hasher).toHaveProperty('verifyPassword');
  });

  it('should create a hasher with custom config', () => {
    const hasher = createPasswordHasher({
      memoryCost: 32768,
      timeCost: 2,
      parallelism: 2,
    });
    expect(hasher).toHaveProperty('hashPassword');
    expect(hasher).toHaveProperty('verifyPassword');
  });

  it('should merge partial config with defaults', () => {
    const hasher = createPasswordHasher({
      memoryCost: 16384,
    });
    expect(hasher).toBeDefined();
  });
});

describe('PasswordHasher', () => {
  let hasher: PasswordHasher;

  beforeEach(() => {
    hasher = createPasswordHasher({
      // Use lower values for faster tests
      memoryCost: 8192,
      timeCost: 2,
      parallelism: 2,
    });
  });

  describe('hashPassword', () => {
    it('should hash a password', async () => {
      const password = 'TestPassword123!';
      const hash = await hasher.hashPassword(password);
      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(hash.length).toBeGreaterThan(0);
    });

    it('should produce different hashes for the same password', async () => {
      const password = 'TestPassword123!';
      const hash1 = await hasher.hashPassword(password);
      const hash2 = await hasher.hashPassword(password);
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyPassword', () => {
    it('should verify a correct password', async () => {
      const password = 'TestPassword123!';
      const hash = await hasher.hashPassword(password);
      const isValid = await hasher.verifyPassword(hash, password);
      expect(isValid).toBe(true);
    });

    it('should reject an incorrect password', async () => {
      const password = 'TestPassword123!';
      const wrongPassword = 'WrongPassword123!';
      const hash = await hasher.hashPassword(password);
      const isValid = await hasher.verifyPassword(hash, wrongPassword);
      expect(isValid).toBe(false);
    });

    it('should reject invalid hash format', async () => {
      const invalidHash = 'invalid-hash-format';
      const isValid = await hasher.verifyPassword(invalidHash, 'password');
      expect(isValid).toBe(false);
    });
  });
});

describe('libuv thread pool', () => {
  it('should leave pool threads free for WebCrypto while verifications are queued', async () => {
    // 5AJ2ARWP. Each job holds a pool thread for milliseconds, far longer than
    // a digest, and eight of them outnumber the default 4-thread pool. The
    // pool is FIFO, so the digest below only resolves first when Argon2 may
    // not occupy every thread. JWT signing and verification (jose, via
    // crypto.subtle) and pg's SCRAM handshake run on that same pool.
    const hasher = createPasswordHasher({ memoryCost: 32768, timeCost: 2, parallelism: 1 });
    const hash = await hasher.hashPassword('TestPassword123!');
    // Warm WebCrypto up, so its one-time setup is not what the race measures.
    await crypto.subtle.digest('SHA-256', new Uint8Array(32));
    const finished: string[] = [];

    const verifications = Array.from({ length: 8 }, () =>
      hasher.verifyPassword(hash, 'WrongPassword123!').then((valid) => {
        finished.push('argon2');
        return valid;
      })
    );
    await crypto.subtle.digest('SHA-256', new Uint8Array(32));
    finished.push('digest');

    expect(finished[0]).toBe('digest');
    // Every queued job still runs to completion with the right answer.
    expect(await Promise.all(verifications)).toEqual(Array(8).fill(false));
  }, 30_000);

  it('should release a slot when a queued job fails', async () => {
    const hasher = createPasswordHasher({ memoryCost: 8192, timeCost: 2, parallelism: 2 });
    const hash = await hasher.hashPassword('TestPassword123!');

    // Invalid hashes reject inside argon2; more of them than there are slots
    // must not wedge the queue for the valid verification that follows.
    await Promise.all(
      Array.from({ length: 8 }, () => hasher.verifyPassword('invalid-hash-format', 'password'))
    );
    expect(await hasher.verifyPassword(hash, 'TestPassword123!')).toBe(true);
  }, 30_000);
});

describe('DEFAULT_PASSWORD_CONFIG', () => {
  it('should have valid default values', () => {
    expect(DEFAULT_PASSWORD_CONFIG.memoryCost).toBeGreaterThan(0);
    expect(DEFAULT_PASSWORD_CONFIG.timeCost).toBeGreaterThan(0);
    expect(DEFAULT_PASSWORD_CONFIG.parallelism).toBeGreaterThan(0);
  });
});
