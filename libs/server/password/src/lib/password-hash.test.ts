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

describe('DEFAULT_PASSWORD_CONFIG', () => {
  it('should have valid default values', () => {
    expect(DEFAULT_PASSWORD_CONFIG.memoryCost).toBeGreaterThan(0);
    expect(DEFAULT_PASSWORD_CONFIG.timeCost).toBeGreaterThan(0);
    expect(DEFAULT_PASSWORD_CONFIG.parallelism).toBeGreaterThan(0);
  });
});
