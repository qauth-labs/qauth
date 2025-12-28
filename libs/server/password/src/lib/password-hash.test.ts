/// <reference types="jest" />

import { ZodError } from 'zod';

import {
  createPasswordHasher,
  DEFAULT_PASSWORD_CONFIG,
  type PasswordHasher,
} from './password-hash';

describe('Password Hashing', () => {
  let hasher: PasswordHasher;

  beforeEach(() => {
    hasher = createPasswordHasher(DEFAULT_PASSWORD_CONFIG);
  });

  describe('createPasswordHasher', () => {
    it('should create a hasher with no config (uses defaults)', () => {
      const defaultHasher = createPasswordHasher();

      expect(defaultHasher).toBeDefined();
      expect(defaultHasher.hashPassword).toBeDefined();
      expect(defaultHasher.verifyPassword).toBeDefined();
    });

    it('should create a hasher with custom config', () => {
      const customHasher = createPasswordHasher({
        memoryCost: 32768,
        timeCost: 2,
        parallelism: 2,
      });

      expect(customHasher).toBeDefined();
      expect(customHasher.hashPassword).toBeDefined();
      expect(customHasher.verifyPassword).toBeDefined();
    });

    it('should create a hasher with partial config (merges with defaults)', () => {
      const partialHasher = createPasswordHasher({
        memoryCost: 32768,
        // timeCost and parallelism will use defaults
      });

      expect(partialHasher).toBeDefined();
      expect(partialHasher.hashPassword).toBeDefined();
      expect(partialHasher.verifyPassword).toBeDefined();
    });

    it('should create a hasher with default config', () => {
      expect(hasher).toBeDefined();
      expect(hasher.hashPassword).toBeDefined();
      expect(hasher.verifyPassword).toBeDefined();
    });

    describe('config validation', () => {
      it('should reject negative memoryCost', () => {
        expect(() => {
          createPasswordHasher({
            memoryCost: -1,
            timeCost: 3,
            parallelism: 4,
          });
        }).toThrow(ZodError);
      });

      it('should reject zero memoryCost', () => {
        expect(() => {
          createPasswordHasher({
            memoryCost: 0,
            timeCost: 3,
            parallelism: 4,
          });
        }).toThrow(ZodError);
      });

      it('should reject negative timeCost', () => {
        expect(() => {
          createPasswordHasher({
            memoryCost: 65536,
            timeCost: -1,
            parallelism: 4,
          });
        }).toThrow(ZodError);
      });

      it('should reject zero timeCost', () => {
        expect(() => {
          createPasswordHasher({
            memoryCost: 65536,
            timeCost: 0,
            parallelism: 4,
          });
        }).toThrow(ZodError);
      });

      it('should reject timeCost greater than 10', () => {
        expect(() => {
          createPasswordHasher({
            memoryCost: 65536,
            timeCost: 11,
            parallelism: 4,
          });
        }).toThrow(ZodError);
      });

      it('should reject negative parallelism', () => {
        expect(() => {
          createPasswordHasher({
            memoryCost: 65536,
            timeCost: 3,
            parallelism: -1,
          });
        }).toThrow(ZodError);
      });

      it('should reject zero parallelism', () => {
        expect(() => {
          createPasswordHasher({
            memoryCost: 65536,
            timeCost: 3,
            parallelism: 0,
          });
        }).toThrow(ZodError);
      });

      it('should reject parallelism greater than 255', () => {
        expect(() => {
          createPasswordHasher({
            memoryCost: 65536,
            timeCost: 3,
            parallelism: 256,
          });
        }).toThrow(ZodError);
      });

      it('should reject non-integer values', () => {
        expect(() => {
          createPasswordHasher({
            memoryCost: 65536.5,
            timeCost: 3,
            parallelism: 4,
          });
        }).toThrow(ZodError);
      });
    });
  });

  describe('hashPassword', () => {
    it('should hash a password successfully', async () => {
      const password = 'mySecurePassword123';
      const hashed = await hasher.hashPassword(password);

      expect(hashed).toBeDefined();
      expect(hashed).not.toBe(password);
      expect(hashed.length).toBeGreaterThan(0);
      expect(hashed).toContain('$argon2id$');
    });

    it('should produce different hashes for the same password', async () => {
      const password = 'mySecurePassword123';
      const hash1 = await hasher.hashPassword(password);
      const hash2 = await hasher.hashPassword(password);

      // Argon2 includes a salt, so hashes should be different
      expect(hash1).not.toBe(hash2);
    });

    it('should produce valid hashes with custom config', async () => {
      const customHasher = createPasswordHasher({
        memoryCost: 32768,
        timeCost: 2,
        parallelism: 2,
      });

      const password = 'mySecurePassword123';
      const hashed = await customHasher.hashPassword(password);

      expect(hashed).toBeDefined();
      expect(hashed).toContain('$argon2id$');
    });
  });

  describe('verifyPassword', () => {
    it('should verify correct password', async () => {
      const password = 'mySecurePassword123';
      const hashed = await hasher.hashPassword(password);

      const isValid = await hasher.verifyPassword(hashed, password);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'mySecurePassword123';
      const wrongPassword = 'wrongPassword';
      const hashed = await hasher.hashPassword(password);

      const isValid = await hasher.verifyPassword(hashed, wrongPassword);
      expect(isValid).toBe(false);
    });

    it('should reject empty password', async () => {
      const password = 'mySecurePassword123';
      const hashed = await hasher.hashPassword(password);

      const isValid = await hasher.verifyPassword(hashed, '');
      expect(isValid).toBe(false);
    });

    it('should return false for invalid hash format', async () => {
      const invalidHash = 'invalid_hash_format';

      const isValid = await hasher.verifyPassword(invalidHash, 'password');
      expect(isValid).toBe(false);
    });
  });
});
