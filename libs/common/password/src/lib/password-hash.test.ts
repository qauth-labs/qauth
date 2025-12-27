/// <reference types="jest" />

import { hashPassword, verifyPassword } from './password-hash';

describe('Password Hashing', () => {
  describe('hashPassword', () => {
    it('should hash a password successfully', async () => {
      const password = 'mySecurePassword123';
      const hashed = await hashPassword(password);

      expect(hashed).toBeDefined();
      expect(hashed).not.toBe(password);
      expect(hashed.length).toBeGreaterThan(0);
      expect(hashed).toContain('$argon2id$');
    });

    it('should produce different hashes for the same password', async () => {
      const password = 'mySecurePassword123';
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);

      // Argon2 includes a salt, so hashes should be different
      expect(hash1).not.toBe(hash2);
    });

    it('should accept custom options', async () => {
      const password = 'mySecurePassword123';
      const hashed = await hashPassword(password, {
        memoryCost: 32768,
        timeCost: 2,
        parallelism: 2,
      });

      expect(hashed).toBeDefined();
      expect(hashed).toContain('$argon2id$');
    });
  });

  describe('verifyPassword', () => {
    it('should verify correct password', async () => {
      const password = 'mySecurePassword123';
      const hashed = await hashPassword(password);

      const isValid = await verifyPassword(hashed, password);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'mySecurePassword123';
      const wrongPassword = 'wrongPassword';
      const hashed = await hashPassword(password);

      const isValid = await verifyPassword(hashed, wrongPassword);
      expect(isValid).toBe(false);
    });

    it('should reject empty password', async () => {
      const password = 'mySecurePassword123';
      const hashed = await hashPassword(password);

      const isValid = await verifyPassword(hashed, '');
      expect(isValid).toBe(false);
    });

    it('should throw error for invalid hash format', async () => {
      const invalidHash = 'invalid_hash_format';

      await expect(verifyPassword(invalidHash, 'password')).rejects.toThrow();
    });
  });
});
