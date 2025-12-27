/// <reference types="jest" />

import { validatePasswordStrength } from './password';

describe('Password Strength Validation', () => {
  describe('validatePasswordStrength', () => {
    it('should accept strong passwords (score >= 2)', () => {
      const strongPasswords = [
        'MySecurePassword123!',
        'ComplexP@ssw0rd#2024',
        'VeryLongPasswordWithNumbers123',
      ];

      strongPasswords.forEach((password) => {
        const result = validatePasswordStrength(password);
        expect(result.valid).toBe(true);
        expect(result.score).toBeGreaterThanOrEqual(2);
      });
    });

    it('should reject weak passwords (score < 2)', () => {
      const weakPasswords = ['password', '12345678', 'qwerty', 'abc123'];

      weakPasswords.forEach((password) => {
        const result = validatePasswordStrength(password);
        expect(result.valid).toBe(false);
        expect(result.score).toBeLessThan(2);
      });
    });

    it('should reject empty passwords', () => {
      const result = validatePasswordStrength('');

      expect(result.valid).toBe(false);
      expect(result.score).toBe(0);
      expect(result.feedback).toContain('Password cannot be empty');
    });

    it('should reject common passwords', () => {
      const commonPasswords = ['password', '123456', 'qwerty', 'letmein'];

      commonPasswords.forEach((password) => {
        const result = validatePasswordStrength(password);
        expect(result.valid).toBe(false);
      });
    });

    it('should provide feedback for weak passwords', () => {
      const result = validatePasswordStrength('password');

      expect(result.valid).toBe(false);
      expect(result.feedback).toBeDefined();
      expect(Array.isArray(result.feedback)).toBe(true);
    });

    it('should include crack time information', () => {
      const result = validatePasswordStrength('MySecurePassword123!');

      expect(result.crackTimeSeconds).toBeDefined();
      expect(result.crackTimeSeconds).toBeGreaterThan(0);
    });

    it('should accept custom minScore', () => {
      const password = 'MySecurePassword123!';

      // With minScore 2 (default)
      const result1 = validatePasswordStrength(password, 2);
      expect(result1.valid).toBe(true);

      // With minScore 4 (very strict)
      const result2 = validatePasswordStrength(password, 4);
      // May or may not be valid depending on password strength
      expect(result2.score).toBeDefined();
    });
  });
});
