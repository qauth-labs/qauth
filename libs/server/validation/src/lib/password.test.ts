/// <reference types="jest" />

import { ZodError } from 'zod';

import {
  createPasswordValidator,
  DEFAULT_PASSWORD_VALIDATION_CONFIG,
  type PasswordValidator,
} from './password';

describe('Password Strength Validation', () => {
  let validator: PasswordValidator;

  beforeEach(() => {
    validator = createPasswordValidator(DEFAULT_PASSWORD_VALIDATION_CONFIG);
  });

  describe('createPasswordValidator', () => {
    it('should create a validator with no config (uses defaults)', () => {
      const defaultValidator = createPasswordValidator();

      expect(defaultValidator).toBeDefined();
      expect(defaultValidator.validatePasswordStrength).toBeDefined();
    });

    it('should create a validator with custom config', () => {
      const customValidator = createPasswordValidator({ minScore: 3 });

      expect(customValidator).toBeDefined();
      expect(customValidator.validatePasswordStrength).toBeDefined();
    });

    it('should create a validator with default config', () => {
      expect(validator).toBeDefined();
      expect(validator.validatePasswordStrength).toBeDefined();
    });

    describe('config validation', () => {
      it('should reject negative minScore', () => {
        expect(() => {
          createPasswordValidator({ minScore: -1 });
        }).toThrow(ZodError);
      });

      it('should reject minScore greater than 4', () => {
        expect(() => {
          createPasswordValidator({ minScore: 5 });
        }).toThrow(ZodError);
      });

      it('should reject non-integer minScore', () => {
        expect(() => {
          createPasswordValidator({ minScore: 2.5 });
        }).toThrow(ZodError);
      });

      it('should accept valid minScore values (0-4)', () => {
        for (let score = 0; score <= 4; score++) {
          expect(() => {
            createPasswordValidator({ minScore: score });
          }).not.toThrow();
        }
      });
    });
  });

  describe('validatePasswordStrength', () => {
    it('should accept strong passwords (score >= 2)', () => {
      const strongPasswords = [
        'MySecurePassword123!',
        'ComplexP@ssw0rd#2024',
        'VeryLongPasswordWithNumbers123',
      ];

      strongPasswords.forEach((password) => {
        const result = validator.validatePasswordStrength(password);
        expect(result.valid).toBe(true);
        expect(result.score).toBeGreaterThanOrEqual(2);
      });
    });

    it('should reject weak passwords (score < 2)', () => {
      const weakPasswords = ['password', '12345678', 'qwerty', 'abc123'];

      weakPasswords.forEach((password) => {
        const result = validator.validatePasswordStrength(password);
        expect(result.valid).toBe(false);
        expect(result.score).toBeLessThan(2);
      });
    });

    it('should reject empty passwords', () => {
      const result = validator.validatePasswordStrength('');

      expect(result.valid).toBe(false);
      expect(result.score).toBe(0);
      expect(result.feedback).toContain('Password cannot be empty');
    });

    it('should reject common passwords', () => {
      const commonPasswords = ['password', '123456', 'qwerty', 'letmein'];

      commonPasswords.forEach((password) => {
        const result = validator.validatePasswordStrength(password);
        expect(result.valid).toBe(false);
      });
    });

    it('should provide feedback for weak passwords', () => {
      const result = validator.validatePasswordStrength('password');

      expect(result.valid).toBe(false);
      expect(result.feedback).toBeDefined();
      expect(Array.isArray(result.feedback)).toBe(true);
    });

    it('should include crack time information', () => {
      const result = validator.validatePasswordStrength('MySecurePassword123!');

      expect(result.crackTimeSeconds).toBeDefined();
      expect(result.crackTimeSeconds).toBeGreaterThan(0);
    });

    it('should use custom minScore from config', () => {
      const strictValidator = createPasswordValidator({ minScore: 4 });
      const lenientValidator = createPasswordValidator({ minScore: 1 });

      const password = 'MySecurePassword123!';

      // Strict validator may reject passwords that lenient validator accepts
      const strictResult = strictValidator.validatePasswordStrength(password);
      const lenientResult = lenientValidator.validatePasswordStrength(password);

      // Both should return the same score
      expect(strictResult.score).toBe(lenientResult.score);

      // Lenient should be valid for most passwords
      expect(lenientResult.valid).toBe(true);
    });
  });
});
