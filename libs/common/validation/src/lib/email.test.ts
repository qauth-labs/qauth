/// <reference types="jest" />

import { isValidEmail, normalizeEmail, validateEmail } from './email';

describe('Email Validation', () => {
  describe('normalizeEmail', () => {
    it('should normalize email to lowercase', () => {
      expect(normalizeEmail('User@Example.com')).toBe('user@example.com');
      expect(normalizeEmail('TEST@EXAMPLE.COM')).toBe('test@example.com');
    });

    it('should trim whitespace', () => {
      expect(normalizeEmail('  user@example.com  ')).toBe('user@example.com');
      expect(normalizeEmail('\tuser@example.com\n')).toBe('user@example.com');
    });

    it('should handle emails with plus signs', () => {
      expect(normalizeEmail('User+Test@Example.com')).toBe('user+test@example.com');
    });

    it('should handle emails with dots', () => {
      expect(normalizeEmail('User.Name@Example.com')).toBe('user.name@example.com');
    });
  });

  describe('validateEmail', () => {
    it('should validate and normalize valid email', () => {
      const email = 'User@Example.com';
      const normalized = validateEmail(email);

      expect(normalized).toBe('user@example.com');
    });

    it('should throw error for invalid email format', () => {
      expect(() => validateEmail('invalid-email')).toThrow();
      expect(() => validateEmail('@example.com')).toThrow();
      expect(() => validateEmail('user@')).toThrow();
      expect(() => validateEmail('user@example')).toThrow();
    });

    it('should handle emails with plus signs', () => {
      const email = 'user+test@example.com';
      const normalized = validateEmail(email);

      expect(normalized).toBe('user+test@example.com');
    });

    it('should handle emails with dots', () => {
      const email = 'user.name@example.com';
      const normalized = validateEmail(email);

      expect(normalized).toBe('user.name@example.com');
    });
  });

  describe('isValidEmail', () => {
    it('should return true for valid emails', () => {
      expect(isValidEmail('user@example.com')).toBe(true);
      expect(isValidEmail('user.name@example.com')).toBe(true);
      expect(isValidEmail('user+test@example.com')).toBe(true);
      expect(isValidEmail('user_name@example.co.uk')).toBe(true);
    });

    it('should return false for invalid emails', () => {
      expect(isValidEmail('invalid-email')).toBe(false);
      expect(isValidEmail('@example.com')).toBe(false);
      expect(isValidEmail('user@')).toBe(false);
      expect(isValidEmail('user@example')).toBe(false);
      expect(isValidEmail('')).toBe(false);
    });
  });
});
