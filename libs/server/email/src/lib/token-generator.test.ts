import { describe, expect, it } from 'vitest';

import type { TokenPair } from '../types';
import {
  constantTimeCompare,
  generateVerificationToken,
  hashToken,
  isValidTokenFormat,
} from './token-generator';

describe('generateVerificationToken', () => {
  it('should generate a token pair', () => {
    const pair = generateVerificationToken();
    expect(pair).toHaveProperty('token');
    expect(pair).toHaveProperty('tokenHash');
  });

  it('should generate tokens with correct length', () => {
    const pair = generateVerificationToken();
    expect(pair.token.length).toBe(64);
    expect(pair.tokenHash.length).toBe(64);
  });

  it('should generate different tokens each time', () => {
    const pair1 = generateVerificationToken();
    const pair2 = generateVerificationToken();
    expect(pair1.token).not.toBe(pair2.token);
    expect(pair1.tokenHash).not.toBe(pair2.tokenHash);
  });

  it('should generate valid hex format tokens', () => {
    const pair = generateVerificationToken();
    expect(isValidTokenFormat(pair.token)).toBe(true);
    expect(isValidTokenFormat(pair.tokenHash)).toBe(true);
  });

  it('should hash the token correctly', () => {
    const pair = generateVerificationToken();
    const expectedHash = hashToken(pair.token);
    expect(pair.tokenHash).toBe(expectedHash);
  });
});

describe('hashToken', () => {
  it('should hash a token', () => {
    const token = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const hash = hashToken(token);
    expect(hash).toBeDefined();
    expect(hash.length).toBe(64);
    expect(hash).not.toBe(token);
  });

  it('should produce the same hash for the same token', () => {
    const token = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const hash1 = hashToken(token);
    const hash2 = hashToken(token);
    expect(hash1).toBe(hash2);
  });

  it('should produce different hashes for different tokens', () => {
    const token1 = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const token2 = 'b2c3d4e5f6789012345678901234567890123456789012345678901234567890';
    const hash1 = hashToken(token1);
    const hash2 = hashToken(token2);
    expect(hash1).not.toBe(hash2);
  });

  it('should produce valid hex format hash', () => {
    const token = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const hash = hashToken(token);
    expect(isValidTokenFormat(hash)).toBe(true);
  });
});

describe('isValidTokenFormat', () => {
  it('should validate correct 64-character hex token', () => {
    const token = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    expect(isValidTokenFormat(token)).toBe(true);
  });

  it('should reject tokens that are too short', () => {
    const token = 'a1b2c3d4e5f6';
    expect(isValidTokenFormat(token)).toBe(false);
  });

  it('should reject tokens that are too long', () => {
    const token = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678901';
    expect(isValidTokenFormat(token)).toBe(false);
  });

  it('should reject tokens with invalid characters', () => {
    const token = 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567g';
    expect(isValidTokenFormat(token)).toBe(false);
  });

  it('should accept uppercase hex characters', () => {
    const token = 'A1B2C3D4E5F67890123456789012345678901234567890123456789012345678';
    expect(isValidTokenFormat(token)).toBe(true);
  });

  it('should accept mixed case hex characters', () => {
    const token = 'a1B2c3D4e5F67890123456789012345678901234567890123456789012345678';
    expect(isValidTokenFormat(token)).toBe(true);
  });

  it('should reject empty string', () => {
    expect(isValidTokenFormat('')).toBe(false);
  });
});

describe('constantTimeCompare', () => {
  it('should return true for identical tokens', () => {
    const token = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    expect(constantTimeCompare(token, token)).toBe(true);
  });

  it('should return false for different tokens', () => {
    const token1 = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const token2 = 'b2c3d4e5f6789012345678901234567890123456789012345678901234567890';
    expect(constantTimeCompare(token1, token2)).toBe(false);
  });

  it('should return false for tokens of different lengths', () => {
    const token1 = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const token2 = 'a1b2c3d4e5f6';
    expect(constantTimeCompare(token1, token2)).toBe(false);
  });

  it('should return false when comparing token with its hash', () => {
    const token = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const hash = hashToken(token);
    expect(constantTimeCompare(token, hash)).toBe(false);
  });

  it('should handle edge case with same prefix but different suffix', () => {
    const token1 = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const token2 = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345679';
    expect(constantTimeCompare(token1, token2)).toBe(false);
  });

  it('should work with generated token pairs', () => {
    const pair: TokenPair = generateVerificationToken();
    // Token should not equal its hash
    expect(constantTimeCompare(pair.token, pair.tokenHash)).toBe(false);
    // Token should equal itself
    expect(constantTimeCompare(pair.token, pair.token)).toBe(true);
  });

  it('should return false for invalid token format', () => {
    const validToken = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const invalidToken = 'invalid-token';
    expect(constantTimeCompare(validToken, invalidToken)).toBe(false);
    expect(constantTimeCompare(invalidToken, validToken)).toBe(false);
    expect(constantTimeCompare(invalidToken, invalidToken)).toBe(false);
  });
});
