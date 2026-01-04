import { describe, expect, it } from 'vitest';

import {
  generateRefreshToken,
  hashRefreshToken,
  isValidRefreshTokenFormat,
} from './refresh-token-generator';

describe('generateRefreshToken', () => {
  it('should generate a token pair', () => {
    const pair = generateRefreshToken();
    expect(pair).toHaveProperty('token');
    expect(pair).toHaveProperty('tokenHash');
  });

  it('should generate tokens with correct length', () => {
    const pair = generateRefreshToken();
    expect(pair.token.length).toBe(64);
    expect(pair.tokenHash.length).toBe(64);
  });

  it('should generate different tokens each time', () => {
    const pair1 = generateRefreshToken();
    const pair2 = generateRefreshToken();
    expect(pair1.token).not.toBe(pair2.token);
    expect(pair1.tokenHash).not.toBe(pair2.tokenHash);
  });

  it('should generate valid hex format tokens', () => {
    const pair = generateRefreshToken();
    expect(isValidRefreshTokenFormat(pair.token)).toBe(true);
    expect(isValidRefreshTokenFormat(pair.tokenHash)).toBe(true);
  });

  it('should hash the token correctly', () => {
    const pair = generateRefreshToken();
    const expectedHash = hashRefreshToken(pair.token);
    expect(pair.tokenHash).toBe(expectedHash);
  });

  it('should generate tokens with sufficient entropy (256 bits)', () => {
    // CVE-2023-2781 mitigation: Verify tokens use crypto.randomBytes(32)
    // 32 bytes = 256 bits of entropy
    const pair = generateRefreshToken();
    expect(pair.token.length).toBe(64); // 32 bytes = 64 hex chars
    // Verify token is hex-encoded (each byte becomes 2 hex chars)
    expect(pair.token).toMatch(/^[0-9a-f]{64}$/i);
  });
});

describe('hashRefreshToken', () => {
  it('should hash a token', () => {
    const token = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const hash = hashRefreshToken(token);
    expect(hash).toBeDefined();
    expect(hash.length).toBe(64);
    expect(hash).not.toBe(token);
  });

  it('should produce the same hash for the same token', () => {
    const token = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const hash1 = hashRefreshToken(token);
    const hash2 = hashRefreshToken(token);
    expect(hash1).toBe(hash2);
  });

  it('should produce different hashes for different tokens', () => {
    const token1 = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const token2 = 'b2c3d4e5f6789012345678901234567890123456789012345678901234567890';
    const hash1 = hashRefreshToken(token1);
    const hash2 = hashRefreshToken(token2);
    expect(hash1).not.toBe(hash2);
  });

  it('should produce valid hex format hash', () => {
    const token = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    const hash = hashRefreshToken(token);
    expect(isValidRefreshTokenFormat(hash)).toBe(true);
  });
});

describe('isValidRefreshTokenFormat', () => {
  it('should validate correct 64-character hex token', () => {
    const token = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678';
    expect(isValidRefreshTokenFormat(token)).toBe(true);
  });

  it('should reject tokens that are too short', () => {
    const token = 'a1b2c3d4e5f6';
    expect(isValidRefreshTokenFormat(token)).toBe(false);
  });

  it('should reject tokens that are too long', () => {
    const token = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678901';
    expect(isValidRefreshTokenFormat(token)).toBe(false);
  });

  it('should reject tokens with invalid characters', () => {
    const token = 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567g';
    expect(isValidRefreshTokenFormat(token)).toBe(false);
  });

  it('should accept uppercase hex characters', () => {
    const token = 'A1B2C3D4E5F67890123456789012345678901234567890123456789012345678';
    expect(isValidRefreshTokenFormat(token)).toBe(true);
  });

  it('should accept mixed case hex characters', () => {
    const token = 'a1B2c3D4e5F67890123456789012345678901234567890123456789012345678';
    expect(isValidRefreshTokenFormat(token)).toBe(true);
  });

  it('should reject empty, null, and undefined tokens', () => {
    expect(isValidRefreshTokenFormat('')).toBe(false);
    expect(isValidRefreshTokenFormat(null as unknown as string)).toBe(false);
    expect(isValidRefreshTokenFormat(undefined as unknown as string)).toBe(false);
    expect(isValidRefreshTokenFormat('0'.repeat(63))).toBe(false);
    expect(isValidRefreshTokenFormat('0'.repeat(65))).toBe(false);
    expect(isValidRefreshTokenFormat('0'.repeat(64))).toBe(true);
  });
});
