import { describe, expect, it } from 'vitest';

import {
  generateCodeChallenge,
  generateCodeVerifier,
  generatePkcePair,
  isValidCodeVerifierFormat,
  verifyCodeChallenge,
} from './pkce';

const RFC7636_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC7636_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

describe('generateCodeVerifier', () => {
  it('should return a 43-character string', () => {
    const v = generateCodeVerifier();
    expect(v).toHaveLength(43);
  });

  it('should match [A-Za-z0-9._~-]{43}', () => {
    const v = generateCodeVerifier();
    expect(v).toMatch(/^[A-Za-z0-9._~-]{43}$/);
  });

  it('should produce different values each call', () => {
    const v1 = generateCodeVerifier();
    const v2 = generateCodeVerifier();
    expect(v1).not.toBe(v2);
  });

  it('should produce verifiers that isValidCodeVerifierFormat accepts', () => {
    const v = generateCodeVerifier();
    expect(isValidCodeVerifierFormat(v)).toBe(true);
  });
});

describe('generateCodeChallenge', () => {
  it('should be deterministic: same verifier → same challenge', () => {
    const v = generateCodeVerifier();
    expect(generateCodeChallenge(v)).toBe(generateCodeChallenge(v));
  });

  it('should produce different challenges for different verifiers', () => {
    const v1 = generateCodeVerifier();
    const v2 = generateCodeVerifier();
    expect(generateCodeChallenge(v1)).not.toBe(generateCodeChallenge(v2));
  });

  it('should output 43-char base64url string', () => {
    const v = generateCodeVerifier();
    const c = generateCodeChallenge(v);
    expect(c).toHaveLength(43);
    expect(c).toMatch(/^[A-Za-z0-9._~-]{43}$/);
  });

  it('should match RFC 7636 Appendix B S256 example', () => {
    expect(generateCodeChallenge(RFC7636_VERIFIER)).toBe(RFC7636_CHALLENGE);
  });

  it('should throw for invalid verifier format', () => {
    expect(() => generateCodeChallenge('short')).toThrow('Invalid code verifier format');
    expect(() => generateCodeChallenge('')).toThrow('Invalid code verifier format');
  });
});

describe('verifyCodeChallenge', () => {
  it('should return true for matching verifier and stored challenge', () => {
    const v = generateCodeVerifier();
    const stored = generateCodeChallenge(v);
    expect(verifyCodeChallenge(v, stored)).toBe(true);
  });

  it('should return false for wrong verifier', () => {
    const v = generateCodeVerifier();
    const stored = generateCodeChallenge(v);
    const other = generateCodeVerifier();
    expect(verifyCodeChallenge(other, stored)).toBe(false);
  });

  it('should return false for mismatched length (no throw)', () => {
    const v = generateCodeVerifier();
    const stored = generateCodeChallenge(v);
    expect(verifyCodeChallenge(v, stored + 'x')).toBe(false);
    expect(verifyCodeChallenge(v, stored.slice(0, -1))).toBe(false);
  });

  it('should return true for RFC 7636 Appendix B verifier/challenge pair', () => {
    expect(verifyCodeChallenge(RFC7636_VERIFIER, RFC7636_CHALLENGE)).toBe(true);
  });

  it('should return false for invalid verifier format', () => {
    expect(verifyCodeChallenge('short', RFC7636_CHALLENGE)).toBe(false);
    expect(verifyCodeChallenge('', 'anything')).toBe(false);
  });
});

describe('isValidCodeVerifierFormat', () => {
  it('should accept valid 43–128 char verifier', () => {
    expect(isValidCodeVerifierFormat(RFC7636_VERIFIER)).toBe(true);
    expect(isValidCodeVerifierFormat('a'.repeat(43))).toBe(true);
    expect(isValidCodeVerifierFormat('a'.repeat(128))).toBe(true);
    expect(isValidCodeVerifierFormat('A-Za_z0.9~-'.repeat(4) + 'abc')).toBe(true);
  });

  it('should reject too short (<43)', () => {
    expect(isValidCodeVerifierFormat('a'.repeat(42))).toBe(false);
  });

  it('should reject too long (>128)', () => {
    expect(isValidCodeVerifierFormat('a'.repeat(129))).toBe(false);
  });

  it('should reject invalid characters', () => {
    expect(isValidCodeVerifierFormat('a'.repeat(42) + '!')).toBe(false);
    expect(isValidCodeVerifierFormat('a'.repeat(42) + ' ')).toBe(false);
  });

  it('should reject empty string, null, undefined', () => {
    expect(isValidCodeVerifierFormat('')).toBe(false);
    expect(isValidCodeVerifierFormat(null as unknown as string)).toBe(false);
    expect(isValidCodeVerifierFormat(undefined as unknown as string)).toBe(false);
  });
});

describe('generatePkcePair', () => {
  it('should return { codeVerifier, codeChallenge }', () => {
    const pair = generatePkcePair();
    expect(pair).toHaveProperty('codeVerifier');
    expect(pair).toHaveProperty('codeChallenge');
  });

  it('should satisfy verifyCodeChallenge(pair.codeVerifier, pair.codeChallenge)', () => {
    const pair = generatePkcePair();
    expect(verifyCodeChallenge(pair.codeVerifier, pair.codeChallenge)).toBe(true);
  });

  it('should produce a new pair each call', () => {
    const p1 = generatePkcePair();
    const p2 = generatePkcePair();
    expect(p1.codeVerifier).not.toBe(p2.codeVerifier);
    expect(p1.codeChallenge).not.toBe(p2.codeChallenge);
  });
});
