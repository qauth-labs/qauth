import { describe, expect, it } from 'vitest';

import { hasRequiredScopes, missingScopes, parseScopes } from './scope';

describe('parseScopes', () => {
  it('splits a space-separated scope string', () => {
    expect(parseScopes('mcp:read mcp:write')).toEqual(['mcp:read', 'mcp:write']);
  });

  it('collapses arbitrary whitespace runs and trims', () => {
    expect(parseScopes('  a\tb\n c  ')).toEqual(['a', 'b', 'c']);
  });

  it('de-duplicates repeated scopes', () => {
    expect(parseScopes('a a b')).toEqual(['a', 'b']);
  });

  it('accepts an array form', () => {
    expect(parseScopes(['a', 'b', 'a'])).toEqual(['a', 'b']);
  });

  it('returns [] for null/undefined/empty', () => {
    expect(parseScopes(undefined)).toEqual([]);
    expect(parseScopes(null)).toEqual([]);
    expect(parseScopes('')).toEqual([]);
    expect(parseScopes('   ')).toEqual([]);
  });
});

describe('missingScopes', () => {
  it('returns [] when all required scopes are present', () => {
    expect(missingScopes(['a', 'b', 'c'], ['a', 'c'])).toEqual([]);
  });

  it('returns only the absent required scopes', () => {
    expect(missingScopes(['a'], ['a', 'b', 'c'])).toEqual(['b', 'c']);
  });

  it('returns [] when nothing is required', () => {
    expect(missingScopes([], [])).toEqual([]);
  });

  it('is case-sensitive (RFC 6749 §3.3)', () => {
    expect(missingScopes(['Read'], ['read'])).toEqual(['read']);
  });
});

describe('hasRequiredScopes', () => {
  it('is true when no scopes are required', () => {
    expect(hasRequiredScopes([], [])).toBe(true);
  });

  it('is false when a required scope is missing', () => {
    expect(hasRequiredScopes(['a'], ['a', 'b'])).toBe(false);
  });
});
