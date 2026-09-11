import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  generateOid4vpResponseCode,
  hashOid4vpResponseCode,
  isOid4vpResponseCode,
  MAX_OID4VP_RESPONSE_CODE_LENGTH,
  OID4VP_RESPONSE_CODE_BYTES,
  OID4VP_RESPONSE_CODE_PATTERN,
} from './response-code';

describe('generateOid4vpResponseCode', () => {
  it('(OID4VP 1.0 §8.2) mints a fresh, cryptographically random value of 128 bits or more', () => {
    const code = generateOid4vpResponseCode();

    expect(OID4VP_RESPONSE_CODE_BYTES).toBe(32);
    expect(OID4VP_RESPONSE_CODE_BYTES * 8).toBeGreaterThanOrEqual(128);
    expect(Buffer.from(code, 'base64url')).toHaveLength(OID4VP_RESPONSE_CODE_BYTES);
  });

  it('is 43 base64url characters — the exact shape the return route accepts', () => {
    const code = generateOid4vpResponseCode();

    expect(code).toHaveLength(MAX_OID4VP_RESPONSE_CODE_LENGTH);
    expect(code).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(code).not.toContain('=');
    expect(isOid4vpResponseCode(code)).toBe(true);
  });

  it('never repeats across a thousand mints', () => {
    const seen = new Set<string>();

    for (let i = 0; i < 1000; i += 1) {
      seen.add(generateOid4vpResponseCode());
    }

    expect(seen.size).toBe(1000);
  });
});

describe('hashOid4vpResponseCode', () => {
  it('is SHA-256 hex — the digest response_code_hash is keyed by', () => {
    expect(hashOid4vpResponseCode('abc')).toBe(
      createHash('sha256').update('abc', 'utf8').digest('hex')
    );
    expect(hashOid4vpResponseCode('abc')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic, so the response endpoint and the return route agree', () => {
    const code = generateOid4vpResponseCode();

    expect(hashOid4vpResponseCode(code)).toBe(hashOid4vpResponseCode(code));
    expect(hashOid4vpResponseCode(code)).not.toBe(hashOid4vpResponseCode(`${code} `));
  });

  it('never persists the code itself', () => {
    const code = generateOid4vpResponseCode();

    expect(hashOid4vpResponseCode(code)).not.toContain(code);
  });
});

describe('OID4VP_RESPONSE_CODE_PATTERN', () => {
  const valid = generateOid4vpResponseCode();

  it('pins the length constant and the pattern to the same 43 characters', () => {
    expect(MAX_OID4VP_RESPONSE_CODE_LENGTH).toBe(43);
    expect(Buffer.alloc(OID4VP_RESPONSE_CODE_BYTES).toString('base64url')).toHaveLength(
      MAX_OID4VP_RESPONSE_CODE_LENGTH
    );
    expect(OID4VP_RESPONSE_CODE_PATTERN.source).toBe('^[A-Za-z0-9_-]{43}$');
    expect(OID4VP_RESPONSE_CODE_PATTERN.flags).toBe('');
  });

  it('accepts every character of the base64url alphabet', () => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    expect(alphabet).toHaveLength(64);
    expect(isOid4vpResponseCode(alphabet.slice(0, 43))).toBe(true);
    expect(isOid4vpResponseCode(alphabet.slice(21))).toBe(true);
  });

  it.each([
    ['one character short', valid.slice(1)],
    ['one character long', `${valid}A`],
    ['base64 padded', `${valid.slice(0, 42)}==`],
    ['leading whitespace', ` ${valid.slice(1)}`],
    ['trailing newline', `${valid.slice(0, 42)}\n`],
    ['trailing newline after a full code', `${valid}\n`],
    ['a NUL byte', `${valid.slice(0, 42)}\0`],
    ['standard base64 alphabet', `${valid.slice(0, 41)}+/`],
    ['percent-encoding', `${valid.slice(0, 40)}%2B`],
    ['a non-ASCII letter', `${valid.slice(0, 42)}é`],
    ['a fullwidth digit', `${valid.slice(0, 42)}１`],
    ['the empty string', ''],
  ])('refuses %s', (_label, value) => {
    expect(isOid4vpResponseCode(value)).toBe(false);
    expect(OID4VP_RESPONSE_CODE_PATTERN.test(value)).toBe(false);
  });
});

describe('isOid4vpResponseCode', () => {
  it.each([undefined, null, 42, true, {}, [generateOid4vpResponseCode()], Symbol('code')])(
    'refuses the non-string %s',
    (value) => {
      expect(isOid4vpResponseCode(value)).toBe(false);
    }
  );

  it('narrows unknown to string on the accepting branch', () => {
    const value: unknown = generateOid4vpResponseCode();

    if (isOid4vpResponseCode(value)) {
      expect(value.length).toBe(MAX_OID4VP_RESPONSE_CODE_LENGTH);
    } else {
      throw new Error('a freshly minted code must be accepted');
    }
  });
});
