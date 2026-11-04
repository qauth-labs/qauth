import { describe, expect, it } from 'vitest';

import { passwordEnvSchema, passwordPolicyWarnings } from './password';

describe('PASSWORD_MIN_SCORE', () => {
  it('reads blank as unset, so the default, never the weakest score', () => {
    for (const blank of ['', '  ']) {
      expect(passwordEnvSchema.parse({ PASSWORD_MIN_SCORE: blank }).PASSWORD_MIN_SCORE).toBe(2);
    }
    expect(passwordEnvSchema.parse({}).PASSWORD_MIN_SCORE).toBe(2);
  });

  it('still reads a set score, 0 included', () => {
    expect(passwordEnvSchema.parse({ PASSWORD_MIN_SCORE: '0' }).PASSWORD_MIN_SCORE).toBe(0);
    expect(passwordEnvSchema.parse({ PASSWORD_MIN_SCORE: '4' }).PASSWORD_MIN_SCORE).toBe(4);
    expect(passwordEnvSchema.safeParse({ PASSWORD_MIN_SCORE: '5' }).success).toBe(false);
  });
});

describe('PASSWORD_MIN_LENGTH (#634)', () => {
  it('defaults to 15, and reads blank as unset', () => {
    expect(passwordEnvSchema.parse({}).PASSWORD_MIN_LENGTH).toBe(15);
    for (const blank of ['', '  ']) {
      expect(passwordEnvSchema.parse({ PASSWORD_MIN_LENGTH: blank }).PASSWORD_MIN_LENGTH).toBe(15);
    }
  });

  it('accepts 8 to 64', () => {
    for (const value of ['8', '12', '15', '64']) {
      expect(passwordEnvSchema.parse({ PASSWORD_MIN_LENGTH: value }).PASSWORD_MIN_LENGTH).toBe(
        Number(value)
      );
    }
  });

  it('fails below 8, so the boot fails (acceptance criterion), and above 64', () => {
    for (const value of ['7', '0', '-1', '65', '12.5', 'fifteen']) {
      expect(passwordEnvSchema.safeParse({ PASSWORD_MIN_LENGTH: value }).success).toBe(false);
    }
  });

  it('warns below 15 (acceptance criterion), naming the variable, and not from 15 up', () => {
    for (const minLength of [8, 14]) {
      const warnings = passwordPolicyWarnings({ PASSWORD_MIN_LENGTH: minLength });
      expect(warnings).toHaveLength(1);
      expect(warnings[0]?.variable).toBe('PASSWORD_MIN_LENGTH');
      expect(warnings[0]?.message).toContain(`PASSWORD_MIN_LENGTH is ${minLength}, below 15`);
      expect(warnings[0]?.message).toContain('NIST SP 800-63B-4');
    }
    for (const minLength of [15, 16, 64]) {
      expect(passwordPolicyWarnings({ PASSWORD_MIN_LENGTH: minLength })).toEqual([]);
    }
  });
});

describe('PASSWORD_BREACH_LIST_SOURCE (#635)', () => {
  it('defaults to off, and reads blank as unset', () => {
    expect(passwordEnvSchema.parse({}).PASSWORD_BREACH_LIST_SOURCE).toBe('off');
    for (const blank of ['', '  ']) {
      expect(
        passwordEnvSchema.parse({ PASSWORD_BREACH_LIST_SOURCE: blank }).PASSWORD_BREACH_LIST_SOURCE
      ).toBe('off');
    }
  });

  it('accepts off, local and k_anonymity, and nothing else', () => {
    for (const value of ['off', 'local', 'k_anonymity'] as const) {
      expect(
        passwordEnvSchema.parse({ PASSWORD_BREACH_LIST_SOURCE: value }).PASSWORD_BREACH_LIST_SOURCE
      ).toBe(value);
    }
    for (const value of ['OFF', 'hibp', 'k-anonymity', 'true']) {
      expect(passwordEnvSchema.safeParse({ PASSWORD_BREACH_LIST_SOURCE: value }).success).toBe(
        false
      );
    }
  });
});

describe('BREACHED_PASSWORD_LIST_PATH (#635)', () => {
  it('is unset when absent or blank, and read as given otherwise', () => {
    expect(passwordEnvSchema.parse({}).BREACHED_PASSWORD_LIST_PATH).toBeUndefined();
    expect(
      passwordEnvSchema.parse({ BREACHED_PASSWORD_LIST_PATH: ' ' }).BREACHED_PASSWORD_LIST_PATH
    ).toBeUndefined();
    expect(
      passwordEnvSchema.parse({ BREACHED_PASSWORD_LIST_PATH: '/etc/qauth/pwned.txt' })
        .BREACHED_PASSWORD_LIST_PATH
    ).toBe('/etc/qauth/pwned.txt');
  });
});

describe('BREACHED_PASSWORD_RANGE_URL (#635)', () => {
  const parse = (value: string | undefined) =>
    passwordEnvSchema.safeParse({ BREACHED_PASSWORD_RANGE_URL: value });

  it('is unset when absent or blank', () => {
    expect(parse(undefined)).toMatchObject({
      success: true,
      data: { BREACHED_PASSWORD_RANGE_URL: undefined },
    });
    expect(parse('')).toMatchObject({
      success: true,
      data: { BREACHED_PASSWORD_RANGE_URL: undefined },
    });
  });

  it('accepts an absolute https URL, read as the URL parser writes it', () => {
    expect(parse('https://api.pwnedpasswords.com/range/')).toMatchObject({
      success: true,
      data: { BREACHED_PASSWORD_RANGE_URL: 'https://api.pwnedpasswords.com/range/' },
    });
    // A bare origin gets its path, so the prefix lands in the path, never the host.
    expect(parse('https://pwned.internal.example:8443')).toMatchObject({
      success: true,
      data: { BREACHED_PASSWORD_RANGE_URL: 'https://pwned.internal.example:8443/' },
    });
  });

  it('fails the boot for anything else, naming the variable', () => {
    for (const value of [
      'http://api.pwnedpasswords.com/range/',
      'api.pwnedpasswords.com/range/',
      '/range/',
      'https://user:secret@api.pwnedpasswords.com/range/',
      'https://api.pwnedpasswords.com/range/?prefix=',
      'https://api.pwnedpasswords.com/range/?',
      'https://api.pwnedpasswords.com/range/#x',
      'https://api.pwnedpasswords.com/range',
    ]) {
      const result = parse(value);
      expect(result.success, value).toBe(false);
      expect(JSON.stringify(result.error?.issues), value).toContain('BREACHED_PASSWORD_RANGE_URL');
      expect(JSON.stringify(result.error?.issues), value).not.toContain('secret');
    }
  });
});
