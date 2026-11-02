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
