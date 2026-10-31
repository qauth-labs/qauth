import { describe, expect, it } from 'vitest';

import { passwordEnvSchema } from './password';

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
