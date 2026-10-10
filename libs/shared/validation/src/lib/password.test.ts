import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

// Pass-through spy on zxcvbn, so the tests can assert how much input it sees
// while the real scorer still runs.
const { zxcvbnSpy } = vi.hoisted(() => ({ zxcvbnSpy: vi.fn() }));
vi.mock('zxcvbn', async (importOriginal) => {
  const actual = (await importOriginal<{ default: (password: string) => unknown }>()).default;
  zxcvbnSpy.mockImplementation(actual);
  return { default: zxcvbnSpy };
});

import {
  createPasswordValidator,
  PASSWORD_MAX_LENGTH,
  passwordSchema,
  ZXCVBN_MAX_INPUT_LENGTH,
} from './password';

/**
 * A password is attacker-sized input to CPU-bound work. zxcvbn's matchers grow
 * super-linearly with length, and scoring runs before any hashing, so an
 * unbounded field let one request hold the event loop. These tests pin both
 * bounds.
 */
describe('createPasswordValidator — input bounds', () => {
  const validator = createPasswordValidator();

  it('rejects a password longer than PASSWORD_MAX_LENGTH without scoring it', () => {
    zxcvbnSpy.mockClear();
    const result = validator.validatePasswordStrength('a'.repeat(PASSWORD_MAX_LENGTH + 1));

    expect(result.valid).toBe(false);
    expect(result.feedback).toEqual([`Password must be at most ${PASSWORD_MAX_LENGTH} characters`]);
    expect(zxcvbnSpy).not.toHaveBeenCalled();
  });

  it('rejects a very large password without scoring it', () => {
    zxcvbnSpy.mockClear();
    const result = validator.validatePasswordStrength('x'.repeat(100_000));

    expect(result.valid).toBe(false);
    expect(zxcvbnSpy).not.toHaveBeenCalled();
  });

  it('scores at most ZXCVBN_MAX_INPUT_LENGTH characters of an accepted password', () => {
    zxcvbnSpy.mockClear();
    const password = 'correct horse battery staple '.repeat(8).slice(0, PASSWORD_MAX_LENGTH);
    validator.validatePasswordStrength(password);

    expect(zxcvbnSpy).toHaveBeenCalledTimes(1);
    expect((zxcvbnSpy.mock.calls[0][0] as string).length).toBe(ZXCVBN_MAX_INPUT_LENGTH);
  });

  it('scores a short password in full', () => {
    zxcvbnSpy.mockClear();
    validator.validatePasswordStrength('Tr0ub4dor&3-horse');

    expect(zxcvbnSpy).toHaveBeenCalledWith('Tr0ub4dor&3-horse');
  });

  it('accepts a strong password at exactly PASSWORD_MAX_LENGTH', () => {
    const password = 'Kx9#mQ2$vL7!pR4&'.repeat(16);
    expect(password).toHaveLength(PASSWORD_MAX_LENGTH);

    expect(validator.validatePasswordStrength(password).valid).toBe(true);
  });

  it('keeps NIST SP 800-63B-4 headroom: the bound is at least 64', () => {
    expect(PASSWORD_MAX_LENGTH).toBeGreaterThanOrEqual(64);
  });

  it('still rejects an empty password', () => {
    expect(validator.validatePasswordStrength('').valid).toBe(false);
  });
});

/**
 * The request-schema bound counts UTF-16 code units, like
 * `validatePasswordStrength`. Zod 4.5+ `.max()` counts code points, which let a
 * password of astral characters through at up to twice the bound.
 */
describe('passwordSchema', () => {
  /** U+1F600: one code point, two UTF-16 code units. */
  const ASTRAL = '\u{1F600}';

  it('accepts a password of exactly PASSWORD_MAX_LENGTH code units', () => {
    expect(passwordSchema.safeParse('a'.repeat(PASSWORD_MAX_LENGTH)).success).toBe(true);
    expect(passwordSchema.safeParse(ASTRAL.repeat(PASSWORD_MAX_LENGTH / 2)).success).toBe(true);
  });

  it('rejects astral characters one code unit pair over the bound, though they are fewer code points', () => {
    const password = ASTRAL.repeat(PASSWORD_MAX_LENGTH / 2 + 1);
    expect(password).toHaveLength(PASSWORD_MAX_LENGTH + 2);

    const result = passwordSchema.safeParse(password);
    expect(result.success).toBe(false);
    expect(result.error?.issues).toEqual([
      expect.objectContaining({
        code: 'too_big',
        maximum: PASSWORD_MAX_LENGTH,
        message: `Too big: expected string to have <=${PASSWORD_MAX_LENGTH} characters`,
      }),
    ]);
  });

  it('agrees with validatePasswordStrength on where the bound falls', () => {
    const validator = createPasswordValidator();
    for (const password of [
      ASTRAL.repeat(PASSWORD_MAX_LENGTH / 2 + 1),
      'a'.repeat(PASSWORD_MAX_LENGTH + 1),
    ]) {
      expect(passwordSchema.safeParse(password).success).toBe(false);
      expect(validator.validatePasswordStrength(password).feedback).toEqual([
        `Password must be at most ${PASSWORD_MAX_LENGTH} characters`,
      ]);
    }
  });

  it('reports one issue, not two, for an over-long password', () => {
    expect(passwordSchema.safeParse('a'.repeat(100_000)).error?.issues).toHaveLength(1);
    expect(passwordSchema.min(1).safeParse('a'.repeat(100_000)).error?.issues).toHaveLength(1);
  });

  it('keeps maxLength in the JSON Schema it generates', () => {
    expect(z.toJSONSchema(passwordSchema)).toMatchObject({
      type: 'string',
      maxLength: PASSWORD_MAX_LENGTH,
    });
  });
});
