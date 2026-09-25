import { describe, expect, it, vi } from 'vitest';

// Pass-through spy on zxcvbn, so the tests can assert how much input it sees
// while the real scorer still runs.
const { zxcvbnSpy } = vi.hoisted(() => ({ zxcvbnSpy: vi.fn() }));
vi.mock('zxcvbn', async (importOriginal) => {
  const actual = (await importOriginal<{ default: (password: string) => unknown }>()).default;
  zxcvbnSpy.mockImplementation(actual);
  return { default: zxcvbnSpy };
});

import { createPasswordValidator, PASSWORD_MAX_LENGTH, ZXCVBN_MAX_INPUT_LENGTH } from './password';

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
