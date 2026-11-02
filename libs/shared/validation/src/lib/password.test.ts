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

import matching from 'zxcvbn/lib/matching';

import {
  createPasswordPolicyValidator,
  createPasswordValidator,
  createPasswordValidators,
  DEFAULT_PASSWORD_POLICY,
  normalizePassword,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH_CEILING,
  PASSWORD_MIN_LENGTH_FLOOR,
  PASSWORD_NORMALIZATION_NFC,
  PASSWORD_SINGLE_FACTOR_MIN_LENGTH,
  passwordContextWords,
  passwordForVerification,
  passwordSchema,
  ZXCVBN_MAX_INPUT_LENGTH,
  ZXCVBN_MAX_L33T_SUBSTITUTIONS,
} from './password';

/**
 * zxcvbn's l33t matcher runs a full dictionary scan once for every consistent
 * combination of substitutions for the l33t characters present, whatever the
 * length: all 20 substitute characters of its table give 736 combinations, and
 * a 100-character password made of them held the event loop for ~7 s on an
 * unauthenticated POST /auth/register, inside the 100-character length cap.
 * The bound is asserted on the work done (substitution maps and dictionary
 * scans), not on time.
 */
describe('createPasswordValidator — l33t substitution bound', () => {
  const validator = createPasswordValidator();
  // The 20 distinct substitute characters of zxcvbn's L33T_TABLE, repeated to
  // ZXCVBN_MAX_INPUT_LENGTH.
  const everyL33tCharacter = '4@8({[<369!|1+7%2$50'.repeat(5);

  it('gives the l33t matcher at most 16 substitution maps', () => {
    const enumerate = vi.spyOn(matching, 'enumerate_l33t_subs');
    try {
      validator.validatePasswordStrength(everyL33tCharacter);
      const mapCounts = enumerate.mock.results.map((result) => result.value.length);

      expect(mapCounts.length).toBeGreaterThan(0);
      expect(Math.max(...mapCounts)).toBeLessThanOrEqual(16);
      expect(ZXCVBN_MAX_L33T_SUBSTITUTIONS).toBe(16);
    } finally {
      enumerate.mockRestore();
    }
  });

  it('bounds the dictionary scans one score costs', () => {
    // Uncapped this is ~1,500 full scans of the password; capped, a few dozen.
    const dictionaryMatch = vi.spyOn(matching, 'dictionary_match');
    try {
      validator.validatePasswordStrength(everyL33tCharacter);
      expect(dictionaryMatch.mock.calls.length).toBeLessThan(100);
    } finally {
      dictionaryMatch.mockRestore();
    }
  });

  it('still finds l33t dictionary words', () => {
    expect(validator.validatePasswordStrength('p@ssw0rd').score).toBe(0);
    expect(validator.validatePasswordStrength('4dm1n1str4t0r').score).toBe(1);
    expect(validator.validatePasswordStrength('l3tm31n!').score).toBe(1);
  });
});

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

describe('createPasswordValidators (#528, #634)', () => {
  // zxcvbn scores 'abcabcabc' 0 and 'correct horse battery staple' 4; neither
  // is in its dictionaries.
  const WEAK = 'abcabcabc';
  const STRONG = 'correct horse battery staple';

  it("builds a validator of the policy's minimum length and lowest score", () => {
    const validators = createPasswordValidators();

    expect(validators.forPolicy({ minLength: 8, minScore: 0 }).check(WEAK).valid).toBe(true);
    expect(validators.forPolicy({ minLength: 8, minScore: 1 }).check(WEAK)).toMatchObject({
      valid: false,
      reasons: ['too_weak'],
    });
    expect(validators.forPolicy({ minLength: 15, minScore: 0 }).check(WEAK)).toMatchObject({
      valid: false,
      reasons: ['too_short'],
    });
    expect(validators.forPolicy({ minLength: 15, minScore: 4 }).check(STRONG).valid).toBe(true);
  });

  it('builds one validator per policy and hands it out again', () => {
    const validators = createPasswordValidators();

    const fifteen = validators.forPolicy({ minLength: 15, minScore: 2 });

    expect(validators.forPolicy({ minLength: 15, minScore: 2 })).toBe(fifteen);
    expect(validators.forPolicy({ minLength: 15, minScore: 3 })).not.toBe(fifteen);
    expect(validators.forPolicy({ minLength: 12, minScore: 2 })).not.toBe(fifteen);
    expect(fifteen.policy).toEqual({ minLength: 15, minScore: 2 });
  });

  it('judges a password as createPasswordPolicyValidator does with the same policy', () => {
    const validators = createPasswordValidators();

    for (const policy of [
      { minLength: 8, minScore: 0 },
      { minLength: 15, minScore: 2 },
      { minLength: 20, minScore: 4 },
    ]) {
      for (const password of [WEAK, 'Tr0ub4dor&3', STRONG]) {
        expect(validators.forPolicy(policy).check(password)).toEqual(
          createPasswordPolicyValidator(policy).check(password)
        );
      }
    }
  });

  it('refuses a policy out of bounds, and keeps nothing for it', () => {
    const validators = createPasswordValidators();

    for (const policy of [
      { minLength: 15, minScore: -1 },
      { minLength: 15, minScore: 5 },
      { minLength: 15, minScore: 2.5 },
      { minLength: 7, minScore: 2 },
      { minLength: 65, minScore: 2 },
      { minLength: Number.NaN, minScore: 2 },
    ]) {
      expect(() => validators.forPolicy(policy)).toThrow(z.ZodError);
      expect(() => validators.forPolicy(policy)).toThrow(z.ZodError);
    }
  });

  it('keeps no state between two sets of validators', () => {
    expect(createPasswordValidators().forPolicy(DEFAULT_PASSWORD_POLICY)).not.toBe(
      createPasswordValidators().forPolicy(DEFAULT_PASSWORD_POLICY)
    );
  });
});

/**
 * The one password policy for every new password (ADR-017 Decision 8, #634),
 * after NIST SP 800-63B-4 §3.1.1.2 "Password Verifiers".
 */
describe('createPasswordPolicyValidator (#634)', () => {
  const policy = createPasswordPolicyValidator();
  /** zxcvbn scores it 4: a password only its length can refuse. */
  const STRONG_14 = 'Kx9#mQ2$vL7!pR';

  it('defaults to a minimum of 15 code points and a lowest score of 2', () => {
    expect(PASSWORD_SINGLE_FACTOR_MIN_LENGTH).toBe(15);
    expect(policy.policy).toEqual({ minLength: 15, minScore: 2 });
    expect(DEFAULT_PASSWORD_POLICY).toEqual({ minLength: 15, minScore: 2 });
  });

  it('refuses a 14-character password with too_short at the default (acceptance criterion)', () => {
    expect(STRONG_14).toHaveLength(14);

    expect(policy.check(STRONG_14)).toEqual({
      valid: false,
      reasons: ['too_short'],
      feedback: ['Password must be at least 15 characters'],
    });
    expect(policy.check(`${STRONG_14}4`)).toMatchObject({ valid: true, score: 4 });
  });

  it('refuses 257 UTF-16 code units with too_long, before it normalises or scores anything (acceptance criterion)', () => {
    const normalize = vi.spyOn(String.prototype, 'normalize');
    zxcvbnSpy.mockClear();
    try {
      const password = 'K'.repeat(PASSWORD_MAX_LENGTH + 1);
      expect(password).toHaveLength(257);

      expect(policy.check(password)).toEqual({
        valid: false,
        reasons: ['too_long'],
        feedback: [`Password must be at most ${PASSWORD_MAX_LENGTH} characters`],
      });
      expect(normalize).not.toHaveBeenCalled();
      expect(zxcvbnSpy).not.toHaveBeenCalled();
    } finally {
      normalize.mockRestore();
    }
  });

  it('measures the bound in code units as typed: 129 astral characters are too long', () => {
    const password = '\u{1F600}'.repeat(129);
    expect(password).toHaveLength(258);

    expect(policy.check(password)).toMatchObject({ reasons: ['too_long'] });
  });

  it('refuses a password that NFC lengthens past the bound, which no login could take', () => {
    // U+0958 decomposes and does not recompose: one code unit as typed, two in NFC.
    const lengthened = '\u0958'.repeat(129);
    expect(lengthened).toHaveLength(129);
    expect(lengthened.normalize('NFC')).toHaveLength(258);

    expect(policy.check(lengthened)).toEqual({
      valid: false,
      reasons: ['too_long'],
      feedback: [`Password must be at most ${PASSWORD_MAX_LENGTH} characters`],
    });
    expect(policy.check('\u0958'.repeat(128))).not.toMatchObject({ reasons: ['too_long'] });
  });

  it('refuses an unpaired surrogate as too_weak, and accepts a paired one', () => {
    // Hashed as UTF-8, an unpaired surrogate becomes U+FFFD: any one would
    // verify as any other.
    const unpaired = `${STRONG_14}4\uD83D`;

    expect(policy.check(unpaired)).toEqual({
      valid: false,
      reasons: ['too_weak'],
      feedback: ['Password is too easy to guess', 'Password contains characters that are not text'],
    });
    expect(policy.check(`${STRONG_14}4\uDE00`)).toMatchObject({ reasons: ['too_weak'] });
    expect(policy.check(`${STRONG_14}4\u{1F600}`).valid).toBe(true);
  });

  it('counts the minimum in code points, not code units', () => {
    // 14 code points in 15 code units: still too short.
    expect(policy.check('Kx9#mQ2$vL7!p\u{1F512}')).toMatchObject({ reasons: ['too_short'] });
    // 15 code points in 16 code units: long enough.
    expect(policy.check('Kx9#mQ2$vL7!pR\u{1F512}').valid).toBe(true);
  });

  it('counts the minimum after NFC normalisation', () => {
    // 15 code points as typed (e + U+0301), 14 once NFC composes them into é.
    const decomposed = 'Kx9#mQ2$vL7!pe\u0301';
    expect([...decomposed]).toHaveLength(15);

    expect(policy.check(decomposed)).toMatchObject({ reasons: ['too_short'] });
  });

  it('refuses a password equal to a dictionary entry, ignoring case, and not one that contains it (acceptance criterion)', () => {
    // Score floor 0, so the blocklist is the only rule that can refuse.
    const blocklistOnly = createPasswordPolicyValidator({ minScore: 0 });

    // An English word of zxcvbn's dictionaries, and a password of its
    // common-passwords list, both at least 15 characters.
    for (const entry of [
      'telecommunications',
      'Telecommunications',
      ' telecommunications ',
      '1qaz2wsx3edc4rfv',
    ]) {
      expect(blocklistOnly.check(entry)).toMatchObject({ valid: false, reasons: ['blocklisted'] });
    }
    expect(blocklistOnly.check('telecommunications-tower-near-the-harbour').valid).toBe(true);
    expect(policy.check('telecommunications-tower-near-the-harbour').valid).toBe(true);
  });

  it('refuses a password equal to a context word, and not one that contains it', () => {
    const blocklistOnly = createPasswordPolicyValidator({ minLength: 8, minScore: 0 });
    const context = {
      email: 'Margaret.Hamilton@Example.org',
      serviceName: 'Northwind Identity',
      realmName: 'northwind-staff',
      clientNames: ['Northwind Mobile App'],
    };

    for (const word of [
      'margaret.hamilton@example.org',
      'Margaret.Hamilton',
      'example.org',
      ' Margaret.Hamilton ',
      'NORTHWIND IDENTITY',
      'northwind-staff',
      'northwind mobile app',
    ]) {
      expect(blocklistOnly.check(word, context)).toMatchObject({
        valid: false,
        reasons: ['blocklisted'],
      });
      // The same word is no context word of another account.
      expect(blocklistOnly.check(word, { email: 'someone@elsewhere.test' }).valid).toBe(true);
    }
    expect(blocklistOnly.check('margaret.hamilton and the river boats', context).valid).toBe(true);
    expect(blocklistOnly.check('northwind identity at the river 1987', context).valid).toBe(true);
  });

  it('passes the context words to zxcvbn as its user inputs', () => {
    zxcvbnSpy.mockClear();
    policy.check('margaret hamilton river 1987', { email: 'margaret@example.org' });

    expect(zxcvbnSpy).toHaveBeenCalledWith('margaret hamilton river 1987', [
      'margaret@example.org',
      'margaret',
      'example.org',
      'example',
    ]);
  });

  it('keeps the score floor and adds no composition rule', () => {
    // Long enough, in no dictionary, yet trivially guessable.
    expect(policy.check('aaaaaaaaaaaaaaaa')).toMatchObject({
      valid: false,
      reasons: ['too_weak'],
    });
    // Lower case and spaces only: no character class is required.
    expect(policy.check('correct horse battery staple').valid).toBe(true);
  });

  it('returns every reason found, each with its message, then zxcvbn feedback', () => {
    const result = policy.check('password');

    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.reasons).toEqual(['too_short', 'blocklisted', 'too_weak']);
    expect(result.feedback.slice(0, 3)).toEqual([
      'Password must be at least 15 characters',
      'Password is a commonly used word or password, or names this service or account',
      'Password is too easy to guess',
    ]);
    expect(result.feedback.length).toBeGreaterThan(3);
  });

  it('returns an accepted password in NFC, with the marker to record', () => {
    const decomposed = 'e\u0301te\u0301 a\u0300 la plage, sous les pins';
    const composed = '\u00e9t\u00e9 \u00e0 la plage, sous les pins';

    for (const typed of [decomposed, composed]) {
      expect(policy.check(typed)).toEqual({
        valid: true,
        password: composed,
        normalization: PASSWORD_NORMALIZATION_NFC,
        score: 4,
      });
    }
  });

  it('refuses a minimum below 8 or above 64', () => {
    expect(PASSWORD_MIN_LENGTH_FLOOR).toBe(8);
    expect(PASSWORD_MIN_LENGTH_CEILING).toBe(64);
    expect(() => createPasswordPolicyValidator({ minLength: 7 })).toThrow(z.ZodError);
    expect(() => createPasswordPolicyValidator({ minLength: 65 })).toThrow(z.ZodError);
    expect(createPasswordPolicyValidator({ minLength: 8 }).check('Kx9#mQ2$').valid).toBe(true);
  });
});

describe('passwordContextWords', () => {
  it('names the address, its local part, its domain and its label, and the service, realm and client names, once each', () => {
    expect(
      passwordContextWords({
        email: 'Ada@Example.org',
        serviceName: ' QAuth ',
        realmName: 'qauth',
        clientNames: ['Portal', ''],
      })
    ).toEqual(['ada@example.org', 'ada', 'example.org', 'example', 'qauth', 'portal']);
    expect(passwordContextWords({})).toEqual([]);
  });

  it('names the local part before a + tag, and every label of the domain but the last', () => {
    expect(passwordContextWords({ email: 'grace+billing@mail.navy.example' })).toEqual([
      'grace+billing@mail.navy.example',
      'grace+billing',
      'grace',
      'mail.navy.example',
      'mail',
      'navy',
    ]);
  });
});

describe('normalisation marker (#634)', () => {
  const composed = 'caf\u00e9-terrace-at-night';
  const decomposed = 'cafe\u0301-terrace-at-night';

  it('verifies both spellings in NFC when the credential records the marker', () => {
    expect(composed).not.toBe(decomposed);
    expect(passwordForVerification(decomposed, PASSWORD_NORMALIZATION_NFC)).toBe(composed);
    expect(passwordForVerification(composed, PASSWORD_NORMALIZATION_NFC)).toBe(composed);
    expect(normalizePassword(decomposed)).toBe(composed);
  });

  it('verifies a credential without the marker on the password as typed', () => {
    expect(passwordForVerification(decomposed, undefined)).toBe(decomposed);
    expect(passwordForVerification(composed, undefined)).toBe(composed);
  });
});
