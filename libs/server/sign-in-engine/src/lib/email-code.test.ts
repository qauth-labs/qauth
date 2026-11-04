import { createHmac } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import {
  answerEmailCode,
  EMAIL_CODE_HMAC_PATTERN,
  EMAIL_CODE_MAX_WRONG_ANSWERS,
  EMAIL_CODE_RESEND_AFTER_MS,
  EMAIL_CODE_SALT_PATTERN,
  EMAIL_CODE_TTL_MS,
  emailCodeExpired,
  emailCodeLength,
  emailCodeParams,
  emailCodeResendDue,
  generateEmailCode,
  generateEmailCodeSalt,
  type HeldEmailCode,
  heldEmailCode,
  sameEmailCodeHmac,
} from './email-code';

// The CSPRNG, observed: every code is drawn from `crypto.randomInt`.
const { randomInt } = vi.hoisted(() => ({ randomInt: vi.fn() }));
vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  randomInt.mockImplementation((max: number) => actual.randomInt(max));
  return { ...actual, randomInt };
});

const T0 = 1_800_000_000_000;
const hmacOf = (salt: string, code: string) =>
  createHmac('sha256', 'email-code-test-key').update(`${salt}\u0000${code}`).digest('base64url');

function held(code: string, overrides: Partial<HeldEmailCode> = {}): HeldEmailCode {
  const salt = overrides.salt ?? generateEmailCodeSalt();
  return heldEmailCode({
    purpose: 'verify_account',
    length: 6,
    salt,
    hmac: hmacOf(salt, code),
    issuedAt: T0,
    ...overrides,
  });
}

describe('the code (ADR-017 Decision 5)', () => {
  it('is drawn from the CSPRNG: 6 digits after a password, 8 for recovery and registration', () => {
    randomInt.mockClear();
    expect(generateEmailCode(6)).toMatch(/^[0-9]{6}$/);
    expect(generateEmailCode(8)).toMatch(/^[0-9]{8}$/);
    expect(randomInt.mock.calls).toEqual([[1_000_000], [100_000_000]]);
    expect(emailCodeLength('verify_account', { afterPassword: true })).toBe(6);
    expect(emailCodeLength('verify_account', { afterPassword: false })).toBe(8);
    expect(emailCodeLength('recovery', { afterPassword: true })).toBe(8);
    expect(emailCodeLength('confirm_sign_in', { afterPassword: true })).toBe(6);
  });

  it('keeps its leading zeros', () => {
    randomInt.mockReturnValueOnce(42);
    expect(generateEmailCode(6)).toBe('000042');
  });

  it('is held as a salt and an HMAC, never as the code', () => {
    const code = '123456';
    const value = held(code);
    expect(value.salt).toMatch(EMAIL_CODE_SALT_PATTERN);
    expect(value.hmac).toMatch(EMAIL_CODE_HMAC_PATTERN);
    expect(JSON.stringify(value)).not.toContain(code);
    expect(generateEmailCodeSalt()).not.toBe(generateEmailCodeSalt());
  });
});

describe('answering a code', () => {
  it('accepts the right code within its 10 minutes, and not after', () => {
    const code = '654321';
    const value = held(code);
    const right = hmacOf(value.salt, code);
    expect(answerEmailCode(value, right, T0)).toEqual({ kind: 'accepted' });
    expect(answerEmailCode(value, right, T0 + EMAIL_CODE_TTL_MS - 1)).toEqual({
      kind: 'accepted',
    });
    expect(EMAIL_CODE_TTL_MS).toBe(10 * 60 * 1000);
    expect(emailCodeExpired(value, T0 + EMAIL_CODE_TTL_MS)).toBe(true);
    expect(answerEmailCode(value, right, T0 + EMAIL_CODE_TTL_MS)).toEqual({ kind: 'expired' });
  });

  it('counts a wrong code, and the 5th wrong answer burns the code', () => {
    const value = held('111111');
    let current = value;
    for (let wrong = 1; wrong < EMAIL_CODE_MAX_WRONG_ANSWERS; wrong++) {
      const answered = answerEmailCode(current, hmacOf(value.salt, '222222'), T0);
      expect(answered.kind).toBe('wrong');
      if (answered.kind !== 'wrong') return;
      expect(answered.held.wrongAnswers).toBe(wrong);
      current = answered.held;
    }
    expect(EMAIL_CODE_MAX_WRONG_ANSWERS).toBe(5);
    expect(answerEmailCode(current, hmacOf(value.salt, '222222'), T0)).toEqual({
      kind: 'burned',
    });
    // The right code after four wrong ones still works: only the 5th wrong one burns.
    expect(answerEmailCode(current, hmacOf(value.salt, '111111'), T0)).toEqual({
      kind: 'accepted',
    });
  });

  it('keeps the count of wrong answers across a resend', () => {
    const first: HeldEmailCode = { ...held('333333'), wrongAnswers: 3 };
    const salt = generateEmailCodeSalt();
    const resent = heldEmailCode({
      purpose: 'verify_account',
      length: 6,
      salt,
      hmac: hmacOf(salt, '444444'),
      issuedAt: T0 + EMAIL_CODE_RESEND_AFTER_MS,
      previous: first,
    });
    expect(resent.wrongAnswers).toBe(3);
    expect(answerEmailCode(resent, hmacOf(salt, '000000'), resent.issuedAt)).toMatchObject({
      kind: 'wrong',
      held: { wrongAnswers: 4 },
    });
    // The old code is gone with its HMAC.
    expect(answerEmailCode(resent, hmacOf(salt, '333333'), resent.issuedAt).kind).toBe('wrong');
  });

  it('compares HMACs of one shape only', () => {
    const value = held('555555');
    expect(sameEmailCodeHmac(value.hmac, value.hmac)).toBe(true);
    expect(sameEmailCodeHmac('', value.hmac)).toBe(false);
    expect(sameEmailCodeHmac(`${value.hmac}A`, value.hmac)).toBe(false);
    expect(sameEmailCodeHmac('555555', value.hmac)).toBe(false);
  });
});

describe('the step params', () => {
  it('say how long the code has left and when another may be asked for', () => {
    const value = held('666666');
    expect(emailCodeParams(value, T0)).toEqual({
      purpose: 'verify_account',
      length: 6,
      expires_in: 600,
      resend_after: 60,
    });
    expect(emailCodeResendDue(value, T0 + 59_999)).toBe(false);
    expect(emailCodeResendDue(value, T0 + 60_000)).toBe(true);
    expect(emailCodeParams(value, T0 + 90_500)).toEqual({
      purpose: 'verify_account',
      length: 6,
      expires_in: 510,
      resend_after: 0,
    });
    // An expired code says what a new one gets.
    expect(emailCodeParams(value, T0 + EMAIL_CODE_TTL_MS)).toMatchObject({
      expires_in: 600,
      resend_after: 0,
    });
  });
});
