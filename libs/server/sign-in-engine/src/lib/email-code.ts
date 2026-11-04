import { randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

import type { StepParams } from '@qauth-labs/server-step-grammar';

/**
 * THE EMAIL CODE (PRO-15, #638; ADR-017 Decision 5): a code mailed to an
 * address proves control of that mailbox. It verifies an account's address
 * and recovers an account; it is never a sign-in factor, so it adds no `amr`
 * value, never counts toward `mfa` and never moves `auth_time` (NIST SP
 * 800-63B-4 §3.1.3.1 does not allow email as an authenticator).
 *
 * This module holds the code's rules as pure functions of a held code and the
 * clock: how a code is made, how long it lives, when another may be asked
 * for, and what a wrong answer does. The engine applies them
 * (`engine.ts`); nothing here does I/O but the CSPRNG.
 *
 * - A code is drawn from a CSPRNG (`crypto.randomInt`, unbiased): 6 digits
 *   after a password, 8 for recovery and registration, where the code alone
 *   creates a verified binding or unlocks a reset.
 * - The transaction holds only its keyed HMAC, under a salt of its own, never
 *   the code; an answer is compared HMAC to HMAC, in constant time.
 * - It lives {@link EMAIL_CODE_TTL_MS} (10 minutes), works once, belongs to
 *   the transaction that asked for it, and is burned at the
 *   {@link EMAIL_CODE_MAX_WRONG_ANSWERS}th wrong answer of that transaction.
 *   A new code ({@link EMAIL_CODE_RESEND_AFTER_MS} after the last) keeps the
 *   transaction's count of wrong answers: a resend never resets it.
 */

/** Why a code was sent: the step grammar's purposes. */
export type EmailCodePurpose = StepParams<'email_code'>['purpose'];

/** How many digits a code has. */
export type EmailCodeLength = StepParams<'email_code'>['length'];

/** How long a code is valid, from when it was issued: 10 minutes (ADR-017 Decision 5). */
export const EMAIL_CODE_TTL_MS = 10 * 60 * 1000;

/** The wrong answers that burn a transaction's code: the 5th (ADR-017 Decision 5). */
export const EMAIL_CODE_MAX_WRONG_ANSWERS = 5;

/**
 * How long after a code another may be asked for: a minute, as ADR-017
 * Decision 3's example offers it. The send caps of PRO-14 still count every
 * code.
 */
export const EMAIL_CODE_RESEND_AFTER_MS = 60 * 1000;

/** The bytes of a code's salt: 128 bits, base64url (22 characters). */
const SALT_BYTES = 16;

/** A code's salt, as the transaction holds it. */
export const EMAIL_CODE_SALT_PATTERN = /^[A-Za-z0-9_-]{22}$/;

/** A code's HMAC: HMAC-SHA-256, base64url without padding (43 characters). */
export const EMAIL_CODE_HMAC_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/**
 * How many digits a code for `purpose` has: 8 where the code alone creates a
 * verified binding or unlocks a reset (recovery, registration), 6 after a
 * correct password (an account's verification, the FiPA endpoint's
 * `confirm_sign_in`).
 */
export function emailCodeLength(
  purpose: EmailCodePurpose,
  options: { readonly afterPassword: boolean }
): EmailCodeLength {
  if (purpose === 'recovery') return 8;
  if (purpose === 'confirm_sign_in') return 6;
  return options.afterPassword ? 6 : 8;
}

/** A new code of `length` digits, from the CSPRNG. Leading zeros are digits too. */
export function generateEmailCode(length: EmailCodeLength): string {
  return String(randomInt(10 ** length)).padStart(length, '0');
}

/** A new code's salt: 16 CSPRNG bytes, base64url. */
export function generateEmailCodeSalt(): string {
  return randomBytes(SALT_BYTES).toString('base64url');
}

/**
 * A code as the transaction holds it: its purpose and length, its salt, its
 * keyed HMAC and when it was issued, never the code itself; and the count of
 * the transaction's wrong answers, which a new code keeps.
 */
export interface HeldEmailCode {
  readonly purpose: EmailCodePurpose;
  readonly length: EmailCodeLength;
  /** The code's own salt, {@link EMAIL_CODE_SALT_PATTERN}. */
  readonly salt: string;
  /** The code's keyed HMAC under its salt, {@link EMAIL_CODE_HMAC_PATTERN}. */
  readonly hmac: string;
  /** When the code was issued, in epoch milliseconds. */
  readonly issuedAt: number;
  /** The wrong answers the transaction counted for its codes, below {@link EMAIL_CODE_MAX_WRONG_ANSWERS}. */
  readonly wrongAnswers: number;
}

/** Whether `held` has passed its {@link EMAIL_CODE_TTL_MS} at `now`. */
export function emailCodeExpired(held: HeldEmailCode, now: number): boolean {
  return now - held.issuedAt >= EMAIL_CODE_TTL_MS;
}

/** Whether another code may be asked for at `now`: {@link EMAIL_CODE_RESEND_AFTER_MS} after `held`. */
export function emailCodeResendDue(held: HeldEmailCode, now: number): boolean {
  return now - held.issuedAt >= EMAIL_CODE_RESEND_AFTER_MS;
}

/** Whole seconds until `at`, at least `min` and at most `max`. */
function secondsUntil(at: number, now: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.ceil((at - now) / 1000)));
}

/**
 * The `email_code` step's params for `held` at `now`: how many seconds the
 * code has left (at most 600) and how many until another may be asked for. A
 * code that has expired says what a new one gets: its whole lifetime, and no
 * wait for it.
 */
export function emailCodeParams(held: HeldEmailCode, now: number): StepParams<'email_code'> {
  const ttlSeconds = EMAIL_CODE_TTL_MS / 1000;
  if (emailCodeExpired(held, now)) {
    return { purpose: held.purpose, length: held.length, expires_in: ttlSeconds, resend_after: 0 };
  }
  return {
    purpose: held.purpose,
    length: held.length,
    expires_in: secondsUntil(held.issuedAt + EMAIL_CODE_TTL_MS, now, 1, ttlSeconds),
    resend_after: secondsUntil(
      held.issuedAt + EMAIL_CODE_RESEND_AFTER_MS,
      now,
      0,
      EMAIL_CODE_RESEND_AFTER_MS / 1000
    ),
  };
}

/**
 * Whether two HMACs are one, in constant time: decoded, of one length, equal
 * byte for byte. A value out of shape is no match.
 */
export function sameEmailCodeHmac(presented: string, held: string): boolean {
  if (!EMAIL_CODE_HMAC_PATTERN.test(presented) || !EMAIL_CODE_HMAC_PATTERN.test(held)) return false;
  const left = Buffer.from(presented, 'base64url');
  const right = Buffer.from(held, 'base64url');
  return left.length === right.length && timingSafeEqual(left, right);
}

/** What an answer did to a held code. */
export type EmailCodeAnswer =
  /** The right code, within its time: it is consumed, and the transaction holds no code. */
  | { readonly kind: 'accepted' }
  /** A wrong code: the transaction holds `held`, which counts it. */
  | { readonly kind: 'wrong'; readonly held: HeldEmailCode }
  /** The {@link EMAIL_CODE_MAX_WRONG_ANSWERS}th wrong answer: the code is burned, and the transaction ends. */
  | { readonly kind: 'burned' }
  /** The code has passed its time: nothing was compared or counted, and `held` stays. */
  | { readonly kind: 'expired' };

/**
 * Answer `held` at `now` with `presentedHmac`, the answered code's HMAC under
 * `held.salt`. An expired code compares nothing; a right one is accepted
 * once; a wrong one counts, and the {@link EMAIL_CODE_MAX_WRONG_ANSWERS}th
 * burns the code.
 */
export function answerEmailCode(
  held: HeldEmailCode,
  presentedHmac: string,
  now: number
): EmailCodeAnswer {
  if (emailCodeExpired(held, now)) return { kind: 'expired' };
  if (sameEmailCodeHmac(presentedHmac, held.hmac)) return { kind: 'accepted' };
  const wrongAnswers = held.wrongAnswers + 1;
  if (wrongAnswers >= EMAIL_CODE_MAX_WRONG_ANSWERS) return { kind: 'burned' };
  return { kind: 'wrong', held: Object.freeze({ ...held, wrongAnswers }) };
}

/**
 * A new code in place of `previous`, if any: its salt, HMAC and issue time,
 * with the wrong answers `previous` counted, so a resend never resets them.
 */
export function heldEmailCode(input: {
  readonly purpose: EmailCodePurpose;
  readonly length: EmailCodeLength;
  readonly salt: string;
  readonly hmac: string;
  readonly issuedAt: number;
  readonly previous?: HeldEmailCode;
}): HeldEmailCode {
  return Object.freeze({
    purpose: input.purpose,
    length: input.length,
    salt: input.salt,
    hmac: input.hmac,
    issuedAt: input.issuedAt,
    wrongAnswers: input.previous?.wrongAnswers ?? 0,
  });
}
