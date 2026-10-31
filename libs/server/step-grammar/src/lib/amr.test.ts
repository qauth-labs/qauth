import { stepNamed } from '@qauth-labs/shared-interaction-contract';
import { describe, expect, it } from 'vitest';

import { transactionAmr } from './amr';
import { StepMappingError } from './mapping-error';
import type { OfferedStep } from './offer';
import type { StepName } from './steps';

/** ADR-017 Decision 10's `amr` table, every row. */

const step = (name: StepName, params: unknown = {}): OfferedStep =>
  ({ step: name, params }) as OfferedStep;
const passkey = step('webauthn_get', stepNamed('webauthn_get').example.step.params);
const passkeyEnrolment = step('webauthn_create', stepNamed('webauthn_create').example.step.params);
const totp = step('totp', { digits: 6 });
const code = (purpose: string, length: number) =>
  step('email_code', { purpose, length, expires_in: 600, resend_after: 60 });
const newPassword = (purpose: string) =>
  step('new_password', { purpose, min_length: 15, max_length: 256 });

describe('a transaction’s amr', () => {
  it('password, with or without the post-password email check: ["pwd"]', () => {
    expect(transactionAmr([step('identifier'), step('password')])).toEqual(['pwd']);
    expect(transactionAmr([step('password'), code('confirm_sign_in', 6)])).toEqual(['pwd']);
    // Verifying the address of an account not yet verified, after its password.
    expect(transactionAmr([step('password'), code('verify_account', 6)])).toEqual(['pwd']);
  });

  it('passkey with user verification: ["pop","mfa"]', () => {
    expect(transactionAmr([passkey])).toEqual(['pop', 'mfa']);
  });

  it('password, then passkey (downgrade rule): ["pwd","pop","mfa"]', () => {
    expect(transactionAmr([step('password'), passkey])).toEqual(['pwd', 'pop', 'mfa']);
  });

  it('password and TOTP: ["pwd","otp","mfa"]', () => {
    expect(transactionAmr([step('identifier'), step('password'), totp])).toEqual([
      'pwd',
      'otp',
      'mfa',
    ]);
  });

  it('registration: omitted', () => {
    expect(
      transactionAmr([step('identifier'), code('verify_account', 8), newPassword('register')])
    ).toBeUndefined();
    // A passkey-only account's registration proves the mailbox and binds a
    // passkey; enrolling one authenticates nothing.
    expect(transactionAmr([code('verify_account', 8), passkeyEnrolment])).toBeUndefined();
  });

  it('reset: omitted, even when the account’s second factor was asked for', () => {
    expect(
      transactionAmr([step('password_reset'), code('recovery', 8), newPassword('reset')])
    ).toBeUndefined();
    expect(
      transactionAmr([step('password_reset'), code('recovery', 8), totp, newPassword('reset')])
    ).toBeUndefined();
  });
});

describe('what adds nothing to a transaction’s amr', () => {
  it('a recovery code standing in for a second factor never makes mfa', () => {
    expect(transactionAmr([step('password'), step('recovery_code')])).toEqual(['pwd']);
  });

  it('a forced password update after the sign-in keeps the sign-in’s amr', () => {
    expect(transactionAmr([step('password'), totp, newPassword('update_required')])).toEqual([
      'pwd',
      'otp',
      'mfa',
    ]);
  });

  it('a step verified twice, or in another order, gives the same values in the table’s order', () => {
    expect(transactionAmr([passkey, step('password'), step('password')])).toEqual([
      'pwd',
      'pop',
      'mfa',
    ]);
  });

  it('a transaction with no factor carries none', () => {
    expect(transactionAmr([])).toBeUndefined();
    expect(
      transactionAmr([step('consent', stepNamed('consent').example.step.params)])
    ).toBeUndefined();
  });
});

describe('transactionAmr', () => {
  it('gives a frozen list', () => {
    const amr = transactionAmr([step('password')]);
    expect(Object.isFrozen(amr)).toBe(true);
  });

  it('refuses a step the grammar does not know, params outside its schema and another member', () => {
    for (const verified of [
      [step('sms_code' as never)],
      [step('totp', { digits: 8 })],
      [{ step: 'password', params: {}, amr: ['hwk'] }],
    ]) {
      expect(() => transactionAmr(verified as never)).toThrow(StepMappingError);
    }
  });
});
