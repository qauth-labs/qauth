import {
  REGISTRATION_NOT_ALLOWED,
  RESET_NOT_ALLOWED,
  type RoundResult,
  type SignInTransaction,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyReply } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));

import { codeMailOf, decisionOf } from './interaction-engines';
import { InteractionExpiredError } from './interaction-expired';

/**
 * The interaction's next state for an engine round, and the mail of a code,
 * for a registration (#640) and a password reset (#642). The rounds themselves are the engine's
 * (`registration.test.ts` in the engine library).
 */

const reply = { header: vi.fn() } as unknown as FastifyReply;
const RECEIVED_AT = 1_700_000_000_000;
const TRANSACTION: SignInTransaction = {
  v: 1,
  realmId: 'realm-1',
  clientId: 'notes-app',
  createdAt: RECEIVED_AT,
  identifier: 'new@example.com',
  verified: [],
  flow: 'register',
};

describe('decisionOf: a registration (#640)', () => {
  it('finishes the interaction for the new account, with no browser session', () => {
    const result: RoundResult = {
      kind: 'complete',
      transaction: null,
      signIn: { subject: 'user-new', identifier: 'new@example.com', registered: true },
    };

    expect(decisionOf(reply, result, RECEIVED_AT)).toEqual({
      kind: 'registered',
      userId: 'user-new',
    });
  });

  it('still signs a completed sign-in in, with its amr, under a new browser session', () => {
    const result: RoundResult = {
      kind: 'complete',
      transaction: null,
      signIn: { subject: 'user-1', identifier: 'a@example.com', amr: ['pwd'], authTime: 1 },
    };

    expect(decisionOf(reply, result, RECEIVED_AT)).toEqual({
      kind: 'authenticated',
      signIn: {
        userId: 'user-1',
        identifier: 'a@example.com',
        amr: ['pwd'],
        issuedAt: RECEIVED_AT,
      },
    });
  });

  it('ends the interaction as an expired one when registration closed since it started', () => {
    const result: RoundResult = {
      kind: 'refused',
      reason: 'request_refused',
      code: REGISTRATION_NOT_ALLOWED,
      transaction: TRANSACTION,
    };

    expect(() => decisionOf(reply, result, RECEIVED_AT)).toThrow(InteractionExpiredError);
  });

  it('answers any other request refusal as an engine fault', () => {
    const result: RoundResult = {
      kind: 'refused',
      reason: 'request_refused',
      code: 'something_else',
      transaction: TRANSACTION,
    };

    expect(() => decisionOf(reply, result, RECEIVED_AT)).toThrow(/something_else/);
    expect(() => decisionOf(reply, result, RECEIVED_AT)).not.toThrow(InteractionExpiredError);
  });
});

describe('codeMailOf: what a code mail says about its address (#640)', () => {
  const MAIL = {
    realmId: 'realm-1',
    address: 'new@example.com',
    purpose: 'verify_account',
    code: '12345678',
    expiresInSeconds: 600,
    afterFirstFactor: false,
  } as const;

  it('mails the plain code to a new address, as to a sign-in', () => {
    const plain = {
      template: 'code',
      purpose: 'verify_account',
      code: '12345678',
      expiresInSeconds: 600,
    };
    expect(codeMailOf({ ...MAIL, registration: 'new_address' })).toEqual(plain);
    expect(codeMailOf(MAIL)).toEqual(plain);
  });

  it('mails the code with the account-exists notice to an address that has an account', () => {
    expect(codeMailOf({ ...MAIL, registration: 'account_exists' })).toEqual({
      template: 'account_exists',
      code: '12345678',
      expiresInSeconds: 600,
    });
  });

  it("mails nothing to a disabled account's address", () => {
    expect(codeMailOf({ ...MAIL, registration: 'withheld' })).toBeUndefined();
  });
});

describe('a password reset (#642)', () => {
  const RESET_TRANSACTION: SignInTransaction = {
    ...TRANSACTION,
    identifier: 'alice@example.com',
    subject: 'user-1',
    verified: [{ step: 'password_reset', params: {} }],
    flow: 'reset',
  };

  it('finishes the interaction for the account as a registration does: no session, no amr, no auth_time', () => {
    const result: RoundResult = {
      kind: 'complete',
      transaction: null,
      signIn: { subject: 'user-1', identifier: 'alice@example.com', recovered: true },
    };

    expect(decisionOf(reply, result, RECEIVED_AT)).toEqual({
      kind: 'registered',
      userId: 'user-1',
    });
  });

  it('ends the interaction as an expired one when the client may no longer reset', () => {
    const result: RoundResult = {
      kind: 'refused',
      reason: 'request_refused',
      code: RESET_NOT_ALLOWED,
      transaction: RESET_TRANSACTION,
    };

    expect(() => decisionOf(reply, result, RECEIVED_AT)).toThrow(InteractionExpiredError);
  });

  it('mails the recovery code to an account it may reset, and nothing to any other address', () => {
    const mail = {
      realmId: 'realm-1',
      address: 'alice@example.com',
      purpose: 'recovery',
      code: '12345678',
      expiresInSeconds: 600,
      afterFirstFactor: false,
    } as const;

    expect(codeMailOf({ ...mail, reset: 'account' })).toEqual({
      template: 'code',
      purpose: 'recovery',
      code: '12345678',
      expiresInSeconds: 600,
    });
    expect(codeMailOf({ ...mail, reset: 'withheld' })).toBeUndefined();
  });
});
