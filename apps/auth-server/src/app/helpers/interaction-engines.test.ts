import {
  REGISTRATION_NOT_ALLOWED,
  RESET_NOT_ALLOWED,
  type RoundResult,
  type SignInTransaction,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyReply } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));

import type { InteractionState } from './interaction';
import { codeMailOf, decisionOf, requestRoundFlagsOf } from './interaction-engines';
import { InteractionExpiredError } from './interaction-expired';
import type { InteractionRequest } from './interaction-record';

/**
 * The interaction's next state for an engine round, and the mail of a code,
 * for a registration (#640) and a password reset (#642). The rounds themselves are the engine's
 * (`registration.test.ts` in the engine library).
 */

const reply = { header: vi.fn(), log: { warn: vi.fn() } } as unknown as FastifyReply;
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
      sessionEpoch: 0,
    });
  });

  it('still signs a completed sign-in in, with its amr and auth_time, under a new browser session', () => {
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
        // The engine's time, which the session stores as its `auth_time` (#662).
        authTime: 1,
        issuedAt: RECEIVED_AT,
      },
    });
  });

  it('says the session took a recovery code when the sign-in did, which no amr value says (#663)', () => {
    const result: RoundResult = {
      kind: 'complete',
      transaction: null,
      signIn: {
        subject: 'user-1',
        identifier: 'a@example.com',
        amr: ['pwd'],
        authTime: 1,
        recoveryCode: true,
      },
    };

    expect(decisionOf(reply, result, RECEIVED_AT)).toEqual({
      kind: 'authenticated',
      signIn: {
        userId: 'user-1',
        identifier: 'a@example.com',
        amr: ['pwd'],
        authTime: 1,
        issuedAt: RECEIVED_AT,
        recoveryCodeUsed: true,
      },
    });
  });

  it('names the new credentials the sign-in bound or proved, for the session to record (#1064)', () => {
    const result: RoundResult = {
      kind: 'complete',
      transaction: null,
      signIn: {
        subject: 'user-1',
        identifier: 'a@example.com',
        amr: ['pwd'],
        authTime: 1,
        newCredentials: ['credential-1'],
      },
    };

    expect(decisionOf(reply, result, RECEIVED_AT)).toEqual({
      kind: 'authenticated',
      signIn: {
        userId: 'user-1',
        identifier: 'a@example.com',
        amr: ['pwd'],
        authTime: 1,
        issuedAt: RECEIVED_AT,
        newCredentialIds: ['credential-1'],
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

describe('decisionOf: a sign-in that cannot go on here (#651)', () => {
  it('ends the interaction as an expired one, never a server error, and logs why', () => {
    const result: RoundResult = {
      kind: 'redirect',
      reason: 'step_not_available',
      transaction: null,
    };

    expect(() => decisionOf(reply, result, RECEIVED_AT)).toThrow(InteractionExpiredError);
    expect(reply.log.warn).toHaveBeenCalledWith(
      { reason: 'step_not_available' },
      expect.any(String)
    );
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
      signIn: { subject: 'user-1', identifier: 'alice@example.com', recovered: true, epoch: 4 },
    };

    // The epoch the reset advanced to goes with the request (a later reset ends it).
    expect(decisionOf(reply, result, RECEIVED_AT)).toEqual({
      kind: 'registered',
      userId: 'user-1',
      sessionEpoch: 4,
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

describe('requestRoundFlagsOf: what the request asks of every round (#1106)', () => {
  const REQUEST = {
    response_type: 'code',
    client_id: 'notes-app',
    redirect_uri: 'https://notes.example.com/callback',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    code_challenge_method: 'S256',
  } as InteractionRequest;

  function authorization(
    request: Partial<InteractionRequest> = {},
    upstreamLink?: Extract<InteractionState, { purpose: 'authorization' }>['upstreamLink']
  ): Extract<InteractionState, { purpose: 'authorization' }> {
    return {
      purpose: 'authorization',
      request: { ...REQUEST, ...request },
      ...(upstreamLink === undefined ? {} : { upstreamLink }),
    } as Extract<InteractionState, { purpose: 'authorization' }>;
  }

  const SIGNING_IN = {
    state: 'signing_in',
    provider: 'oidc_corp',
    name: 'Corp',
    externalSub: 'sub-1',
    iss: 'https://corp.example.com',
  } as const;

  it('lets a plain sign-in switch to a registration, and asks for nothing else', () => {
    expect(requestRoundFlagsOf(authorization(), false)).toEqual({ switchFlows: true });
  });

  it('runs a registration for prompt=create, and a fresh sign-in for prompt=login or max_age', () => {
    expect(requestRoundFlagsOf(authorization({ prompt: 'create' }), false)).toEqual({
      flow: 'register',
      switchFlows: true,
    });
    expect(requestRoundFlagsOf(authorization({ prompt: 'login' }), false)).toEqual({
      switchFlows: true,
      freshSignIn: true,
    });
    expect(requestRoundFlagsOf(authorization({ max_age: 0 }), false)).toEqual({
      switchFlows: true,
      freshSignIn: true,
    });
  });

  it('makes the sign-in to link an upstream account a fresh sign-in that withholds the provider it links', () => {
    expect(
      requestRoundFlagsOf(authorization({ prompt: 'create' }, SIGNING_IN as never), true)
    ).toEqual({ freshSignIn: true, withheldUpstream: 'oidc_corp' });
  });

  it('never lets an interaction that holds a link switch flows', () => {
    expect(requestRoundFlagsOf(authorization({}, SIGNING_IN as never), false)).toEqual({});
  });

  it('asks nothing of an account page’s round: its own flags come with it', () => {
    const account = { purpose: 'account', request: {} } as Extract<
      InteractionState,
      { purpose: 'account' }
    >;
    expect(requestRoundFlagsOf(account, false)).toEqual({});
  });
});
