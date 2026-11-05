import { STEP_URNS, type StepName } from '@qauth-labs/server-step-grammar';
import { describe, expect, it, vi } from 'vitest';

import {
  type FakeAccount,
  FakeAddresses,
  FakeBreachList,
  FakeCodeSender,
  FakeDirectory,
  fakeEmailCodeDigest,
  fakeIdentifierDigest,
  FakePasswords,
  FakePasswordUpdates,
  FakePolicy,
  FakeRegistrations,
  passwordAccount,
  recordingAudit,
} from '../testing/fakes';
import { createMemoryLadder } from '../testing/memory-ladder';
import { EMAIL_CODE_MAX_WRONG_ANSWERS } from './email-code';
import {
  createSignInEngine,
  REGISTRATION_NOT_ALLOWED,
  SIGN_IN_MIN_RESPONSE_TIME_MS,
  type SignInEngineDependencies,
} from './engine';
import type { LimitsHook, LimitVerdict } from './hooks';
import type { Clock } from './ports';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import { readSignInTransaction, type SignInTransaction } from './transaction';

/**
 * Registration inside the engine (#640; ADR-017 Decision 8;
 * `graphs/flows/core/sign-up/flow.yaml`): the mailbox first, then the
 * password, then the account.
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'notes-web';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const PASSWORD = 'correct horse battery staple';
const NEW_PASSWORD = 'seven amber kites over the old harbour';
const LISTED = 'listed amber kites over the old harbour';
const ADDRESS = 'alice@example.com';
const T0 = 1_800_000_000_000;

function manualClock(start = T0): Clock & { advance(ms: number): void } {
  let now = start;
  return {
    now: () => now,
    sleep: async (ms) => {
      now += ms;
    },
    advance: (ms) => {
      now += ms;
    },
  };
}

function build(
  accounts: readonly [string, FakeAccount][] = [],
  options: Partial<SignInEngineDependencies> = {}
) {
  const directory = new FakeDirectory(new Map(accounts));
  const clock = manualClock();
  const ladder = createMemoryLadder(() => clock.now());
  const addresses = new FakeAddresses(directory);
  const registrations = new FakeRegistrations(directory);
  const updates = new FakePasswordUpdates(directory);
  const breachList = new FakeBreachList(new Set([LISTED]));
  const engine = createSignInEngine({
    accounts: directory,
    passwords: new FakePasswords(),
    policy: new FakePolicy(),
    identifierDigest: fakeIdentifierDigest,
    requireVerifiedAccount: false,
    emailCodes: { digest: fakeEmailCodeDigest, addresses },
    passwordUpdates: updates,
    breachCheck: breachList,
    registrations,
    hooks: { ladder },
    clock,
    ...options,
  });
  return {
    engine,
    directory,
    sender: new FakeCodeSender(),
    addresses,
    registrations,
    updates,
    clock,
  };
}
type Built = ReturnType<typeof build>;

type Ctx = RoundContext & { readonly records: ReturnType<typeof recordingAudit>['records'] };

function context(built: Built, overrides: Partial<RoundContext> = {}): Ctx {
  const audit = recordingAudit();
  return {
    realm: { id: REALM },
    client: { id: CLIENT },
    flow: 'register',
    audit: audit.sink,
    records: audit.records,
    sendCode: built.sender.send,
    ...overrides,
  };
}

function answer(step: StepName, fields: Record<string, unknown>): RoundAnswer {
  return { step: STEP_URNS[step], fields };
}

const addressAnswer = (address = ADDRESS) => answer('identifier', { login_hint: address });
const codeAnswer = (otp?: string) => answer('email_code', otp === undefined ? {} : { otp });
const newPasswordAnswer = (password: string) => answer('new_password', { new_password: password });

/** The transaction a result keeps; fails the test when it keeps none. */
function kept(result: RoundResult): SignInTransaction {
  if (result.transaction === null) throw new Error(`${result.kind} kept no transaction`);
  return result.transaction;
}

/** Round 0, then the address: the code's round. */
async function toCode(built: Built, ctx: Ctx, address = ADDRESS): Promise<RoundResult> {
  const first = await built.engine.advance(null, null, ctx);
  return built.engine.advance(kept(first), addressAnswer(address), ctx);
}

/** A wrong code of eight digits: never the one mailed. */
const wrongCode = (right: string) => (right === '00000000' ? '11111111' : '00000000');

describe('a registration round 0', () => {
  it('asks for the address alone', async () => {
    const built = build();
    const ctx = context(built);
    const result = await built.engine.advance(null, null, ctx);
    expect(result).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'identifier', params: {} }, alternatives: [] },
      personal: {},
    });
    expect(kept(result).flow).toBe('register');
    expect(built.sender.sent).toEqual([]);
  });

  it('keeps the flow in the stored transaction, and refuses a registration that went upstream', async () => {
    const built = build();
    const result = await built.engine.advance(null, null, context(built));
    const stored = JSON.parse(JSON.stringify(kept(result)));
    expect(readSignInTransaction(stored)?.flow).toBe('register');
    expect(readSignInTransaction({ ...stored, upstream: { provider: 'oidc_corp' } })).toBeNull();
    expect(readSignInTransaction({ ...stored, flow: 'reset' })).toBeNull();
  });
});

describe('the registration gate', () => {
  it('refuses every round while the realm or the client does not allow it, with nothing mailed', async () => {
    const built = build();
    built.registrations.allows = false;
    const ctx = context(built);
    const result = await built.engine.advance(null, null, ctx);
    expect(result).toMatchObject({
      kind: 'refused',
      reason: 'request_refused',
      code: REGISTRATION_NOT_ALLOWED,
    });
    expect(ctx.records).toEqual([
      { outcome: 'refused', step: 'identifier', reason: 'registration_closed' },
    ]);
    expect(built.sender.sent).toEqual([]);
    expect(built.registrations.gates).toEqual([{ realmId: REALM, clientId: CLIENT }]);
  });

  it('is read again on every round: closing it mid-flow refuses the next one', async () => {
    const built = build();
    const ctx = context(built);
    const code = await toCode(built, ctx);
    expect(code.kind).toBe('step');
    built.registrations.allows = false;
    const result = await built.engine.advance(kept(code), codeAnswer(built.sender.last), ctx);
    expect(result).toMatchObject({ kind: 'refused', code: REGISTRATION_NOT_ALLOWED });
    expect(built.registrations.gates).toHaveLength(3);
    expect(built.registrations.created).toEqual([]);
  });

  it('sends the person elsewhere when the engine cannot register', async () => {
    const built = build([], { registrations: undefined });
    const result = await built.engine.advance(null, null, context(built));
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
  });

  it('sends the person elsewhere when the transport cannot serve the steps', async () => {
    const built = build();
    const result = await built.engine.advance(
      null,
      null,
      context(built, { serves: ['identifier', 'password'] })
    );
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
  });
});

describe('a registration keeps its flow', () => {
  it('ends a registration handed to a sign-in round, and a sign-in handed to a registration', async () => {
    const built = build();
    const registration = await built.engine.advance(null, null, context(built));
    const asSignIn = context(built, { flow: undefined });
    expect(await built.engine.advance(kept(registration), null, asSignIn)).toMatchObject({
      kind: 'refused',
      reason: 'transaction_ended',
    });
    expect(asSignIn.records).toEqual([
      { outcome: 'ended', step: 'identifier', reason: 'transaction_invalid' },
    ]);
    const signIn = await built.engine.advance(null, null, context(built, { flow: undefined }));
    expect(await built.engine.advance(kept(signIn), null, context(built))).toMatchObject({
      kind: 'refused',
      reason: 'transaction_ended',
    });
  });
});

describe('the first answer: the mailbox', () => {
  it('mails a new address an 8-digit verify_account code, with no account created', async () => {
    const built = build();
    const ctx = context(built);
    const result = await toCode(built, ctx);
    expect(result).toMatchObject({
      kind: 'step',
      offer: {
        current: {
          step: 'email_code',
          params: { purpose: 'verify_account', length: 8, expires_in: 600, resend_after: 60 },
        },
        alternatives: [],
      },
      personal: { identifier: ADDRESS },
    });
    expect(built.sender.sent).toEqual([
      {
        realmId: REALM,
        address: ADDRESS,
        purpose: 'verify_account',
        code: expect.stringMatching(/^[0-9]{8}$/),
        expiresInSeconds: 600,
        afterFirstFactor: false,
        registration: 'new_address',
      },
    ]);
    expect(built.registrations.created).toEqual([]);
    expect(built.directory.accounts.size).toBe(0);
  });

  it('answers an existing address and a disabled one exactly as a new one, in body and in time', async () => {
    const results: { result: unknown; elapsed: number }[] = [];
    for (const account of [
      undefined,
      passwordAccount(USER, PASSWORD),
      passwordAccount(USER, PASSWORD, { verified: false }),
      passwordAccount(USER, PASSWORD, { enabled: false }),
    ]) {
      const built = build(account === undefined ? [] : [[ADDRESS, account]]);
      const ctx = context(built);
      const first = await built.engine.advance(null, null, ctx);
      const before = built.clock.now();
      const result = await built.engine.advance(kept(first), addressAnswer(), ctx);
      if (result.kind !== 'step') throw new Error(result.kind);
      results.push({
        result: { offer: result.offer, personal: result.personal },
        elapsed: built.clock.now() - before,
      });
    }
    for (const entry of results.slice(1)) expect(entry).toEqual(results[0]);
    expect(results[0]?.elapsed).toBe(SIGN_IN_MIN_RESPONSE_TIME_MS);
  });

  it('tells only the mail that an account holds the address', async () => {
    const built = build([[ADDRESS, passwordAccount(USER, PASSWORD)]]);
    await toCode(built, context(built));
    expect(built.sender.sent).toEqual([
      expect.objectContaining({ registration: 'account_exists', afterFirstFactor: false }),
    ]);
  });

  it('caps registration starts on the first code only', async () => {
    const reserveRegistrationStart = vi.fn(async (): Promise<LimitVerdict> => ({
      kind: 'continue',
    }));
    const limits: LimitsHook = {
      round: async () => ({ kind: 'continue' }),
      reserve: async () => ({ kind: 'reserved', settle: async () => undefined }),
      reserveRegistrationStart,
    };
    const ladder = createMemoryLadder(() => T0);
    const built = build([], { hooks: { limits, ladder } });
    const ctx = context(built, { endUserIp: '192.0.2.10', environment: 'production' });
    const code = await toCode(built, ctx);
    expect(reserveRegistrationStart).toHaveBeenCalledTimes(1);
    expect(reserveRegistrationStart).toHaveBeenCalledWith({
      realmId: REALM,
      clientId: CLIENT,
      environment: 'production',
      endUserIp: '192.0.2.10',
    });
    built.clock.advance(61_000);
    const resent = await built.engine.advance(kept(code), codeAnswer(), ctx);
    expect(resent.kind).toBe('step');
    expect(built.sender.sent).toHaveLength(2);
    expect(reserveRegistrationStart).toHaveBeenCalledTimes(1);

    reserveRegistrationStart.mockResolvedValueOnce({ kind: 'throttled', retryAfterSeconds: 1200 });
    const capped = build([], { hooks: { limits, ladder } });
    const cappedCtx = context(capped);
    const refused = await toCode(capped, cappedCtx);
    expect(refused).toMatchObject({
      kind: 'refused',
      reason: 'throttled',
      retryAfterSeconds: 1200,
    });
    expect(capped.sender.sent).toEqual([]);
    expect(cappedCtx.records.at(-1)).toMatchObject({
      outcome: 'refused',
      step: 'email_code',
      reason: 'rate_limited',
    });
  });

  it('counts a wrong code and burns the code at the fifth', async () => {
    const built = build();
    const ctx = context(built);
    let result = await toCode(built, ctx);
    for (let i = 1; i < EMAIL_CODE_MAX_WRONG_ANSWERS; i += 1) {
      result = await built.engine.advance(
        kept(result),
        codeAnswer(wrongCode(built.sender.last)),
        ctx
      );
      expect(result).toMatchObject({
        kind: 'step',
        offer: { current: { step: 'email_code', error: 'invalid_credentials' } },
      });
    }
    result = await built.engine.advance(
      kept(result),
      codeAnswer(wrongCode(built.sender.last)),
      ctx
    );
    expect(result).toMatchObject({ kind: 'refused', reason: 'transaction_ended' });
    expect(built.registrations.created).toEqual([]);
  });
});

describe('after the code: a new address', () => {
  it('asks for a new password, then creates the verified account with no amr and no auth_time', async () => {
    const built = build();
    const ctx = context(built);
    const code = await toCode(built, ctx);
    const password = await built.engine.advance(kept(code), codeAnswer(built.sender.last), ctx);
    expect(password).toMatchObject({
      kind: 'step',
      offer: {
        current: {
          step: 'new_password',
          params: { purpose: 'register', min_length: 15, max_length: 256 },
        },
        alternatives: [],
      },
      personal: { identifier: ADDRESS },
    });
    // No account exists before the password passes.
    expect(built.registrations.created).toEqual([]);
    expect(built.directory.accounts.size).toBe(0);
    expect(built.addresses.calls).toEqual([]);

    const weak = await built.engine.advance(kept(password), newPasswordAnswer('short'), ctx);
    expect(weak).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'new_password', error: 'password_rejected' } },
    });
    expect(built.registrations.created).toEqual([]);

    const listed = await built.engine.advance(kept(weak), newPasswordAnswer(LISTED), ctx);
    expect(listed).toMatchObject({
      kind: 'step',
      offer: {
        current: {
          step: 'new_password',
          error: 'password_rejected',
          params: { reasons: ['blocklisted'] },
        },
      },
    });

    const done = await built.engine.advance(kept(listed), newPasswordAnswer(NEW_PASSWORD), ctx);
    const created = built.registrations.created[0];
    expect(done).toEqual({
      kind: 'complete',
      transaction: null,
      signIn: { subject: created?.userId, identifier: ADDRESS, registered: true },
    });
    if (done.kind !== 'complete') return;
    expect(done.signIn).not.toHaveProperty('amr');
    expect(done.signIn).not.toHaveProperty('authTime');
    expect(built.registrations.created).toEqual([
      {
        realmId: REALM,
        clientId: CLIENT,
        identifier: ADDRESS,
        password: NEW_PASSWORD,
        normalization: 'nfc',
        userId: created?.userId,
      },
    ]);
    expect(ctx.records.map((record) => [record.outcome, record.step, record.reason])).toEqual([
      ['passed', 'identifier', undefined],
      ['passed', 'email_code', undefined],
      ['refused', 'new_password', 'password_rejected'],
      ['refused', 'new_password', 'password_breached'],
      ['passed', 'new_password', undefined],
    ]);
    expect(ctx.records.at(-1)).toMatchObject({ userId: created?.userId });
  });

  it('ends the transaction when another account took the address meanwhile', async () => {
    const built = build();
    const ctx = context(built);
    const code = await toCode(built, ctx);
    const password = await built.engine.advance(kept(code), codeAnswer(built.sender.last), ctx);
    built.registrations.conflict = true;
    const result = await built.engine.advance(kept(password), newPasswordAnswer(NEW_PASSWORD), ctx);
    expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(ctx.records.at(-1)).toMatchObject({
      outcome: 'ended',
      step: 'new_password',
      reason: 'registration_conflict',
    });
  });
});

describe('after the code: an existing account', () => {
  it('helps a verified account sign in with its password, creating nothing', async () => {
    const built = build([[ADDRESS, passwordAccount(USER, PASSWORD)]]);
    const ctx = context(built);
    const code = await toCode(built, ctx);
    const signIn = await built.engine.advance(kept(code), codeAnswer(built.sender.last), ctx);
    expect(signIn).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'password' } },
    });
    const done = await built.engine.advance(
      kept(signIn),
      answer('password', { password: PASSWORD }),
      ctx
    );
    expect(done).toMatchObject({
      kind: 'complete',
      signIn: { subject: USER, identifier: ADDRESS, amr: ['pwd'], authTime: expect.any(Number) },
    });
    if (done.kind === 'complete') expect(done.signIn.registered).toBeUndefined();
    expect(built.registrations.created).toEqual([]);
    expect(built.addresses.calls).toEqual([]);
  });

  it('verifies an unverified account’s address once its password is proved too', async () => {
    const built = build([[ADDRESS, passwordAccount(USER, PASSWORD, { verified: false })]]);
    const ctx = context(built);
    const code = await toCode(built, ctx);
    const signIn = await built.engine.advance(kept(code), codeAnswer(built.sender.last), ctx);
    const done = await built.engine.advance(
      kept(signIn),
      answer('password', { password: PASSWORD }),
      ctx
    );
    expect(done).toMatchObject({ kind: 'complete', signIn: { subject: USER, amr: ['pwd'] } });
    expect(built.addresses.calls).toEqual([{ realmId: REALM, userId: USER, identifier: ADDRESS }]);
    // One code: the registration's proved the mailbox already.
    expect(built.sender.sent).toHaveLength(1);
  });
});

describe('a disabled user', () => {
  it('gets no mail, and every code answered for it is a wrong one, with nothing changed', async () => {
    const built = build([[ADDRESS, passwordAccount(USER, PASSWORD, { enabled: false })]]);
    const ctx = context(built);
    let result = await toCode(built, ctx);
    // The capped sender is told to withhold the mail: counted, never mailed.
    expect(built.sender.sent).toEqual([
      expect.objectContaining({ registration: 'withheld', afterFirstFactor: false }),
    ]);
    for (let i = 1; i < EMAIL_CODE_MAX_WRONG_ANSWERS; i += 1) {
      result = await built.engine.advance(kept(result), codeAnswer(built.sender.last), ctx);
      expect(result).toMatchObject({
        kind: 'step',
        offer: { current: { step: 'email_code', error: 'invalid_credentials' } },
      });
      expect(ctx.records.at(-1)).toMatchObject({
        outcome: 'refused',
        step: 'email_code',
        reason: 'account_disabled',
      });
    }
    result = await built.engine.advance(kept(result), codeAnswer(built.sender.last), ctx);
    expect(result).toMatchObject({ kind: 'refused', reason: 'transaction_ended' });
    expect(built.addresses.calls).toEqual([]);
    expect(built.registrations.created).toEqual([]);
    expect(built.updates.replaced).toEqual([]);
    expect(built.directory.accounts.get(ADDRESS)).toMatchObject({ enabled: false, verified: true });
  });

  it('answers a code mailed before the user was disabled as a wrong one', async () => {
    const built = build([[ADDRESS, passwordAccount(USER, PASSWORD)]]);
    const ctx = context(built);
    const code = await toCode(built, ctx);
    const account = built.directory.accounts.get(ADDRESS);
    if (account === undefined) throw new Error('no account');
    built.directory.accounts.set(ADDRESS, { ...account, enabled: false });
    const result = await built.engine.advance(kept(code), codeAnswer(built.sender.last), ctx);
    expect(result).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'email_code', error: 'invalid_credentials' } },
    });
  });
});
