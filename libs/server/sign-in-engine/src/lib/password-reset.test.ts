import { STEP_URNS, type StepName, transactionAmr } from '@qauth-labs/server-step-grammar';
import { describe, expect, it, vi } from 'vitest';

import {
  type FakeAccount,
  FakeAddresses,
  FakeBreachList,
  FakeCodeSender,
  FakeDirectory,
  fakeEmailCodeDigest,
  fakeHash,
  fakeIdentifierDigest,
  FakePasswords,
  FakePasswordUpdates,
  FakePolicy,
  FakeResets,
  FakeSessionEpochs,
  passwordAccount,
  recordingAudit,
} from '../testing/fakes';
import { createMemoryLadder } from '../testing/memory-ladder';
import {
  createSignInEngine,
  RESET_NOT_ALLOWED,
  SIGN_IN_MIN_RESPONSE_TIME_MS,
  type SignInEngineDependencies,
} from './engine';
import type { Clock, SignInAccount } from './ports';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import type { AnyStepHandler } from './steps/handler';
import { readSignInTransaction, type SignInTransaction } from './transaction';

/**
 * The owner's password reset inside the engine (#642; ADR-017 Decision 8;
 * `graphs/flows/core/password-reset/flow.yaml`): the mailbox first, then any
 * other authenticator, then the new password, and the session epoch.
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'notes-web';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const OTHER_USER = '0199fa20-5e1a-7000-8000-000000000002';
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
  accounts: readonly [string, FakeAccount][] = [[ADDRESS, passwordAccount(USER, PASSWORD)]],
  options: Partial<SignInEngineDependencies> = {}
) {
  const directory = new FakeDirectory(new Map(accounts));
  const clock = manualClock();
  const ladder = createMemoryLadder(() => clock.now());
  const epochs = new FakeSessionEpochs();
  const resets = new FakeResets(directory, epochs, () => clock.now());
  const updates = new FakePasswordUpdates(directory);
  const engine = createSignInEngine({
    accounts: directory,
    passwords: new FakePasswords(),
    policy: new FakePolicy(),
    identifierDigest: fakeIdentifierDigest,
    requireVerifiedAccount: false,
    emailCodes: { digest: fakeEmailCodeDigest, addresses: new FakeAddresses(directory) },
    passwordUpdates: updates,
    breachCheck: new FakeBreachList(new Set([LISTED])),
    resets,
    sessionEpochs: epochs,
    hooks: { ladder },
    clock,
    ...options,
  });
  return { engine, directory, sender: new FakeCodeSender(), resets, epochs, updates, clock };
}
type Built = ReturnType<typeof build>;

type Ctx = RoundContext & { readonly records: ReturnType<typeof recordingAudit>['records'] };

function context(built: Built, overrides: Partial<RoundContext> = {}): Ctx {
  const audit = recordingAudit();
  return {
    realm: { id: REALM },
    client: { id: CLIENT },
    audit: audit.sink,
    records: audit.records,
    sendCode: built.sender.send,
    ...overrides,
  };
}

function answer(step: StepName, fields: Record<string, unknown>): RoundAnswer {
  return { step: STEP_URNS[step], fields };
}

const startAnswer = (address?: string) =>
  answer('password_reset', address === undefined ? {} : { login_hint: address });
const codeAnswer = (otp?: string) => answer('email_code', otp === undefined ? {} : { otp });
const newPasswordAnswer = (password: string) => answer('new_password', { new_password: password });

/** The transaction a result keeps; fails the test when it keeps none. */
function kept(result: RoundResult): SignInTransaction {
  if (result.transaction === null) throw new Error(`${result.kind} kept no transaction`);
  return result.transaction;
}

/** A wrong code of eight digits: never the one mailed. */
const wrongCode = (right: string) => (right === '00000000' ? '11111111' : '00000000');

const PASSWORD_STEP_WITH_RESET = {
  current: { step: 'password', params: {} },
  alternatives: [{ step: 'password_reset', params: {} }],
};

const RECOVERY_CODE = { step: 'email_code', params: { purpose: 'recovery', length: 8 } };

const RESET_PASSWORD_STEP = {
  step: 'new_password',
  params: { purpose: 'reset', min_length: 15, max_length: 256 },
};

/** Round 0 with the address, as the authorization request's login_hint: the password step. */
async function passwordStep(built: Built, ctx: Ctx, address = ADDRESS): Promise<RoundResult> {
  return built.engine.advance(null, null, { ...ctx, loginHint: address });
}

/** The password step, then its reset: the code's round. */
async function toCode(built: Built, ctx: Ctx, address = ADDRESS): Promise<RoundResult> {
  const first = await passwordStep(built, ctx, address);
  return built.engine.advance(kept(first), startAnswer(), ctx);
}

/** Through the code: the round that follows the mailbox proof. */
async function toAfterCode(built: Built, ctx: Ctx): Promise<RoundResult> {
  const code = await toCode(built, ctx);
  return built.engine.advance(kept(code), codeAnswer(built.sender.last), ctx);
}

/** A second factor that proves `userId` for any six digits, usable while the account holds an enabled one. */
function fakeTotp(userId = USER) {
  const verify = vi.fn(async () => ({
    kind: 'proved' as const,
    account: { userId, enabled: true, verified: true },
  }));
  const handler = {
    step: 'totp',
    role: 'second_factor',
    factor: 'totp',
    usableBy: (account: SignInAccount) =>
      account.factors.some((factor) => factor.type === 'totp' && !factor.disabled),
    params: () => ({ digits: 6 }),
    verify,
  } as unknown as AnyStepHandler;
  return { handler, verify };
}

describe('the reset offered at the password step', () => {
  it('stands beside the password, the same for every address', async () => {
    const built = build([
      [ADDRESS, passwordAccount(USER, PASSWORD)],
      ['dora@example.com', passwordAccount(OTHER_USER, PASSWORD, { enabled: false })],
    ]);
    const known = await passwordStep(built, context(built));
    const unknown = await passwordStep(built, context(built), 'nobody@example.com');
    const disabled = await passwordStep(built, context(built), 'dora@example.com');
    for (const result of [known, unknown, disabled]) {
      expect(result).toMatchObject({ kind: 'step', offer: PASSWORD_STEP_WITH_RESET });
    }
    expect(built.resets.gates).toEqual([
      { realmId: REALM, clientId: CLIENT },
      { realmId: REALM, clientId: CLIENT },
      { realmId: REALM, clientId: CLIENT },
    ]);
  });

  it('is never offered under max_age or prompt=login', async () => {
    const built = build();
    const result = await passwordStep(built, context(built, { freshSignIn: true }));
    expect(result).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'password' }, alternatives: [] },
    });
  });

  it('is not offered while the client may not reset, nor when the transport cannot serve it', async () => {
    const built = build();
    built.resets.allows = false;
    expect(await passwordStep(built, context(built))).toMatchObject({
      offer: { alternatives: [] },
    });
    built.resets.allows = true;
    const narrow = context(built, { serves: ['identifier', 'password', 'email_code'] });
    expect(await passwordStep(built, narrow)).toMatchObject({ offer: { alternatives: [] } });
  });

  it('is not offered by an engine without the reset port', async () => {
    const built = build(undefined, { resets: undefined });
    expect(await passwordStep(built, context(built))).toMatchObject({
      offer: { current: { step: 'password' }, alternatives: [] },
    });
  });
});

describe('the reset’s first code', () => {
  it('turns the sign-in into a reset and mails an 8-digit recovery code to an enabled account', async () => {
    const built = build();
    const ctx = context(built);
    const result = await toCode(built, ctx);
    expect(result).toMatchObject({
      kind: 'step',
      offer: { current: RECOVERY_CODE, alternatives: [] },
      personal: { identifier: ADDRESS },
    });
    const transaction = kept(result);
    expect(transaction.flow).toBe('reset');
    expect(transaction.verified).toEqual([{ step: 'password_reset', params: {} }]);
    expect(transaction.subject).toBeUndefined();
    expect(built.sender.sent).toEqual([
      expect.objectContaining({
        address: ADDRESS,
        purpose: 'recovery',
        afterFirstFactor: false,
        reset: 'account',
      }),
    ]);
    expect(built.sender.last).toMatch(/^[0-9]{8}$/);
    // The request's login_hint answered the identifier step; the reset's start is audited after it.
    expect(ctx.records).toEqual([
      { outcome: 'passed', step: 'identifier', identifierHmac: expect.any(String) },
      { outcome: 'passed', step: 'password_reset', identifierHmac: expect.any(String) },
    ]);
  });

  it('answers an unknown address, a disabled user and an account without a password alike, and mails none of them', async () => {
    const built = build([
      [ADDRESS, passwordAccount(USER, PASSWORD)],
      ['dora@example.com', passwordAccount(OTHER_USER, PASSWORD, { enabled: false })],
      [
        'pat@example.com',
        { ...passwordAccount('0199fa20-5e1a-7000-8000-000000000003', PASSWORD), password: null },
      ],
    ]);
    const shapes = [];
    for (const address of [ADDRESS, 'nobody@example.com', 'dora@example.com', 'pat@example.com']) {
      const result = await toCode(built, context(built), address);
      if (result.kind !== 'step') throw new Error('not a step');
      shapes.push({ offer: result.offer, personal: { ...result.personal, identifier: 'x' } });
    }
    expect(new Set(shapes.map((shape) => JSON.stringify(shape))).size).toBe(1);
    expect(built.sender.sent.map((mail) => mail.reset)).toEqual([
      'account',
      'withheld',
      'withheld',
      'withheld',
    ]);
  });

  it('takes nothing of a disabled user: its right code is answered as a wrong one', async () => {
    const built = build([[ADDRESS, passwordAccount(USER, PASSWORD, { enabled: false })]]);
    const ctx = context(built);
    const code = await toCode(built, ctx);
    const answered = await built.engine.advance(kept(code), codeAnswer(built.sender.last), ctx);
    expect(answered).toMatchObject({
      kind: 'step',
      offer: { current: { ...RECOVERY_CODE, error: 'invalid_credentials' } },
    });
    expect(kept(answered).subject).toBeUndefined();
    expect(ctx.records.at(-1)).toMatchObject({
      outcome: 'refused',
      step: 'email_code',
      reason: 'account_disabled',
    });
    expect(built.resets.resets).toEqual([]);
  });

  it('takes nothing of an unclaimed account: no mail, and its right code is answered as a wrong one', async () => {
    // Its address was never proved: someone other than the mailbox owner may
    // have created it, and a reset would keep its sub (#641 ends it instead).
    const built = build([[ADDRESS, passwordAccount(USER, PASSWORD, { verified: false })]]);
    const ctx = context(built);
    const code = await toCode(built, ctx);
    expect(built.sender.sent.map((mail) => mail.reset)).toEqual(['withheld']);
    const answered = await built.engine.advance(kept(code), codeAnswer(built.sender.last), ctx);
    expect(answered).toMatchObject({
      kind: 'step',
      offer: { current: { ...RECOVERY_CODE, error: 'invalid_credentials' } },
    });
    expect(kept(answered).subject).toBeUndefined();
    expect(ctx.records.at(-1)).toMatchObject({
      outcome: 'refused',
      step: 'email_code',
      reason: 'account_unclaimed',
    });
    expect(built.resets.resets).toEqual([]);
  });

  it('refuses a wrong code and keeps the transaction', async () => {
    const built = build();
    const ctx = context(built);
    const code = await toCode(built, ctx);
    const wrong = await built.engine.advance(
      kept(code),
      codeAnswer(wrongCode(built.sender.last)),
      ctx
    );
    expect(wrong).toMatchObject({
      kind: 'step',
      offer: { current: { ...RECOVERY_CODE, error: 'invalid_credentials' } },
    });
    expect(kept(wrong).subject).toBeUndefined();
  });

  it('ends the transaction for another address on the reset’s start', async () => {
    const built = build();
    const ctx = context(built);
    const first = await passwordStep(built, ctx);
    const result = await built.engine.advance(kept(first), startAnswer('bob@example.com'), ctx);
    expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(built.sender.sent).toEqual([]);
  });
});

describe('a reset started on its own', () => {
  it('asks for the address alone, then mails the code', async () => {
    const built = build();
    const ctx = context(built, { flow: 'reset' });
    const first = await built.engine.advance(null, null, ctx);
    expect(first).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'password_reset', params: {} }, alternatives: [] },
      personal: {},
    });
    expect(built.sender.sent).toEqual([]);
    const code = await built.engine.advance(kept(first), startAnswer(ADDRESS), ctx);
    expect(code).toMatchObject({ kind: 'step', offer: { current: RECOVERY_CODE } });
    expect(kept(code).identifier).toBe(ADDRESS);
  });

  it('refuses a start that brings no address', async () => {
    const built = build();
    const ctx = context(built, { flow: 'reset' });
    const first = await built.engine.advance(null, null, ctx);
    const result = await built.engine.advance(kept(first), startAnswer(), ctx);
    expect(result).toMatchObject({ kind: 'refused', reason: 'invalid_answer' });
  });

  it('mails the code at once for a request that names the address', async () => {
    const built = build();
    const result = await built.engine.advance(
      null,
      null,
      context(built, { flow: 'reset', loginHint: ADDRESS })
    );
    expect(result).toMatchObject({ kind: 'step', offer: { current: RECOVERY_CODE } });
  });

  it('is answered with a redirect under max_age or prompt=login', async () => {
    const built = build();
    const ctx = context(built);
    const code = await toCode(built, ctx);
    const result = await built.engine.advance(
      kept(code),
      codeAnswer(built.sender.last),
      context(built, { freshSignIn: true })
    );
    expect(result).toEqual({ kind: 'redirect', reason: 'request', transaction: null });
    expect(built.resets.resets).toEqual([]);
  });
});

describe('the reset gate', () => {
  it('is read on every round: closing it refuses the next one with reset_not_allowed', async () => {
    const built = build();
    const ctx = context(built);
    const code = await toCode(built, ctx);
    built.resets.allows = false;
    const closed = context(built);
    const result = await built.engine.advance(kept(code), codeAnswer(built.sender.last), closed);
    expect(result).toMatchObject({
      kind: 'refused',
      reason: 'request_refused',
      code: RESET_NOT_ALLOWED,
    });
    expect(closed.records).toEqual([
      {
        outcome: 'refused',
        step: 'email_code',
        reason: 'reset_closed',
        identifierHmac: expect.any(String),
      },
    ]);
    expect(built.sender.sent).toHaveLength(1);
  });
});

describe('a password-only account', () => {
  it('sets a new password after its code, and completes with no amr and no auth_time', async () => {
    const built = build([
      [
        ADDRESS,
        passwordAccount(USER, PASSWORD, {
          password: { disabled: true, hash: fakeHash(PASSWORD) },
          requiredActions: ['update_password'],
        }),
      ],
    ]);
    const ctx = context(built);
    const afterCode = await toAfterCode(built, ctx);
    expect(afterCode).toMatchObject({
      kind: 'step',
      offer: { current: RESET_PASSWORD_STEP, alternatives: [] },
      personal: { identifier: ADDRESS },
    });
    const transaction = kept(afterCode);
    expect(transaction.subject).toBe(USER);
    expect(transaction.authTime).toBeUndefined();
    // The stored form reads back: a reset holds a subject with no auth_time.
    expect(readSignInTransaction(JSON.parse(JSON.stringify(transaction)))).toEqual(transaction);

    const done = await built.engine.advance(transaction, newPasswordAnswer(NEW_PASSWORD), ctx);
    expect(done).toEqual({
      kind: 'complete',
      transaction: null,
      signIn: { subject: USER, identifier: ADDRESS, recovered: true, epoch: 1 },
    });
    expect(built.resets.resets).toEqual([
      {
        realmId: REALM,
        clientId: CLIENT,
        userId: USER,
        identifier: ADDRESS,
        password: NEW_PASSWORD,
        normalization: 'nfc',
      },
    ]);
    const account = built.directory.accounts.get(ADDRESS);
    expect(account?.password?.hash).toBe(fakeHash(NEW_PASSWORD));
    expect(account?.password?.disabled).toBe(false);
    expect(account?.requiredActions).toEqual([]);
    expect(ctx.records.slice(-2)).toEqual([
      { outcome: 'passed', step: 'email_code', userId: USER },
      { outcome: 'passed', step: 'new_password', userId: USER },
    ]);
  });

  it('keeps the transaction’s amr empty: a reset is no factor', () => {
    expect(
      transactionAmr([
        { step: 'password_reset', params: {} },
        {
          step: 'email_code',
          params: { purpose: 'recovery', length: 8, expires_in: 600, resend_after: 60 },
        },
        { step: 'new_password', params: { purpose: 'reset', min_length: 15, max_length: 256 } },
      ])
    ).toBeUndefined();
  });

  it('refuses a new password the policy or the breach list refuses, and writes nothing', async () => {
    const built = build();
    const ctx = context(built);
    const afterCode = await toAfterCode(built, ctx);
    const short = await built.engine.advance(kept(afterCode), newPasswordAnswer('short'), ctx);
    expect(short).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'new_password', error: 'password_rejected' } },
    });
    const listed = await built.engine.advance(kept(short), newPasswordAnswer(LISTED), ctx);
    expect(listed).toMatchObject({
      kind: 'step',
      offer: {
        current: {
          step: 'new_password',
          params: { purpose: 'reset', reasons: ['blocklisted'] },
          error: 'password_rejected',
        },
      },
    });
    expect(built.resets.resets).toEqual([]);
  });

  it('ends with nothing written when the account was disabled after its code', async () => {
    const built = build();
    const ctx = context(built);
    const afterCode = await toAfterCode(built, ctx);
    const account = built.directory.accounts.get(ADDRESS);
    if (account === undefined) throw new Error('no account');
    built.directory.accounts.set(ADDRESS, { ...account, enabled: false });
    const result = await built.engine.advance(
      kept(afterCode),
      newPasswordAnswer(NEW_PASSWORD),
      ctx
    );
    expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(ctx.records.at(-1)).toMatchObject({ outcome: 'ended', reason: 'account_disabled' });
    expect(built.resets.resets).toEqual([]);
  });

  it('answers no earlier than the floor on every round', async () => {
    const built = build();
    const ctx = context(built);
    const start = built.clock.now();
    await toCode(built, ctx);
    expect(built.clock.now() - start).toBeGreaterThanOrEqual(2 * SIGN_IN_MIN_RESPONSE_TIME_MS);
  });
});

describe('an account with another authenticator', () => {
  it('proves it after the code: email alone never sets a new password', async () => {
    const totp = fakeTotp();
    const built = build(
      [[ADDRESS, passwordAccount(USER, PASSWORD, { others: [{ type: 'totp', disabled: false }] })]],
      { steps: [totp.handler] }
    );
    const ctx = context(built);
    const afterCode = await toAfterCode(built, ctx);
    expect(afterCode).toMatchObject({ kind: 'step', offer: { current: { step: 'totp' } } });
    // A new password before the TOTP is ignored.
    const eager = await built.engine.advance(kept(afterCode), newPasswordAnswer(NEW_PASSWORD), ctx);
    expect(eager).toMatchObject({ kind: 'step', offer: { current: { step: 'totp' } } });
    expect(built.updates.checks).toEqual([]);
    const proved = await built.engine.advance(kept(eager), answer('totp', { otp: '123456' }), ctx);
    expect(totp.verify).toHaveBeenCalledTimes(1);
    expect(proved).toMatchObject({ kind: 'step', offer: { current: RESET_PASSWORD_STEP } });
    const done = await built.engine.advance(kept(proved), newPasswordAnswer(NEW_PASSWORD), ctx);
    expect(done).toEqual({
      kind: 'complete',
      transaction: null,
      signIn: { subject: USER, identifier: ADDRESS, recovered: true, epoch: 1 },
    });
  });

  it('answers a redirect when the transport cannot ask for it, and writes nothing', async () => {
    const built = build([
      [
        ADDRESS,
        passwordAccount(USER, PASSWORD, { others: [{ type: 'passkey', disabled: false }] }),
      ],
    ]);
    const ctx = context(built);
    const result = await toAfterCode(built, ctx);
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
    expect(built.resets.resets).toEqual([]);
  });

  it('counts a disabled one all the same', async () => {
    const totp = fakeTotp();
    const built = build(
      [[ADDRESS, passwordAccount(USER, PASSWORD, { others: [{ type: 'totp', disabled: true }] })]],
      { steps: [totp.handler] }
    );
    const result = await toAfterCode(built, context(built));
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
    expect(totp.verify).not.toHaveBeenCalled();
    expect(built.resets.resets).toEqual([]);
  });

  it('ends the transaction when the authenticator proves another account', async () => {
    const totp = fakeTotp(OTHER_USER);
    const built = build(
      [[ADDRESS, passwordAccount(USER, PASSWORD, { others: [{ type: 'totp', disabled: false }] })]],
      { steps: [totp.handler] }
    );
    const ctx = context(built);
    const afterCode = await toAfterCode(built, ctx);
    const result = await built.engine.advance(
      kept(afterCode),
      answer('totp', { otp: '123456' }),
      ctx
    );
    expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(built.resets.resets).toEqual([]);
  });
});

describe('the flow of a transaction', () => {
  it('never turns a reset into a registration, nor a sign-in into a reset by the request', async () => {
    const built = build();
    const ctx = context(built);
    const code = await toCode(built, ctx);
    expect(
      await built.engine.advance(kept(code), null, context(built, { flow: 'register' }))
    ).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    const signIn = await passwordStep(built, context(built));
    expect(
      await built.engine.advance(kept(signIn), null, context(built, { flow: 'reset' }))
    ).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
  });

  it('refuses a stored reset that went upstream, and a sign-in that holds a subject with no auth_time', async () => {
    const built = build();
    const code = await toCode(built, context(built));
    const stored = JSON.parse(JSON.stringify(kept(code)));
    expect(readSignInTransaction({ ...stored, upstream: { provider: 'oidc_corp' } })).toBeNull();
    expect(readSignInTransaction({ ...stored, subject: USER, flow: undefined })).toBeNull();
    expect(readSignInTransaction({ ...stored, subject: USER })).not.toBeNull();
  });
});

describe('the session epoch', () => {
  /** A password sign-in of an unverified account: its correct password, then its verification code's step. */
  async function provedSignIn(built: Built, ctx: Ctx): Promise<RoundResult> {
    const first = await passwordStep(built, ctx);
    return built.engine.advance(kept(first), answer('password', { password: PASSWORD }), ctx);
  }

  it('ends a transaction that proved the account before its last reset', async () => {
    const built = build([[ADDRESS, passwordAccount(USER, PASSWORD, { verified: false })]]);
    const ctx = context(built);
    const proved = await provedSignIn(built, ctx);
    expect(kept(proved).subject).toBe(USER);
    built.epochs.advance(USER, built.clock.now());
    const next = context(built);
    const result = await built.engine.advance(kept(proved), codeAnswer(built.sender.last), next);
    expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(next.records).toEqual([
      { outcome: 'ended', step: 'email_code', reason: 'reset_since', userId: USER },
    ]);
  });

  it('lets a transaction that began after the reset go on', async () => {
    const built = build([[ADDRESS, passwordAccount(USER, PASSWORD, { verified: false })]]);
    built.epochs.advance(USER, built.clock.now() - 1);
    const ctx = context(built);
    const proved = await provedSignIn(built, ctx);
    const result = await built.engine.advance(kept(proved), codeAnswer(built.sender.last), ctx);
    expect(result).toMatchObject({ kind: 'complete', signIn: { subject: USER } });
    expect(built.epochs.reads).toEqual([USER]);
  });

  it('ends a reset another reset of the same account overtook', async () => {
    const built = build();
    const ctx = context(built);
    const first = await toAfterCode(built, ctx);
    const second = await toAfterCode(built, context(built));
    const done = await built.engine.advance(kept(second), newPasswordAnswer(NEW_PASSWORD), ctx);
    expect(done).toMatchObject({ kind: 'complete', signIn: { recovered: true } });
    const stale = await built.engine.advance(
      kept(first),
      newPasswordAnswer('another amber kite over the harbour'),
      ctx
    );
    expect(stale).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(built.resets.resets).toHaveLength(1);
  });

  it('refuses the round when the epoch cannot be read', async () => {
    const built = build([[ADDRESS, passwordAccount(USER, PASSWORD, { verified: false })]]);
    const ctx = context(built);
    const proved = await provedSignIn(built, ctx);
    vi.spyOn(built.epochs, 'notBefore').mockRejectedValueOnce(new Error('redis and postgres down'));
    const result = await built.engine.advance(kept(proved), codeAnswer(built.sender.last), ctx);
    expect(result).toMatchObject({ kind: 'refused', reason: 'unavailable' });
  });
});
