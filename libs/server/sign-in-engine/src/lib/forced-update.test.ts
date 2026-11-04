import { STEP_URNS, type StepName } from '@qauth-labs/server-step-grammar';
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
  passwordAccount,
  recordingAudit,
} from '../testing/fakes';
import { createSignInEngine, type SignInEngineDependencies } from './engine';
import type { Clock } from './ports';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import type { AnyStepHandler } from './steps/handler';
import { readSignInTransaction, type SignInTransaction } from './transaction';

/**
 * The breach-list check and the forced password update (#635; ADR-017
 * Decision 4 rule 8 and Decision 8, ADR-020 §3;
 * `graphs/flows/core/sign-in/flow.yaml`).
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'native-app';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
/** On the fake breach list. */
const LISTED = 'correct horse battery staple';
/** Not on it. */
const UNLISTED = 'a quiet violet tram crosses nine rivers';
/** A new password the policy accepts and the list does not hold. */
const NEW_PASSWORD = 'seven amber kites over the old harbour';
/** A new password the policy accepts and the list holds. */
const NEW_LISTED = 'purple monkey dishwasher on tuesday';
const IDENTIFIER = 'alice@example.com';
const T0 = 1_800_000_000_000;

function manualClock(start = T0): Clock {
  let now = start;
  return {
    now: () => now,
    sleep: async (ms) => {
      now += ms;
    },
  };
}

interface Built {
  readonly engine: ReturnType<typeof createSignInEngine>;
  readonly directory: FakeDirectory;
  readonly sender: FakeCodeSender;
  readonly addresses: FakeAddresses;
  readonly policy: FakePolicy;
  readonly breachList: FakeBreachList;
  readonly updates: FakePasswordUpdates;
}

function build(
  account: FakeAccount = passwordAccount(USER, LISTED),
  options: Partial<SignInEngineDependencies> = {}
): Built {
  const directory = new FakeDirectory(new Map([[IDENTIFIER, account]]));
  const addresses = new FakeAddresses(directory);
  const policy = new FakePolicy();
  const breachList = new FakeBreachList(new Set([LISTED, NEW_LISTED]));
  const updates = new FakePasswordUpdates(directory);
  const engine = createSignInEngine({
    accounts: directory,
    passwords: new FakePasswords(),
    policy,
    identifierDigest: fakeIdentifierDigest,
    requireVerifiedAccount: true,
    emailCodes: { digest: fakeEmailCodeDigest, addresses },
    breachCheck: breachList,
    passwordUpdates: updates,
    clock: manualClock(),
    ...options,
  });
  return {
    engine,
    directory,
    sender: new FakeCodeSender(),
    addresses,
    policy,
    breachList,
    updates,
  };
}

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

const codeAnswer = (otp: string) => answer('email_code', { otp });
const newPasswordAnswer = (password: string) => answer('new_password', { new_password: password });

/** The transaction a result keeps; fails the test when it keeps none. */
function kept(result: RoundResult): SignInTransaction {
  if (result.transaction === null) throw new Error(`${result.kind} kept no transaction`);
  return result.transaction;
}

/** Round 0 with the login_hint, then `password`. */
async function signIn(
  built: Built,
  password: string,
  ctx: RoundContext = context(built)
): Promise<RoundResult> {
  const first = await built.engine.advance(null, null, { ...ctx, loginHint: IDENTIFIER });
  return built.engine.advance(kept(first), answer('password', { password }), ctx);
}

const UPDATE_STEP = {
  step: 'new_password',
  params: { purpose: 'update_required', min_length: 15, max_length: 256 },
} as const;

/** A TOTP second factor that proves `USER` for any six digits. */
function fakeTotp() {
  const verify = vi.fn(async () => ({
    kind: 'proved' as const,
    account: { userId: USER, enabled: true, verified: true },
  }));
  const handler = {
    step: 'totp',
    role: 'second_factor',
    factor: 'totp',
    usableBy: () => true,
    params: () => ({ digits: 6 }),
    verify,
  } as unknown as AnyStepHandler;
  return { handler, verify };
}

describe('the breach-list check of a presented password', () => {
  it('changes nothing with the setting off: the password completes, nothing is mailed or asked', async () => {
    const built = build();
    built.breachList.off = true;
    const ctx = context(built);
    const result = await signIn(built, LISTED, ctx);
    expect(result).toMatchObject({ kind: 'complete', signIn: { subject: USER, amr: ['pwd'] } });
    expect(built.sender.sent).toEqual([]);
    expect(built.updates.checks).toEqual([]);
    expect(ctx.records.map((record) => record.outcome)).toEqual(['passed', 'passed']);
  });

  it('changes nothing for an engine built without a breach list', async () => {
    const built = build(undefined, { breachCheck: undefined });
    const result = await signIn(built, LISTED);
    expect(result).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd'] } });
    expect(built.breachList.checked).toEqual([]);
  });

  it('checks only a right password, as it was verified', async () => {
    const built = build();
    const wrong = await signIn(built, 'not the password at all, sorry');
    expect(wrong).toMatchObject({
      kind: 'step',
      offer: { current: { error: 'invalid_credentials' } },
    });
    expect(built.breachList.checked).toEqual([]);
    const unknown = build(passwordAccount(USER, UNLISTED));
    unknown.directory.accounts.clear();
    await signIn(unknown, UNLISTED);
    expect(unknown.breachList.checked).toEqual([]);
    const right = build(passwordAccount(USER, UNLISTED));
    const completed = await signIn(right, UNLISTED);
    expect(completed).toMatchObject({ kind: 'complete' });
    expect(right.breachList.checked).toEqual([{ realmId: REALM, password: UNLISTED }]);
  });

  it('checks the NFC form of a password whose credential records the marker', async () => {
    const typed = 'café au lait on a long grey morning';
    const nfc = typed.normalize('NFC');
    const built = build(
      passwordAccount(USER, nfc, {
        password: { disabled: false, hash: fakeHash(nfc), normalization: 'nfc' },
      })
    );
    const result = await signIn(built, typed);
    expect(result).toMatchObject({ kind: 'complete' });
    expect(built.breachList.checked).toEqual([{ realmId: REALM, password: nfc }]);
  });

  it.each([
    ['a failed check', 'lookup_failed' as const, false],
    ['a port that throws', 'unavailable' as const, true],
  ])('lets the sign-in proceed after %s, and records it', async (_, failure, throws) => {
    const built = build();
    if (throws) built.breachList.throws = true;
    else built.breachList.failure = failure;
    const ctx = context(built);
    const result = await signIn(built, LISTED, ctx);
    expect(result).toMatchObject({ kind: 'complete', signIn: { subject: USER, amr: ['pwd'] } });
    expect(ctx.records).toEqual([
      { outcome: 'passed', step: 'identifier', identifierHmac: expect.any(String) },
      { outcome: 'passed', step: 'password', userId: USER },
      {
        outcome: 'unchecked',
        step: 'password',
        reason: 'breach_check_failed',
        failure,
        userId: USER,
      },
    ]);
  });
});

describe('a listed password on a password-only account', () => {
  it('asks for an 8-digit recovery code first, and no session or code is issued', async () => {
    const built = build();
    const ctx = context(built);
    const result = await signIn(built, LISTED, ctx);
    expect(result).toMatchObject({
      kind: 'step',
      offer: {
        current: { step: 'email_code', params: { purpose: 'recovery', length: 8 } },
        alternatives: [],
      },
      personal: { identifier: IDENTIFIER },
    });
    expect(kept(result).breachedPassword).toBe(true);
    // The transaction's stored form keeps it.
    expect(readSignInTransaction(JSON.parse(JSON.stringify(kept(result))))).toMatchObject({
      breachedPassword: true,
    });
    expect(built.sender.sent).toEqual([
      {
        realmId: REALM,
        address: IDENTIFIER,
        purpose: 'recovery',
        code: expect.stringMatching(/^[0-9]{8}$/),
        expiresInSeconds: 600,
        afterFirstFactor: true,
      },
    ]);
  });

  it('sets no new password without the code: an eager new password is ignored', async () => {
    const built = build();
    const second = await signIn(built, LISTED);
    const eager = await built.engine.advance(
      kept(second),
      newPasswordAnswer(NEW_PASSWORD),
      context(built)
    );
    expect(eager).toMatchObject({ kind: 'step', offer: { current: { step: 'email_code' } } });
    expect(built.updates.checks).toEqual([]);
    expect(built.updates.replaced).toEqual([]);
    // A wrong code is refused, and still no new password is asked for.
    const wrong = await built.engine.advance(
      kept(eager),
      codeAnswer(built.sender.last === '00000000' ? '11111111' : '00000000'),
      context(built)
    );
    expect(wrong).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'email_code', error: 'invalid_credentials' } },
    });
    expect(built.updates.replaced).toEqual([]);
  });

  it('asks for the new password after the code, checks it, and completes once it is set', async () => {
    const built = build();
    const second = await signIn(built, LISTED);
    const ctx = context(built);
    const third = await built.engine.advance(kept(second), codeAnswer(built.sender.last), ctx);
    expect(third).toEqual({
      kind: 'step',
      transaction: kept(third),
      offer: { current: UPDATE_STEP, alternatives: [] },
      personal: { identifier: IDENTIFIER },
    });
    expect(ctx.records).toEqual([{ outcome: 'passed', step: 'email_code', userId: USER }]);

    // A new password the policy refuses.
    const weakCtx = context(built);
    const weak = await built.engine.advance(kept(third), newPasswordAnswer('password'), weakCtx);
    expect(weak).toMatchObject({
      kind: 'step',
      offer: {
        current: {
          step: 'new_password',
          params: { ...UPDATE_STEP.params, reasons: ['too_short', 'blocklisted', 'too_weak'] },
          error: 'password_rejected',
        },
      },
    });
    expect(weakCtx.records).toEqual([
      { outcome: 'refused', step: 'new_password', reason: 'password_rejected', userId: USER },
    ]);

    // A new password on the breach list: the new one must pass the check too.
    const listedCtx = context(built);
    const listed = await built.engine.advance(kept(weak), newPasswordAnswer(NEW_LISTED), listedCtx);
    expect(listed).toMatchObject({
      kind: 'step',
      offer: {
        current: {
          step: 'new_password',
          params: { ...UPDATE_STEP.params, reasons: ['blocklisted'] },
          error: 'password_rejected',
        },
      },
    });
    expect(listedCtx.records).toEqual([
      { outcome: 'refused', step: 'new_password', reason: 'password_breached', userId: USER },
    ]);
    expect(built.updates.replaced).toEqual([]);

    // A good one: replaced, and the sign-in completes with the password's amr.
    const doneCtx = context(built);
    const done = await built.engine.advance(kept(listed), newPasswordAnswer(NEW_PASSWORD), doneCtx);
    expect(done).toEqual({
      kind: 'complete',
      transaction: null,
      signIn: {
        subject: USER,
        identifier: IDENTIFIER,
        amr: ['pwd'],
        authTime: kept(second).authTime,
      },
    });
    expect(built.updates.replaced).toEqual([
      {
        realmId: REALM,
        userId: USER,
        identifier: IDENTIFIER,
        password: NEW_PASSWORD,
        normalization: 'nfc',
      },
    ]);
    expect(built.breachList.checked.map((check) => check.password)).toEqual([
      LISTED,
      NEW_LISTED,
      NEW_PASSWORD,
    ]);
    expect(doneCtx.records).toEqual([{ outcome: 'passed', step: 'new_password', userId: USER }]);
    // The next sign-in with the new password completes at once.
    const next = await signIn(built, NEW_PASSWORD);
    expect(next).toMatchObject({ kind: 'complete' });
  });

  it('accepts a new password whose check fails, and records the failure', async () => {
    const built = build();
    const second = await signIn(built, LISTED);
    const third = await built.engine.advance(
      kept(second),
      codeAnswer(built.sender.last),
      context(built)
    );
    built.breachList.failure = 'lookup_failed';
    const ctx = context(built);
    const done = await built.engine.advance(kept(third), newPasswordAnswer(NEW_PASSWORD), ctx);
    expect(done).toMatchObject({ kind: 'complete' });
    expect(ctx.records).toEqual([
      { outcome: 'passed', step: 'new_password', userId: USER },
      {
        outcome: 'unchecked',
        step: 'new_password',
        reason: 'breach_check_failed',
        failure: 'lookup_failed',
        userId: USER,
      },
    ]);
  });

  it('mails no second code when the inline verification already proved the mailbox', async () => {
    const built = build(passwordAccount(USER, LISTED, { verified: false }));
    const second = await signIn(built, LISTED);
    expect(second).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'email_code', params: { purpose: 'verify_account', length: 6 } } },
    });
    const third = await built.engine.advance(
      kept(second),
      codeAnswer(built.sender.last),
      context(built)
    );
    expect(third).toMatchObject({ kind: 'step', offer: { current: UPDATE_STEP } });
    expect(built.sender.sent).toHaveLength(1);
  });

  it('ends the transaction when the account changed before the write', async () => {
    const built = build();
    const second = await signIn(built, LISTED);
    const third = await built.engine.advance(
      kept(second),
      codeAnswer(built.sender.last),
      context(built)
    );
    built.updates.replace = async () => ({ kind: 'refused', reason: 'account_disabled' });
    const ctx = context(built);
    const ended = await built.engine.advance(kept(third), newPasswordAnswer(NEW_PASSWORD), ctx);
    expect(ended).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(ctx.records).toEqual([
      { outcome: 'ended', step: 'new_password', reason: 'account_disabled', userId: USER },
    ]);
  });

  it('refuses the round, writing nothing, when the store fails', async () => {
    const built = build();
    const second = await signIn(built, LISTED);
    const third = await built.engine.advance(
      kept(second),
      codeAnswer(built.sender.last),
      context(built)
    );
    built.updates.replace = async () => {
      throw new Error('database down');
    };
    const refused = await built.engine.advance(
      kept(third),
      newPasswordAnswer(NEW_PASSWORD),
      context(built)
    );
    expect(refused).toMatchObject({ kind: 'refused', reason: 'unavailable' });
    expect(kept(refused).verified.map((step) => step.step)).toEqual(['password', 'email_code']);
  });
});

describe('a listed password on an account with a second factor', () => {
  it('asks for the TOTP first, never a code, and the new password only after it', async () => {
    const totp = fakeTotp();
    const built = build(
      passwordAccount(USER, LISTED, { others: [{ type: 'totp', disabled: false }] }),
      {
        steps: [totp.handler],
      }
    );
    const second = await signIn(built, LISTED);
    expect(second).toMatchObject({ kind: 'step', offer: { current: { step: 'totp' } } });
    expect(built.sender.sent).toEqual([]);
    // A new password before the TOTP is ignored.
    const eager = await built.engine.advance(
      kept(second),
      newPasswordAnswer(NEW_PASSWORD),
      context(built)
    );
    expect(eager).toMatchObject({ kind: 'step', offer: { current: { step: 'totp' } } });
    expect(built.updates.checks).toEqual([]);
    const third = await built.engine.advance(
      kept(eager),
      answer('totp', { otp: '123456' }),
      context(built)
    );
    expect(totp.verify).toHaveBeenCalledTimes(1);
    expect(third).toMatchObject({ kind: 'step', offer: { current: UPDATE_STEP } });
    const done = await built.engine.advance(
      kept(third),
      newPasswordAnswer(NEW_PASSWORD),
      context(built)
    );
    expect(done).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd', 'otp', 'mfa'] } });
    expect(built.sender.sent).toEqual([]);
  });

  it('answers a redirect when the second factor cannot be asked for: email never stands in for it', async () => {
    const built = build(
      passwordAccount(USER, LISTED, { others: [{ type: 'totp', disabled: false }] })
    );
    const result = await signIn(built, LISTED);
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
    expect(built.sender.sent).toEqual([]);
  });

  it('asks for the second factor the MFA policy requires once, then the new password', async () => {
    const totp = fakeTotp();
    const built = build(
      passwordAccount(USER, LISTED, { others: [{ type: 'totp', disabled: false }] }),
      {
        steps: [totp.handler],
      }
    );
    built.policy.policy = { realm: 'required', client: 'off' };
    const second = await signIn(built, LISTED);
    const third = await built.engine.advance(
      kept(second),
      answer('totp', { otp: '123456' }),
      context(built)
    );
    expect(third).toMatchObject({ kind: 'step', offer: { current: UPDATE_STEP } });
    expect(totp.verify).toHaveBeenCalledTimes(1);
  });
});

describe('an update_password required action', () => {
  it('makes the next sign-in ask for a new password, and a completed update clears it', async () => {
    const built = build(passwordAccount(USER, UNLISTED, { requiredActions: ['update_password'] }));
    const second = await signIn(built, UNLISTED);
    expect(second).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'email_code', params: { purpose: 'recovery' } } },
    });
    expect(kept(second).breachedPassword).toBeUndefined();
    const third = await built.engine.advance(
      kept(second),
      codeAnswer(built.sender.last),
      context(built)
    );
    expect(third).toMatchObject({ kind: 'step', offer: { current: UPDATE_STEP } });
    const done = await built.engine.advance(
      kept(third),
      newPasswordAnswer(NEW_PASSWORD),
      context(built)
    );
    expect(done).toMatchObject({ kind: 'complete' });
    expect(built.directory.accounts.get(IDENTIFIER)?.requiredActions).toEqual([]);
    const next = await signIn(built, NEW_PASSWORD);
    expect(next).toMatchObject({ kind: 'complete' });
    expect(built.sender.sent).toHaveLength(1);
  });

  it('acts on update_password alone: the other actions are later steps', async () => {
    const built = build(
      passwordAccount(USER, UNLISTED, {
        requiredActions: ['setup_mfa', 'setup_passkey', 'complete_profile'],
      })
    );
    const result = await signIn(built, UNLISTED);
    expect(result).toMatchObject({ kind: 'complete' });
  });

  it('refuses a directory that reads no required actions: a store fault, never an empty list', async () => {
    const built = build(passwordAccount(USER, UNLISTED));
    const findByUserId = built.directory.findByUserId.bind(built.directory);
    built.directory.findByUserId = async (realmId, userId) => {
      const account = await findByUserId(realmId, userId);
      if (account === null) return null;
      const broken: Record<string, unknown> = { ...account };
      delete broken['requiredActions'];
      return broken as unknown as typeof account;
    };
    const result = await signIn(built, UNLISTED);
    expect(result).toMatchObject({ kind: 'refused', reason: 'unavailable' });
  });
});

describe('an update the sign-in cannot run', () => {
  it('answers a redirect when the transport does not serve new_password', async () => {
    const built = build();
    const ctx = context(built, { serves: ['identifier', 'password', 'email_code'] });
    const result = await signIn(built, LISTED, ctx);
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
    expect(built.sender.sent).toEqual([]);
  });

  it('answers a redirect for an engine built without the update, never completing', async () => {
    const built = build(undefined, { passwordUpdates: undefined });
    const result = await signIn(built, LISTED);
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
  });

  it('answers a redirect for a password-only account in an engine built without email codes', async () => {
    const built = build(undefined, { emailCodes: undefined });
    const result = await signIn(built, LISTED);
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
  });

  it('refuses to register a handler for new_password: the update is the engine’s own', () => {
    const handler = {
      step: 'new_password',
      role: 'first_factor',
      factor: 'password',
      params: () => ({}),
      verify: async () => ({
        kind: 'refused',
        error: 'password_rejected',
        audit: { reason: 'invalid_answer' },
      }),
    } as unknown as AnyStepHandler;
    expect(() => build(undefined, { steps: [handler] })).toThrow(/never a sign-in step/);
  });
});
