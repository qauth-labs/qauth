import {
  createInteractionMapper,
  STEP_NAMES,
  STEP_URNS,
  type StepName,
  transactionAmr,
} from '@qauth-labs/server-step-grammar';
import { describe, expect, it, vi } from 'vitest';

import {
  type FakeAccount,
  FakeAddresses,
  FakeCodeSender,
  FakeDirectory,
  fakeEmailCodeDigest,
  fakeIdentifierDigest,
  FakePasswords,
  FakePolicy,
  passwordAccount,
  recordingAudit,
} from '../testing/fakes';
import { createMemoryLadder, type MemoryLadder } from '../testing/memory-ladder';
import { EMAIL_CODE_RESEND_AFTER_MS, EMAIL_CODE_TTL_MS } from './email-code';
import { createSignInEngine, type SignInEngineDependencies } from './engine';
import type { LadderHook, LimitsHook } from './hooks';
import type { Clock } from './ports';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import type { AnyStepHandler } from './steps/handler';
import type { SignInTransaction } from './transaction';

/**
 * The inline verification of an unverified account after its password
 * (#638; ADR-017 Decisions 5 and 8;
 * `graphs/flows/core/account-verification/flow.yaml`).
 */

/** Every step but the bot challenge: a transport that cannot serve it (#643). */
const WITHOUT_CAPTCHA: readonly StepName[] = STEP_NAMES.filter((name) => name !== 'captcha');

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'native-app';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const PASSWORD = 'correct horse battery staple';
const IDENTIFIER = 'alice@example.com';
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

interface Built {
  readonly engine: ReturnType<typeof createSignInEngine>;
  readonly directory: FakeDirectory;
  readonly sender: FakeCodeSender;
  readonly addresses: FakeAddresses;
  readonly policy: FakePolicy;
  readonly clock: ReturnType<typeof manualClock>;
  readonly ladder: MemoryLadder;
}

function build(
  account: FakeAccount = passwordAccount(USER, PASSWORD, { verified: false }),
  options: Partial<SignInEngineDependencies> & {
    readonly ladder?: LadderHook;
    /** Whether the realm's mail reaches anyone (#1051); absent, it does. */
    readonly deliverable?: boolean;
  } = {}
): Built {
  const directory = new FakeDirectory(new Map([[IDENTIFIER, account]]));
  const clock = manualClock();
  const ladder = createMemoryLadder(() => clock.now());
  const addresses = new FakeAddresses(directory);
  const policy = new FakePolicy();
  const { ladder: ladderHook, deliverable, ...rest } = options;
  const engine = createSignInEngine({
    accounts: directory,
    passwords: new FakePasswords(),
    policy,
    identifierDigest: fakeIdentifierDigest,
    requireVerifiedAccount: true,
    emailCodes: {
      digest: fakeEmailCodeDigest,
      addresses,
      ...(deliverable === undefined ? {} : { deliverable: async () => deliverable }),
    },
    hooks: { ladder: ladderHook ?? ladder },
    clock,
    ...rest,
  });
  return { engine, directory, sender: new FakeCodeSender(), addresses, policy, clock, ladder };
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

const codeAnswer = (otp?: string) => answer('email_code', otp === undefined ? {} : { otp });

/** The transaction a result keeps; fails the test when it keeps none. */
function kept(result: RoundResult): SignInTransaction {
  if (result.transaction === null) throw new Error(`${result.kind} kept no transaction`);
  return result.transaction;
}

/** Round 0 with the login_hint, then the right password: the code's round. */
async function toCode(built: Built, ctx = context(built)): Promise<RoundResult> {
  const first = await built.engine.advance(null, null, { ...ctx, loginHint: IDENTIFIER });
  return built.engine.advance(kept(first), answer('password', { password: PASSWORD }), ctx);
}

/** A wrong code of six digits: never the one mailed. */
const wrongCode = (right: string) => (right === '000000' ? '111111' : '000000');

const interaction = createInteractionMapper();

describe('the code step after a correct password', () => {
  it.each([true])(
    'offers email_code with verify_account to an unverified account under the realm’s gate (REQUIRE_VERIFIED_ACCOUNT %s)',
    async (requireVerifiedAccount) => {
      const built = build(undefined, { requireVerifiedAccount });
      const ctx = context(built);
      const result = await toCode(built, ctx);
      expect(result).toMatchObject({
        kind: 'step',
        offer: {
          current: {
            step: 'email_code',
            params: { purpose: 'verify_account', length: 6, expires_in: 600, resend_after: 60 },
          },
          alternatives: [],
        },
        personal: { identifier: IDENTIFIER },
      });
      if (result.kind !== 'step') return;
      expect(result.offer.current).not.toHaveProperty('error');
      // The Interaction API can put it on the wire.
      expect(interaction.stepView(result.offer)).toMatchObject({
        step: STEP_URNS.email_code,
        alternatives: [],
      });
      expect(built.sender.sent).toEqual([
        {
          realmId: REALM,
          address: IDENTIFIER,
          purpose: 'verify_account',
          code: expect.stringMatching(/^[0-9]{6}$/),
          expiresInSeconds: 600,
          afterFirstFactor: true,
        },
      ]);
      expect(ctx.records).toEqual([
        { outcome: 'passed', step: 'identifier', identifierHmac: expect.any(String) },
        { outcome: 'passed', step: 'password', userId: USER },
      ]);
    }
  );

  it('signs an unverified account in with no code while the realm’s gate is off (ADR-017 Decision 8, amended)', async () => {
    const built = build(undefined, { requireVerifiedAccount: false });
    const result = await toCode(built);
    expect(result).toMatchObject({ kind: 'complete', signIn: { subject: USER } });
    expect(built.sender.sent).toEqual([]);
    expect(built.addresses.calls).toEqual([]);
  });

  it('refuses an unverified account under the gate where no code can arrive, and mails nothing (#1051)', async () => {
    const built = build(undefined, { requireVerifiedAccount: true, deliverable: false });
    const ctx = context(built);
    const result = await toCode(built, ctx);
    expect(result).toMatchObject({
      kind: 'step',
      offer: { current: { error: 'invalid_credentials' } },
    });
    expect(built.sender.sent).toEqual([]);
  });

  it('mails no code to a verified account', async () => {
    const built = build(passwordAccount(USER, PASSWORD));
    const result = await toCode(built);
    expect(result).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd'] } });
    expect(built.sender.sent).toEqual([]);
    expect(built.addresses.calls).toEqual([]);
  });

  it('gives an account that lacks the second factor the policy requires the set-up redirect, never a code', async () => {
    const built = build();
    built.policy.policy = { realm: 'required', client: 'off' };
    const result = await toCode(built);
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
    expect(built.sender.sent).toEqual([]);
  });

  it('verifies the address before the second factor the policy requires (rule 8)', async () => {
    const verifyTotp = vi.fn(async () => ({
      kind: 'proved' as const,
      account: { userId: USER, enabled: true, verified: true },
    }));
    const totp = {
      step: 'totp',
      role: 'second_factor',
      factor: 'totp',
      usableBy: () => true,
      params: () => ({ digits: 6 }),
      verify: verifyTotp,
    } as unknown as AnyStepHandler;
    const built = build(
      passwordAccount(USER, PASSWORD, {
        verified: false,
        others: [{ type: 'totp', disabled: false }],
      }),
      { steps: [totp] }
    );
    built.policy.policy = { realm: 'required', client: 'off' };
    const second = await toCode(built);
    expect(second).toMatchObject({ kind: 'step', offer: { current: { step: 'email_code' } } });
    expect(built.sender.sent).toHaveLength(1);
    // An eager answer to the second factor is ignored while the code is pending.
    const eager = await built.engine.advance(
      kept(second),
      answer('totp', { otp: '123456' }),
      context(built)
    );
    expect(eager).toMatchObject({ kind: 'step', offer: { current: { step: 'email_code' } } });
    expect(verifyTotp).not.toHaveBeenCalled();
    const third = await built.engine.advance(
      kept(eager),
      codeAnswer(built.sender.last),
      context(built)
    );
    expect(third).toMatchObject({ kind: 'step', offer: { current: { step: 'totp' } } });
    expect(built.addresses.calls).toHaveLength(1);
    // The code worked once: the transaction holds none, and answering it again verifies nothing.
    expect(kept(third).emailCode).toBeUndefined();
    const replayed = await built.engine.advance(
      kept(third),
      codeAnswer(built.sender.last),
      context(built)
    );
    expect(replayed).toMatchObject({ kind: 'step', offer: { current: { step: 'totp' } } });
    expect(built.addresses.calls).toHaveLength(1);
    const fourth = await built.engine.advance(
      kept(replayed),
      answer('totp', { otp: '123456' }),
      context(built)
    );
    expect(verifyTotp).toHaveBeenCalledTimes(1);
    expect(fourth).toMatchObject({
      kind: 'complete',
      signIn: { amr: ['pwd', 'otp', 'mfa'] },
    });
    expect(built.sender.sent).toHaveLength(1);
  });

  it('redirects a transport that cannot serve the step, mailing nothing', async () => {
    const built = build();
    const result = await toCode(built, context(built, { serves: ['identifier', 'password'] }));
    expect(result).toMatchObject({ kind: 'redirect', reason: 'step_not_available' });
    expect(built.sender.sent).toEqual([]);
  });

  it('refuses a round with no capped sender: a transport bug, not an answer', async () => {
    const built = build();
    const { sendCode, ...ctx } = context(built);
    expect(sendCode).toBeDefined();
    await expect(toCode(built, ctx)).rejects.toThrow(/no email-code sender/);
  });
});

describe('a right code', () => {
  it('marks the address verified and completes with no amr value and no new auth_time', async () => {
    const built = build();
    const second = await toCode(built);
    built.clock.advance(30_000);
    const ctx = context(built);
    const third = await built.engine.advance(kept(second), codeAnswer(built.sender.last), ctx);
    expect(third).toEqual({
      kind: 'complete',
      transaction: null,
      signIn: {
        subject: USER,
        identifier: IDENTIFIER,
        amr: ['pwd'],
        authTime: kept(second).authTime,
      },
    });
    expect(built.addresses.calls).toEqual([
      { realmId: REALM, userId: USER, identifier: IDENTIFIER },
    ]);
    expect(built.directory.accounts.get(IDENTIFIER)?.verified).toBe(true);
    expect(ctx.records).toEqual([{ outcome: 'passed', step: 'email_code', userId: USER }]);
    // The email-code step alone carries no amr value.
    expect(
      transactionAmr([
        {
          step: 'email_code',
          params: { purpose: 'verify_account', length: 6, expires_in: 600, resend_after: 60 },
        },
      ])
    ).toBeUndefined();
    // A right code clears the email-code counter.
    expect(
      built.ladder.counter(
        REALM,
        await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER }),
        'email_code'
      )
    ).toBeUndefined();
  });

  it('works once: the transaction it completed is gone, and a new code replaces an old one', async () => {
    const built = build();
    const second = await toCode(built);
    const first = built.sender.last;
    built.clock.advance(EMAIL_CODE_RESEND_AFTER_MS);
    const resent = await built.engine.advance(kept(second), codeAnswer(), context(built));
    expect(built.sender.sent).toHaveLength(2);
    expect(resent).toMatchObject({ kind: 'step', offer: { current: { step: 'email_code' } } });
    // The first code no longer works in the transaction that holds the new one.
    if (first !== built.sender.last) {
      const old = await built.engine.advance(kept(resent), codeAnswer(first), context(built));
      expect(old).toMatchObject({
        kind: 'step',
        offer: { current: { step: 'email_code', error: 'invalid_credentials' } },
      });
    }
    const done = await built.engine.advance(
      kept(resent),
      codeAnswer(built.sender.last),
      context(built)
    );
    expect(done).toMatchObject({ kind: 'complete', transaction: null });
  });

  it('is bound to its transaction: another transaction’s code is a wrong one', async () => {
    const built = build();
    const a = await toCode(built);
    const codeA = built.sender.last;
    const b = await toCode(built);
    const codeB = built.sender.last;
    const crossed = await built.engine.advance(kept(b), codeAnswer(codeA), context(built));
    if (codeA !== codeB) {
      expect(crossed).toMatchObject({
        kind: 'step',
        offer: { current: { error: 'invalid_credentials' } },
      });
    }
    expect(kept(a).emailCode?.salt).not.toBe(kept(b).emailCode?.salt);
  });

  it('ends the transaction when the account was disabled meanwhile, and writes nothing', async () => {
    const built = build();
    const second = await toCode(built);
    const code = built.sender.last;
    const addresses = {
      markVerified: vi.fn(async () => ({
        kind: 'refused' as const,
        reason: 'account_disabled' as const,
      })),
    };
    const engine = createSignInEngine({
      accounts: built.directory,
      passwords: new FakePasswords(),
      policy: built.policy,
      identifierDigest: fakeIdentifierDigest,
      requireVerifiedAccount: true,
      emailCodes: { digest: fakeEmailCodeDigest, addresses },
      clock: built.clock,
    });
    const ctx = context(built);
    const result = await engine.advance(kept(second), codeAnswer(code), ctx);
    expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(ctx.records).toEqual([
      { outcome: 'ended', step: 'email_code', reason: 'account_disabled', userId: USER },
    ]);
  });

  it('keeps the code when the address cannot be written: the same code works on the next round', async () => {
    const built = build();
    const second = await toCode(built);
    const code = built.sender.last;
    const onUnavailable = vi.fn();
    const failing = createSignInEngine({
      accounts: built.directory,
      passwords: new FakePasswords(),
      policy: built.policy,
      identifierDigest: fakeIdentifierDigest,
      requireVerifiedAccount: true,
      emailCodes: {
        digest: fakeEmailCodeDigest,
        addresses: { markVerified: async () => Promise.reject(new Error('database down')) },
      },
      clock: built.clock,
      onUnavailable,
    });
    const result = await failing.advance(kept(second), codeAnswer(code), context(built));
    expect(result).toMatchObject({ kind: 'refused', reason: 'unavailable' });
    expect(kept(result).emailCode).toEqual(kept(second).emailCode);
    expect(onUnavailable).toHaveBeenCalledWith(expect.objectContaining({ port: 'addresses' }));
    const retried = await built.engine.advance(kept(result), codeAnswer(code), context(built));
    expect(retried).toMatchObject({ kind: 'complete' });
  });
});

describe('a wrong, expired or malformed code', () => {
  it('refuses a wrong code with invalid_credentials, and the 5th wrong answer burns it', async () => {
    const built = build();
    let current = await toCode(built);
    const wrong = wrongCode(built.sender.last);
    for (let attempt = 1; attempt <= 4; attempt++) {
      const ctx = context(built);
      current = await built.engine.advance(kept(current), codeAnswer(wrong), ctx);
      expect(current).toMatchObject({
        kind: 'step',
        offer: { current: { step: 'email_code', error: 'invalid_credentials' } },
      });
      expect(kept(current).emailCode?.wrongAnswers).toBe(attempt);
      expect(ctx.records).toEqual([
        { outcome: 'refused', step: 'email_code', reason: 'invalid_code', userId: USER },
      ]);
    }
    const ctx = context(built);
    const burned = await built.engine.advance(kept(current), codeAnswer(wrong), ctx);
    expect(burned).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(ctx.records).toEqual([
      { outcome: 'ended', step: 'email_code', reason: 'code_burned', userId: USER },
    ]);
    expect(built.addresses.calls).toEqual([]);
  });

  it('keeps the count of wrong answers across a resend', async () => {
    const built = build();
    let current = await toCode(built);
    for (let attempt = 1; attempt <= 3; attempt++) {
      current = await built.engine.advance(
        kept(current),
        codeAnswer(wrongCode(built.sender.last)),
        context(built)
      );
    }
    built.clock.advance(EMAIL_CODE_RESEND_AFTER_MS);
    current = await built.engine.advance(kept(current), codeAnswer(), context(built));
    expect(built.sender.sent).toHaveLength(2);
    expect(kept(current).emailCode?.wrongAnswers).toBe(3);
    const wrong = wrongCode(built.sender.last);
    current = await built.engine.advance(kept(current), codeAnswer(wrong), context(built));
    expect(kept(current).emailCode?.wrongAnswers).toBe(4);
    const burned = await built.engine.advance(kept(current), codeAnswer(wrong), context(built));
    expect(burned).toMatchObject({ kind: 'refused', reason: 'transaction_ended' });
  });

  it('mails no new code before a minute has passed', async () => {
    const built = build();
    const second = await toCode(built);
    built.clock.advance(EMAIL_CODE_RESEND_AFTER_MS - 2_000);
    const again = await built.engine.advance(kept(second), codeAnswer(), context(built));
    expect(built.sender.sent).toHaveLength(1);
    expect(again).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'email_code', params: { resend_after: expect.any(Number) } } },
    });
    expect(kept(again).emailCode).toEqual(kept(second).emailCode);
  });

  it('does not take a code after its 10 minutes: refused with code_expired, nothing compared or counted', async () => {
    const built = build();
    const second = await toCode(built);
    const code = built.sender.last;
    const reservations = built.ladder.reservations.length;
    built.clock.advance(EMAIL_CODE_TTL_MS);
    const ctx = context(built);
    const expired = await built.engine.advance(kept(second), codeAnswer(code), ctx);
    expect(expired).toMatchObject({
      kind: 'step',
      offer: {
        current: { step: 'email_code', error: 'code_expired', params: { resend_after: 0 } },
      },
    });
    expect(ctx.records).toEqual([
      { outcome: 'refused', step: 'email_code', reason: 'code_expired', userId: USER },
    ]);
    expect(built.ladder.reservations).toHaveLength(reservations);
    expect(kept(expired).emailCode?.wrongAnswers).toBe(0);
    expect(built.addresses.calls).toEqual([]);
    // A round with no answer says so too; a new code then works.
    const idle = await built.engine.advance(kept(expired), null, context(built));
    expect(idle).toMatchObject({ offer: { current: { error: 'code_expired' } } });
    const resent = await built.engine.advance(kept(idle), codeAnswer(), context(built));
    expect(built.sender.sent).toHaveLength(2);
    const done = await built.engine.advance(
      kept(resent),
      codeAnswer(built.sender.last),
      context(built)
    );
    expect(done.kind).toBe('complete');
  });

  it('refuses an otp of another length as invalid_answer, nothing compared or counted', async () => {
    const built = build();
    const second = await toCode(built);
    const reservations = built.ladder.reservations.length;
    const result = await built.engine.advance(kept(second), codeAnswer('12345678'), context(built));
    expect(result).toMatchObject({ kind: 'refused', reason: 'invalid_answer' });
    expect(built.ladder.reservations).toHaveLength(reservations);
    expect(kept(result).emailCode?.wrongAnswers).toBe(0);
  });

  it('ignores an answer to another step, as every eager answer', async () => {
    const built = build();
    const second = await toCode(built);
    const result = await built.engine.advance(
      kept(second),
      answer('password', { password: PASSWORD }),
      context(built)
    );
    expect(result).toMatchObject({ kind: 'step', offer: { current: { step: 'email_code' } } });
    expect(built.sender.sent).toHaveLength(1);
  });
});

describe('the email-code ladder (ADR-017 Decision 7)', () => {
  it('counts wrong codes across transactions, refuses the next attempt inside its wait unverified, and accepts a right code after it', async () => {
    const built = build();
    const hmac = await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER });
    let a = await toCode(built);
    for (let attempt = 0; attempt < 4; attempt++) {
      a = await built.engine.advance(
        kept(a),
        codeAnswer(wrongCode(built.sender.last)),
        context(built)
      );
    }
    expect(built.ladder.counter(REALM, hmac, 'email_code')?.failures).toBe(4);
    // A second transaction: its first wrong code is the identifier's 5th.
    let b = await toCode(built);
    const codeB = built.sender.last;
    b = await built.engine.advance(kept(b), codeAnswer(wrongCode(codeB)), context(built));
    expect(kept(b).emailCode?.wrongAnswers).toBe(1);
    const fifth = built.ladder.counter(REALM, hmac, 'email_code');
    expect(fifth?.failures).toBe(5);
    expect(fifth?.waitUntil).toBeGreaterThan(built.clock.now());
    // The right code inside the wait: refused, not compared, the account
    // unverified. The transport does not serve the bot challenge the
    // threshold asks for (#643): the wait and the 429 alone.
    const ctx = context(built, { serves: WITHOUT_CAPTCHA });
    const waited = await built.engine.advance(kept(b), codeAnswer(codeB), ctx);
    expect(waited).toMatchObject({ kind: 'refused', reason: 'throttled', retryAfterSeconds: 1 });
    expect(ctx.records).toEqual([
      { outcome: 'refused', step: 'email_code', reason: 'locked_out', userId: USER },
    ]);
    expect(kept(waited).emailCode?.wrongAnswers).toBe(1);
    expect(built.addresses.calls).toEqual([]);
    expect(built.directory.accounts.get(IDENTIFIER)?.verified).toBe(false);
    // The password's counter is a separate one: it was cleared by the password.
    expect(built.ladder.counter(REALM, hmac, 'password')).toBeUndefined();
    // Outside the wait the right code is accepted, and the counter cleared.
    built.clock.advance(1_000);
    const done = await built.engine.advance(
      kept(waited),
      codeAnswer(codeB),
      context(built, { serves: WITHOUT_CAPTCHA })
    );
    expect(done).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd'] } });
    expect(built.directory.accounts.get(IDENTIFIER)?.verified).toBe(true);
    expect(built.ladder.counter(REALM, hmac, 'email_code')).toBeUndefined();
  });

  it('makes no end-user IP known to an unverified account at its password, and does once the code verifies it', async () => {
    const built = build();
    const hmac = await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER });
    const ctx = context(built, { endUserIp: '203.0.113.7' });
    const second = await toCode(built, ctx);
    // An abandoned code step leaves no known IP behind.
    expect(built.ladder.knownIps(REALM, hmac).size).toBe(0);
    expect(built.ladder.counter(REALM, hmac, 'password')).toBeUndefined();
    await built.engine.advance(kept(second), codeAnswer(built.sender.last), ctx);
    expect(built.directory.accounts.get(IDENTIFIER)?.verified).toBe(true);
    // The owner's next sign-in, now verified, makes it known.
    await toCode(built, ctx);
    expect([...built.ladder.knownIps(REALM, hmac).keys()]).toEqual(['203.0.113.7']);
  });

  it('reserves on the email_code counter with no end-user IP, and never suppresses the mail', async () => {
    const reserve = vi.fn<LadderHook['reserve']>(async () => ({
      kind: 'reserved' as const,
      settle: async () => ({ ceilingReached: false }),
    }));
    const built = build(undefined, { ladder: { reserve } });
    const ctx = context(built, { endUserIp: '203.0.113.7' });
    const second = await toCode(built, ctx);
    await built.engine.advance(kept(second), codeAnswer(wrongCode(built.sender.last)), ctx);
    expect(reserve.mock.calls.map(([input]) => input)).toEqual([
      expect.objectContaining({ factor: 'password', endUserIp: '203.0.113.7' }),
      { realmId: REALM, identifierHmac: expect.any(String), factor: 'email_code' },
    ]);
  });

  it('refuses the round when the ladder store fails, before the code is compared', async () => {
    const onUnavailable = vi.fn();
    let failing = false;
    const ladder: LadderHook = {
      reserve: async () => {
        if (failing) throw new Error('redis down');
        return { kind: 'reserved', settle: async () => ({ ceilingReached: false }) };
      },
    };
    const built = build(undefined, { ladder, onUnavailable });
    const second = await toCode(built);
    failing = true;
    const result = await built.engine.advance(
      kept(second),
      codeAnswer(built.sender.last),
      context(built)
    );
    expect(result).toMatchObject({ kind: 'refused', reason: 'unavailable' });
    expect(built.addresses.calls).toEqual([]);
    expect(onUnavailable).toHaveBeenCalledWith(expect.objectContaining({ port: 'ladder' }));
  });
});

describe('the round limits (#636)', () => {
  /** A limits hook recording each reservation's step and outcome, and the ladder's after it. */
  const recording = () => {
    const events: string[] = [];
    const limits: LimitsHook = {
      round: async () => ({ kind: 'continue' }),
      reserve: async () => {
        events.push('reserve');
        return {
          kind: 'reserved',
          settle: async (outcome, options) => {
            events.push(
              `settle:${outcome}${options?.userId === undefined ? '' : `:${options.userId}`}`
            );
          },
        };
      },
    };
    const ladder: LadderHook = {
      reserve: async ({ factor }) => {
        events.push(`ladder:${factor}`);
        return { kind: 'reserved', settle: async () => ({ ceilingReached: false }) };
      },
    };
    return { events, limits, ladder };
  };

  it('counts an email code as a credential round, before its ladder: a wrong one fails, a right one succeeds', async () => {
    const { events, limits, ladder } = recording();
    const built = build(undefined, { ladder, hooks: { limits, ladder } });
    let round = await toCode(built);
    round = await built.engine.advance(
      kept(round),
      codeAnswer(wrongCode(built.sender.last)),
      context(built)
    );
    await built.engine.advance(kept(round), codeAnswer(built.sender.last), context(built));
    expect(events).toEqual([
      // The password.
      'reserve',
      'ladder:password',
      `settle:success:${USER}`,
      // The wrong code, then the right one.
      'reserve',
      'ladder:email_code',
      'settle:failure',
      'reserve',
      'ladder:email_code',
      `settle:success:${USER}`,
    ]);
  });

  it('refuses a code inside a delay before it is compared or counted on the ladder', async () => {
    const { events, ladder } = recording();
    let throttle = false;
    const limits: LimitsHook = {
      round: async () => ({ kind: 'continue' }),
      reserve: async () =>
        throttle
          ? { kind: 'throttled', retryAfterSeconds: 30 }
          : { kind: 'reserved', settle: async () => undefined },
    };
    const built = build(undefined, { ladder, hooks: { limits, ladder } });
    const second = await toCode(built);
    throttle = true;
    events.length = 0;
    const ctx = context(built);
    const result = await built.engine.advance(kept(second), codeAnswer(built.sender.last), ctx);
    expect(result).toMatchObject({ kind: 'refused', reason: 'throttled', retryAfterSeconds: 30 });
    expect(events).toEqual([]);
    expect(built.addresses.calls).toEqual([]);
    expect(ctx.records).toContainEqual(
      expect.objectContaining({ outcome: 'refused', step: 'email_code', reason: 'rate_limited' })
    );
  });
});

describe('the send caps (PRO-14, #637)', () => {
  it('refuses the round with the cap’s wait when a cap answers 429, holding no code', async () => {
    const built = build();
    built.sender.outcome = { kind: 'capped', retryAfterSeconds: 120 };
    const ctx = context(built);
    const capped = await toCode(built, ctx);
    expect(capped).toMatchObject({ kind: 'refused', reason: 'throttled', retryAfterSeconds: 120 });
    expect(kept(capped).emailCode).toBeUndefined();
    expect(kept(capped).subject).toBe(USER);
    expect(ctx.records.at(-1)).toEqual({
      outcome: 'refused',
      step: 'email_code',
      reason: 'send_capped',
      userId: USER,
    });
    // Once the cap lifts, the next round mails the code.
    built.sender.outcome = { kind: 'accepted' };
    const next = await built.engine.advance(kept(capped), null, context(built));
    expect(next).toMatchObject({ kind: 'step', offer: { current: { step: 'email_code' } } });
  });

  it('refuses the round when the caps fail: fail closed', async () => {
    const built = build();
    const ctx = context(built, {
      sendCode: async () => Promise.reject(new Error('redis down')),
    });
    const result = await toCode(built, ctx);
    expect(result).toMatchObject({ kind: 'refused', reason: 'unavailable' });
    expect(kept(result).emailCode).toBeUndefined();
  });
});

describe('the code is never kept or told', () => {
  it('holds only a salt and an HMAC in the transaction, and names no code in any audit record', async () => {
    const built = build();
    const ctx = context(built);
    const second = await toCode(built, ctx);
    const code = built.sender.last;
    const stored = kept(second);
    expect(stored.emailCode).toEqual({
      purpose: 'verify_account',
      length: 6,
      salt: expect.stringMatching(/^[A-Za-z0-9_-]{22}$/),
      hmac: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      issuedAt: built.clock.now() - 500,
      wrongAnswers: 0,
    });
    expect(JSON.stringify(stored)).not.toContain(`"${code}"`);
    expect(stored.emailCode?.hmac).toBe(
      await fakeEmailCodeDigest({ realmId: REALM, salt: stored.emailCode?.salt ?? '', code })
    );
    const wrong = await built.engine.advance(stored, codeAnswer(wrongCode(code)), ctx);
    expect(JSON.stringify(wrong)).not.toContain(`"${code}"`);
    expect(JSON.stringify(wrong)).not.toContain(`"${wrongCode(code)}"`);
    expect(JSON.stringify(ctx.records)).not.toContain(`"${code}"`);
    expect(JSON.stringify(ctx.records)).not.toContain(`"${wrongCode(code)}"`);
  });

  it('refuses a transaction whose held code is out of shape', async () => {
    const built = build();
    const second = await toCode(built);
    const stored = kept(second);
    const tampered = {
      ...stored,
      emailCode: { ...stored.emailCode, hmac: '123456' },
    } as unknown as SignInTransaction;
    const result = await built.engine.advance(
      tampered,
      codeAnswer(built.sender.last),
      context(built)
    );
    expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
  });
});

describe('an engine built without email codes', () => {
  it('refuses an email_code handler as a sign-in step', () => {
    expect(() =>
      build(undefined, {
        steps: [
          {
            step: 'email_code',
            role: 'second_factor',
            factor: 'totp',
            params: () => ({}),
            verify: async () => ({ kind: 'refused' }),
          } as unknown as AnyStepHandler,
        ],
      })
    ).toThrow(/never a sign-in step/);
  });
});
