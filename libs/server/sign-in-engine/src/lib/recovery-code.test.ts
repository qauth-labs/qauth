import {
  createFipaMapper,
  FIPA_SERVES_ALL,
  FIPA_STEP_NAMES,
  STEP_NAMES,
  STEP_URNS,
  type StepName,
  type StepOffer,
} from '@qauth-labs/server-step-grammar';
import { describe, expect, it, vi } from 'vitest';

import {
  type FakeAccount,
  FakeDirectory,
  fakeIdentifierDigest,
  FakePasswords,
  FakePolicy,
  passwordAccount,
  recordingAudit,
} from '../testing/fakes';
import { createMemoryLadder, memoryLadderSubject } from '../testing/memory-ladder';
import {
  createMemoryRecoveryCodes,
  type MemoryRecoveryCodes,
} from '../testing/memory-recovery-codes';
import { createProofOfWorkProvider, PROOF_OF_WORK_MIN_DIFFICULTY } from './bot-challenge';
import { createSignInEngine, type SignInEngineDependencies } from './engine';
import type { Clock } from './ports';
import { generateRecoveryCode, RECOVERY_CODE_PATTERN } from './recovery-codes';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import { createCaptchaStep } from './steps/captcha';
import type { AnyStepHandler } from './steps/handler';
import { readSignInTransaction, type SignInTransaction } from './transaction';

/**
 * Recovery codes at sign-in (#649; ADR-017 Decisions 4, 7 and 8;
 * `graphs/flows/core/recovery-code/flow.yaml`): a code stands in for the
 * factor rule 8 asks for on the hosted pages, with no `amr` value, counted
 * on the account's own ladder; and a new set is shown once.
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'web-client';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const PASSWORD = 'a quiet violet tram crosses nine rivers';
const IDENTIFIER = 'alice@example.com';
const T0 = 1_800_000_000_000;
const MINUTE = 60_000;

/** The FiPA endpoint's steps: every step it may serve, so never a recovery step. */
const FIPA_SERVES: readonly StepName[] = FIPA_STEP_NAMES;

/**
 * The hosted pages' steps but the bot challenge: past the free failures the
 * ladder's soft threshold asks for one, and a transport that does not serve
 * it meets the ladder's waits alone (ADR-017 Decision 7).
 */
const NO_CHALLENGE: readonly StepName[] = STEP_NAMES.filter((step) => step !== 'captcha');

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

/** A passkey-bound account with a password: no passkey step is registered, so only a code goes on. */
const passkeyAccount = (overrides: Partial<FakeAccount> = {}) =>
  passwordAccount(USER, PASSWORD, { others: [{ type: 'passkey', disabled: false }], ...overrides });

/** An account with a password and TOTP. */
const totpAccount = (disabled = false) =>
  passwordAccount(USER, PASSWORD, { others: [{ type: 'totp', disabled }] });

/** A TOTP second factor that proves `USER` for any six digits, while the account's TOTP is usable. */
function fakeTotp() {
  const verify = vi.fn(async () => ({
    kind: 'proved' as const,
    account: { userId: USER, enabled: true, verified: true },
  }));
  const handler = {
    step: 'totp',
    role: 'second_factor',
    factor: 'totp',
    usableBy: (account: { factors: readonly { type: string; disabled: boolean }[] }) =>
      account.factors.some((factor) => factor.type === 'totp' && !factor.disabled),
    params: () => ({ digits: 6 }),
    verify,
  } as unknown as AnyStepHandler;
  return { handler, verify };
}

interface Built {
  readonly engine: ReturnType<typeof createSignInEngine>;
  readonly directory: FakeDirectory;
  readonly policy: FakePolicy;
  readonly ladder: ReturnType<typeof createMemoryLadder>;
  readonly codes: MemoryRecoveryCodes;
  readonly clock: ReturnType<typeof manualClock>;
}

function build(
  account: FakeAccount = passkeyAccount(),
  options: Partial<SignInEngineDependencies> = {}
): Built {
  const clock = manualClock();
  const directory = new FakeDirectory(new Map([[IDENTIFIER, account]]));
  const policy = new FakePolicy();
  const ladder = createMemoryLadder(clock.now);
  const codes = createMemoryRecoveryCodes(clock.now);
  const engine = createSignInEngine({
    accounts: directory,
    passwords: new FakePasswords(),
    policy,
    identifierDigest: fakeIdentifierDigest,
    requireVerifiedAccount: true,
    recoveryCodes: codes,
    hooks: { ladder },
    clock,
    ...options,
  });
  return { engine, directory, policy, ladder, codes, clock };
}

type Ctx = RoundContext & { readonly records: ReturnType<typeof recordingAudit>['records'] };

function context(overrides: Partial<RoundContext> = {}): Ctx {
  const audit = recordingAudit();
  return {
    realm: { id: REALM },
    client: { id: CLIENT },
    audit: audit.sink,
    records: audit.records,
    ...overrides,
  };
}

function answer(step: StepName, fields: Record<string, unknown>): RoundAnswer {
  return { step: STEP_URNS[step], fields };
}

const codeAnswer = (code: string) => answer('recovery_code', { recovery_code: code });

/** The transaction a result keeps; fails the test when it keeps none. */
function kept(result: RoundResult): SignInTransaction {
  if (result.transaction === null) throw new Error(`${result.kind} kept no transaction`);
  return result.transaction;
}

/** Round 0 with the login_hint, then the password. */
async function signIn(built: Built, ctx: RoundContext = context()): Promise<RoundResult> {
  const first = await built.engine.advance(null, null, { ...ctx, loginHint: IDENTIFIER });
  return built.engine.advance(kept(first), answer('password', { password: PASSWORD }), ctx);
}

/** A set the person saved: issued and confirmed. */
async function issued(built: Built): Promise<readonly string[]> {
  const { codes, setId } = await built.codes.replace({ realmId: REALM, userId: USER });
  await built.codes.confirm({ realmId: REALM, userId: USER, setId });
  return codes;
}

const recoveryCounter = (built: Built) =>
  built.ladder.counter(REALM, memoryLadderSubject({ userId: USER }), 'recovery_code');

describe('a recovery code in place of a lost factor', () => {
  it('is offered after the password, alone when no step of the factor can be served', async () => {
    const built = build();
    await issued(built);
    const offered = await signIn(built);
    expect(offered).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'recovery_code', params: {} }, alternatives: [] },
      personal: { identifier: IDENTIFIER },
    });
  });

  it('completes the sign-in once, with no amr value and the password’s auth_time', async () => {
    const built = build();
    const set = await issued(built);
    const ctx = context();
    const offered = await signIn(built, ctx);
    const passwordTime = kept(offered).authTime;
    built.clock.advance(MINUTE);
    const done = await built.engine.advance(kept(offered), codeAnswer(set[2] as string), ctx);
    expect(done).toEqual({
      kind: 'complete',
      transaction: null,
      // The sign-in says it took a code, which no `amr` value does (#663).
      signIn: {
        subject: USER,
        identifier: IDENTIFIER,
        amr: ['pwd'],
        authTime: passwordTime,
        recoveryCode: true,
      },
    });
    expect(built.codes.usedNotices).toEqual([{ realmId: REALM, userId: USER }]);
    expect(ctx.records.at(-1)).toEqual({ outcome: 'passed', step: 'recovery_code', userId: USER });
    expect(await built.codes.status({ realmId: REALM, userId: USER })).toEqual({
      issued: true,
      unused: 9,
      confirmed: true,
    });
    // The same code again, in a new sign-in: refused.
    const again = await signIn(built);
    const refused = await built.engine.advance(
      kept(again),
      codeAnswer(set[2] as string),
      context()
    );
    expect(refused).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'recovery_code', error: 'invalid_credentials' } },
    });
  });

  it('is never offered to a transport that cannot serve it: the FiPA endpoint redirects', async () => {
    const built = build();
    await issued(built);
    const result = await signIn(built, context({ serves: FIPA_SERVES }));
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
    // An offer whose current step is the recovery code is redirect_to_web there too.
    const mapper = createFipaMapper(FIPA_SERVES_ALL);
    const offer: StepOffer = { current: { step: 'recovery_code', params: {} }, alternatives: [] };
    expect(
      mapper.challenge(offer, {
        issuer: 'https://auth.example.com',
        newAuthSession: () => 'a'.repeat(43),
        interactionTypesSupported: [STEP_URNS.password, STEP_URNS.recovery_code],
      })
    ).toEqual({
      status: 403,
      body: { error: 'redirect_to_web', iss: 'https://auth.example.com' },
    });
  });

  it('is not offered to an account that holds no unused code', async () => {
    const none = build();
    expect(await signIn(none)).toMatchObject({ kind: 'redirect', reason: 'step_not_available' });
    const usedUp = build();
    const set = await issued(usedUp);
    for (const code of set) {
      await usedUp.codes.redeem({ realmId: REALM, userId: USER, clientId: CLIENT, code });
    }
    expect(await signIn(usedUp)).toMatchObject({ kind: 'redirect', reason: 'step_not_available' });
  });

  it('is not offered by an engine built without recovery codes', async () => {
    const built = build(passkeyAccount(), { recoveryCodes: undefined });
    await issued(built);
    expect(await signIn(built)).toMatchObject({ kind: 'redirect', reason: 'step_not_available' });
  });

  it('is offered after the factor’s own step, and the factor may still be answered', async () => {
    const totp = fakeTotp();
    const built = build(totpAccount(), { steps: [totp.handler] });
    built.policy.policy = { realm: 'required', client: 'off' };
    await issued(built);
    const offered = await signIn(built);
    expect(offered).toMatchObject({
      kind: 'step',
      offer: {
        current: { step: 'totp' },
        alternatives: [{ step: 'recovery_code', params: {} }],
      },
    });
    const done = await built.engine.advance(
      kept(offered),
      answer('totp', { otp: '123456' }),
      context()
    );
    expect(done).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd', 'otp', 'mfa'] } });
    expect(totp.verify).toHaveBeenCalledTimes(1);
  });

  it('refuses a malformed answer without counting it', async () => {
    const built = build();
    await issued(built);
    const offered = await signIn(built);
    const result = await built.engine.advance(
      kept(offered),
      codeAnswer('not a code at all!!'),
      context()
    );
    expect(result).toMatchObject({ kind: 'refused', reason: 'invalid_answer' });
    expect(recoveryCounter(built)).toBeUndefined();
  });
});

describe('a recovery code under an MFA policy', () => {
  it('never satisfies it: the person binds a new second factor after the code, even while one is usable', async () => {
    // ADR-017 Decision 8: where the policy requires a second factor, the user
    // binds a new one before the transaction completes. With no set-up step
    // in this engine, that is a redirect; the TOTP held is never asked for.
    const totp = fakeTotp();
    const built = build(totpAccount(), { steps: [totp.handler] });
    built.policy.policy = { realm: 'required', client: 'off' };
    const set = await issued(built);
    const offered = await signIn(built);
    const after = await built.engine.advance(
      kept(offered),
      codeAnswer(set[0] as string),
      context()
    );
    expect(after).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
    expect(totp.verify).not.toHaveBeenCalled();
    expect(built.codes.usedNotices).toHaveLength(1);
  });

  it('sends the person on to bind a new second factor, a redirect until a set-up step exists', async () => {
    const totp = fakeTotp();
    // The account's TOTP is disabled: only the code goes on.
    const built = build(totpAccount(true), { steps: [totp.handler] });
    built.policy.policy = { realm: 'off', client: 'required' };
    const set = await issued(built);
    const offered = await signIn(built);
    expect(offered).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'recovery_code' }, alternatives: [] },
    });
    const after = await built.engine.advance(
      kept(offered),
      codeAnswer(set[0] as string),
      context()
    );
    expect(after).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
    expect(totp.verify).not.toHaveBeenCalled();
  });
});

describe('the recovery-code ladder', () => {
  it('counts a wrong code on the account, across transactions, and a right password never clears it', async () => {
    const built = build();
    await issued(built);
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      // A new transaction each time, from another address.
      const offered = await signIn(built, context({ endUserIp: `192.0.2.${attempt}` }));
      const refused = await built.engine.advance(
        kept(offered),
        codeAnswer(generateRecoveryCode()),
        context({ endUserIp: `192.0.2.${attempt}` })
      );
      expect(refused).toMatchObject({
        kind: 'step',
        offer: { current: { step: 'recovery_code', error: 'invalid_credentials' } },
      });
      expect(recoveryCounter(built)?.failures).toBe(attempt);
    }
    // Four right passwords later, the count stands; the password's own is clear.
    expect(
      built.ladder.counter(
        REALM,
        await fakeIdentifierDigest({
          realmId: REALM,
          identifier: IDENTIFIER,
        }),
        'password'
      )
    ).toBeUndefined();
    expect(recoveryCounter(built)?.failures).toBe(4);
  });

  it('makes the 6th attempt wait from 5 failures, with no known-IP exemption, checking nothing', async () => {
    const built = build();
    const set = await issued(built);
    const ctx = context({ endUserIp: '192.0.2.10', serves: NO_CHALLENGE });
    let transaction = kept(await signIn(built, ctx));
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      transaction = kept(
        await built.engine.advance(transaction, codeAnswer(generateRecoveryCode()), ctx)
      );
    }
    const verifications = built.codes.hasher.verifications;
    const waiting = await built.engine.advance(transaction, codeAnswer(set[0] as string), ctx);
    expect(waiting).toMatchObject({ kind: 'refused', reason: 'throttled' });
    expect(built.codes.hasher.verifications).toBe(verifications);
    expect(built.codes.usedNotices).toEqual([]);
    expect(ctx.records.at(-1)).toMatchObject({ outcome: 'refused', reason: 'locked_out' });
    // Once the wait is over, the right code is taken and clears the counter.
    built.clock.advance(MINUTE);
    const done = await built.engine.advance(transaction, codeAnswer(set[0] as string), ctx);
    expect(done).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd'] } });
    expect(recoveryCounter(built)).toBeUndefined();
  });

  it('tells the user and the operator at 100 failures in a row, and on each failure after', async () => {
    const built = build();
    await issued(built);
    const ctx = context({ serves: NO_CHALLENGE });
    for (let attempt = 1; attempt <= 101; attempt += 1) {
      // Past the last wait, in a sign-in of its own: transactions do not live a day.
      built.clock.advance(16 * MINUTE);
      const transaction = kept(await signIn(built, ctx));
      const result = await built.engine.advance(
        transaction,
        codeAnswer(generateRecoveryCode()),
        ctx
      );
      expect(result).toMatchObject({
        kind: 'step',
        offer: { current: { error: 'invalid_credentials' } },
      });
      expect(built.codes.ceilingNotices).toHaveLength(Math.max(0, attempt - 99));
    }
    expect(built.codes.ceilingNotices[0]).toEqual({ realmId: REALM, userId: USER });
  });

  it('asks for the bot challenge once the account is past its free failures', async () => {
    const captcha = createCaptchaStep(
      createProofOfWorkProvider({ difficulty: () => PROOF_OF_WORK_MIN_DIFFICULTY })
    );
    const built = build(passkeyAccount(), { steps: [captcha] });
    await issued(built);
    const ctx = context();
    let transaction = kept(await signIn(built, ctx));
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      built.clock.advance(16 * MINUTE);
      transaction = kept(
        await built.engine.advance(transaction, codeAnswer(generateRecoveryCode()), ctx)
      );
    }
    const next = await built.engine.advance(transaction, null, ctx);
    expect(next).toMatchObject({ kind: 'step', offer: { current: { step: 'captcha' } } });
  });
});

describe('a new set of recovery codes, shown once', () => {
  /** An account with TOTP whose policy asks for it, and no set yet. */
  function enrolled(serves: readonly StepName[] = STEP_NAMES) {
    const totp = fakeTotp();
    const built = build(totpAccount(), { steps: [totp.handler] });
    built.policy.policy = { realm: 'required', client: 'off' };
    const ctx = context({ serves });
    return { built, ctx };
  }

  async function provedTotp(built: Built, ctx: RoundContext): Promise<RoundResult> {
    const offered = await signIn(built, ctx);
    return built.engine.advance(kept(offered), answer('totp', { otp: '123456' }), ctx);
  }

  it('is shown after the factor beyond the password, as the round’s personal data alone', async () => {
    const { built, ctx } = enrolled();
    const shown = await provedTotp(built, ctx);
    expect(shown).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'recovery_codes', params: { count: 10 } }, alternatives: [] },
    });
    if (shown.kind !== 'step') throw new Error('no step');
    const codes = (shown.personal as { codes: string[] }).codes;
    expect(codes).toHaveLength(10);
    for (const code of codes) expect(code).toMatch(RECOVERY_CODE_PATTERN);
    // The transaction names the set and keeps no code.
    const stored = JSON.stringify(kept(shown));
    for (const code of codes) expect(stored).not.toContain(code);
    expect(readSignInTransaction(kept(shown))?.recoveryCodesShown).toBe(
      built.codes.store.rows[0]?.id
    );
    // The confirmation completes the sign-in, with the factors' amr alone.
    const done = await built.engine.advance(
      kept(shown),
      answer('recovery_codes', { acknowledged: true }),
      ctx
    );
    expect(done).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd', 'otp', 'mfa'] } });
    // The set is the person's now: confirmed in the store.
    await expect(built.codes.status({ realmId: REALM, userId: USER })).resolves.toMatchObject({
      issued: true,
      confirmed: true,
    });
    // The codes shown are the account's.
    expect(
      await built.codes.redeem({
        realmId: REALM,
        userId: USER,
        clientId: CLIENT,
        code: codes[0] as string,
      })
    ).toEqual({ kind: 'redeemed' });
  });

  it('is shown anew when a round brings no confirmation, and the set shown before is gone', async () => {
    const { built, ctx } = enrolled();
    const first = await provedTotp(built, ctx);
    if (first.kind !== 'step') throw new Error('no step');
    const before = (first.personal as { codes: string[] }).codes;
    const again = await built.engine.advance(
      kept(first),
      answer('password', { password: 'x' }),
      ctx
    );
    if (again.kind !== 'step') throw new Error('no step');
    const after = (again.personal as { codes: string[] }).codes;
    expect(after).not.toEqual(before);
    expect(built.codes.store.rows).toHaveLength(10);
    expect(
      await built.codes.redeem({
        realmId: REALM,
        userId: USER,
        clientId: CLIENT,
        code: before[0] as string,
      })
    ).toEqual({ kind: 'refused' });
  });

  it('is shown again, as a new set, at the next sign-in when nobody confirmed the one shown', async () => {
    const { built, ctx } = enrolled();
    // The page was closed before the confirmation: the set is stored, unseen for sure.
    const lost = await provedTotp(built, ctx);
    if (lost.kind !== 'step') throw new Error('no step');
    const unseen = (lost.personal as { codes: string[] }).codes;
    await expect(built.codes.status({ realmId: REALM, userId: USER })).resolves.toMatchObject({
      issued: true,
      confirmed: false,
    });

    const next = await provedTotp(built, ctx);
    expect(next).toMatchObject({ kind: 'step', offer: { current: { step: 'recovery_codes' } } });
    if (next.kind !== 'step') throw new Error('no step');
    expect((next.personal as { codes: string[] }).codes).not.toEqual(unseen);
    expect(built.codes.store.rows).toHaveLength(10);
    const done = await built.engine.advance(
      kept(next),
      answer('recovery_codes', { acknowledged: true }),
      ctx
    );
    expect(done).toMatchObject({ kind: 'complete' });
    // Confirmed, the set is not shown again.
    expect(await provedTotp(built, ctx)).toMatchObject({ kind: 'complete' });
  });

  it('is shown anew when another sign-in replaced the set before its confirmation', async () => {
    const { built, ctx } = enrolled();
    const mine = await provedTotp(built, ctx);
    if (mine.kind !== 'step') throw new Error('no step');
    const saved = (mine.personal as { codes: string[] }).codes;
    // Another sign-in of the account, at the same time, replaced the set
    // shown here with its own, which nobody confirmed.
    const theirs = await provedTotp(built, ctx);
    if (theirs.kind !== 'step') throw new Error('no step');

    // The confirmation of the set shown here confirms nothing: those codes
    // no longer work, so a new set is shown in their place.
    const again = await built.engine.advance(
      kept(mine),
      answer('recovery_codes', { acknowledged: true }),
      ctx
    );
    expect(again).toMatchObject({ kind: 'step', offer: { current: { step: 'recovery_codes' } } });
    if (again.kind !== 'step') throw new Error('no step');
    const fresh = (again.personal as { codes: string[] }).codes;
    expect(fresh).not.toEqual(saved);
    await expect(built.codes.status({ realmId: REALM, userId: USER })).resolves.toMatchObject({
      confirmed: false,
    });
    const done = await built.engine.advance(
      kept(again),
      answer('recovery_codes', { acknowledged: true }),
      ctx
    );
    expect(done).toMatchObject({ kind: 'complete' });
    // The set confirmed is the one shown last, and its codes work.
    await expect(built.codes.status({ realmId: REALM, userId: USER })).resolves.toMatchObject({
      confirmed: true,
    });
    expect(
      await built.codes.redeem({
        realmId: REALM,
        userId: USER,
        clientId: CLIENT,
        code: fresh[0] as string,
      })
    ).toEqual({ kind: 'redeemed' });
  });

  it('replaces no set the person confirmed in another sign-in meanwhile', async () => {
    const { built, ctx } = enrolled();
    const mine = await provedTotp(built, ctx);
    const theirs = await provedTotp(built, ctx);
    if (theirs.kind !== 'step') throw new Error('no step');
    const confirmedThere = (theirs.personal as { codes: string[] }).codes;
    expect(
      await built.engine.advance(
        kept(theirs),
        answer('recovery_codes', { acknowledged: true }),
        ctx
      )
    ).toMatchObject({ kind: 'complete' });

    // This sign-in's set was replaced, and the account holds a confirmed set
    // now: nothing is owed, and that set stays.
    const done = await built.engine.advance(
      kept(mine),
      answer('recovery_codes', { acknowledged: true }),
      ctx
    );
    expect(done).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd', 'otp', 'mfa'] } });
    expect(
      await built.codes.redeem({
        realmId: REALM,
        userId: USER,
        clientId: CLIENT,
        code: confirmedThere[0] as string,
      })
    ).toEqual({ kind: 'redeemed' });
  });

  it('refuses a confirmation that is not true', async () => {
    const { built, ctx } = enrolled();
    const shown = await provedTotp(built, ctx);
    const refused = await built.engine.advance(
      kept(shown),
      answer('recovery_codes', { acknowledged: false }),
      ctx
    );
    expect(refused).toMatchObject({ kind: 'refused', reason: 'invalid_answer' });
  });

  it('sends a FiPA client to the hosted pages to see it', async () => {
    const { built, ctx } = enrolled(FIPA_SERVES);
    expect(await provedTotp(built, ctx)).toEqual({
      kind: 'redirect',
      reason: 'step_not_available',
      transaction: null,
    });
  });

  it('is not shown to an account that holds a set, nor after the password alone', async () => {
    const { built, ctx } = enrolled();
    await issued(built);
    expect(await provedTotp(built, ctx)).toMatchObject({ kind: 'complete' });
    // TOTP bound, no policy: the password alone never completes (ADR-017
    // Decision 4, rule 8), and it shows nothing before the TOTP.
    const bare = build(totpAccount(), { steps: [fakeTotp().handler] });
    expect(await signIn(bare)).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'totp' } },
    });
    expect(bare.codes.store.rows).toEqual([]);
  });
});
