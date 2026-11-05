import { createHash } from 'node:crypto';

import { STEP_URNS, type StepName, type StepParams } from '@qauth-labs/server-step-grammar';
import { describe, expect, it } from 'vitest';

import {
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
import { createMemoryRoundLimits } from '../testing/memory-round-limits';
import {
  type BotChallengeProvider,
  checkedChallengeParams,
  createProofOfWorkProvider,
  isProofOfWorkDifficulty,
  leadingZeroBits,
  PROOF_OF_WORK_DEFAULT_DIFFICULTY,
  proofOfWorkInput,
  solvesProofOfWork,
} from './bot-challenge';
import {
  createSignInEngine,
  REGISTRATION_NOT_ALLOWED,
  type SignInEngineDependencies,
} from './engine';
import type { HookRound, SignInHooks } from './hooks';
import { PASSWORD_LADDER_POLICY } from './ladder';
import type { Clock } from './ports';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import { createRoundLimiter, ROUND_LIMIT_POLICY } from './round-limits';
import { createCaptchaStep } from './steps/captcha';
import type { SignInTransaction } from './transaction';

/**
 * The bot challenge (PRO-19, #643; ADR-017 Decisions 4 and 7): the built-in
 * proof of work, and rule 5 of the engine's order — when the `captcha` step
 * is due, what its answer does, and what a client that cannot answer it gets.
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'native-app';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const PASSWORD = 'correct horse battery staple';
const WRONG = 'not the password at all';
const IDENTIFIER = 'alice@example.com';
const IP = '203.0.113.9';
const T0 = 1_800_000_000_000;
/** A difficulty a test solves in a few hundred hashes. */
const EASY = 6;
/** A token no log, audit record or transaction may hold. */
const TOKEN_MARK = 'TOKEN-NEVER-KEPT';

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

function answer(step: StepName, fields: Record<string, unknown>): RoundAnswer {
  return { step: STEP_URNS[step], fields };
}
const passwordAnswer = (password: string, loginHint?: string) =>
  answer('password', { password, ...(loginHint === undefined ? {} : { login_hint: loginHint }) });
const tokenAnswer = (token: string) => answer('captcha', { captcha_token: token });

/** The nonce that solves `params`, found by trying each in turn. */
function solve(params: StepParams<'captcha'>): string {
  for (let nonce = 0; nonce < 1_000_000; nonce += 1) {
    if (solvesProofOfWork(params, String(nonce))) return String(nonce);
  }
  throw new Error('no solution');
}

/** A nonce that does not solve `params`. */
function miss(params: StepParams<'captcha'>): string {
  for (let nonce = 0; ; nonce += 1) {
    if (!solvesProofOfWork(params, String(nonce))) return String(nonce);
  }
}

/** The proof of work at {@link EASY}, counting its puzzles. */
function easyProofOfWork(): BotChallengeProvider & { puzzles: number } {
  const inner = createProofOfWorkProvider({ difficulty: () => EASY });
  const provider = {
    puzzles: 0,
    async params(round: { readonly realmId: string; readonly clientId: string }) {
      provider.puzzles += 1;
      return inner.params(round);
    },
    verify: inner.verify,
  };
  return provider;
}

/** The params of the `captcha` step a result offers. */
function offered(result: RoundResult): StepParams<'captcha'> {
  if (result.kind !== 'step' || result.offer.current.step !== 'captcha') {
    throw new Error(`expected the captcha step, got ${JSON.stringify(result)}`);
  }
  return result.offer.current.params as StepParams<'captcha'>;
}

function kept(result: RoundResult): SignInTransaction {
  if (result.transaction === null) throw new Error(`${result.kind} kept no transaction`);
  return result.transaction;
}

function build(options: Partial<SignInEngineDependencies> = {}) {
  const directory = new FakeDirectory(new Map([[IDENTIFIER, passwordAccount(USER, PASSWORD)]]));
  const passwords = new FakePasswords();
  const clock = manualClock();
  const provider = easyProofOfWork();
  const engine = createSignInEngine({
    accounts: directory,
    passwords,
    policy: new FakePolicy(),
    identifierDigest: fakeIdentifierDigest,
    requireVerifiedAccount: true,
    clock,
    steps: [createCaptchaStep(provider)],
    ...options,
  });
  return { engine, directory, passwords, clock, provider };
}

function context(
  overrides: Partial<RoundContext> = {},
  audit = recordingAudit()
): RoundContext & { records: ReturnType<typeof recordingAudit>['records'] } {
  return {
    realm: { id: REALM },
    client: { id: CLIENT },
    audit: audit.sink,
    records: audit.records,
    ...overrides,
  };
}

/** A round limiter over memory, on a clock of its own, with the IP's failures to cross its soft threshold. */
function limits(perClient = false) {
  let now = T0;
  const store = createMemoryRoundLimits(() => now);
  const limiter = createRoundLimiter(store, { ipDigest: fakeIdentifierDigest, perClient });
  /**
   * `count` failed credential rounds from `ip`, as wrong passwords would
   * leave them, each past the delay the one before started.
   */
  const fail = async (count: number, ip = IP) => {
    for (let i = 0; i < count; i += 1) {
      if (i > 0) now += ROUND_LIMIT_POLICY.endUserIp.delayMs;
      const verdict = await limiter.reserve({
        realmId: REALM,
        clientId: CLIENT,
        endUserIp: ip,
        environment: 'production',
      });
      if (verdict.kind !== 'reserved') throw new Error('throttled');
      await verdict.settle('failure');
    }
  };
  return { store, limiter, fail, advance: (ms: number) => (now += ms) };
}

describe('the proof of work', () => {
  it('counts the leading zero bits of a digest', () => {
    expect(leadingZeroBits(Uint8Array.from([0xff]))).toBe(0);
    expect(leadingZeroBits(Uint8Array.from([0x01, 0xff]))).toBe(7);
    expect(leadingZeroBits(Uint8Array.from([0x00, 0x00, 0x10]))).toBe(19);
    expect(leadingZeroBits(new Uint8Array(4))).toBe(32);
  });

  it('takes a decimal nonce whose SHA-256 over challenge:nonce starts with enough zero bits', () => {
    const params = { provider: 'pow', challenge: 'a'.repeat(43), difficulty: EASY } as const;
    const nonce = solve(params);
    const digest = createHash('sha256').update(proofOfWorkInput(params.challenge, nonce)).digest();
    expect(leadingZeroBits(digest)).toBeGreaterThanOrEqual(EASY);
    expect(solvesProofOfWork(params, nonce)).toBe(true);
    expect(solvesProofOfWork(params, miss(params))).toBe(false);
    // Another puzzle, the same nonce: almost surely no solution.
    expect(solvesProofOfWork({ ...params, difficulty: 32 }, nonce)).toBe(false);
  });

  it('agrees with the page’s solver on a shared vector', () => {
    // The vector of `@qauth-labs/shared-interaction-client`'s solver test.
    const challenge = 'cWF1dGgtcG93LXRlc3QtdmVjdG9yLW9mLTMyLWJ5dGVz';
    for (const [difficulty, nonce] of [
      [12, '2596'],
      [16, '4124'],
    ] as const) {
      const params = { provider: 'pow', challenge, difficulty } as const;
      expect(solve(params)).toBe(nonce);
      expect(solvesProofOfWork(params, nonce)).toBe(true);
    }
  });

  it('refuses a token that is not a plain decimal nonce, and hosted params', () => {
    const params = { provider: 'pow', challenge: 'a'.repeat(43), difficulty: 1 } as const;
    for (const token of ['', '01', '-1', '+1', '1e3', ' 1', '1 ', '0x1', '1'.repeat(17), '٣']) {
      expect(solvesProofOfWork(params, token)).toBe(false);
    }
    const nonce = solve(params);
    expect(solvesProofOfWork({ provider: 'turnstile', site_key: '0x4AAAA' } as never, nonce)).toBe(
      false
    );
  });

  it('issues a fresh 256-bit puzzle at the realm’s difficulty, and checks its solution', async () => {
    const realms: string[] = [];
    const provider = createProofOfWorkProvider({
      difficulty: ({ realmId }) => (realms.push(realmId), EASY),
    });
    const first = await provider.params({ realmId: REALM, clientId: CLIENT });
    const second = await provider.params({ realmId: REALM, clientId: CLIENT });
    expect(first).toMatchObject({ provider: 'pow', difficulty: EASY });
    expect(first.provider === 'pow' && first.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(second).not.toEqual(first);
    expect(realms).toEqual([REALM, REALM]);
    expect(await provider.verify({ realmId: REALM, params: first, token: solve(first) })).toBe(
      true
    );
    expect(await provider.verify({ realmId: REALM, params: first, token: miss(first) })).toBe(
      false
    );
  });

  it('refuses a difficulty outside 1 to 32, and params outside the step’s schema', async () => {
    for (const difficulty of [0, 33, 1.5, Number.NaN]) {
      const provider = createProofOfWorkProvider({ difficulty: () => difficulty });
      await expect(provider.params({ realmId: REALM, clientId: CLIENT })).rejects.toThrow();
    }
    expect(isProofOfWorkDifficulty(PROOF_OF_WORK_DEFAULT_DIFFICULTY)).toBe(true);
    expect(() =>
      checkedChallengeParams({
        provider: 'pow',
        challenge: 'a'.repeat(43),
        difficulty: 4,
        site_key: 'k',
      })
    ).toThrow();
    expect(() => checkedChallengeParams({ provider: 'pow' })).toThrow();
  });
});

describe('rule 5: when the challenge is due', () => {
  it('offers it on the next round once a soft threshold of the round limits holds', async () => {
    const limiter = limits();
    const built = build({ hooks: { limits: limiter.limiter } });
    const ctx = context({ loginHint: IDENTIFIER, endUserIp: IP });
    await limiter.fail(ROUND_LIMIT_POLICY.endUserIp.softFailures - 1);
    const before = await built.engine.advance(null, null, ctx);
    expect(before).toMatchObject({ kind: 'step', offer: { current: { step: 'password' } } });
    await limiter.fail(1);
    const after = await built.engine.advance(null, null, ctx);
    expect(offered(after)).toMatchObject({ provider: 'pow', difficulty: EASY });
    expect(after).toMatchObject({ offer: { alternatives: [] } });
    // Another IP is not asked.
    const elsewhere = await built.engine.advance(
      null,
      null,
      context({ loginHint: IDENTIFIER, endUserIp: '198.51.100.1' })
    );
    expect(elsewhere).toMatchObject({ offer: { current: { step: 'password' } } });
  });

  it('offers it once the identifier’s ladder is past its free failures, whichever way it is named', async () => {
    const clock = manualClock();
    const ladder = createMemoryLadder(() => clock.now());
    const built = build({ hooks: { ladder }, clock });
    for (let i = 0; i < PASSWORD_LADDER_POLICY.freeFailures; i += 1) {
      const wrong = await built.engine.advance(null, passwordAnswer(WRONG, IDENTIFIER), context());
      expect(wrong).toMatchObject({ kind: 'step' });
      clock.advance(60 * 60_000);
    }
    // A login_hint, or the password answer's own: the password is not checked.
    const verifications = built.passwords.verifications;
    expect(
      offered(await built.engine.advance(null, null, context({ loginHint: IDENTIFIER })))
    ).toMatchObject({ provider: 'pow' });
    expect(
      offered(await built.engine.advance(null, passwordAnswer(PASSWORD, IDENTIFIER), context()))
    ).toMatchObject({ provider: 'pow' });
    expect(built.passwords.verifications).toBe(verifications);
    // Another identifier is not asked.
    expect(
      await built.engine.advance(null, null, context({ loginHint: 'bob@example.com' }))
    ).toMatchObject({ offer: { current: { step: 'password' } } });
  });

  it('offers it when the deployment’s own hook says it is due', async () => {
    const built = build({ hooks: { botChallenge: async () => ({ kind: 'due' }) } });
    expect(
      offered(await built.engine.advance(null, null, context({ loginHint: IDENTIFIER })))
    ).toMatchObject({ provider: 'pow' });
  });

  it('asks nothing while no threshold holds', async () => {
    const built = build({
      hooks: { limits: limits().limiter, ladder: createMemoryLadder(() => T0) },
    });
    const result = await built.engine.advance(
      null,
      passwordAnswer(PASSWORD, IDENTIFIER),
      context({ endUserIp: IP })
    );
    expect(result).toMatchObject({ kind: 'complete' });
    expect(built.provider.puzzles).toBe(0);
  });
});

describe('rule 5: the answer', () => {
  it('resumes the pending step after a right answer, and the pass covers one credential round', async () => {
    const limiter = limits();
    const built = build({ hooks: { limits: limiter.limiter } });
    const ctx = context({ loginHint: IDENTIFIER, endUserIp: IP });
    await limiter.fail(ROUND_LIMIT_POLICY.endUserIp.softFailures);
    const challenged = await built.engine.advance(null, null, ctx);
    const params = offered(challenged);
    const passed = await built.engine.advance(kept(challenged), tokenAnswer(solve(params)), ctx);
    expect(passed).toMatchObject({ kind: 'step', offer: { current: { step: 'password' } } });
    expect(ctx.records.at(-2)).toEqual({ outcome: 'passed', step: 'captcha' });
    // The pass is spent by the next credential round; the delay of the limits still holds it.
    limiter.advance(ROUND_LIMIT_POLICY.endUserIp.delayMs);
    const wrong = await built.engine.advance(kept(passed), passwordAnswer(WRONG), ctx);
    expect(wrong).toMatchObject({ kind: 'step', offer: { current: { step: 'password' } } });
    expect(built.passwords.verifications).toBe(1);
    // The threshold still holds: the next round asks again.
    const again = await built.engine.advance(kept(wrong), passwordAnswer(PASSWORD), ctx);
    expect(offered(again)).not.toEqual(params);
    expect(built.passwords.verifications).toBe(1);
    const repassed = await built.engine.advance(
      kept(again),
      tokenAnswer(solve(offered(again))),
      ctx
    );
    limiter.advance(ROUND_LIMIT_POLICY.endUserIp.delayMs);
    expect(await built.engine.advance(kept(repassed), passwordAnswer(PASSWORD), ctx)).toMatchObject(
      { kind: 'complete' }
    );
  });

  it('keeps one puzzle until it is answered, and never takes a solution twice', async () => {
    const built = build({ hooks: { botChallenge: async () => ({ kind: 'due' }) } });
    const ctx = context({ loginHint: IDENTIFIER });
    const first = await built.engine.advance(null, null, ctx);
    const params = offered(first);
    // Asked again before an answer: the same puzzle.
    const second = await built.engine.advance(kept(first), null, ctx);
    expect(offered(second)).toEqual(params);
    expect(built.provider.puzzles).toBe(1);
    const nonce = solve(params);
    const passed = await built.engine.advance(kept(second), tokenAnswer(nonce), ctx);
    expect(passed).toMatchObject({ offer: { current: { step: 'password' } } });
    // The puzzle is gone from the transaction once answered.
    expect(kept(passed).captcha).toBeUndefined();
    expect(kept(passed).captchaPassed).toBe(true);
    // A pass held while the hook still says due: the pending step, not another puzzle.
    const pending = await built.engine.advance(kept(passed), null, ctx);
    expect(pending).toMatchObject({ offer: { current: { step: 'password' } } });
    // A credential round spends it; the same solution then answers nothing.
    const spent = await built.engine.advance(kept(pending), passwordAnswer(WRONG), ctx);
    const next = offered(await built.engine.advance(kept(spent), null, ctx));
    expect(next).not.toEqual(params);
    const replayed = await built.engine.advance(kept(spent), tokenAnswer(nonce), ctx);
    if (!solvesProofOfWork(next, nonce)) {
      expect(replayed).toMatchObject({
        offer: { current: { step: 'captcha', error: 'captcha_failed' } },
      });
    }
  });

  it('refuses a wrong token with captcha_failed and a new puzzle, and counts it as a failed round', async () => {
    const limiter = limits();
    const built = build({ hooks: { limits: limiter.limiter } });
    const ctx = context({ loginHint: IDENTIFIER, endUserIp: IP });
    await limiter.fail(ROUND_LIMIT_POLICY.endUserIp.softFailures);
    let result = await built.engine.advance(null, null, ctx);
    const first = offered(result);
    result = await built.engine.advance(kept(result), tokenAnswer(miss(first)), ctx);
    expect(result).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'captcha', error: 'captcha_failed' } },
    });
    expect(offered(result)).not.toEqual(first);
    expect(ctx.records.at(-1)).toEqual({
      outcome: 'refused',
      step: 'captcha',
      reason: 'captcha_failed',
    });
    expect(built.passwords.verifications).toBe(0);
    // That one came inside the delay the last failure started: not counted.
    // Each wrong token outside the delay is one more failed round of the IP,
    // until its hard limit refuses every round with 429.
    for (
      let i = ROUND_LIMIT_POLICY.endUserIp.softFailures;
      i < ROUND_LIMIT_POLICY.endUserIp.hardFailures;
      i += 1
    ) {
      limiter.advance(ROUND_LIMIT_POLICY.endUserIp.delayMs);
      result = await built.engine.advance(kept(result), tokenAnswer(miss(offered(result))), ctx);
      expect(result).toMatchObject({ offer: { current: { error: 'captcha_failed' } } });
    }
    expect(await built.engine.advance(kept(result), null, ctx)).toMatchObject({
      kind: 'refused',
      reason: 'throttled',
    });
  });

  it('refuses a token over 4096 bytes as an invalid answer, unchecked', async () => {
    let checked = 0;
    const built = build({
      hooks: { botChallenge: async () => ({ kind: 'due' }) },
      steps: [
        createCaptchaStep({
          params: easyProofOfWork().params,
          verify: async () => ((checked += 1), true),
        }),
      ],
    });
    const ctx = context({ loginHint: IDENTIFIER });
    const first = await built.engine.advance(null, null, ctx);
    const result = await built.engine.advance(kept(first), tokenAnswer('1'.repeat(4097)), ctx);
    expect(result).toMatchObject({ kind: 'refused', reason: 'invalid_answer' });
    expect(checked).toBe(0);
  });

  it('never keeps the token: not in an audit record, a hook’s round or the transaction', async () => {
    const rounds: HookRound[] = [];
    const tokens: string[] = [];
    const hooks: SignInHooks = {
      botChallenge: async (round) => (rounds.push(round), { kind: 'due' }),
      request: async (round) => (rounds.push(round), { kind: 'continue' }),
    };
    for (const verdict of [true, false]) {
      const built = build({
        hooks,
        steps: [
          createCaptchaStep({
            params: easyProofOfWork().params,
            verify: async ({ token }) => (tokens.push(token), verdict),
          }),
        ],
      });
      const ctx = context({ loginHint: IDENTIFIER });
      const first = await built.engine.advance(null, null, ctx);
      const result = await built.engine.advance(kept(first), tokenAnswer(TOKEN_MARK), ctx);
      expect(JSON.stringify(ctx.records)).not.toContain(TOKEN_MARK);
      expect(JSON.stringify(result)).not.toContain(TOKEN_MARK);
    }
    expect(tokens).toEqual([TOKEN_MARK, TOKEN_MARK]);
    expect(JSON.stringify(rounds)).not.toContain(TOKEN_MARK);
  });
});

describe('rule 5: a challenge that cannot be answered', () => {
  const due: SignInHooks = { botChallenge: async () => ({ kind: 'due' }) };

  it('refuses the round when no provider is configured: never passed, never redirected', async () => {
    const built = build({ hooks: due, steps: [] });
    const result = await built.engine.advance(
      null,
      passwordAnswer(PASSWORD, IDENTIFIER),
      context()
    );
    expect(result).toMatchObject({ kind: 'refused', reason: 'unavailable' });
    expect(built.passwords.verifications).toBe(0);
  });

  it('refuses the round when the provider cannot answer, or answers out of shape', async () => {
    const providers: BotChallengeProvider[] = [
      {
        params: async () => {
          throw new Error('provider down');
        },
        verify: async () => true,
      },
      { params: async () => ({ provider: 'pow' }) as never, verify: async () => true },
      {
        params: easyProofOfWork().params,
        verify: async () => {
          throw new Error('provider down');
        },
      },
      { params: easyProofOfWork().params, verify: async () => 'yes' as never },
    ];
    for (const provider of providers) {
      const built = build({ hooks: due, steps: [createCaptchaStep(provider)] });
      const ctx = context({ loginHint: IDENTIFIER });
      const first = await built.engine.advance(null, null, ctx);
      const result =
        first.kind === 'step'
          ? await built.engine.advance(kept(first), tokenAnswer('12345'), ctx)
          : first;
      expect(result).toMatchObject({ kind: 'refused', reason: 'unavailable' });
      expect(built.passwords.verifications).toBe(0);
    }
  });

  it('lets a client that did not list captcha go on under the delay and the 429 of the limits', async () => {
    const limiter = limits();
    const built = build({ hooks: { limits: limiter.limiter } });
    const ctx = context({
      loginHint: IDENTIFIER,
      endUserIp: IP,
      serves: ['identifier', 'password'],
    });
    await limiter.fail(ROUND_LIMIT_POLICY.endUserIp.softFailures);
    const first = await built.engine.advance(null, null, ctx);
    expect(first).toMatchObject({ kind: 'step', offer: { current: { step: 'password' } } });
    // The delay the last failure started: 429, the password unchecked.
    expect(await built.engine.advance(kept(first), passwordAnswer(PASSWORD), ctx)).toMatchObject({
      kind: 'refused',
      reason: 'throttled',
    });
    expect(built.passwords.verifications).toBe(0);
    // Past the hard limit: 429 on every round.
    limiter.advance(ROUND_LIMIT_POLICY.endUserIp.delayMs);
    await limiter.fail(
      ROUND_LIMIT_POLICY.endUserIp.hardFailures - ROUND_LIMIT_POLICY.endUserIp.softFailures
    );
    expect(await built.engine.advance(null, null, ctx)).toMatchObject({
      kind: 'refused',
      reason: 'throttled',
    });
    expect(built.provider.puzzles).toBe(0);
  });
});

describe('rule 5: at registration', () => {
  class ChallengingRegistrations extends FakeRegistrations {
    requires = true;
    readonly asked: { readonly realmId: string; readonly clientId: string }[] = [];
    async challengeRequired(input: { readonly realmId: string; readonly clientId: string }) {
      this.asked.push(input);
      return this.requires;
    }
  }

  function buildRegistration(options: Partial<SignInEngineDependencies> = {}) {
    const directory = new FakeDirectory(new Map());
    const registrations = new ChallengingRegistrations(directory);
    const provider = easyProofOfWork();
    const engine = createSignInEngine({
      accounts: directory,
      passwords: new FakePasswords(),
      policy: new FakePolicy(),
      identifierDigest: fakeIdentifierDigest,
      requireVerifiedAccount: false,
      emailCodes: { digest: fakeEmailCodeDigest, addresses: new FakeAddresses(directory) },
      passwordUpdates: new FakePasswordUpdates(directory),
      breachCheck: new FakeBreachList(new Set()),
      registrations,
      hooks: { ladder: createMemoryLadder(() => T0) },
      clock: manualClock(),
      steps: [createCaptchaStep(provider)],
      ...options,
    });
    const sender = new FakeCodeSender();
    const ctx = (overrides: Partial<RoundContext> = {}) =>
      context({ flow: 'register', sendCode: sender.send, ...overrides });
    return { engine, registrations, provider, sender, ctx };
  }

  it('asks a client that requires it before the address, once per registration', async () => {
    const built = buildRegistration();
    const ctx = built.ctx();
    const first = await built.engine.advance(null, null, ctx);
    const params = offered(first);
    expect(built.registrations.asked).toEqual([{ realmId: REALM, clientId: CLIENT }]);
    const passed = await built.engine.advance(kept(first), tokenAnswer(solve(params)), ctx);
    expect(passed).toMatchObject({ kind: 'step', offer: { current: { step: 'identifier' } } });
    const code = await built.engine.advance(
      kept(passed),
      answer('identifier', { login_hint: IDENTIFIER }),
      ctx
    );
    expect(code).toMatchObject({ kind: 'step', offer: { current: { step: 'email_code' } } });
    expect(built.sender.sent).toHaveLength(1);
    expect(built.provider.puzzles).toBe(1);
  });

  it('asks nothing of a client that does not require it', async () => {
    const built = buildRegistration();
    built.registrations.requires = false;
    const first = await built.engine.advance(null, null, built.ctx());
    expect(first).toMatchObject({ kind: 'step', offer: { current: { step: 'identifier' } } });
    expect(built.provider.puzzles).toBe(0);
  });

  it('refuses the registration of a client that cannot answer the challenge it requires', async () => {
    const built = buildRegistration();
    const result = await built.engine.advance(
      null,
      answer('identifier', { login_hint: IDENTIFIER }),
      built.ctx({ serves: ['identifier', 'email_code', 'new_password'] })
    );
    expect(result).toMatchObject({
      kind: 'refused',
      reason: 'request_refused',
      code: REGISTRATION_NOT_ALLOWED,
    });
    expect(built.sender.sent).toHaveLength(0);
  });

  it('refuses the registration when the requirement cannot be read, or no provider answers', async () => {
    const unreadable = buildRegistration();
    unreadable.registrations.challengeRequired = async () => {
      throw new Error('database down');
    };
    expect(await unreadable.engine.advance(null, null, unreadable.ctx())).toMatchObject({
      kind: 'refused',
      reason: 'unavailable',
    });
    const bare = buildRegistration({ steps: [] });
    expect(await bare.engine.advance(null, null, bare.ctx())).toMatchObject({
      kind: 'refused',
      reason: 'unavailable',
    });
  });
});
