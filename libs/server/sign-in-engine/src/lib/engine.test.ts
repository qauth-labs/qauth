import {
  createFipaMapper,
  createInteractionMapper,
  STEP_URNS,
  type StepName,
} from '@qauth-labs/server-step-grammar';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  type FakeAccount,
  FakeDirectory,
  fakeHash,
  fakeIdentifierDigest,
  FakePasswords,
  FakePolicy,
  passwordAccount,
  recordingAudit,
} from '../testing/fakes';
import { createMemoryLadder } from '../testing/memory-ladder';
import {
  createSignInEngine,
  SIGN_IN_MIN_RESPONSE_TIME_MS,
  type SignInEngineDependencies,
} from './engine';
import { type LadderHook, NOTHING_DUE, type SignInHooks } from './hooks';
import { PASSWORD_LADDER_POLICY } from './ladder';
import {
  type Clock,
  type MfaPolicy,
  type PasswordHardAction,
  type SignInAccount,
  SYSTEM_CLOCK,
} from './ports';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import type { AnyStepHandler, StepHandler, StepVerdict } from './steps/handler';
import { SIGN_IN_TRANSACTION_MAX_AGE_MS, type SignInTransaction } from './transaction';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'native-app';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const OTHER_USER = '0199fa20-5e1a-7000-8000-000000000002';
const PASSWORD = 'correct horse battery staple';
/** One account of {@link accountKinds}, which must exist. */
function kindAccount(kind: Exclude<AccountKind, 'unknown'>): FakeAccount {
  const account = accountKinds()[kind];
  if (account === null) throw new Error(kind);
  return account;
}
const WRONG = 'not the password at all';
const IDENTIFIER = 'alice@example.com';

/** When {@link manualClock} starts, in epoch milliseconds. */
const T0 = 1_800_000_000_000;

/** A transaction as the engine writes it for {@link context}'s realm and client, begun at {@link T0}. */
function tx(fields: Partial<SignInTransaction> = {}): SignInTransaction {
  return {
    v: 1,
    realmId: REALM,
    clientId: CLIENT,
    createdAt: T0,
    verified: [],
    ...fields,
  } as SignInTransaction;
}

/** A clock whose waits pass at once, recording them, so a test need not wait 500 ms a round. */
function manualClock(start = T0): Clock & { slept: number[]; advance(ms: number): void } {
  let now = start;
  const slept: number[] = [];
  return {
    slept,
    now: () => now,
    sleep: async (ms) => {
      slept.push(ms);
      now += ms;
    },
    advance: (ms) => {
      now += ms;
    },
  };
}

type AccountKind =
  | 'unknown'
  | 'passwordOnly'
  | 'passkeyOnly'
  | 'passwordAndPasskey'
  | 'disabled'
  | 'locked'
  | 'unverified'
  | 'unreadable';

/** The account kinds the engine must not tell apart before a factor succeeds. */
function accountKinds(): Record<AccountKind, FakeAccount | null> {
  return {
    unknown: null,
    passwordOnly: passwordAccount(USER, PASSWORD),
    passkeyOnly: passwordAccount(USER, PASSWORD, {
      password: null,
      others: [{ type: 'passkey', disabled: false }],
    }),
    passwordAndPasskey: passwordAccount(USER, PASSWORD, {
      others: [{ type: 'passkey', disabled: false }],
    }),
    disabled: passwordAccount(USER, PASSWORD, { enabled: false }),
    // The ladder's hard action disabled the password (#615): it is locked.
    locked: passwordAccount(USER, PASSWORD, {
      password: { disabled: true, hash: fakeHash(PASSWORD) },
    }),
    unverified: passwordAccount(USER, PASSWORD, { verified: false }),
    unreadable: passwordAccount(USER, PASSWORD, { password: { disabled: false, hash: null } }),
  };
}

interface Built {
  readonly engine: ReturnType<typeof createSignInEngine>;
  readonly directory: FakeDirectory;
  readonly passwords: FakePasswords;
  readonly policy: FakePolicy;
  readonly clock: ReturnType<typeof manualClock>;
}

function build(
  accounts: Record<string, FakeAccount | null> = {
    [IDENTIFIER]: passwordAccount(USER, PASSWORD),
  },
  options: Partial<SignInEngineDependencies> = {}
): Built {
  const directory = new FakeDirectory(
    new Map(
      Object.entries(accounts).filter((entry): entry is [string, FakeAccount] => entry[1] !== null)
    )
  );
  const passwords = new FakePasswords();
  const policy = new FakePolicy();
  const clock = manualClock();
  const engine = createSignInEngine({
    accounts: directory,
    passwords,
    policy,
    identifierDigest: fakeIdentifierDigest,
    requireVerifiedAccount: true,
    clock,
    ...options,
  });
  return { engine, directory, passwords, policy, clock };
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

function answer(step: StepName, fields: Record<string, unknown>): RoundAnswer {
  return { step: STEP_URNS[step], fields };
}

const passwordAnswer = (password: string, loginHint?: string) =>
  answer('password', { password, ...(loginHint === undefined ? {} : { login_hint: loginHint }) });

/** Run round 0 with a login_hint, then a password round: the two rounds of a FiPA or browser sign-in. */
async function signIn(
  built: Built,
  password: string,
  ctx = context({ loginHint: IDENTIFIER })
): Promise<{ first: RoundResult; second: RoundResult }> {
  const first = await built.engine.advance(null, null, ctx);
  if (first.kind !== 'step') throw new Error(`round 0 answered ${first.kind}`);
  const second = await built.engine.advance(first.transaction, passwordAnswer(password), ctx);
  return { first, second };
}

const interaction = createInteractionMapper();
const fipa = createFipaMapper({ serves: ['identifier', 'password', 'password_reset'] });

/** What each transport would put on the wire for a step result. */
function wire(result: RoundResult): string {
  if (result.kind !== 'step') return JSON.stringify(result);
  return JSON.stringify({
    result,
    stepView: interaction.stepView(result.offer),
    personalView: interaction.personalView(result.offer, result.personal),
    fipa: fipa.challenge(result.offer, {
      issuer: 'https://auth.example.com',
      newAuthSession: () => 'A'.repeat(43),
      interactionTypesSupported: [STEP_URNS.identifier, STEP_URNS.password],
    }),
  });
}

/** A seeded generator, so the property test is the same on every run. */
function generator(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state * 1_103_515_245 + 12_345) % 2_147_483_648;
    return state / 2_147_483_648;
  };
}

function randomIdentifier(random: () => number): string {
  const letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.+_-';
  const pick = (length: number) =>
    Array.from({ length }, () => letters[Math.floor(random() * letters.length)]).join('');
  const local = `${pick(1 + Math.floor(random() * 20))}x`
    .replace(/^[.]+/, 'a')
    .replace(/[.]+x$/, 'x');
  return `${local}@${['example.com', 'Example.ORG', 'mail.example.net'][Math.floor(random() * 3)]}`;
}

describe('the first response is the same for every account (ADR-017 Decision 4)', () => {
  it('is byte-identical for every account kind, for any identifier and password (property)', async () => {
    const random = generator(614);
    for (let run = 0; run < 40; run++) {
      const typed = randomIdentifier(random);
      const identifier = typed.toLowerCase();
      const guess = random() < 0.5 ? PASSWORD : `${WRONG}-${run}`;
      const outputs = new Map<string, string[]>();
      for (const [kind, account] of Object.entries(accountKinds())) {
        const built = build({ [identifier]: account });
        const runs: string[] = [];
        // Round 0 from the request's login_hint.
        const hinted = await built.engine.advance(null, null, context({ loginHint: typed }));
        runs.push(wire(hinted));
        // Round 0 with no hint, then the identifier answer.
        const asked = await built.engine.advance(null, null, context());
        runs.push(wire(asked));
        const identified = await built.engine.advance(
          asked.transaction as SignInTransaction,
          answer('identifier', { login_hint: typed }),
          context()
        );
        runs.push(wire(identified));
        // A wrong password, eager and then as an answer to the password step.
        runs.push(
          wire(
            await built.engine.advance(null, passwordAnswer(`${WRONG}-${run}`, typed), context())
          )
        );
        runs.push(
          wire(
            await built.engine.advance(
              identified.transaction as SignInTransaction,
              passwordAnswer(`${WRONG}-${run}`),
              context()
            )
          )
        );
        // Every round took exactly the floor.
        runs.push(JSON.stringify(built.clock.slept.map((ms) => ms > 0)));
        // The right password, or any other, wherever it does not complete.
        if (!['passwordOnly', 'passwordAndPasskey'].includes(kind) || guess !== PASSWORD) {
          runs.push(
            wire(
              await built.engine.advance(
                identified.transaction as SignInTransaction,
                passwordAnswer(guess),
                context()
              )
            )
          );
        }
        outputs.set(kind, runs);
      }
      const reference = outputs.get('unknown') ?? [];
      expect(reference.length).toBeGreaterThan(0);
      for (const [kind, runs] of outputs) {
        expect(runs.slice(0, reference.length), `${kind} for ${typed}`).toEqual(
          reference.slice(0, runs.length)
        );
      }
    }
  });

  it('gives an offer that names no account, whichever login_hint the request carries', async () => {
    const built = build(accountKinds());
    const offers = new Set<string>();
    for (const hint of ['unknown@example.com', 'alice@example.com', 'Bob@Example.com']) {
      const result = await built.engine.advance(null, null, context({ loginHint: hint }));
      expect(result.kind).toBe('step');
      if (result.kind === 'step') offers.add(JSON.stringify(result.offer));
    }
    expect([...offers]).toEqual([
      JSON.stringify({ current: { step: 'password', params: {} }, alternatives: [] }),
    ]);
  });

  it('reads no account before a credential is answered', async () => {
    const built = build(accountKinds());
    await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
    await built.engine.advance(null, answer('identifier', { login_hint: IDENTIFIER }), context());
    expect(built.directory.reads).toEqual([]);
    expect(built.passwords.verifications).toBe(0);
  });

  it('refuses an unverified account under REQUIRE_VERIFIED_ACCOUNT like a wrong password, and lets it in when the gate is off', async () => {
    const accounts = { [IDENTIFIER]: passwordAccount(USER, PASSWORD, { verified: false }) };
    const gated = await signIn(build(accounts), PASSWORD);
    expect(gated.second).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'password', error: 'invalid_credentials' } },
    });
    const open = await signIn(build(accounts, { requireVerifiedAccount: false }), PASSWORD);
    expect(open.second.kind).toBe('complete');
  });
});

describe('the dummy hash', () => {
  it('verifies an unknown identifier against the dummy hash, once', async () => {
    const built = build({});
    const verify = vi.spyOn(built.passwords, 'verify');
    const decoy = vi.spyOn(built.passwords, 'verifyDecoy');
    const { second } = await signIn(built, PASSWORD, context({ loginHint: 'nobody@example.com' }));
    expect(second).toMatchObject({
      kind: 'step',
      offer: { current: { error: 'invalid_credentials' } },
    });
    expect(decoy).toHaveBeenCalledTimes(1);
    expect(decoy).toHaveBeenCalledWith(PASSWORD);
    expect(verify).not.toHaveBeenCalled();
  });

  it.each<AccountKind>(['passkeyOnly', 'locked', 'unreadable'])(
    'verifies against the dummy hash when the account has no usable password (%s)',
    async (kind) => {
      const built = build({ [IDENTIFIER]: accountKinds()[kind] });
      await signIn(built, PASSWORD);
      expect(built.passwords.decoys).toBe(1);
      expect(built.passwords.verified).toEqual([]);
    }
  );

  it('verifies the real hash, once, for every other refused password', async () => {
    for (const kind of ['passwordOnly', 'disabled', 'unverified'] as const) {
      const built = build({ [IDENTIFIER]: accountKinds()[kind] });
      await signIn(built, kind === 'passwordOnly' ? WRONG : PASSWORD);
      expect(built.passwords.verifications, kind).toBe(1);
      expect(built.passwords.decoys, kind).toBe(0);
    }
  });
});

describe('the timing floor', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /** Start `round` on the system clock under fake timers, and see when it settles. */
  async function settlesAt(
    round: () => Promise<RoundResult>
  ): Promise<{ at499: boolean; at500: boolean }> {
    let settled = false;
    const done = round().then(() => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(SIGN_IN_MIN_RESPONSE_TIME_MS - 1);
    const at499 = settled;
    await vi.advanceTimersByTimeAsync(1);
    const at500 = settled;
    await done;
    return { at499, at500 };
  }

  it('answers no round before 500 ms, whatever it answers (fake clock)', async () => {
    vi.useFakeTimers();
    const rounds: Record<string, (engine: Built['engine']) => Promise<RoundResult>> = {
      identifierStep: (engine) => engine.advance(null, null, context()),
      passwordStep: (engine) => engine.advance(null, null, context({ loginHint: IDENTIFIER })),
      wrongPassword: (engine) => engine.advance(null, passwordAnswer(WRONG, IDENTIFIER), context()),
      unknownIdentifier: (engine) =>
        engine.advance(null, passwordAnswer(WRONG, 'nobody@example.com'), context()),
      complete: (engine) => engine.advance(null, passwordAnswer(PASSWORD, IDENTIFIER), context()),
      invalidAnswer: (engine) =>
        engine.advance(null, answer('identifier', { login_hint: 'not an address' }), context()),
      endedTransaction: (engine) => engine.advance({ ...tx(), subject: USER }, null, context()),
    };
    for (const [name, round] of Object.entries(rounds)) {
      const built = build(undefined, { clock: SYSTEM_CLOCK });
      expect(await settlesAt(() => round(built.engine)), name).toEqual({
        at499: false,
        at500: true,
      });
    }
    // A policy that cannot be read is refused no sooner either.
    const unreadable = build(undefined, {
      clock: SYSTEM_CLOCK,
      policy: { read: async () => Promise.reject(new Error('down')) },
    });
    expect(await settlesAt(() => unreadable.engine.advance(null, null, context()))).toEqual({
      at499: false,
      at500: true,
    });
  });

  it('counts the floor from the request’s arrival, and adds nothing to a round already slower', async () => {
    const built = build();
    const started = built.clock.now();
    await built.engine.advance(null, null, context({ receivedAt: started - 200 }));
    expect(built.clock.slept).toEqual([300]);
    const slow = build(undefined, {
      policy: {
        read: async () => {
          slow.clock.advance(700);
          return { realm: 'off', client: 'off' };
        },
      },
    });
    await slow.engine.advance(null, null, context());
    expect(slow.clock.slept).toEqual([]);
  });

  it('waits the floor before a failed audit write fails the round', async () => {
    const built = build();
    await expect(
      built.engine.advance(
        null,
        null,
        context({
          loginHint: IDENTIFIER,
          audit: async () => Promise.reject(new Error('event store down')),
        })
      )
    ).rejects.toThrow('event store down');
    expect(built.clock.slept).toEqual([SIGN_IN_MIN_RESPONSE_TIME_MS]);
  });
});

describe('one subject per transaction', () => {
  it('ends the transaction on a second login_hint, audited as subject_mismatch', async () => {
    const built = build();
    const ctx = context({ loginHint: IDENTIFIER });
    const first = await built.engine.advance(null, null, ctx);
    const second = context({ loginHint: 'mallory@example.com' });
    const result = await built.engine.advance(first.transaction as SignInTransaction, null, second);
    expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(second.records).toEqual([
      {
        outcome: 'ended',
        step: 'identifier',
        reason: 'subject_mismatch',
        identifierHmac: await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER }),
      },
    ]);
    expect(built.passwords.verifications).toBe(0);
  });

  it('ends the transaction on another identifier in an answer', async () => {
    const built = build();
    const first = await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
    for (const next of [
      answer('identifier', { login_hint: 'mallory@example.com' }),
      passwordAnswer(PASSWORD, 'mallory@example.com'),
    ]) {
      const ctx = context();
      const result = await built.engine.advance(first.transaction as SignInTransaction, next, ctx);
      expect(result.kind === 'refused' && result.reason).toBe('transaction_ended');
      expect(ctx.records).toMatchObject([{ outcome: 'ended', reason: 'subject_mismatch' }]);
    }
    expect(built.passwords.verifications).toBe(0);
  });

  it('keeps the transaction when the same identifier comes again, in any case', async () => {
    const built = build();
    const first = await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
    const again = await built.engine.advance(
      first.transaction as SignInTransaction,
      answer('identifier', { login_hint: 'Alice@Example.COM' }),
      context({ loginHint: IDENTIFIER })
    );
    expect(again.kind).toBe('step');
  });

  it('ends the transaction on another user’s proof, audited under the first subject', async () => {
    // A passkey step that proves another user than the password did.
    const passkey = fakeFactorStep('webauthn_get', 'first_factor', 'passkey', OTHER_USER);
    const built = build({ [IDENTIFIER]: kindAccount('passwordAndPasskey') }, { steps: [passkey] });
    const ctx = context({ loginHint: IDENTIFIER });
    const first = await built.engine.advance(null, null, ctx);
    const afterPassword = await built.engine.advance(
      first.transaction as SignInTransaction,
      passwordAnswer(PASSWORD),
      ctx
    );
    // The downgrade rule asks for the passkey after the password.
    expect(afterPassword).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'webauthn_get' } },
    });
    const proofCtx = context();
    const result = await built.engine.advance(
      afterPassword.transaction as SignInTransaction,
      answer('webauthn_get', { webauthn_response: WEBAUTHN_RESPONSE }),
      proofCtx
    );
    expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(proofCtx.records).toEqual([
      { outcome: 'ended', step: 'webauthn_get', reason: 'subject_mismatch', userId: USER },
    ]);
  });
});

describe('eager answers', () => {
  it('ignores a password while the identifier step is next: not verified, not counted', async () => {
    const reserve = vi.fn<LadderHook['reserve']>();
    const built = build(undefined, { hooks: { ladder: { reserve } } });
    const ctx = context();
    const result = await built.engine.advance(null, passwordAnswer(PASSWORD), ctx);
    expect(result).toMatchObject({ kind: 'step', offer: { current: { step: 'identifier' } } });
    expect(reserve).not.toHaveBeenCalled();
    expect(built.passwords.verifications).toBe(0);
    expect(built.directory.reads).toEqual([]);
    expect(ctx.records).toEqual([]);
  });

  it('verifies a password sent with its identifier on round 0: the one-call path', async () => {
    const built = build();
    const result = await built.engine.advance(
      null,
      passwordAnswer(PASSWORD, IDENTIFIER),
      context()
    );
    expect(result).toMatchObject({ kind: 'complete', signIn: { subject: USER, amr: ['pwd'] } });
  });

  it('ignores a password while a bot challenge is due, and checks nothing', async () => {
    const hooks: SignInHooks = {
      botChallenge: async () => ({ kind: 'due', retryAfterSeconds: 30 }),
    };
    const built = build(undefined, { hooks });
    const result = await built.engine.advance(
      null,
      passwordAnswer(PASSWORD, IDENTIFIER),
      context()
    );
    expect(result).toMatchObject({ kind: 'refused', reason: 'throttled', retryAfterSeconds: 30 });
    expect(built.passwords.verifications).toBe(0);
  });

  it('ignores an answer to a step the grammar does not know', async () => {
    const built = build();
    const result = await built.engine.advance(
      null,
      { step: 'urn:qauth:ia:unknown:v1-rc.0', fields: { password: PASSWORD } },
      context({ loginHint: IDENTIFIER })
    );
    expect(result).toMatchObject({ kind: 'step', offer: { current: { step: 'password' } } });
    expect(built.passwords.verifications).toBe(0);
  });
});

describe('the MFA policy, read on every round', () => {
  it('refuses the round when the policy cannot be read, before any credential is checked', async () => {
    const onUnavailable = vi.fn();
    const built = build(undefined, {
      policy: { read: async () => Promise.reject(new Error('policy store down')) },
      onUnavailable,
    });
    const ctx = context();
    const result = await built.engine.advance(null, passwordAnswer(PASSWORD, IDENTIFIER), ctx);
    expect(result).toEqual({
      kind: 'refused',
      reason: 'unavailable',
      transaction: tx(),
    });
    expect(built.passwords.verifications).toBe(0);
    expect(ctx.records).toEqual([]);
    expect(onUnavailable).toHaveBeenCalledWith(expect.objectContaining({ port: 'policy' }));
  });

  it('refuses the round when the policy names a mode the engine does not know', async () => {
    const built = build(undefined, {
      policy: { read: async () => ({ realm: 'sometimes', client: 'off' }) as unknown as MfaPolicy },
    });
    const result = await built.engine.advance(
      null,
      passwordAnswer(PASSWORD, IDENTIFIER),
      context()
    );
    expect(result).toMatchObject({ kind: 'refused', reason: 'unavailable' });
    expect(built.passwords.verifications).toBe(0);
  });

  it('reads the policy on every round and keeps none of it in the transaction', async () => {
    const totp = fakeFactorStep('totp', 'second_factor', 'totp', USER);
    const built = build(
      {
        [IDENTIFIER]: passwordAccount(USER, PASSWORD, {
          others: [{ type: 'totp', disabled: false }],
        }),
      },
      { steps: [totp] }
    );
    built.policy.policy = { realm: 'required', client: 'off' };
    const { second } = await signIn(built, PASSWORD);
    expect(second).toMatchObject({ kind: 'step', offer: { current: { step: 'totp' } } });
    expect(JSON.stringify(second.transaction)).not.toMatch(/required|policy|mfa/);
    // A policy change reaches the live transaction on its next round.
    built.policy.policy = { realm: 'off', client: 'off' };
    const third = await built.engine.advance(
      second.transaction as SignInTransaction,
      null,
      context()
    );
    expect(third.kind).toBe('complete');
    expect(built.policy.reads).toBe(3);
  });

  it('asks for the second factor and completes with mfa', async () => {
    const totp = fakeFactorStep('totp', 'second_factor', 'totp', USER);
    const built = build(
      {
        [IDENTIFIER]: passwordAccount(USER, PASSWORD, {
          others: [{ type: 'totp', disabled: false }],
        }),
      },
      { steps: [totp] }
    );
    built.policy.policy = { realm: 'off', client: 'required' };
    const { second } = await signIn(built, PASSWORD);
    const third = await built.engine.advance(
      second.transaction as SignInTransaction,
      answer('totp', { otp: '123456' }),
      context()
    );
    expect(third).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd', 'otp', 'mfa'] } });
  });

  it('never completes without a second factor the policy requires; with no step for it, redirects', async () => {
    for (const policy of [
      { realm: 'required', client: 'off' },
      { realm: 'off', client: 'required' },
      { realm: 'required_for_admins', client: 'off' },
    ] as MfaPolicy[]) {
      const built = build({ [IDENTIFIER]: passwordAccount(USER, PASSWORD, { admin: true }) });
      built.policy.policy = policy;
      const { second } = await signIn(built, PASSWORD);
      expect(second, JSON.stringify(policy)).toMatchObject({
        kind: 'redirect',
        reason: 'step_not_available',
      });
    }
    const notAdmin = build();
    notAdmin.policy.policy = { realm: 'required_for_admins', client: 'optional' };
    expect((await signIn(notAdmin, PASSWORD)).second.kind).toBe('complete');
  });
});

describe('the downgrade rule', () => {
  it('never completes a passkey-bound account on its password, even when the passkey is disabled', async () => {
    for (const disabled of [false, true]) {
      const built = build({
        [IDENTIFIER]: passwordAccount(USER, PASSWORD, {
          others: [{ type: 'passkey', disabled }],
        }),
      });
      const { second } = await signIn(built, PASSWORD);
      expect(second, `disabled: ${disabled}`).toMatchObject({
        kind: 'redirect',
        reason: 'step_not_available',
      });
      // The transaction ends with the redirect: no later round can complete it.
      expect(second.transaction).toBeNull();
    }
  });

  it('asks for the passkey after the password, and completes with both', async () => {
    const passkey = fakeFactorStep('webauthn_get', 'first_factor', 'passkey', USER);
    const built = build({ [IDENTIFIER]: kindAccount('passwordAndPasskey') }, { steps: [passkey] });
    const first = await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
    const second = await built.engine.advance(
      first.transaction as SignInTransaction,
      passwordAnswer(PASSWORD),
      context()
    );
    expect(second).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'webauthn_get' }, alternatives: [] },
    });
    const third = await built.engine.advance(
      second.transaction as SignInTransaction,
      answer('webauthn_get', { webauthn_response: WEBAUTHN_RESPONSE }),
      context()
    );
    expect(third).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd', 'pop', 'mfa'] } });
  });
});

describe('try another way', () => {
  it('offers before the first factor only what every account is offered', async () => {
    const passkey = fakeFactorStep('webauthn_get', 'first_factor', 'passkey', USER);
    const offers = new Set<string>();
    for (const account of Object.values(accountKinds())) {
      const built = build({ [IDENTIFIER]: account }, { steps: [passkey] });
      const result = await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
      if (result.kind === 'step') offers.add(JSON.stringify(result.offer));
      const refused = await built.engine.advance(
        result.transaction as SignInTransaction,
        passwordAnswer(WRONG),
        context()
      );
      if (refused.kind === 'step') offers.add(JSON.stringify(refused.offer));
    }
    // ADR-017 Decision 4: with a login_hint, the same password-required shape
    // for every account, with the passkey offered.
    expect([...offers].map((offer) => JSON.parse(offer))).toEqual([
      {
        current: { step: 'password', params: {} },
        alternatives: [{ step: 'webauthn_get', params: PASSKEY_PARAMS }],
      },
      {
        current: { step: 'password', params: {}, error: 'invalid_credentials' },
        alternatives: [{ step: 'webauthn_get', params: PASSKEY_PARAMS }],
      },
    ]);
  });

  it('offers a discoverable passkey first when no identifier is known, preferred, beside the password and the identifier', async () => {
    const passkey = fakeFactorStep('webauthn_get', 'first_factor', 'passkey', USER);
    const offers = new Set<string>();
    for (const account of Object.values(accountKinds())) {
      const built = build({ [IDENTIFIER]: account }, { steps: [passkey] });
      const result = await built.engine.advance(null, null, context());
      if (result.kind === 'step') offers.add(JSON.stringify(result.offer));
    }
    expect([...offers].map((offer) => JSON.parse(offer))).toEqual([
      {
        current: { step: 'webauthn_get', params: PASSKEY_PARAMS },
        alternatives: [
          { step: 'password', params: {} },
          { step: 'identifier', params: {} },
        ],
        required: false,
      },
    ]);
    // A FiPA client that did not list webauthn_get gets the password it listed.
    const built = build({ [IDENTIFIER]: kindAccount('passwordOnly') }, { steps: [passkey] });
    const first = await built.engine.advance(null, null, context());
    if (first.kind !== 'step') throw new Error(first.kind);
    const listing = createFipaMapper({ serves: ['identifier', 'password', 'webauthn_get'] });
    expect(
      listing.challenge(first.offer, {
        issuer: 'https://auth.example.com',
        newAuthSession: () => 'A'.repeat(43),
        interactionTypesSupported: [STEP_URNS.identifier, STEP_URNS.password],
      }).body
    ).toMatchObject({ interaction_type_required: STEP_URNS.password });
  });

  it('signs in with a discoverable passkey before any identifier', async () => {
    const passkey = fakeFactorStep('webauthn_get', 'first_factor', 'passkey', USER);
    const built = build({ [IDENTIFIER]: kindAccount('passkeyOnly') }, { steps: [passkey] });
    const ctx = context();
    const done = await built.engine.advance(
      null,
      answer('webauthn_get', { webauthn_response: WEBAUTHN_RESPONSE }),
      ctx
    );
    expect(done).toMatchObject({
      kind: 'complete',
      signIn: { subject: USER, amr: ['pop', 'mfa'] },
    });
    expect(done.kind === 'complete' && done.signIn.identifier).toBeUndefined();
    expect(ctx.records).toEqual([{ outcome: 'passed', step: 'webauthn_get', userId: USER }]);
    const totp = fakeFactorStep('totp', 'second_factor', 'totp', USER);
    const mfa = build(
      {
        [IDENTIFIER]: passwordAccount(USER, PASSWORD, {
          password: null,
          others: [
            { type: 'passkey', disabled: false },
            { type: 'totp', disabled: false },
          ],
        }),
      },
      { steps: [passkey, totp] }
    );
    mfa.policy.policy = { realm: 'required', client: 'off' };
    const proved = await mfa.engine.advance(
      null,
      answer('webauthn_get', { webauthn_response: WEBAUTHN_RESPONSE }),
      context()
    );
    // A passkey alone carries mfa: the policy is met.
    expect(proved.kind).toBe('complete');
  });

  it('offers after the first factor only the account’s remaining methods that meet the rules', async () => {
    const totp = fakeFactorStep('totp', 'second_factor', 'totp', USER);
    const passkey = fakeFactorStep('webauthn_get', 'first_factor', 'passkey', USER);
    const account = passwordAccount(USER, PASSWORD, {
      others: [{ type: 'totp', disabled: false }],
    });
    const built = build({ [IDENTIFIER]: account }, { steps: [passkey, totp] });
    built.policy.policy = { realm: 'required', client: 'off' };
    const result = await built.engine.advance(
      null,
      passwordAnswer(PASSWORD, IDENTIFIER),
      context()
    );
    // No passkey is bound, so only TOTP is offered: the password is spent, and nothing else
    // meets the policy.
    expect(result).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'totp' }, alternatives: [] },
    });
  });

  it('refuses an email code as a sign-in step: email never stands in for an authenticator', () => {
    const emailCode = {
      ...fakeFactorStep('totp', 'second_factor', 'totp', USER),
      step: 'email_code',
    };
    expect(() => build(undefined, { steps: [emailCode as unknown as AnyStepHandler] })).toThrow(
      /email_code is never a sign-in step/
    );
  });
});

describe('audit records', () => {
  it('hold no password, code or raw identifier, and name the person once', async () => {
    const records: unknown[] = [];
    const sink = async (record: unknown) => {
      records.push(record);
    };
    const totp = fakeFactorStep('totp', 'second_factor', 'totp', USER);
    const accounts: Record<string, FakeAccount | null> = {};
    for (const [kind, account] of Object.entries(accountKinds())) {
      accounts[`${kind.toLowerCase()}@example.com`] = account;
    }
    accounts['second@example.com'] = passwordAccount(USER, PASSWORD, {
      others: [{ type: 'totp', disabled: false }],
    });
    const built = build(accounts, { steps: [totp] });
    const ctx = (loginHint?: string) =>
      ({
        realm: { id: REALM },
        client: { id: CLIENT },
        audit: sink,
        ...(loginHint ? { loginHint } : {}),
      }) as RoundContext;
    for (const identifier of Object.keys(accounts)) {
      const typed = identifier.toUpperCase();
      for (const password of [PASSWORD, WRONG]) {
        built.policy.policy = {
          realm: identifier.startsWith('second') ? 'required' : 'off',
          client: 'off',
        };
        const first = await built.engine.advance(null, null, ctx(typed));
        const second = await built.engine.advance(
          first.transaction as SignInTransaction,
          passwordAnswer(password),
          ctx(typed)
        );
        if (second.kind === 'step' && second.offer.current.step === 'totp') {
          await built.engine.advance(
            second.transaction as SignInTransaction,
            answer('totp', { otp: '654321' }),
            ctx(typed)
          );
        }
      }
      // A second identifier ends the transaction.
      const first = await built.engine.advance(null, null, ctx(typed));
      await built.engine.advance(
        first.transaction as SignInTransaction,
        null,
        ctx('other@example.com')
      );
    }
    expect(records.length).toBeGreaterThan(20);
    const text = JSON.stringify(records);
    for (const secret of [
      PASSWORD,
      WRONG,
      '654321',
      'other@example.com',
      ...Object.keys(accounts),
    ]) {
      expect(text.toLowerCase()).not.toContain(secret.toLowerCase());
    }
    for (const local of Object.keys(accounts).map((identifier) => identifier.split('@')[0])) {
      expect(text.toLowerCase()).not.toContain(`"${local}`);
    }
    for (const record of records as Record<string, unknown>[]) {
      expect(Object.keys(record).sort()).toEqual(expect.arrayContaining(['outcome', 'step']));
      const named = ['userId', 'identifierHmac'].filter((key) => record[key] !== undefined);
      expect(named, JSON.stringify(record)).toHaveLength(1);
      if (record['identifierHmac'] !== undefined) {
        expect(record['identifierHmac']).toMatch(/^[A-Za-z0-9_-]{43}$/);
      }
      expect(
        Object.keys(record).every((key) =>
          ['outcome', 'step', 'reason', 'userId', 'identifierHmac'].includes(key)
        )
      ).toBe(true);
    }
  });

  it('records every step, by HMAC until a user is resolved and by user after', async () => {
    const built = build();
    const ctx = context({ loginHint: IDENTIFIER });
    await signIn(built, WRONG, ctx);
    const hmac = await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER });
    const right = context();
    const first = await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
    await built.engine.advance(
      first.transaction as SignInTransaction,
      passwordAnswer(PASSWORD),
      right
    );
    expect(ctx.records).toEqual([
      { outcome: 'passed', step: 'identifier', identifierHmac: hmac },
      { outcome: 'refused', step: 'password', reason: 'invalid_credentials', identifierHmac: hmac },
    ]);
    expect(right.records).toEqual([{ outcome: 'passed', step: 'password', userId: USER }]);
  });

  it('names the reason of each refusal, which the answer never shows', async () => {
    const reasons: Record<string, string> = {};
    for (const kind of ['disabled', 'unverified', 'unknown', 'locked'] as const) {
      const built = build({ [IDENTIFIER]: accountKinds()[kind] });
      const ctx = context({ loginHint: IDENTIFIER });
      await signIn(built, PASSWORD, ctx);
      const refused = ctx.records.find((record) => record.outcome === 'refused');
      reasons[kind] = `${refused?.reason}:${refused?.userId === undefined ? 'hmac' : 'user'}`;
    }
    expect(reasons).toEqual({
      disabled: 'account_disabled:hmac',
      unverified: 'email_not_verified:hmac',
      unknown: 'invalid_credentials:hmac',
      locked: 'invalid_credentials:hmac',
    });
  });
});

describe('what the review of #614 pinned', () => {
  it('refuses a disabled account any factor step proves, like a wrong answer, and fixes no subject', async () => {
    const passkey: AnyStepHandler = {
      ...fakeFactorStep('webauthn_get', 'first_factor', 'passkey', USER),
      verify: async () => ({
        kind: 'proved',
        account: { userId: USER, enabled: false, verified: true },
      }),
    } as AnyStepHandler;
    const built = build({ [IDENTIFIER]: kindAccount('passwordAndPasskey') }, { steps: [passkey] });
    const ctx = context({ loginHint: IDENTIFIER });
    const result = await built.engine.advance(
      null,
      answer('webauthn_get', { webauthn_response: WEBAUTHN_RESPONSE }),
      ctx
    );
    expect(result).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'webauthn_get', error: 'invalid_credentials' } },
    });
    expect(result.transaction).not.toHaveProperty('subject');
    expect(ctx.records.at(-1)).toEqual({
      outcome: 'refused',
      step: 'webauthn_get',
      reason: 'account_disabled',
      identifierHmac: await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER }),
    });
  });

  it('gives the same answer whichever way the password went when settling the ladder fails', async () => {
    const onUnavailable = vi.fn();
    const ladder: LadderHook = {
      reserve: async () => ({
        kind: 'reserved',
        settle: async () => Promise.reject(new Error('redis down')),
      }),
    };
    const built = build(undefined, { hooks: { ladder }, onUnavailable });
    const wrong = await built.engine.advance(null, passwordAnswer(WRONG, IDENTIFIER), context());
    const right = await built.engine.advance(null, passwordAnswer(PASSWORD, IDENTIFIER), context());
    expect(wrong).toMatchObject({
      kind: 'step',
      offer: { current: { error: 'invalid_credentials' } },
    });
    expect(right.kind).toBe('complete');
    expect(onUnavailable).toHaveBeenCalledTimes(2);
  });

  it('reads only what the password needs before it is checked, and the whole account after', async () => {
    const built = build();
    await built.engine.advance(null, passwordAnswer(WRONG, IDENTIFIER), context());
    expect(built.directory.reads).toEqual([`identifier:${REALM}:${IDENTIFIER}`]);
    await built.engine.advance(null, passwordAnswer(PASSWORD, IDENTIFIER), context());
    expect(built.directory.reads.slice(1)).toEqual([
      `identifier:${REALM}:${IDENTIFIER}`,
      `user:${REALM}:${USER}`,
    ]);
  });

  it('takes no identifier from an answer to a step nobody offered', async () => {
    const built = build();
    const ctx = context();
    const result = await built.engine.advance(
      null,
      answer('password_reset', { login_hint: IDENTIFIER }),
      ctx
    );
    expect(result).toMatchObject({ kind: 'step', offer: { current: { step: 'identifier' } } });
    expect(result.transaction).toEqual(tx());
    expect(ctx.records).toEqual([]);
  });

  it('keeps the identifier a refused round fixed, so the next round audits it no more', async () => {
    const ladder: LadderHook = { reserve: async () => ({ kind: 'wait', retryAfterSeconds: 8 }) };
    const built = build(undefined, { hooks: { ladder } });
    const ctx = context();
    const result = await built.engine.advance(null, passwordAnswer(PASSWORD, IDENTIFIER), ctx);
    expect(result).toMatchObject({
      kind: 'refused',
      reason: 'throttled',
      transaction: { identifier: IDENTIFIER, verified: [] },
    });
    const next = context();
    await built.engine.advance(result.transaction as SignInTransaction, null, next);
    expect(next.records).toEqual([]);
  });
});

describe('what the second review of #614 pinned', () => {
  const discoverablePasskey = (verify: () => Promise<StepVerdict>): AnyStepHandler =>
    ({
      ...fakeFactorStep('webauthn_get', 'first_factor', 'passkey', USER),
      verify,
    }) as AnyStepHandler;

  it('ends the transaction on another user’s proof, even when that user is disabled', async () => {
    const passkey = discoverablePasskey(async () => ({
      kind: 'proved',
      account: { userId: OTHER_USER, enabled: false, verified: true },
    }));
    const built = build({ [IDENTIFIER]: kindAccount('passwordAndPasskey') }, { steps: [passkey] });
    const { second } = await signIn(built, PASSWORD);
    expect(second).toMatchObject({ kind: 'step', offer: { current: { step: 'webauthn_get' } } });
    const ctx = context();
    const result = await built.engine.advance(
      second.transaction as SignInTransaction,
      answer('webauthn_get', { webauthn_response: WEBAUTHN_RESPONSE }),
      ctx
    );
    expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(ctx.records).toEqual([
      { outcome: 'ended', step: 'webauthn_get', reason: 'subject_mismatch', userId: USER },
    ]);
  });

  it('audits a factor refused before any identifier, naming nobody', async () => {
    const passkey = discoverablePasskey(async () => ({
      kind: 'refused',
      error: 'invalid_credentials',
      audit: { reason: 'invalid_credentials' },
    }));
    const built = build({}, { steps: [passkey] });
    const ctx = context();
    const result = await built.engine.advance(
      null,
      answer('webauthn_get', { webauthn_response: WEBAUTHN_RESPONSE }),
      ctx
    );
    // A refused preferred step stays preferred.
    expect(result).toMatchObject({
      kind: 'step',
      offer: {
        current: { step: 'webauthn_get', error: 'invalid_credentials' },
        alternatives: [{ step: 'password' }, { step: 'identifier' }],
        required: false,
      },
    });
    expect(ctx.records).toEqual([
      { outcome: 'refused', step: 'webauthn_get', reason: 'invalid_credentials' },
    ]);
  });

  it('offers the password with the identifier step when the transport cannot serve the passkey', async () => {
    const passkey = fakeFactorStep('webauthn_get', 'first_factor', 'passkey', USER);
    const built = build(undefined, { steps: [passkey] });
    const result = await built.engine.advance(
      null,
      null,
      context({ serves: ['identifier', 'password'] })
    );
    expect(result).toMatchObject({
      kind: 'step',
      offer: {
        current: { step: 'password' },
        alternatives: [{ step: 'identifier' }],
        required: false,
      },
    });
  });

  it('ends a transaction whose subject has no identifier unless a discoverable factor proved it', async () => {
    const built = build();
    const forged = tx({
      subject: USER,
      verified: [{ step: 'password', params: {} }] as never,
      authTime: T0,
    });
    const ctx = context();
    expect(await built.engine.advance(forged, null, ctx)).toEqual({
      kind: 'refused',
      reason: 'transaction_ended',
      transaction: null,
    });
    expect(ctx.records).toEqual([
      { outcome: 'ended', step: 'identifier', reason: 'transaction_invalid' },
    ]);
  });

  it('keeps no identifier a mismatch brought when the record of the mismatch cannot be written', async () => {
    const built = build(undefined, {
      identifierDigest: async () => Promise.reject(new Error('identifier key store down')),
    });
    // The request's login_hint and the answer's differ: the round ends the
    // transaction, and its record needs the identifier's HMAC.
    const result = await built.engine.advance(
      null,
      answer('identifier', { login_hint: 'bob@example.com' }),
      context({ loginHint: IDENTIFIER })
    );
    expect(result).toEqual({ kind: 'refused', reason: 'unavailable', transaction: tx() });
  });

  it('ends the transaction when a discoverable factor proves another account than the identifier names', async () => {
    const passkey = fakeFactorStep('webauthn_get', 'first_factor', 'passkey', OTHER_USER);
    const built = build({ [IDENTIFIER]: kindAccount('passwordAndPasskey') }, { steps: [passkey] });
    const first = await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
    expect(first).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'password' }, alternatives: [{ step: 'webauthn_get' }] },
    });
    const ctx = context();
    const result = await built.engine.advance(
      first.transaction as SignInTransaction,
      answer('webauthn_get', { webauthn_response: WEBAUTHN_RESPONSE }),
      ctx
    );
    expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(ctx.records).toEqual([
      {
        outcome: 'ended',
        step: 'webauthn_get',
        reason: 'subject_mismatch',
        identifierHmac: await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER }),
      },
    ]);
  });

  it('accepts a discoverable factor that proves the account the identifier names', async () => {
    const passkey = fakeFactorStep('webauthn_get', 'first_factor', 'passkey', USER);
    const built = build({ [IDENTIFIER]: kindAccount('passwordAndPasskey') }, { steps: [passkey] });
    const first = await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
    const result = await built.engine.advance(
      first.transaction as SignInTransaction,
      answer('webauthn_get', { webauthn_response: WEBAUTHN_RESPONSE }),
      context()
    );
    expect(result).toMatchObject({ kind: 'complete', signIn: { subject: USER } });
  });

  it('refuses to build with a totp step that is not a second factor', () => {
    const totp = fakeFactorStep('totp', 'second_factor', 'totp', USER);
    expect(() =>
      build(undefined, {
        steps: [{ ...totp, role: 'first_factor', factor: 'password' } as AnyStepHandler],
      })
    ).toThrow(/totp is only a second factor/);
  });

  it('keeps the password verdict when the reporter of a failed settle throws too', async () => {
    const ladder: LadderHook = {
      reserve: async () => ({
        kind: 'reserved',
        settle: async () => Promise.reject(new Error('redis down')),
      }),
    };
    const built = build(undefined, {
      hooks: { ladder },
      onUnavailable: () => {
        throw new Error('the log is down too');
      },
    });
    const { second } = await signIn(built, PASSWORD);
    expect(second).toMatchObject({ kind: 'complete', signIn: { subject: USER } });
  });

  it('keeps no identifier from a round that failed before its record was written', async () => {
    let failing = true;
    const built = build(undefined, {
      identifierDigest: async (input) => {
        if (failing) throw new Error('signer down');
        return fakeIdentifierDigest(input);
      },
    });
    const first = await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
    expect(first).toEqual({
      kind: 'refused',
      reason: 'unavailable',
      transaction: tx(),
    });
    failing = false;
    const ctx = context({ loginHint: IDENTIFIER });
    await built.engine.advance(first.transaction as SignInTransaction, null, ctx);
    expect(ctx.records).toMatchObject([{ outcome: 'passed', step: 'identifier' }]);
  });
});

describe('a disabled user', () => {
  it('gets the ordinary invalid-credentials answer, no subject and nothing to mint', async () => {
    const built = build({ [IDENTIFIER]: kindAccount('disabled') });
    const { second } = await signIn(built, PASSWORD);
    expect(second).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'password', error: 'invalid_credentials' } },
      transaction: { identifier: IDENTIFIER, verified: [] },
    });
    expect(second.transaction).not.toHaveProperty('subject');
  });

  it('ends a later round once the account is disabled after its factor', async () => {
    const passkey = fakeFactorStep('webauthn_get', 'first_factor', 'passkey', USER);
    const accounts = new Map<string, FakeAccount>([
      [IDENTIFIER, kindAccount('passwordAndPasskey')],
    ]);
    const directory = new FakeDirectory(accounts);
    const built = build(undefined, { accounts: directory, steps: [passkey] });
    const { second } = await signIn(built, PASSWORD);
    expect(second.kind).toBe('step');
    accounts.set(IDENTIFIER, { ...kindAccount('passwordAndPasskey'), enabled: false });
    const ctx = context();
    const third = await built.engine.advance(second.transaction as SignInTransaction, null, ctx);
    expect(third).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(ctx.records).toMatchObject([
      { outcome: 'ended', reason: 'account_disabled', userId: USER },
    ]);
  });
});

describe('the hooks', () => {
  it('reserves on the ladder before the verifier runs, and settles each outcome', async () => {
    const events: string[] = [];
    const ladder: LadderHook = {
      reserve: async ({ identifierHmac, factor }) => {
        events.push(`reserve:${factor}:${identifierHmac.length}`);
        return {
          kind: 'reserved',
          settle: async (outcome) => {
            events.push(`settle:${outcome}`);
            return NOTHING_DUE;
          },
        };
      },
    };
    const built = build(undefined, { hooks: { ladder } });
    const verify = built.passwords.verify.bind(built.passwords);
    built.passwords.verify = async (hash, presented) => {
      events.push('verify');
      return verify(hash, presented);
    };
    await signIn(built, WRONG);
    await signIn(built, PASSWORD);
    expect(events).toEqual([
      'reserve:password:43',
      'verify',
      'settle:failure',
      'reserve:password:43',
      'verify',
      'settle:success',
    ]);
  });

  it('refuses an attempt inside the ladder’s wait unverified, alike for every account', async () => {
    const ladder: LadderHook = { reserve: async () => ({ kind: 'wait', retryAfterSeconds: 64 }) };
    const answers = new Set<string>();
    for (const account of Object.values(accountKinds())) {
      const built = build({ [IDENTIFIER]: account }, { hooks: { ladder } });
      const ctx = context({ loginHint: IDENTIFIER });
      const { second } = await signIn(built, PASSWORD, ctx);
      answers.add(JSON.stringify(second));
      expect(built.passwords.verifications).toBe(0);
      expect(built.directory.reads).toEqual([]);
      expect(ctx.records.at(-1)).toMatchObject({ outcome: 'refused', reason: 'locked_out' });
    }
    expect(answers.size).toBe(1);
    expect(JSON.parse([...answers][0])).toMatchObject({
      kind: 'refused',
      reason: 'throttled',
      retryAfterSeconds: 64,
    });
  });

  it('refuses the round for a limiter, the request checks, or a store the hooks need', async () => {
    const cases: [SignInHooks, Partial<RoundResult>][] = [
      [
        { limits: async () => ({ kind: 'throttled', retryAfterSeconds: 9 }) },
        { reason: 'throttled' },
      ],
      [
        { request: async () => ({ kind: 'refuse', code: 'unmet_authentication_requirements' }) },
        { reason: 'request_refused' },
      ],
      [{ request: async () => ({ kind: 'redirect' }) }, { kind: 'redirect' }],
      [{ limits: async () => Promise.reject(new Error('redis down')) }, { reason: 'unavailable' }],
      [
        { ladder: { reserve: async () => Promise.reject(new Error('redis down')) } },
        { reason: 'unavailable' },
      ],
    ];
    for (const [hooks, expected] of cases) {
      const built = build(undefined, { hooks });
      const result = await built.engine.advance(
        null,
        passwordAnswer(PASSWORD, IDENTIFIER),
        context()
      );
      expect(result).toMatchObject(expected);
      expect(built.passwords.verifications).toBe(0);
    }
  });

  it('audits a round a limiter or the request checks refused, under the identifier the transaction holds', async () => {
    const cases: [SignInHooks, string][] = [
      [{ limits: async () => ({ kind: 'throttled', retryAfterSeconds: 9 }) }, 'rate_limited'],
      [
        { request: async () => ({ kind: 'refuse', code: 'unmet_authentication_requirements' }) },
        'request_refused',
      ],
    ];
    for (const [hooks, reason] of cases) {
      // Before any identifier: the record names nobody.
      const fresh = build(undefined, { hooks });
      const first = context();
      await fresh.engine.advance(null, passwordAnswer(PASSWORD, IDENTIFIER), first);
      expect(first.records).toEqual([{ outcome: 'refused', step: 'password', reason }]);

      // Once the transaction holds one: the record names its HMAC.
      let throttle = false;
      const gated: SignInHooks = Object.fromEntries(
        Object.entries(hooks).map(([name, hook]) => [
          name,
          async (round: never) =>
            throttle ? (hook as (r: never) => unknown)(round) : { kind: 'continue' },
        ])
      );
      const held = build(undefined, { hooks: gated });
      const round0 = await held.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
      throttle = true;
      const later = context();
      await held.engine.advance(round0.transaction as SignInTransaction, null, later);
      expect(later.records).toEqual([
        {
          outcome: 'refused',
          step: 'identifier',
          reason,
          identifierHmac: await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER }),
        },
      ]);
    }
  });

  it('names a refused round by the identifier step when the answer names a step it has no handler for', async () => {
    const built = build(undefined, {
      hooks: { limits: async () => ({ kind: 'throttled', retryAfterSeconds: 9 }) },
    });
    const ctx = context();
    await built.engine.advance(null, answer('totp', { otp: '123456' }), ctx);
    expect(ctx.records).toEqual([
      { outcome: 'refused', step: 'identifier', reason: 'rate_limited' },
    ]);
  });

  it('runs the hooks in the rule order and never shows them an answer’s fields', async () => {
    const seen: string[] = [];
    const hooks: SignInHooks = {
      limits: async (round) => (seen.push(`limits:${JSON.stringify(round)}`), { kind: 'continue' }),
      request: async (round) => (seen.push(`request:${round.answered}`), { kind: 'continue' }),
      botChallenge: async (round) => (seen.push(`bot:${round.answered}`), { kind: 'not_due' }),
    };
    const built = build(undefined, { hooks });
    await built.engine.advance(null, passwordAnswer(PASSWORD, IDENTIFIER), context());
    expect(seen.map((entry) => entry.split(':')[0])).toEqual(['limits', 'request', 'bot']);
    expect(seen.join()).not.toContain(PASSWORD);
    expect(seen.join()).not.toContain(IDENTIFIER);
    expect(seen[1]).toBe('request:password');
  });

  it('offers a due bot challenge alone when a handler serves it, then resumes the pending step', async () => {
    let due = true;
    const captcha: StepHandler<'captcha'> = {
      step: 'captcha',
      role: 'challenge',
      params: () => ({ provider: 'pow', challenge: 'c'.repeat(22), difficulty: 8 }),
      verify: async (_round, read) => {
        if (read.answer.captcha_token !== 'solved') {
          return { kind: 'refused', error: 'captcha_failed', audit: { reason: 'captcha_failed' } };
        }
        due = false;
        return { kind: 'passed' };
      },
    };
    const built = build(undefined, {
      steps: [captcha],
      hooks: {
        botChallenge: async () =>
          due ? { kind: 'due', retryAfterSeconds: 5 } : { kind: 'not_due' },
      },
    });
    const ctx = context({ loginHint: IDENTIFIER });
    const first = await built.engine.advance(null, passwordAnswer(PASSWORD), ctx);
    expect(first).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'captcha' }, alternatives: [] },
    });
    expect(built.passwords.verifications).toBe(0);
    const wrong = await built.engine.advance(
      first.transaction as SignInTransaction,
      answer('captcha', { captcha_token: 'guess' }),
      ctx
    );
    expect(wrong).toMatchObject({
      offer: { current: { step: 'captcha', error: 'captcha_failed' } },
    });
    const solved = await built.engine.advance(
      first.transaction as SignInTransaction,
      answer('captcha', { captcha_token: 'solved' }),
      ctx
    );
    expect(solved).toMatchObject({ kind: 'step', offer: { current: { step: 'password' } } });
    // The solved challenge is audited, as every processed step is; it comes
    // before the identifier is taken, so its record names nobody.
    expect(ctx.records.slice(-2)).toEqual([
      { outcome: 'passed', step: 'captcha' },
      {
        outcome: 'passed',
        step: 'identifier',
        identifierHmac: await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER }),
      },
    ]);
    // A transport that does not serve the captcha step gets the delay and 429.
    due = true;
    const native = await built.engine.advance(
      null,
      null,
      context({ loginHint: IDENTIFIER, serves: ['identifier', 'password'] })
    );
    expect(native).toMatchObject({ kind: 'refused', reason: 'throttled', retryAfterSeconds: 5 });
  });
});

describe('answers and transactions', () => {
  it('completes with the subject, amr and auth_time, and the transport mints from it', async () => {
    const built = build();
    const ctx = context({ loginHint: IDENTIFIER });
    const first = await built.engine.advance(null, null, ctx);
    const verifiedAt = built.clock.now();
    const second = await built.engine.advance(
      first.transaction as SignInTransaction,
      passwordAnswer(PASSWORD),
      ctx
    );
    // The transaction ends with the completion: no later round mints again.
    expect(second).toEqual({
      kind: 'complete',
      transaction: null,
      signIn: { subject: USER, identifier: IDENTIFIER, amr: ['pwd'], authTime: verifiedAt },
    });
  });

  it.each([
    ['an identifier that is not an email address', answer('identifier', { login_hint: 'alice' })],
    [
      'an identifier over 254 bytes',
      answer('identifier', { login_hint: `${'é'.repeat(124)}@example.com` }),
    ],
    ['an identifier answer without one', answer('identifier', {})],
    ['a password answer with a malformed identifier', passwordAnswer(PASSWORD, 'a@b')],
  ])('refuses %s as a fault of the request, checking nothing', async (_name, malformed) => {
    const built = build();
    const ctx = context();
    const result = await built.engine.advance(null, malformed, ctx);
    expect(result).toEqual({
      kind: 'refused',
      reason: 'invalid_answer',
      transaction: tx(),
    });
    expect(built.passwords.verifications).toBe(0);
    // Audited, naming nobody: the transaction holds no identifier.
    expect(ctx.records).toEqual([
      {
        outcome: 'refused',
        step: malformed.step === STEP_URNS.password ? 'password' : 'identifier',
        reason: 'invalid_answer',
      },
    ]);
  });

  it('refuses a password answer outside the step’s schema as a fault of the request', async () => {
    const built = build();
    const first = await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
    const result = await built.engine.advance(
      first.transaction as SignInTransaction,
      answer('password', { password: 'x'.repeat(257) }),
      context()
    );
    expect(result).toMatchObject({ kind: 'refused', reason: 'invalid_answer' });
    expect(built.passwords.verifications).toBe(0);
  });

  it('ignores a login_hint that is not an identifier, asking for one instead', async () => {
    const built = build();
    const result = await built.engine.advance(null, null, context({ loginHint: 'not an address' }));
    expect(result).toMatchObject({ kind: 'step', offer: { current: { step: 'identifier' } } });
  });

  it.each([
    ['another version', { ...tx(), v: 2 }],
    ['a subject without an identifier', { ...tx(), subject: USER }],
    ['an unknown step', tx({ verified: [{ step: 'sms', params: {} }] as never })],
    ['an extra member', { ...tx(), policy: 'off' }],
    ['no realm', { v: 1, clientId: CLIENT, createdAt: T0, verified: [] }],
    ['another realm', tx({ realmId: '0199fa20-0000-7000-8000-00000000bbbb' })],
    ['another client', tx({ clientId: 'another-app' })],
    ['a start more than a minute ahead', tx({ createdAt: T0 + 60_001 })],
  ])(
    'ends a transaction this round may not use (%s), audited naming nobody',
    async (_name, stored) => {
      const built = build();
      const ctx = context();
      const result = await built.engine.advance(stored as unknown as SignInTransaction, null, ctx);
      expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
      expect(ctx.records).toEqual([
        { outcome: 'ended', step: 'identifier', reason: 'transaction_invalid' },
      ]);
      expect(built.directory.reads).toEqual([]);
    }
  );

  it('ends a transaction older than two hours, audited as transaction_expired', async () => {
    const built = build();
    const first = await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
    built.clock.advance(SIGN_IN_TRANSACTION_MAX_AGE_MS);
    const ctx = context();
    const result = await built.engine.advance(
      first.transaction as SignInTransaction,
      passwordAnswer(PASSWORD),
      ctx
    );
    expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(ctx.records).toEqual([
      { outcome: 'ended', step: 'password', reason: 'transaction_expired' },
    ]);
    expect(built.passwords.verifications).toBe(0);
  });

  it('keeps a transaction just inside two hours', async () => {
    const built = build();
    const first = await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
    // Round 0 waited out its floor; the transaction began when it arrived.
    built.clock.advance(SIGN_IN_TRANSACTION_MAX_AGE_MS - SIGN_IN_MIN_RESPONSE_TIME_MS);
    const result = await built.engine.advance(
      first.transaction as SignInTransaction,
      passwordAnswer(PASSWORD),
      context()
    );
    expect(result).toMatchObject({ kind: 'complete' });
  });

  it('ends a transaction a client forged, naming a victim and a proof, without completing', async () => {
    const built = build();
    const ctx = context();
    const forged = {
      v: 1,
      identifier: IDENTIFIER,
      subject: USER,
      verified: [{ step: 'password', params: {} }],
      authTime: 1,
    } as unknown as SignInTransaction;
    expect(await built.engine.advance(forged, null, ctx)).toEqual({
      kind: 'refused',
      reason: 'transaction_ended',
      transaction: null,
    });
    expect(ctx.records).toEqual([
      { outcome: 'ended', step: 'identifier', reason: 'transaction_invalid' },
    ]);
  });

  it('ends a live transaction handed to a round of another realm or another client', async () => {
    for (const elsewhere of [
      { realm: { id: '0199fa20-0000-7000-8000-00000000bbbb' } },
      { client: { id: 'another-app' } },
    ]) {
      const built = build();
      const first = await built.engine.advance(null, null, context({ loginHint: IDENTIFIER }));
      const ctx = context(elsewhere);
      const result = await built.engine.advance(
        first.transaction as SignInTransaction,
        passwordAnswer(PASSWORD),
        ctx
      );
      expect(result).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
      expect(ctx.records).toEqual([
        { outcome: 'ended', step: 'password', reason: 'transaction_invalid' },
      ]);
      expect(built.passwords.verifications).toBe(0);
    }
  });

  it('refuses the round when the account directory or the identifier key fails', async () => {
    const failing = build(undefined, {
      accounts: {
        findByIdentifier: async () => Promise.reject(new Error('db down')),
        findByUserId: async () => null,
      },
    });
    expect(
      await failing.engine.advance(null, passwordAnswer(PASSWORD, IDENTIFIER), context())
    ).toMatchObject({ kind: 'refused', reason: 'unavailable' });
    const keyless = build(undefined, { identifierDigest: async () => 'short' });
    expect(
      await keyless.engine.advance(null, null, context({ loginHint: IDENTIFIER }))
    ).toMatchObject({
      kind: 'refused',
      reason: 'unavailable',
    });
    expect(keyless.passwords.verifications).toBe(0);
  });

  it('redirects when the transport serves no first factor', async () => {
    const built = build();
    const result = await built.engine.advance(
      null,
      null,
      context({ loginHint: IDENTIFIER, serves: ['identifier'] })
    );
    expect(result).toMatchObject({ kind: 'redirect', reason: 'step_not_available' });
  });

  it('offers only what both transports can put on the wire', async () => {
    const built = build();
    const results = [
      await built.engine.advance(null, null, context()),
      await built.engine.advance(null, null, context({ loginHint: IDENTIFIER })),
      await built.engine.advance(null, passwordAnswer(WRONG, IDENTIFIER), context()),
    ];
    for (const result of results) expect(() => wire(result)).not.toThrow();
  });

  it('refuses a handler the engine cannot place', () => {
    const duplicate = {
      ...fakeFactorStep('totp', 'second_factor', 'totp', USER),
      step: 'password',
    };
    expect(() => build(undefined, { steps: [duplicate as unknown as AnyStepHandler] })).toThrow(
      /has a handler/
    );
    const noFactor = {
      ...fakeFactorStep('totp', 'second_factor', 'totp', USER),
      factor: undefined,
    };
    expect(() => build(undefined, { steps: [noFactor as unknown as AnyStepHandler] })).toThrow(
      /names no factor/
    );
    const fakeChallenge = {
      ...fakeFactorStep('totp', 'second_factor', 'totp', USER),
      role: 'challenge',
    };
    expect(() => build(undefined, { steps: [fakeChallenge as unknown as AnyStepHandler] })).toThrow(
      /captcha step/
    );
  });
});

/** The params of the fake passkey step. */
const PASSKEY_PARAMS = {
  challenge: 'C'.repeat(43),
  rpId: 'auth.example.com',
  userVerification: 'required',
} as const;

/** A WebAuthn assertion as `PublicKeyCredential.toJSON()` gives it. */
const WEBAUTHN_RESPONSE = JSON.stringify({
  id: 'credential',
  rawId: 'credential',
  type: 'public-key',
  response: { clientDataJSON: 'e30', authenticatorData: 'AAAA', signature: 'AAAA' },
  clientExtensionResults: {},
});

/** A factor step that a later issue would add, proving `userId`'s account on any answer. */
function fakeFactorStep(
  step: 'webauthn_get' | 'totp',
  role: 'first_factor' | 'second_factor',
  factor: 'passkey' | 'totp',
  userId: string
): AnyStepHandler {
  const handler = {
    step,
    role,
    factor,
    ...(factor === 'passkey' ? { discoverable: true } : {}),
    usableBy: (account: SignInAccount) =>
      account.factors.some((bound) => bound.type === factor && !bound.disabled),
    params: () => (step === 'totp' ? { digits: 6 } : PASSKEY_PARAMS),
    personal: (round: { identifier?: string }) =>
      round.identifier === undefined ? {} : { identifier: round.identifier },
    verify: async () => ({
      kind: 'proved' as const,
      account: { userId, enabled: true, verified: true },
    }),
  };
  return handler as unknown as AnyStepHandler;
}

describe('the failure ladder (#615)', () => {
  /** A ladder whose every failure settles at the hard ceiling. */
  const atCeiling: LadderHook = {
    reserve: async () => ({ kind: 'reserved', settle: async () => ({ ceilingReached: true }) }),
  };
  const recordingHardAction = () => {
    const calls: string[] = [];
    const action: PasswordHardAction = {
      ceilingReached: async (input) => {
        calls.push(`ceiling:${input.realmId}:${input.userId}:${input.identifier}`);
      },
      clearIgnoredMark: async (input) => {
        calls.push(`clear:${input.realmId}:${input.userId}:${input.identifier}`);
      },
    };
    return { calls, action };
  };

  it('hands the round’s end-user IP to the reservation', async () => {
    const reserve = vi.fn<LadderHook['reserve']>(async () => ({
      kind: 'reserved',
      settle: async () => NOTHING_DUE,
    }));
    const built = build(undefined, { hooks: { ladder: { reserve } } });
    await signIn(built, WRONG, context({ loginHint: IDENTIFIER, endUserIp: '203.0.113.9' }));
    expect(reserve).toHaveBeenCalledWith({
      realmId: REALM,
      identifierHmac: await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER }),
      factor: 'password',
      endUserIp: '203.0.113.9',
    });
  });

  it('fires the hard action at the ceiling for an enabled account whose password is usable', async () => {
    const { calls, action } = recordingHardAction();
    const built = build(undefined, { hooks: { ladder: atCeiling }, passwordHardAction: action });
    const { second } = await signIn(built, WRONG);
    expect(second).toMatchObject({ offer: { current: { error: 'invalid_credentials' } } });
    expect(calls).toEqual([`ceiling:${REALM}:${USER}:${IDENTIFIER}`]);
  });

  it('never fires it for no account, a disabled user, a disabled or missing password, and answers each alike', async () => {
    const answers = new Set<string>();
    for (const kind of ['unknown', 'disabled', 'locked', 'passkeyOnly'] as const) {
      const { calls, action } = recordingHardAction();
      const built = build(
        { [IDENTIFIER]: accountKinds()[kind] },
        { hooks: { ladder: atCeiling }, passwordHardAction: action }
      );
      const { second } = await signIn(built, PASSWORD);
      answers.add(wire(second));
      expect(calls, kind).toEqual([]);
    }
    expect(answers.size).toBe(1);
  });

  it('fires nothing below the ceiling', async () => {
    const { calls, action } = recordingHardAction();
    const built = build(undefined, { passwordHardAction: action });
    await signIn(built, WRONG);
    expect(calls).toEqual([]);
  });

  it('clears a mark the lookup ignored once the password proves the account, and only then', async () => {
    const { calls, action } = recordingHardAction();
    const marked = passwordAccount(USER, PASSWORD, {
      password: { disabled: false, hash: fakeHash(PASSWORD), ignoredMark: true },
    });
    const built = build({ [IDENTIFIER]: marked }, { passwordHardAction: action });
    await signIn(built, WRONG);
    expect(calls).toEqual([]);
    const { second } = await signIn(built, PASSWORD);
    expect(second).toMatchObject({ kind: 'complete', signIn: { subject: USER } });
    expect(calls).toEqual([`clear:${REALM}:${USER}:${IDENTIFIER}`]);
  });

  it('keeps the answer when the hard action fails, and reports it', async () => {
    const onUnavailable = vi.fn();
    const failing: PasswordHardAction = {
      ceilingReached: async () => Promise.reject(new Error('database down')),
      clearIgnoredMark: async () => Promise.reject(new Error('database down')),
    };
    const built = build(undefined, {
      hooks: { ladder: atCeiling },
      passwordHardAction: failing,
      onUnavailable,
    });
    const { second } = await signIn(built, WRONG);
    expect(second).toMatchObject({ offer: { current: { error: 'invalid_credentials' } } });
    expect(onUnavailable).toHaveBeenCalledWith(expect.objectContaining({ port: 'hardAction' }));
  });

  describe('on the memory ladder', () => {
    const answerOnce = (built: Built, ip?: string) =>
      built.engine.advance(
        null,
        passwordAnswer(WRONG, IDENTIFIER),
        context(ip === undefined ? {} : { endUserIp: ip })
      );

    it('lets parallel attempts, each in its own transaction, reach the verifier no more often than one at a time', async () => {
      const sequential = build();
      const ladderA = createMemoryLadder(sequential.clock.now);
      const one = build(undefined, { hooks: { ladder: ladderA } });
      for (let i = 0; i < 200; i += 1) await answerOnce(one);
      const parallel = build();
      const ladderB = createMemoryLadder(parallel.clock.now);
      const many = build(undefined, { hooks: { ladder: ladderB } });
      await Promise.all(Array.from({ length: 200 }, () => answerOnce(many)));
      expect(many.passwords.verifications).toBeLessThanOrEqual(one.passwords.verifications);
      expect(many.passwords.verifications).toBe(PASSWORD_LADDER_POLICY.freeFailures);
    });

    it('refuses an attempt inside a wait, unverified and uncounted', async () => {
      const clock = { now: () => T0 };
      const ladder = createMemoryLadder(() => clock.now());
      const built = build(undefined, { hooks: { ladder } });
      for (let i = 0; i < 5; i += 1) await answerOnce(built);
      const hmac = await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER });
      expect(ladder.counter(REALM, hmac, 'password')).toMatchObject({ failures: 5 });
      const result = await answerOnce(built);
      expect(result).toMatchObject({ kind: 'refused', reason: 'throttled', retryAfterSeconds: 1 });
      expect(built.passwords.verifications).toBe(5);
      expect(ladder.counter(REALM, hmac, 'password')).toMatchObject({ failures: 5 });
    });

    it('clears the password counter on a correct password, and no other counter', async () => {
      const ladder = createMemoryLadder(() => T0);
      const built = build(undefined, { hooks: { ladder } });
      const hmac = await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER });
      // A second factor's counter under the same identifier (#653 reuses the primitive).
      const totp = await ladder.reserve({ realmId: REALM, identifierHmac: hmac, factor: 'totp' });
      if (totp.kind !== 'reserved') throw new Error('totp reservation refused');
      await totp.settle('failure');
      for (let i = 0; i < 3; i += 1) await answerOnce(built);
      expect(ladder.counter(REALM, hmac, 'password')).toMatchObject({ failures: 3 });
      const result = await built.engine.advance(
        null,
        passwordAnswer(PASSWORD, IDENTIFIER),
        context()
      );
      expect(result.kind).toBe('complete');
      expect(ladder.counter(REALM, hmac, 'password')).toBeUndefined();
      expect(ladder.counter(REALM, hmac, 'totp')).toMatchObject({ failures: 1 });
    });

    it('lets a known IP skip the wait, still counting toward the ceiling', async () => {
      let now = T0;
      const ladder = createMemoryLadder(() => now);
      const built = build(undefined, { hooks: { ladder } });
      const hmac = await fakeIdentifierDigest({ realmId: REALM, identifier: IDENTIFIER });
      const known = '198.51.100.7';
      const right = await built.engine.advance(
        null,
        passwordAnswer(PASSWORD, IDENTIFIER),
        context({ endUserIp: known })
      );
      expect(right.kind).toBe('complete');
      now += 1_000;
      for (let i = 0; i < 5; i += 1) await answerOnce(built, known);
      expect(await answerOnce(built, '192.0.2.1')).toMatchObject({ reason: 'throttled' });
      expect(await answerOnce(built, known)).toMatchObject({
        kind: 'step',
        offer: { current: { error: 'invalid_credentials' } },
      });
      expect(ladder.counter(REALM, hmac, 'password')).toMatchObject({ failures: 6 });
      // Past the known-IP window (the run is still kept) the address waits like any other.
      now = T0 + PASSWORD_LADDER_POLICY.knownIpMs;
      await answerOnce(built, known);
      expect(await answerOnce(built, known)).toMatchObject({ reason: 'throttled' });
    });

    it('fires the hard action once the run reaches 100 counted failures, and not before', async () => {
      let now = T0;
      const ladder = createMemoryLadder(() => now);
      const { calls, action } = recordingHardAction();
      const built = build(undefined, { hooks: { ladder }, passwordHardAction: action });
      for (let i = 1; i <= 100; i += 1) {
        await answerOnce(built);
        expect(calls.length, `failure ${i}`).toBe(i === 100 ? 1 : 0);
        now += PASSWORD_LADDER_POLICY.maxWaitMs;
      }
    });
  });
});
