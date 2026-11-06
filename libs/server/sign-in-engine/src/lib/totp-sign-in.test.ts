import {
  FIPA_STEP_NAMES,
  STEP_NAMES,
  STEP_URNS,
  type StepName,
} from '@qauth-labs/server-step-grammar';
import { describe, expect, it } from 'vitest';

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
import { createMemoryLadder, memoryLadderSubject } from '../testing/memory-ladder';
import {
  createMemoryRecoveryCodes,
  type MemoryRecoveryCodes,
} from '../testing/memory-recovery-codes';
import { createMemoryTotp, type MemoryTotp } from '../testing/memory-totp';
import {
  createSignInEngine,
  type SignInEngineDependencies,
  TOTP_BINDING_MAX_AUTH_AGE_MS,
} from './engine';
import { TOTP_LADDER_POLICY } from './ladder';
import type { Clock } from './ports';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import { totpCode, totpStep } from './totp';
import type { SignInTransaction } from './transaction';

/**
 * TOTP at sign-in (#653; ADR-017 Decisions 4, 7 and 8, ADR-020 §3,
 * `graphs/flows/core/totp/flow.yaml`): the `totp` step after the first
 * factor, its counter on the ladder, its notices and hard action, and the
 * `totp_setup` step an MFA policy asks of an account with no second factor.
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'web-client';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const PASSWORD = 'a quiet violet tram crosses nine rivers';
const IDENTIFIER = 'alice@example.com';
const T0 = 1_800_000_000_000;
const MINUTE = 60_000;
const STEP_MS = 30_000;
/** The hosted pages' steps but the bot challenge. */
const HOSTED: readonly StepName[] = STEP_NAMES.filter((step) => step !== 'captcha');

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
  readonly policy: FakePolicy;
  readonly ladder: ReturnType<typeof createMemoryLadder>;
  readonly codes: MemoryRecoveryCodes;
  readonly totp: MemoryTotp;
  readonly sender: FakeCodeSender;
  readonly clock: ReturnType<typeof manualClock>;
}

/**
 * An account with a password; `totp` binds a TOTP to it, `'disabled'` a
 * disabled one, with the set of recovery codes its set-up issued, saved.
 */
async function build(
  options: {
    readonly account?: Partial<FakeAccount>;
    readonly totp?: 'bound' | 'disabled';
    readonly deps?: Partial<SignInEngineDependencies>;
  } = {}
): Promise<Built & { secret: Uint8Array | null; set: readonly string[] }> {
  const clock = manualClock();
  const directory = new FakeDirectory(
    new Map([[IDENTIFIER, passwordAccount(USER, PASSWORD, options.account)]])
  );
  const policy = new FakePolicy();
  const ladder = createMemoryLadder(clock.now);
  const codes = createMemoryRecoveryCodes(clock.now);
  const totp = createMemoryTotp(clock);
  // A bound or disabled TOTP shows in the account the directory reads.
  totp.onChange = (row) => {
    const current = directory.accounts.get(IDENTIFIER);
    if (current === undefined) throw new Error('no account');
    directory.accounts.set(IDENTIFIER, {
      ...current,
      others: [
        ...current.others.filter((factor) => factor.type !== 'totp'),
        { type: 'totp', disabled: row.disabled },
      ],
    });
  };
  let secret: Uint8Array | null = null;
  if (options.totp !== undefined) {
    secret = totp.enrol(USER, { realmId: REALM });
    if (options.totp === 'disabled') {
      const row = totp.rows.get(`${REALM}:${USER}`);
      if (row === undefined) throw new Error('no row');
      totp.rows.set(`${REALM}:${USER}`, { ...row, disabled: true });
      totp.onChange({ ...row, disabled: true });
    }
  }
  const sender = new FakeCodeSender();
  const engine = createSignInEngine({
    accounts: directory,
    passwords: new FakePasswords(),
    policy,
    identifierDigest: fakeIdentifierDigest,
    requireVerifiedAccount: true,
    emailCodes: { digest: fakeEmailCodeDigest, addresses: new FakeAddresses(directory) },
    recoveryCodes: codes,
    totp,
    hooks: { ladder },
    clock,
    ...options.deps,
  });
  const built = { engine, directory, policy, ladder, codes, totp, sender, clock, secret };
  return { ...built, set: options.totp === undefined ? [] : await issued(built) };
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
    serves: HOSTED,
    ...overrides,
  };
}

function answer(step: StepName, fields: Record<string, unknown>): RoundAnswer {
  return { step: STEP_URNS[step], fields };
}

/** The transaction a result keeps; fails the test when it keeps none. */
function kept(result: RoundResult): SignInTransaction {
  if (result.transaction === null) throw new Error(`${result.kind} kept no transaction`);
  return result.transaction;
}

/** The step a result offers; fails the test for any other result. */
function stepOf(result: RoundResult): StepName {
  if (result.kind !== 'step') throw new Error(`a ${result.kind}, not a step`);
  return result.offer.current.step;
}

/** The personal data a step result shows. */
function personalOf(result: RoundResult): { readonly secret?: unknown } {
  if (result.kind !== 'step') throw new Error(`a ${result.kind}, not a step`);
  return result.personal as { readonly secret?: unknown };
}

/** Round 0 with the login_hint, then the password: a new transaction each call. */
async function signIn(built: Built, ctx: Ctx = context(built)): Promise<RoundResult> {
  const first = await built.engine.advance(null, null, { ...ctx, loginHint: IDENTIFIER });
  return built.engine.advance(kept(first), answer('password', { password: PASSWORD }), ctx);
}

/** A code `secret` does not give for any step of the window now. */
function wrongCode(secret: Uint8Array, now: number): string {
  const window = [-1, 0, 1].map((offset) => totpCode(secret, totpStep(now) + offset));
  for (let n = 0; ; n += 1) {
    const code = String(n).padStart(6, '0');
    if (!window.includes(code)) return code;
  }
}

const totpCounter = (built: Built) =>
  built.ladder.counter(REALM, memoryLadderSubject({ userId: USER }), 'totp');

/** A set the person saved: issued and confirmed. */
async function issued(built: Pick<Built, 'codes'>): Promise<readonly string[]> {
  const { codes, setId } = await built.codes.replace({ realmId: REALM, userId: USER });
  await built.codes.confirm({ realmId: REALM, userId: USER, setId });
  return codes;
}

function secretOf(built: Built & { secret: Uint8Array | null }): Uint8Array {
  if (built.secret === null) throw new Error('no TOTP');
  return built.secret;
}

describe('the totp step after the first factor', () => {
  it('is asked of an account that holds a TOTP, with no policy, and completes with ["pwd","otp","mfa"]', async () => {
    const built = await build({ totp: 'bound' });
    const ctx = context(built);
    const offered = await signIn(built, ctx);
    expect(offered).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'totp', params: { digits: 6 } } },
    });
    const done = await built.engine.advance(
      kept(offered),
      answer('totp', { otp: built.totp.codeFor(secretOf(built)) }),
      ctx
    );
    expect(done).toMatchObject({
      kind: 'complete',
      signIn: { subject: USER, amr: ['pwd', 'otp', 'mfa'] },
    });
    expect(ctx.records).toContainEqual({ outcome: 'passed', step: 'totp', userId: USER });
    expect(built.totp.notices).toEqual([]);
  });

  it('accepts a code of the previous step once; the same code in a new sign-in is refused', async () => {
    const built = await build({ totp: 'bound' });
    const code = built.totp.codeFor(secretOf(built), -1);
    const first = await signIn(built);
    expect(
      await built.engine.advance(kept(first), answer('totp', { otp: code }), context(built))
    ).toMatchObject({ kind: 'complete' });
    const second = await signIn(built);
    expect(
      await built.engine.advance(kept(second), answer('totp', { otp: code }), context(built))
    ).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'totp', error: 'invalid_credentials' } },
    });
  });

  it('refuses a wrong code, counts it on the account, and tells the user after a correct password', async () => {
    const built = await build({ totp: 'bound' });
    const ctx = context(built);
    const offered = await signIn(built, ctx);
    const refused = await built.engine.advance(
      kept(offered),
      answer('totp', { otp: wrongCode(secretOf(built), built.clock.now()) }),
      ctx
    );
    expect(refused).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'totp', error: 'invalid_credentials' } },
    });
    expect(totpCounter(built)?.failures).toBe(1);
    expect(built.totp.notices).toEqual([
      { kind: 'failed_after_password', realmId: REALM, userId: USER },
    ]);
    expect(ctx.records).toContainEqual({
      outcome: 'refused',
      step: 'totp',
      userId: USER,
      reason: 'invalid_credentials',
    });
  });

  it('shares one counter across transactions, clients and IPs: inside a wait a code is neither checked nor counted', async () => {
    const built = await build({ totp: 'bound' });
    const secret = secretOf(built);
    // Past the free failures, each wait outlasts the next sign-in's rounds:
    // the 7th failure sets 4 s.
    const failures = TOTP_LADDER_POLICY.freeFailures + 2;
    for (let attempt = 1; attempt <= failures; attempt += 1) {
      const ctx = context(built, {
        client: { id: `client-${attempt}` },
        endUserIp: `192.0.2.${attempt}`,
      });
      const offered = await signIn(built, ctx);
      const waitUntil = totpCounter(built)?.waitUntil ?? 0;
      if (waitUntil > built.clock.now()) built.clock.advance(waitUntil - built.clock.now());
      const refused = await built.engine.advance(
        kept(offered),
        answer('totp', { otp: wrongCode(secret, built.clock.now()) }),
        ctx
      );
      expect(refused, String(attempt)).toMatchObject({
        offer: { current: { error: 'invalid_credentials' } },
      });
    }
    expect(totpCounter(built)?.failures).toBe(failures);
    // The next attempt is early: the right code, from yet another client and IP, waits.
    const ctx = context(built, { client: { id: 'client-x' }, endUserIp: '198.51.100.7' });
    const offered = await signIn(built, ctx);
    const lastStep = built.totp.rows.get(`${REALM}:${USER}`)?.lastStep;
    const early = await built.engine.advance(
      kept(offered),
      answer('totp', { otp: built.totp.codeFor(secret) }),
      ctx
    );
    expect(early).toMatchObject({ kind: 'refused', reason: 'throttled' });
    expect(built.totp.rows.get(`${REALM}:${USER}`)?.lastStep).toBe(lastStep);
    expect(totpCounter(built)?.failures).toBe(failures);
    // Past the wait, the right code goes through and clears the counter.
    if (early.kind !== 'refused' || early.reason !== 'throttled') throw new Error('not throttled');
    built.clock.advance(early.retryAfterSeconds * 1000);
    const done = await built.engine.advance(
      kept(early),
      answer('totp', { otp: built.totp.codeFor(secret) }),
      ctx
    );
    expect(done).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd', 'otp', 'mfa'] } });
    expect(totpCounter(built)).toBeUndefined();
  });

  it('is never cleared by a correct password', async () => {
    const built = await build({ totp: 'bound' });
    const secret = secretOf(built);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const offered = await signIn(built);
      await built.engine.advance(
        kept(offered),
        answer('totp', { otp: wrongCode(secret, built.clock.now()) }),
        context(built)
      );
    }
    expect(totpCounter(built)?.failures).toBe(3);
    // A right password, in a new transaction: the TOTP's counter stays.
    const offered = await signIn(built);
    expect(stepOf(offered)).toBe('totp');
    expect(totpCounter(built)?.failures).toBe(3);
  });

  it('fires the hard action at 100 failures: the TOTP is disabled and a recovery code stands in for it', async () => {
    const built = await build({ totp: 'bound' });
    const secret = secretOf(built);
    const ceiling = TOTP_LADDER_POLICY.hardCeiling ?? 0;
    for (let attempt = 1; attempt <= ceiling; attempt += 1) {
      const offered = await signIn(built);
      expect(stepOf(offered), String(attempt)).toBe('totp');
      await built.engine.advance(
        kept(offered),
        answer('totp', { otp: wrongCode(secret, built.clock.now()) }),
        context(built)
      );
      expect(built.totp.rows.get(`${REALM}:${USER}`)?.disabled).toBe(attempt >= ceiling);
      built.clock.advance(TOTP_LADDER_POLICY.maxWaitMs);
    }
    expect(built.totp.notices.filter((notice) => notice.kind === 'ceiling_reached')).toEqual([
      { kind: 'ceiling_reached', realmId: REALM, userId: USER },
    ]);
    // Disabled, the TOTP still counts as bound: the password alone never
    // completes, and the recovery code is all that is offered.
    const offered = await signIn(built);
    expect(offered).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'recovery_code' }, alternatives: [] },
    });
  });

  it('leaves the TOTP as it is at the ceiling while the hard action is not armed', async () => {
    const built = await build({ totp: 'bound' });
    built.totp.armed = false;
    const secret = secretOf(built);
    for (let attempt = 1; attempt <= (TOTP_LADDER_POLICY.hardCeiling ?? 0) + 1; attempt += 1) {
      const offered = await signIn(built);
      await built.engine.advance(
        kept(offered),
        answer('totp', { otp: wrongCode(secret, built.clock.now()) }),
        context(built)
      );
      built.clock.advance(TOTP_LADDER_POLICY.maxWaitMs);
    }
    expect(built.totp.rows.get(`${REALM}:${USER}`)?.disabled).toBe(false);
    expect(built.totp.notices.some((notice) => notice.kind === 'ceiling_reached')).toBe(false);
    expect(stepOf(await signIn(built))).toBe('totp');
  });

  it('keeps its verdict when a notice fails', async () => {
    const built = await build({ totp: 'bound' });
    built.totp.failNext = 'failed_after_password';
    const offered = await signIn(built);
    const refused = await built.engine.advance(
      kept(offered),
      answer('totp', { otp: wrongCode(secretOf(built), built.clock.now()) }),
      context(built)
    );
    expect(refused).toMatchObject({
      kind: 'step',
      offer: { current: { error: 'invalid_credentials' } },
    });
    expect(totpCounter(built)?.failures).toBe(1);
  });

  it('counts a disabled TOTP as bound: a recovery code stands in for it, then a new one is set up', async () => {
    const built = await build({ totp: 'disabled' });
    const { set } = built;
    const ctx = context(built);
    const offered = await signIn(built, ctx);
    expect(offered).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'recovery_code' }, alternatives: [] },
    });
    const setUp = await built.engine.advance(
      kept(offered),
      answer('recovery_code', { recovery_code: set[0] }),
      ctx
    );
    // No policy asks for mfa, yet the sign-in does not complete on the code
    // alone: a disabled TOTP is set up again, or every sign-in would spend a
    // recovery code until none is left.
    expect(stepOf(setUp)).toBe('totp_setup');
    let result = await firstCode(built, setUp, ctx);
    // The account holds a factor beyond the password: no mailed code.
    expect(built.sender.sent).toEqual([]);
    expect(built.totp.rows.get(`${REALM}:${USER}`)?.disabled).toBe(false);
    while (result.kind === 'step' && stepOf(result) === 'recovery_codes') {
      result = await built.engine.advance(
        kept(result),
        answer('recovery_codes', { acknowledged: true }),
        ctx
      );
    }
    expect(result).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd', 'otp', 'mfa'] } });
  });

  it('sends a FiPA client to the hosted pages for a disabled TOTP: it cannot redeem a recovery code', async () => {
    const built = await build({ totp: 'disabled' });
    const fipa = await signIn(built, context(built, { serves: FIPA_STEP_NAMES }));
    expect(fipa).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
  });

  it('is asked of a FiPA client that listed it, and is a redirect for one that did not', async () => {
    const built = await build({ totp: 'bound' });
    const listed = await signIn(built, context(built, { serves: FIPA_STEP_NAMES }));
    expect(stepOf(listed)).toBe('totp');
    const without = await signIn(
      built,
      context(built, { serves: FIPA_STEP_NAMES.filter((step) => step !== 'totp') })
    );
    expect(without).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
  });
});

/** Answer the set-up offered in `offered` with the right first code. */
async function firstCode(built: Built, offered: RoundResult, ctx: Ctx): Promise<RoundResult> {
  const secret = String(personalOf(offered).secret);
  const row = Buffer.from(base32Decode(secret));
  return built.engine.advance(
    kept(offered),
    answer('totp_setup', { otp: totpCode(new Uint8Array(row), totpStep(built.clock.now())) }),
    ctx
  );
}

/** RFC 4648 §6's base32, unpadded: what the set-up step shows. */
function base32Decode(text: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of text) {
    buffer = (buffer << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

describe('the TOTP set-up under an MFA policy', () => {
  it('gives an account with no second factor the set-up step, never a code', async () => {
    const built = await build();
    built.policy.policy = { realm: 'required', client: 'off' };
    const ctx = context(built);
    const offered = await signIn(built, ctx);
    expect(offered).toMatchObject({
      kind: 'step',
      offer: {
        current: { step: 'totp_setup', params: { algorithm: 'SHA1', digits: 6, period: 30 } },
        alternatives: [],
      },
      personal: {
        identifier: IDENTIFIER,
        secret: expect.stringMatching(/^[A-Z2-7]{32}$/),
        otpauth_uri: expect.stringMatching(/^otpauth:\/\/totp\//),
      },
    });
    expect(built.sender.sent).toEqual([]);
    expect(built.totp.rows.size).toBe(0);
    // The transaction holds the ciphertext, never the secret.
    const secret = String(personalOf(offered).secret);
    expect(JSON.stringify(kept(offered))).not.toContain(secret);
    expect(kept(offered).totpEnrolment?.sealed).toMatch(/^v1\.memory\./);
  });

  it('binds only after a first valid code, then the mailbox, and shows the first set of recovery codes', async () => {
    const built = await build();
    built.policy.policy = { realm: 'off', client: 'required' };
    const ctx = context(built);
    const offered = await signIn(built, ctx);
    const secret = String(personalOf(offered).secret);
    // A wrong first code: the same secret again, nothing bound.
    const decoded = base32Decode(secret);
    const refused = await built.engine.advance(
      kept(offered),
      answer('totp_setup', { otp: wrongCode(decoded, built.clock.now()) }),
      ctx
    );
    expect(refused).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'totp_setup', error: 'invalid_credentials' } },
      personal: { secret },
    });
    expect(built.totp.rows.size).toBe(0);
    // The right one: the password-only account's mailbox next, still nothing bound.
    const checked = await firstCode(built, refused, ctx);
    expect(checked).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'email_code', params: { purpose: 'recovery', length: 8 } } },
    });
    expect(built.totp.rows.size).toBe(0);
    const bound = await built.engine.advance(
      kept(checked),
      answer('email_code', { otp: built.sender.last }),
      ctx
    );
    expect(built.totp.rows.get(`${REALM}:${USER}`)).toMatchObject({
      lastStep: totpStep(built.clock.now()),
      disabled: false,
    });
    expect(built.totp.notices).toEqual([{ kind: 'bound', realmId: REALM, userId: USER }]);
    expect(ctx.records).toContainEqual({ outcome: 'passed', step: 'totp_setup', userId: USER });
    // The first TOTP enrolment issues a set of recovery codes.
    expect(stepOf(bound)).toBe('recovery_codes');
    const done = await built.engine.advance(
      kept(bound),
      answer('recovery_codes', { acknowledged: true }),
      ctx
    );
    // The first code proved the bound TOTP: the policy is met.
    expect(done).toMatchObject({
      kind: 'complete',
      signIn: { subject: USER, amr: ['pwd', 'otp', 'mfa'] },
    });
    // The secret the set-up showed is the one bound.
    expect(Buffer.from(built.totp.secretOf(USER, REALM)).equals(Buffer.from(decoded))).toBe(true);
  });

  it('verifies an unclaimed account’s address first, which proves the mailbox: no second code', async () => {
    const built = await build({ account: { verified: false } });
    built.policy.policy = { realm: 'required', client: 'off' };
    const ctx = context(built);
    const verifying = await signIn(built, ctx);
    expect(verifying).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'email_code', params: { purpose: 'verify_account' } } },
    });
    expect(built.totp.sealed).toEqual([]);
    const offered = await built.engine.advance(
      kept(verifying),
      answer('email_code', { otp: built.sender.last }),
      ctx
    );
    expect(stepOf(offered)).toBe('totp_setup');
    const sent = built.sender.sent.length;
    const bound = await firstCode(built, offered, ctx);
    expect(built.sender.sent).toHaveLength(sent);
    expect(stepOf(bound)).toBe('recovery_codes');
    expect(built.totp.rows.size).toBe(1);
  });

  it('ends the transaction when the binding finds the account unclaimed', async () => {
    const built = await build();
    built.policy.policy = { realm: 'required', client: 'off' };
    built.totp.bindRefusal = 'account_unclaimed';
    const ctx = context(built);
    const offered = await signIn(built, ctx);
    const checked = await firstCode(built, offered, ctx);
    const done = await built.engine.advance(
      kept(checked),
      answer('email_code', { otp: built.sender.last }),
      ctx
    );
    expect(done).toMatchObject({ kind: 'refused', transaction: null });
    expect(built.totp.rows.size).toBe(0);
    expect(ctx.records).toContainEqual({
      outcome: 'ended',
      step: 'totp_setup',
      userId: USER,
      reason: 'account_unclaimed',
    });
  });

  it('binds nothing once the factor is more than 5 minutes old: the transaction ends', async () => {
    const built = await build();
    built.policy.policy = { realm: 'required', client: 'off' };
    const ctx = context(built);
    const offered = await signIn(built, ctx);
    built.clock.advance(TOTP_BINDING_MAX_AUTH_AGE_MS + MINUTE);
    const done = await firstCode(built, offered, ctx);
    expect(done).toMatchObject({ kind: 'refused', transaction: null });
    expect(built.totp.rows.size).toBe(0);
    expect(ctx.records).toContainEqual({
      outcome: 'ended',
      step: 'totp_setup',
      userId: USER,
      reason: 'authentication_stale',
    });
  });

  it('sends a FiPA client to the hosted pages, with no secret drawn', async () => {
    const built = await build();
    built.policy.policy = { realm: 'required', client: 'off' };
    const result = await signIn(built, context(built, { serves: FIPA_STEP_NAMES }));
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
    expect(built.totp.sealed).toEqual([]);
    expect(built.sender.sent).toEqual([]);
  });

  it('rebinds after a recovery code stood in for a disabled TOTP, and the new one replaces it', async () => {
    const built = await build({ totp: 'disabled' });
    built.policy.policy = { realm: 'required', client: 'off' };
    const { set } = built;
    const ctx = context(built);
    const offered = await signIn(built, ctx);
    expect(stepOf(offered)).toBe('recovery_code');
    const setUp = await built.engine.advance(
      kept(offered),
      answer('recovery_code', { recovery_code: set[0] }),
      ctx
    );
    expect(stepOf(setUp)).toBe('totp_setup');
    const before = built.totp.rows.get(`${REALM}:${USER}`)?.sealed;
    // The account holds a factor beyond the password: no mailed code.
    let result = await firstCode(built, setUp, ctx);
    expect(built.sender.sent).toEqual([]);
    const row = built.totp.rows.get(`${REALM}:${USER}`);
    expect(row?.disabled).toBe(false);
    expect(row?.sealed).not.toBe(before);
    while (result.kind === 'step' && stepOf(result) === 'recovery_codes') {
      result = await built.engine.advance(
        kept(result),
        answer('recovery_codes', { acknowledged: true }),
        ctx
      );
    }
    expect(result).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd', 'otp', 'mfa'] } });
  });

  it('asks an account that holds a TOTP for it, not for a new one', async () => {
    const built = await build({ totp: 'bound' });
    built.policy.policy = { realm: 'required', client: 'off' };
    const offered = await signIn(built);
    expect(stepOf(offered)).toBe('totp');
    expect(built.totp.sealed).toHaveLength(1);
  });

  it('shows the same secret on every round that offers the step again', async () => {
    const built = await build();
    built.policy.policy = { realm: 'required', client: 'off' };
    const ctx = context(built);
    const offered = await signIn(built, ctx);
    built.clock.advance(STEP_MS);
    const again = await built.engine.advance(kept(offered), null, ctx);
    expect(personalOf(again).secret).toBe(personalOf(offered).secret);
    expect(built.totp.sealed).toHaveLength(1);
  });
});
