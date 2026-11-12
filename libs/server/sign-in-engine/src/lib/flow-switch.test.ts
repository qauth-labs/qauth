import {
  STEP_NAMES,
  STEP_URNS,
  type StepName,
  type StepOffer,
  type StepParams,
} from '@qauth-labs/server-step-grammar';
import { describe, expect, it } from 'vitest';

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
  FakeResets,
  passwordAccount,
  recordingAudit,
} from '../testing/fakes';
import { createMemoryLadder } from '../testing/memory-ladder';
import { createMemoryPasskeys } from '../testing/memory-passkeys';
import { createMemoryRecoveryCodes } from '../testing/memory-recovery-codes';
import { createProofOfWorkProvider, solvesProofOfWork } from './bot-challenge';
import { createSignInEngine, type SignInEngineDependencies } from './engine';
import type { Clock } from './ports';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import { createCaptchaStep } from './steps/captcha';
import { readSignInTransaction, type SignInTransaction } from './transaction';

/**
 * The switch between a sign-in and a registration within one interaction
 * (#1079; ADR-017 Decision 8): the `register` path marker beside a sign-in's
 * first step, under the registration's gate, and the `sign_in` marker, the
 * way back, beside a registration's address step.
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'notes-web';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const PASSWORD = 'correct horse battery staple';
const NEW_PASSWORD = 'seven amber kites over the old harbour';
const KNOWN = 'alice@example.com';
const UNKNOWN = 'nobody@example.com';
const T0 = 1_800_000_000_000;

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

/** A registration gate that may also require the bot challenge (#643). */
class ChallengingRegistrations extends FakeRegistrations {
  requires = false;
  async challengeRequired() {
    return this.requires;
  }
}

function build(
  accounts: readonly [string, FakeAccount][] = [[KNOWN, passwordAccount(USER, PASSWORD)]],
  options: Partial<SignInEngineDependencies> = {}
) {
  const directory = new FakeDirectory(new Map(accounts));
  const clock = manualClock();
  const registrations = new ChallengingRegistrations(directory);
  const resets = new FakeResets(directory, undefined, clock.now);
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
    resets,
    hooks: { ladder: createMemoryLadder(() => clock.now()) },
    clock,
    steps: [
      createCaptchaStep(
        createProofOfWorkProvider({ difficulty: () => 4, random: (size) => Buffer.alloc(size, 7) })
      ),
    ],
    ...options,
  });
  return { engine, directory, registrations, resets, clock, sender: new FakeCodeSender() };
}
type Built = ReturnType<typeof build>;

type Ctx = RoundContext & { readonly records: ReturnType<typeof recordingAudit>['records'] };

/** A round of the Interaction API for an authorization request: the flows may switch. */
function context(built: Built, overrides: Partial<RoundContext> = {}): Ctx {
  const audit = recordingAudit();
  return {
    realm: { id: REALM },
    client: { id: CLIENT },
    audit: audit.sink,
    records: audit.records,
    sendCode: built.sender.send,
    serves: HOSTED,
    switchFlows: true,
    ...overrides,
  };
}

function answer(step: StepName, fields: Record<string, unknown> = {}): RoundAnswer {
  return { step: STEP_URNS[step], fields };
}
const identifierAnswer = (address: string) => answer('identifier', { login_hint: address });

/** The transaction a result keeps, through its stored form; fails the test when it keeps none. */
function kept(result: RoundResult): SignInTransaction {
  if (result.transaction === null) throw new Error(`${result.kind} kept no transaction`);
  const read = readSignInTransaction(JSON.parse(JSON.stringify(result.transaction)));
  if (read === null) throw new Error('the kept transaction does not read back');
  return read;
}

function offerOf(result: RoundResult): StepOffer {
  if (result.kind !== 'step') throw new Error(`a ${JSON.stringify(result)}, not a step`);
  return result.offer;
}

/** The current step and the alternatives a result offers, by name. */
function offered(result: RoundResult): readonly StepName[] {
  const offer = offerOf(result);
  return [offer.current.step, ...offer.alternatives.map((step) => step.step)];
}

describe('the register marker beside a sign-in’s first step', () => {
  it('is offered last, with no params, while the realm and the client allow sign-up', async () => {
    const built = build();
    const result = await built.engine.advance(null, null, context(built));
    expect(offerOf(result)).toMatchObject({
      current: { step: 'identifier' },
      alternatives: [{ step: 'register', params: {} }],
    });
    expect(kept(result).flow).toBeUndefined();
    expect(built.registrations.gates).toEqual([{ realmId: REALM, clientId: CLIENT }]);
  });

  it.each<[string, (built: Built) => Partial<RoundContext>]>([
    [
      'the realm or the client does not allow sign-up',
      (built) => {
        built.registrations.allows = false;
        return {};
      },
    ],
    ['the request asks for a fresh sign-in (max_age, prompt=login)', () => ({ freshSignIn: true })],
    ['the transport does not let the flows switch', () => ({ switchFlows: false })],
    [
      'the transport does not serve the marker',
      () => ({ serves: HOSTED.filter((s) => s !== 'register') }),
    ],
    [
      'the transport does not serve a registration’s steps',
      () => ({
        serves: HOSTED.filter((s) => s !== 'new_password'),
      }),
    ],
    ['the round is a reset’s start', () => ({ flow: 'reset' })],
  ])('is not offered when %s', async (_why, set) => {
    const built = build();
    const ctx = context(built, set(built));
    const result = await built.engine.advance(null, null, ctx);
    if (result.kind === 'step') expect(offered(result)).not.toContain('register');
  });

  it('is not offered by an engine that cannot register', async () => {
    const built = build(undefined, { registrations: undefined });
    const result = await built.engine.advance(null, null, context(built));
    expect(offered(result)).toEqual(['identifier']);
  });

  it('is the same for a known and an unknown identifier: offered before any, and after neither', async () => {
    const results: RoundResult[] = [];
    for (const address of [KNOWN, UNKNOWN]) {
      const built = build();
      const ctx = context(built);
      const first = await built.engine.advance(null, null, ctx);
      expect(offered(first)).toEqual(['identifier', 'register']);
      results.push(await built.engine.advance(kept(first), identifierAnswer(address), ctx));
    }
    const [known, unknown] = results as [RoundResult, RoundResult];
    expect(offerOf(known)).toEqual(offerOf(unknown));
    expect(offered(known)).not.toContain('register');
    expect(offered(known)).toContain('password_reset');
  });
});

describe('answering register', () => {
  it('turns the sign-in into a registration at its first round, in the same round', async () => {
    const built = build();
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const before = kept(first);
    built.clock.advance(5_000);
    const switched = await built.engine.advance(before, answer('register'), ctx);
    expect(offerOf(switched)).toMatchObject({
      current: { step: 'identifier', params: {} },
      alternatives: [{ step: 'sign_in', params: {} }],
    });
    const transaction = kept(switched);
    expect(transaction).toMatchObject({ flow: 'register', verified: [] });
    // As old as the sign-in it replaces: switching never extends a transaction.
    expect(transaction.createdAt).toBe(before.createdAt);
    expect(ctx.records).toContainEqual({ outcome: 'passed', step: 'register' });
    expect(built.sender.sent).toEqual([]);
  });

  it('is taken at round 0 too, from a first step the transport offered itself', async () => {
    const built = build();
    const switched = await built.engine.advance(null, answer('register'), context(built));
    expect(offered(switched)).toEqual(['identifier', 'sign_in']);
    expect(kept(switched).flow).toBe('register');
  });

  it('ends in a registration for the request, as prompt=create would, though the request asked for none', async () => {
    const built = build([]);
    const ctx = context(built);
    let result = await built.engine.advance(null, answer('register'), ctx);
    result = await built.engine.advance(kept(result), identifierAnswer(UNKNOWN), ctx);
    expect(offerOf(result).current).toMatchObject({
      step: 'email_code',
      params: { purpose: 'verify_account', length: 8 },
    });
    result = await built.engine.advance(
      kept(result),
      answer('email_code', { otp: built.sender.last }),
      ctx
    );
    expect(offerOf(result).current).toMatchObject({
      step: 'new_password',
      params: { purpose: 'register' },
    });
    result = await built.engine.advance(
      kept(result),
      answer('new_password', { new_password: NEW_PASSWORD }),
      ctx
    );
    const created = built.registrations.created[0];
    expect(result).toEqual({
      kind: 'complete',
      transaction: null,
      signIn: { subject: created?.userId, identifier: UNKNOWN, registered: true },
    });
  });

  it('asks for the bot challenge first where the realm or the client requires one', async () => {
    const built = build();
    built.registrations.requires = true;
    const ctx = context(built, { serves: STEP_NAMES });
    const first = await built.engine.advance(null, null, ctx);
    expect(offered(first)).toEqual(['identifier', 'register']);
    const switched = await built.engine.advance(kept(first), answer('register'), ctx);
    expect(offered(switched)).toEqual(['captcha']);
    const params = offerOf(switched).current.params as StepParams<'captcha'>;
    let nonce = 0;
    while (!solvesProofOfWork(params, String(nonce))) nonce += 1;
    const passed = await built.engine.advance(
      kept(switched),
      answer('captcha', { captcha_token: String(nonce) }),
      ctx
    );
    expect(offered(passed)).toEqual(['identifier', 'sign_in']);
    expect(kept(passed).flow).toBe('register');
  });

  it('is refused as an invalid answer once the gate closed, and the sign-in stays where it was', async () => {
    const built = build();
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    built.registrations.allows = false;
    const refused = await built.engine.advance(kept(first), answer('register'), ctx);
    expect(refused).toMatchObject({ kind: 'refused', reason: 'invalid_answer' });
    expect(kept(refused)).toEqual(kept(first));
    expect(ctx.records).toEqual([
      { outcome: 'refused', step: 'register', reason: 'invalid_answer' },
    ]);
  });

  it('is refused after an identifier, and on a transport that does not let the flows switch', async () => {
    const built = build();
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const named = await built.engine.advance(kept(first), identifierAnswer(UNKNOWN), ctx);
    expect(await built.engine.advance(kept(named), answer('register'), ctx)).toMatchObject({
      kind: 'refused',
      reason: 'invalid_answer',
    });
    const fixed = context(built, { switchFlows: false });
    expect(await built.engine.advance(null, answer('register'), fixed)).toMatchObject({
      kind: 'refused',
      reason: 'invalid_answer',
    });
  });
});

describe('answering sign_in, the way back', () => {
  it('turns a prompt=create registration into a sign-in at its first round', async () => {
    const built = build();
    const ctx = context(built, { flow: 'register' });
    const first = await built.engine.advance(null, null, ctx);
    expect(offered(first)).toEqual(['identifier', 'sign_in']);
    const back = await built.engine.advance(kept(first), answer('sign_in'), ctx);
    // The sign-in's first step, which offers the registration again.
    expect(offered(back)).toEqual(['identifier', 'register']);
    expect(kept(back).flow).toBeUndefined();
    expect(ctx.records).toContainEqual({ outcome: 'passed', step: 'sign_in' });
    // The request still says prompt=create: the transaction's flow decides.
    const named = await built.engine.advance(kept(back), identifierAnswer(KNOWN), ctx);
    expect(offerOf(named).current.step).toBe('password');
    const done = await built.engine.advance(
      kept(named),
      answer('password', { password: PASSWORD }),
      ctx
    );
    expect(done).toMatchObject({ kind: 'complete', signIn: { subject: USER, amr: ['pwd'] } });
    expect(built.registrations.created).toEqual([]);
  });

  it('goes back and forth within one interaction', async () => {
    const built = build();
    const ctx = context(built);
    let result = await built.engine.advance(null, answer('register'), ctx);
    result = await built.engine.advance(kept(result), answer('sign_in'), ctx);
    expect(kept(result).flow).toBeUndefined();
    result = await built.engine.advance(kept(result), answer('register'), ctx);
    expect(kept(result).flow).toBe('register');
    expect(offered(result)).toEqual(['identifier', 'sign_in']);
  });

  it('is offered under no gate of its own, and not once the registration holds the address', async () => {
    const built = build();
    const ctx = context(built, { flow: 'register' });
    const first = await built.engine.advance(null, null, ctx);
    const code = await built.engine.advance(kept(first), identifierAnswer(UNKNOWN), ctx);
    expect(offered(code)).toEqual(['email_code']);
    expect(await built.engine.advance(kept(code), answer('sign_in'), ctx)).toMatchObject({
      kind: 'refused',
      reason: 'invalid_answer',
    });
  });

  it('lets a sign-in it went back to become a reset', async () => {
    const built = build();
    const ctx = context(built, { flow: 'register' });
    const first = await built.engine.advance(null, null, ctx);
    const back = await built.engine.advance(kept(first), answer('sign_in'), ctx);
    const named = await built.engine.advance(kept(back), identifierAnswer(KNOWN), ctx);
    expect(offered(named)).toContain('password_reset');
    const reset = await built.engine.advance(kept(named), answer('password_reset'), ctx);
    expect(offerOf(reset).current).toMatchObject({
      step: 'email_code',
      params: { purpose: 'recovery' },
    });
    expect(kept(reset).flow).toBe('reset');
    // The reset's next round, with the request still saying prompt=create.
    const again = await built.engine.advance(kept(reset), answer('email_code', {}), ctx);
    expect(again.kind).toBe('step');
  });
});

describe('the transaction of another flow', () => {
  it('still ends on a transport that does not let the flows switch', async () => {
    const built = build();
    const registration = kept(
      await built.engine.advance(null, null, context(built, { flow: 'register' }))
    );
    const ctx = context(built, { switchFlows: false });
    expect(await built.engine.advance(registration, identifierAnswer(KNOWN), ctx)).toMatchObject({
      kind: 'refused',
      reason: 'transaction_ended',
    });
  });
});

describe('with passkeys on the hosted pages', () => {
  function withPasskeys() {
    const clock = manualClock();
    return build(undefined, {
      passkeys: createMemoryPasskeys(),
      recoveryCodes: createMemoryRecoveryCodes(clock.now),
    });
  }

  it('offers register after the sign-in’s first factors, and sign_in after a registration’s address step', async () => {
    const built = withPasskeys();
    const signIn = await built.engine.advance(null, null, context(built));
    expect(offered(signIn)).toEqual([
      'webauthn_get',
      'password',
      'identifier',
      'recovery_code',
      'register',
    ]);
    const registration = await built.engine.advance(
      kept(signIn),
      answer('register'),
      context(built)
    );
    expect(offered(registration)).toEqual(['webauthn_create', 'identifier', 'sign_in']);
    expect(kept(registration).ceremony?.step).toBe('webauthn_create');
    const back = await built.engine.advance(kept(registration), answer('sign_in'), context(built));
    expect(offered(back)[0]).toBe('webauthn_get');
    expect(kept(back).ceremony?.step).toBe('webauthn_get');
  });
});
