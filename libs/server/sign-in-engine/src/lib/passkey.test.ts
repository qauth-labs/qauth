import {
  createFipaMapper,
  FIPA_SERVES_ALL,
  FIPA_STEP_NAMES,
  STEP_NAMES,
  STEP_URNS,
  type StepName,
  type StepOffer,
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
import {
  createMemoryPasskeys,
  fakeAssertion,
  fakeRegistration,
  type MemoryPasskeys,
} from '../testing/memory-passkeys';
import {
  createMemoryRecoveryCodes,
  type MemoryRecoveryCodes,
} from '../testing/memory-recovery-codes';
import {
  createSignInEngine,
  PASSKEY_BINDING_MAX_AUTH_AGE_MS,
  type SignInEngineDependencies,
} from './engine';
import { strongestBoundFactor } from './factors';
import type { Clock, SignInAccount } from './ports';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import { holdsUsablePasskey } from './steps/passkey';
import { readSignInTransaction, type SignInTransaction } from './transaction';

/**
 * Passkeys at sign-in (#651; ADR-017 Decisions 4, 8 and 10;
 * `graphs/flows/core/passkey/flow.yaml`): the `webauthn_get` step,
 * passkey-first, the downgrade rule, user verification, the `amr` values, and
 * the optional `webauthn_create` enrolment after a sign-in.
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'web-client';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const OTHER_USER = '0199fa20-5e1a-7000-8000-000000000002';
const PASSWORD = 'a quiet violet tram crosses nine rivers';
const IDENTIFIER = 'alice@example.com';
const OTHER_IDENTIFIER = 'bob@example.com';
const PASSKEY = 'credential-alice';
const OTHER_PASSKEY = 'credential-bob';
const T0 = 1_800_000_000_000;
const MINUTE = 60_000;

/** The FiPA endpoint's steps when the client listed every one it may: never a recovery step. */
const FIPA_SERVES: readonly StepName[] = FIPA_STEP_NAMES;
/** A FiPA client that did not list `webauthn_get`. */
const FIPA_WITHOUT_PASSKEY: readonly StepName[] = FIPA_STEP_NAMES.filter(
  (step) => step !== 'webauthn_get'
);
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

/** An account with a password and a passkey; `disabled` disables the passkey. */
const passkeyAccount = (disabled = false, overrides: Partial<FakeAccount> = {}) =>
  passwordAccount(USER, PASSWORD, { others: [{ type: 'passkey', disabled }], ...overrides });

interface Built {
  readonly engine: ReturnType<typeof createSignInEngine>;
  readonly directory: FakeDirectory;
  readonly passkeys: MemoryPasskeys;
  readonly codes: MemoryRecoveryCodes;
  readonly sender: FakeCodeSender;
  readonly clock: ReturnType<typeof manualClock>;
}

function build(
  account: FakeAccount = passkeyAccount(),
  options: Partial<SignInEngineDependencies> & {
    readonly disabledPasskey?: boolean;
    /** Whether the realm's mail reaches anyone (#1051); absent, it does. */
    readonly deliverable?: boolean;
  } = {}
): Built {
  const clock = manualClock();
  const directory = new FakeDirectory(
    new Map([
      [IDENTIFIER, account],
      [
        OTHER_IDENTIFIER,
        passwordAccount(OTHER_USER, PASSWORD, { others: [{ type: 'passkey', disabled: false }] }),
      ],
    ])
  );
  const holds = account.others.some((factor) => factor.type === 'passkey');
  const passkeys = createMemoryPasskeys([
    ...(holds ? [{ id: PASSKEY, userId: USER, disabled: options.disabledPasskey ?? false }] : []),
    { id: OTHER_PASSKEY, userId: OTHER_USER, disabled: false },
  ]);
  // A bound passkey shows in the account the directory reads.
  passkeys.onBind = () => {
    const current = directory.accounts.get(IDENTIFIER);
    if (current === undefined) throw new Error('no account');
    directory.accounts.set(IDENTIFIER, {
      ...current,
      others: [...current.others, { type: 'passkey', disabled: false }],
    });
  };
  const codes = createMemoryRecoveryCodes(clock.now);
  const deps: Partial<SignInEngineDependencies> = { ...options };
  delete (deps as { disabledPasskey?: boolean }).disabledPasskey;
  delete (deps as { deliverable?: boolean }).deliverable;
  const { deliverable } = options;
  const engine = createSignInEngine({
    accounts: directory,
    passwords: new FakePasswords(),
    policy: new FakePolicy(),
    identifierDigest: fakeIdentifierDigest,
    requireVerifiedAccount: true,
    emailCodes: {
      digest: fakeEmailCodeDigest,
      addresses: new FakeAddresses(directory),
      ...(deliverable === undefined ? {} : { deliverable: async () => deliverable }),
    },
    recoveryCodes: codes,
    passkeys,
    clock,
    ...deps,
  });
  return { engine, directory, passkeys, codes, sender: new FakeCodeSender(), clock };
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

/** The offer a step result made; fails the test for any other result. */
function offerOf(result: RoundResult): StepOffer {
  if (result.kind !== 'step') throw new Error(`a ${result.kind}, not a step`);
  return result.offer;
}

/** The params `step` was offered with in `result`. */
function paramsOf(result: RoundResult, step: StepName): unknown {
  const offer = offerOf(result);
  const offered = [offer.current, ...offer.alternatives].find((entry) => entry.step === step);
  if (offered === undefined) throw new Error(`${step} was not offered`);
  return offered.params;
}

const assertion = (result: RoundResult, credential = PASSKEY, userVerified = true) =>
  answer('webauthn_get', {
    webauthn_response: fakeAssertion(credential, paramsOf(result, 'webauthn_get'), {
      userVerified,
    }),
  });

/** Round 0 with the login_hint, then the password. */
async function signInWithPassword(built: Built, ctx: Ctx): Promise<RoundResult> {
  const first = await built.engine.advance(null, null, { ...ctx, loginHint: IDENTIFIER });
  return built.engine.advance(kept(first), answer('password', { password: PASSWORD }), ctx);
}

/** Every challenge of `result` replaced, so two offers compare by shape. */
function withoutChallenges(result: RoundResult): unknown {
  return JSON.parse(
    JSON.stringify({ ...result, transaction: null }).replace(
      /"challenge":"[A-Za-z0-9_-]+"/g,
      '"challenge":"…"'
    )
  );
}

describe('passkey-first', () => {
  it('asks for a discoverable passkey first, preferred, with the password, the identifier and a recovery code', async () => {
    const built = build();
    const result = await built.engine.advance(null, null, context(built));
    expect(result).toMatchObject({
      kind: 'step',
      offer: {
        current: {
          step: 'webauthn_get',
          params: { rpId: 'auth.example.com', userVerification: 'required' },
        },
        // The hosted pages offer a recovery code to every account (#655).
        alternatives: [{ step: 'password' }, { step: 'identifier' }, { step: 'recovery_code' }],
        required: false,
      },
      personal: {},
    });
    // No account is read for it.
    expect(built.directory.reads).toEqual([]);
  });

  it('with a login_hint, asks for the password and offers the passkey', async () => {
    const built = build();
    const result = await built.engine.advance(null, null, {
      ...context(built),
      loginHint: IDENTIFIER,
    });
    expect(result).toMatchObject({
      kind: 'step',
      offer: {
        current: { step: 'password', params: {} },
        alternatives: [{ step: 'webauthn_get', params: { userVerification: 'required' } }],
      },
      personal: { identifier: IDENTIFIER },
    });
    expect(offerOf(result).required).toBeUndefined();
    expect(built.directory.reads).toEqual([]);
  });

  it('answers the same first response for an account with a passkey and one without', async () => {
    const holder = build(passkeyAccount());
    const without = build(passwordAccount(USER, PASSWORD));
    for (const loginHint of [undefined, IDENTIFIER]) {
      const ctx = (built: Built) => ({
        ...context(built),
        ...(loginHint === undefined ? {} : { loginHint }),
      });
      const a = await holder.engine.advance(null, null, ctx(holder));
      const b = await without.engine.advance(null, null, ctx(without));
      expect(withoutChallenges(a)).toEqual(withoutChallenges(b));
      // A wrong password: the same answer again.
      const wrong = answer('password', { password: 'not the password at all, no' });
      const c = await holder.engine.advance(kept(a), wrong, ctx(holder));
      const d = await without.engine.advance(kept(b), wrong, ctx(without));
      expect(withoutChallenges(c)).toEqual(withoutChallenges(d));
    }
  });

  it('gives way to the password a FiPA client listed when it did not list webauthn_get', async () => {
    const built = build();
    const result = await built.engine.advance(
      null,
      null,
      context(built, { serves: FIPA_WITHOUT_PASSKEY })
    );
    expect(offerOf(result)).toMatchObject({
      current: { step: 'password' },
      alternatives: [{ step: 'identifier' }],
    });
    expect(built.passkeys.calls).toEqual([]);
  });

  it('keeps the same ceremony while it is young, and starts a new one after 4 minutes', async () => {
    const built = build();
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const again = await built.engine.advance(kept(first), null, ctx);
    expect(paramsOf(again, 'webauthn_get')).toEqual(paramsOf(first, 'webauthn_get'));
    built.clock.advance(4 * MINUTE);
    const later = await built.engine.advance(kept(again), null, ctx);
    expect(paramsOf(later, 'webauthn_get')).not.toEqual(paramsOf(first, 'webauthn_get'));
    expect(built.passkeys.calls).toEqual(['startAssertion', 'startAssertion']);
  });
});

describe('a passkey assertion', () => {
  it('with the UV flag signs in with amr ["pop","mfa"]', async () => {
    const built = build();
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const done = await built.engine.advance(kept(first), assertion(first), ctx);
    // A passkey sign-in owes the account its first set of recovery codes.
    expect(offerOf(done).current.step).toBe('recovery_codes');
    const confirmed = await built.engine.advance(
      kept(done),
      answer('recovery_codes', { acknowledged: true }),
      ctx
    );
    expect(confirmed).toEqual({
      kind: 'complete',
      transaction: null,
      // The passkey named the account; the sign-in goes on with its identifier.
      signIn: {
        subject: USER,
        identifier: IDENTIFIER,
        amr: ['pop', 'mfa'],
        authTime: expect.any(Number),
      },
    });
    expect(ctx.records).toContainEqual({ outcome: 'passed', step: 'webauthn_get', userId: USER });
  });

  it('goes on with the account’s identifier: an address not proved yet gets its code, not a redirect', async () => {
    const built = build(passkeyAccount(false, { verified: false }));
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);

    const next = await built.engine.advance(kept(first), assertion(first), ctx);

    expect(next).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'email_code' } },
      personal: { identifier: IDENTIFIER },
    });
    expect(kept(next)).toMatchObject({ subject: USER, identifier: IDENTIFIER });
  });

  it('without the UV flag is refused, and a new ceremony is offered', async () => {
    const built = build();
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const refused = await built.engine.advance(kept(first), assertion(first, PASSKEY, false), ctx);
    expect(refused).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'webauthn_get', error: 'invalid_credentials' } },
    });
    expect(paramsOf(refused, 'webauthn_get')).not.toEqual(paramsOf(first, 'webauthn_get'));
    expect(kept(refused).subject).toBeUndefined();
    expect(ctx.records.at(-1)).toEqual({
      outcome: 'refused',
      step: 'webauthn_get',
      reason: 'invalid_credentials',
    });
  });

  it('is refused by the engine itself when the port verified it without UV', async () => {
    const built = build();
    built.passkeys.forceUserVerified = false;
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const refused = await built.engine.advance(kept(first), assertion(first), ctx);
    expect(refused).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'webauthn_get', error: 'invalid_credentials' } },
    });
    expect(kept(refused).verified).toEqual([]);
  });

  it('is answered once: the same assertion again is refused', async () => {
    const built = build();
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const replayed = assertion(first, PASSKEY, false);
    const refused = await built.engine.advance(kept(first), replayed, ctx);
    const valid = answer('webauthn_get', {
      webauthn_response: fakeAssertion(PASSKEY, paramsOf(first, 'webauthn_get')),
    });
    const again = await built.engine.advance(kept(refused), valid, ctx);
    expect(offerOf(again).current).toMatchObject({
      step: 'webauthn_get',
      error: 'invalid_credentials',
    });
  });

  it('of a disabled account is refused like any other', async () => {
    const built = build(passkeyAccount(false, { enabled: false }));
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const refused = await built.engine.advance(kept(first), assertion(first), ctx);
    expect(offerOf(refused).current).toMatchObject({
      step: 'webauthn_get',
      error: 'invalid_credentials',
    });
    const unknown = build();
    const ctxUnknown = context(unknown);
    const start = await unknown.engine.advance(null, null, ctxUnknown);
    const noSuch = await unknown.engine.advance(
      kept(start),
      assertion(start, 'no-such-credential'),
      ctxUnknown
    );
    expect(withoutChallenges(noSuch)).toEqual(withoutChallenges(refused));
  });

  it('of another account than the login_hint names ends the transaction', async () => {
    const built = build();
    const ctx = { ...context(built), loginHint: IDENTIFIER };
    const first = await built.engine.advance(null, null, ctx);
    const ended = await built.engine.advance(kept(first), assertion(first, OTHER_PASSKEY), ctx);
    expect(ended).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
    expect(ctx.records.at(-1)).toMatchObject({ outcome: 'ended', reason: 'subject_mismatch' });
  });

  it('with the login_hint’s account signs in with ["pop","mfa"]', async () => {
    const built = build();
    const ctx = { ...context(built), loginHint: IDENTIFIER };
    await built.codes
      .replace({ realmId: REALM, userId: USER })
      .then((set) => built.codes.confirm({ realmId: REALM, userId: USER, setId: set.setId }));
    const first = await built.engine.advance(null, null, ctx);
    const done = await built.engine.advance(kept(first), assertion(first), ctx);
    expect(done).toMatchObject({
      kind: 'complete',
      signIn: { subject: USER, identifier: IDENTIFIER, amr: ['pop', 'mfa'] },
    });
  });
});

describe('the downgrade rule', () => {
  it('asks a passkey-bound account for its passkey after a correct password', async () => {
    const built = build();
    const ctx = context(built);
    const afterPassword = await signInWithPassword(built, ctx);
    expect(afterPassword).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'webauthn_get' } },
      personal: { identifier: IDENTIFIER },
    });
    expect(offerOf(afterPassword).required).toBeUndefined();
    expect(kept(afterPassword).subject).toBe(USER);
  });

  it('completes with ["pwd","pop","mfa"] after the password then the passkey', async () => {
    const built = build();
    await built.codes
      .replace({ realmId: REALM, userId: USER })
      .then((set) => built.codes.confirm({ realmId: REALM, userId: USER, setId: set.setId }));
    const ctx = context(built);
    const afterPassword = await signInWithPassword(built, ctx);
    const done = await built.engine.advance(kept(afterPassword), assertion(afterPassword), ctx);
    expect(done).toMatchObject({
      kind: 'complete',
      signIn: { subject: USER, identifier: IDENTIFIER, amr: ['pwd', 'pop', 'mfa'] },
    });
  });

  it('refuses another account’s passkey after the password: the transaction ends', async () => {
    const built = build();
    const ctx = context(built);
    const afterPassword = await signInWithPassword(built, ctx);
    const ended = await built.engine.advance(
      kept(afterPassword),
      assertion(afterPassword, OTHER_PASSKEY),
      ctx
    );
    expect(ended).toMatchObject({ kind: 'refused', reason: 'transaction_ended' });
  });

  it('counts a disabled passkey as bound: the password alone never completes', async () => {
    const account = passkeyAccount(true);
    const signedIn: SignInAccount = {
      userId: USER,
      enabled: true,
      admin: false,
      verified: true,
      factors: [
        { type: 'password', disabled: false },
        { type: 'passkey', disabled: true },
      ],
      requiredActions: [],
    };
    expect(strongestBoundFactor(signedIn)).toBe(2);
    expect(holdsUsablePasskey(signedIn)).toBe(false);
    const built = build(account, { disabledPasskey: true });
    const result = await signInWithPassword(built, context(built));
    // No step can meet it, and the account holds no recovery code: a redirect.
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
  });

  it('offers a recovery code in place of a disabled passkey on the hosted pages', async () => {
    const built = build(passkeyAccount(true), { disabledPasskey: true });
    await built.codes.replace({ realmId: REALM, userId: USER });
    const result = await signInWithPassword(built, context(built));
    expect(offerOf(result)).toMatchObject({
      current: { step: 'recovery_code' },
      alternatives: [],
    });
  });

  it('sends a FiPA client that did not list webauthn_get to the hosted pages', async () => {
    const built = build();
    const result = await signInWithPassword(
      built,
      context(built, { serves: FIPA_WITHOUT_PASSKEY })
    );
    expect(result).toEqual({ kind: 'redirect', reason: 'step_not_available', transaction: null });
    // The step it could not serve is redirect_to_web on its wire.
    const mapper = createFipaMapper(FIPA_SERVES_ALL);
    const offer: StepOffer = {
      current: {
        step: 'webauthn_get',
        params: {
          challenge: 'a'.repeat(43),
          rpId: 'auth.example.com',
          userVerification: 'required',
        },
      },
      alternatives: [],
    };
    expect(
      mapper.challenge(offer, {
        issuer: 'https://auth.example.com',
        newAuthSession: () => 'a'.repeat(43),
        interactionTypesSupported: [STEP_URNS.password],
      })
    ).toEqual({ status: 403, body: { error: 'redirect_to_web', iss: 'https://auth.example.com' } });
  });

  it('asks a FiPA client that listed webauthn_get for the passkey', async () => {
    const built = build();
    const result = await signInWithPassword(built, context(built, { serves: FIPA_SERVES }));
    expect(offerOf(result).current.step).toBe('webauthn_get');
  });

  it('never lets an emailed code stand in for the passkey', async () => {
    const built = build(passkeyAccount(false, { verified: false }));
    const ctx = context(built);
    const afterPassword = await signInWithPassword(built, ctx);
    // The address is verified inline first, then the passkey is still owed.
    expect(offerOf(afterPassword).current.step).toBe('webauthn_get');
  });
});

describe('the passkey enrolment', () => {
  const passwordOnly = () => passwordAccount(USER, PASSWORD);

  it('is offered after a password-only sign-in, and declining it completes with ["pwd"]', async () => {
    const built = build(passwordOnly());
    const ctx = context(built);
    const offered = await signInWithPassword(built, ctx);
    expect(offered).toMatchObject({
      kind: 'step',
      offer: {
        current: {
          step: 'webauthn_create',
          params: {
            optional: true,
            options: {
              authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
              attestation: 'none',
            },
          },
        },
        alternatives: [],
      },
      personal: {
        identifier: IDENTIFIER,
        user: { name: IDENTIFIER },
        excludeCredentials: [],
      },
    });
    const declined = await built.engine.advance(kept(offered), answer('webauthn_create', {}), ctx);
    expect(declined).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd'] } });
    expect(built.passkeys.calls).toEqual(['startAssertion', 'startRegistration']);
  });

  it('is skipped, and the sign-in completes, when its registration cannot start', async () => {
    const reported: unknown[] = [];
    const built = build(passwordOnly(), { onUnavailable: (error) => reported.push(error) });
    (built.passkeys as { startRegistration: unknown }).startRegistration = async () => {
      throw new Error('challenge store down');
    };
    const ctx = context(built);

    const done = await signInWithPassword(built, ctx);

    expect(done).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd'] } });
    expect(reported).toEqual([expect.objectContaining({ port: 'passkeys' })]);
  });

  it('binds the passkey of a verified account after its fresh password, with no mailed code, tells the user, and shows the first set', async () => {
    const built = build(passwordOnly());
    const ctx = context(built);
    const offered = await signInWithPassword(built, ctx);
    // The account decides, never a channel (ADR-017 Decision 8, amended
    // 2026-11-08): a verified account binds after its fresh password.
    const coded = await built.engine.advance(
      kept(offered),
      answer('webauthn_create', {
        webauthn_response: fakeRegistration('credential-new', paramsOf(offered, 'webauthn_create')),
      }),
      ctx
    );
    expect(built.sender.sent).toEqual([]);
    expect(built.passkeys.passkeys.get('credential-new')).toMatchObject({ userId: USER });
    expect(built.passkeys.notices).toEqual([{ realmId: REALM, userId: USER }]);
    expect(ctx.records).toContainEqual({
      outcome: 'passed',
      step: 'webauthn_create',
      userId: USER,
    });
    // The first enrolment issues a set of recovery codes.
    expect(offerOf(coded).current.step).toBe('recovery_codes');
    const done = await built.engine.advance(
      kept(coded),
      answer('recovery_codes', { acknowledged: true }),
      ctx
    );
    // The new passkey adds no amr value: the password's alone.
    expect(done).toMatchObject({ kind: 'complete', signIn: { subject: USER, amr: ['pwd'] } });
  });

  it('offers no passkey to an unclaimed account: the account decides, never a channel', async () => {
    const noMail = build(passwordAccount(USER, PASSWORD, { verified: false }), {
      requireVerifiedAccount: false,
    });
    const ctx = context(noMail);
    const done = await signInWithPassword(noMail, ctx);
    expect(done).toMatchObject({ kind: 'complete', signIn: { subject: USER, amr: ['pwd'] } });
    expect(noMail.passkeys.calls).not.toContain('startRegistration');
    expect(noMail.sender.sent).toEqual([]);
  });

  it('needs no second code when the transaction proved the mailbox already', async () => {
    const built = build(passwordAccount(USER, PASSWORD, { verified: false }));
    const ctx = context(built);
    const verifying = await signInWithPassword(built, ctx);
    expect(offerOf(verifying).current.step).toBe('email_code');
    const offered = await built.engine.advance(
      kept(verifying),
      answer('email_code', { otp: built.sender.last }),
      ctx
    );
    expect(offerOf(offered).current.step).toBe('webauthn_create');
    const sent = built.sender.sent.length;
    const bound = await built.engine.advance(
      kept(offered),
      answer('webauthn_create', {
        webauthn_response: fakeRegistration('credential-new', paramsOf(offered, 'webauthn_create')),
      }),
      ctx
    );
    expect(built.sender.sent).toHaveLength(sent);
    expect(offerOf(bound).current.step).toBe('recovery_codes');
  });

  it('binds nothing once the password is more than 5 minutes old', async () => {
    const built = build(passwordOnly());
    const ctx = context(built);
    const offered = await signInWithPassword(built, ctx);
    built.clock.advance(PASSKEY_BINDING_MAX_AUTH_AGE_MS + MINUTE);
    const done = await built.engine.advance(
      kept(offered),
      answer('webauthn_create', {
        webauthn_response: fakeRegistration('credential-new', paramsOf(offered, 'webauthn_create')),
      }),
      ctx
    );
    expect(done).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd'] } });
    expect(built.passkeys.passkeys.has('credential-new')).toBe(false);
  });

  it('refuses a registration without user verification, with a new ceremony', async () => {
    const built = build(passwordOnly());
    const ctx = context(built);
    const offered = await signInWithPassword(built, ctx);
    const refused = await built.engine.advance(
      kept(offered),
      answer('webauthn_create', {
        webauthn_response: fakeRegistration(
          'credential-new',
          paramsOf(offered, 'webauthn_create'),
          {
            userVerified: false,
          }
        ),
      }),
      ctx
    );
    expect(offerOf(refused).current).toMatchObject({
      step: 'webauthn_create',
      error: 'invalid_credentials',
    });
    expect(paramsOf(refused, 'webauthn_create')).not.toEqual(paramsOf(offered, 'webauthn_create'));
  });

  it('is not offered where the first set cannot be shown, nor to a passkey sign-in', async () => {
    const fipa = build(passwordOnly());
    const result = await signInWithPassword(fipa, context(fipa, { serves: FIPA_SERVES }));
    expect(result).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd'] } });
    const built = build();
    await built.codes
      .replace({ realmId: REALM, userId: USER })
      .then((set) => built.codes.confirm({ realmId: REALM, userId: USER, setId: set.setId }));
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    expect(await built.engine.advance(kept(first), assertion(first), ctx)).toMatchObject({
      kind: 'complete',
    });
    expect(built.passkeys.calls).not.toContain('startRegistration');
  });

  it('ends the transaction when the account was disabled before the binding', async () => {
    const built = build(passwordOnly());
    built.passkeys.bindRefusal = 'account_disabled';
    const ctx = context(built);
    const offered = await signInWithPassword(built, ctx);
    const ended = await built.engine.advance(
      kept(offered),
      answer('webauthn_create', {
        webauthn_response: fakeRegistration('credential-new', paramsOf(offered, 'webauthn_create')),
      }),
      ctx
    );
    expect(ended).toEqual({ kind: 'refused', reason: 'transaction_ended', transaction: null });
  });
});

describe('the held ceremony', () => {
  it('is part of the stored transaction, and a malformed one ends it', async () => {
    const built = build();
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const stored = JSON.parse(JSON.stringify(kept(first))) as Record<string, unknown>;
    expect(readSignInTransaction(stored)?.ceremony).toMatchObject({
      step: 'webauthn_get',
      startedAt: T0,
    });
    const broken = { ...stored, ceremony: { ...(stored['ceremony'] as object), key: 'short' } };
    expect(readSignInTransaction(broken)).toBeNull();
    // A registration ceremony before any factor is no state the engine writes.
    const early = {
      ...stored,
      ceremony: { ...(stored['ceremony'] as object), step: 'webauthn_create' },
    };
    expect(readSignInTransaction(early)).toBeNull();
  });
});

describe('the passkey the person asked for (#844)', () => {
  /** A passkey account whose first set of recovery codes is saved. */
  const withSavedSet = async (built: Built) => {
    const set = await built.codes.replace({ realmId: REALM, userId: USER });
    await built.codes.confirm({ realmId: REALM, userId: USER, setId: set.setId });
  };

  it('adds a second passkey after the downgrade rule, with no mailed code and no new set', async () => {
    const built = build();
    await withSavedSet(built);
    const ctx = context(built, { enrol: 'passkey' });
    const afterPassword = await signInWithPassword(built, ctx);
    // The strongest bound factor first: the passkey the account holds.
    expect(offerOf(afterPassword).current.step).toBe('webauthn_get');
    const offered = await built.engine.advance(kept(afterPassword), assertion(afterPassword), ctx);
    expect(offered).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'webauthn_create', params: { optional: true } } },
      personal: { user: { name: IDENTIFIER } },
    });
    const sent = built.sender.sent.length;
    const done = await built.engine.advance(
      kept(offered),
      answer('webauthn_create', {
        webauthn_response: fakeRegistration('credential-new', paramsOf(offered, 'webauthn_create')),
      }),
      ctx
    );
    expect(built.passkeys.passkeys.get('credential-new')).toMatchObject({ userId: USER });
    expect(built.sender.sent).toHaveLength(sent);
    expect(done).toMatchObject({
      kind: 'complete',
      signIn: { subject: USER, amr: ['pwd', 'pop', 'mfa'] },
    });
  });

  it('is not offered without the request to an account that holds a passkey', async () => {
    const built = build();
    await withSavedSet(built);
    const ctx = context(built);
    const afterPassword = await signInWithPassword(built, ctx);
    const done = await built.engine.advance(kept(afterPassword), assertion(afterPassword), ctx);
    expect(done).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd', 'pop', 'mfa'] } });
    expect(built.passkeys.calls).not.toContain('startRegistration');
  });

  it('may be declined: the sign-in completes and nothing is bound', async () => {
    const built = build();
    await withSavedSet(built);
    const ctx = context(built, { enrol: 'passkey' });
    const afterPassword = await signInWithPassword(built, ctx);
    const offered = await built.engine.advance(kept(afterPassword), assertion(afterPassword), ctx);
    const declined = await built.engine.advance(kept(offered), answer('webauthn_create', {}), ctx);
    expect(declined).toMatchObject({ kind: 'complete' });
    expect([...built.passkeys.passkeys.keys()]).toEqual([PASSKEY, OTHER_PASSKEY]);
  });

  it('binds it to a verified password-only account with no mailed code, as the offer does', async () => {
    const built = build(passwordAccount(USER, PASSWORD));
    const ctx = context(built, { enrol: 'passkey' });
    const offered = await signInWithPassword(built, ctx);
    const registered = await built.engine.advance(
      kept(offered),
      answer('webauthn_create', {
        webauthn_response: fakeRegistration('credential-new', paramsOf(offered, 'webauthn_create')),
      }),
      ctx
    );
    expect(built.passkeys.passkeys.get('credential-new')).toMatchObject({ userId: USER });
    expect(built.sender.sent).toEqual([]);
    expect(registered).not.toMatchObject({ offer: { current: { step: 'email_code' } } });
  });
});
