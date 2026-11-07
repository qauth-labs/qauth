import {
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
import {
  createMemoryPasskeys,
  fakeAssertion,
  fakeRegistration,
  MEMORY_PASSKEY_ACCOUNT_NAME,
} from '../testing/memory-passkeys';
import { createMemoryRecoveryCodes, memoryLookupDigest } from '../testing/memory-recovery-codes';
import {
  createSignInEngine,
  PASSKEY_BINDING_MAX_AUTH_AGE_MS,
  REGISTRATION_NOT_ALLOWED,
  type SignInEngineDependencies,
} from './engine';
import type { Clock } from './ports';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import { readSignInTransaction, type SignInTransaction } from './transaction';

/**
 * Accounts whose primary identity is a passkey, with no address (#655;
 * ADR-017 Decision 8, question 30; `graphs/flows/core/passkey-sign-up`):
 * registration by passkey on the hosted pages, its mandatory recovery codes,
 * and the recovery of a lost passkey with a code typed before any first
 * factor.
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'notes-web';
const PASSKEY_USER = '0199fa20-5e1a-7000-8000-000000000003';
const PASSWORD_USER = '0199fa20-5e1a-7000-8000-000000000001';
const PASSWORD = 'correct horse battery staple';
const ADDRESS = 'alice@example.com';
const OLD_PASSKEY = 'credential-lost';
const NEW_PASSKEY = 'credential-new';
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

/** A passkey-only account: no address, no password, one passkey. */
const passkeyOnly = (userId = PASSKEY_USER): FakeAccount => ({
  userId,
  enabled: true,
  verified: true,
  admin: false,
  password: null,
  others: [{ type: 'passkey', disabled: false }],
});

function build(options: Partial<SignInEngineDependencies> = {}) {
  const clock = manualClock();
  const directory = new FakeDirectory(
    new Map([
      [`passkey:${PASSKEY_USER}`, passkeyOnly()],
      [ADDRESS, passwordAccount(PASSWORD_USER, PASSWORD)],
    ])
  );
  const passkeys = createMemoryPasskeys([
    { id: OLD_PASSKEY, userId: PASSKEY_USER, disabled: false },
  ]);
  // A bound passkey shows in the account the directory reads.
  passkeys.onBind = (passkey) => {
    const key = `passkey:${passkey.userId}`;
    const current = directory.accounts.get(key);
    if (current === undefined) return;
    directory.accounts.set(key, {
      ...current,
      others: [...current.others, { type: 'passkey', disabled: false }],
    });
  };
  // Only an account with no address and passkeys alone is found by a code.
  const codes = createMemoryRecoveryCodes(clock.now, {
    findable: ({ userId }) =>
      [...directory.accounts.values()].some(
        (account) => account.userId === userId && account.password === null
      ),
  });
  const registrations = new FakeRegistrations(directory);
  registrations.passkeys = passkeys;
  const ladder = createMemoryLadder(() => clock.now());
  const engine = createSignInEngine({
    accounts: directory,
    passwords: new FakePasswords(),
    policy: new FakePolicy(),
    identifierDigest: fakeIdentifierDigest,
    requireVerifiedAccount: true,
    emailCodes: { digest: fakeEmailCodeDigest, addresses: new FakeAddresses(directory) },
    passwordUpdates: new FakePasswordUpdates(directory),
    breachCheck: new FakeBreachList(new Set()),
    registrations,
    recoveryCodes: codes,
    passkeys,
    hooks: { ladder },
    clock,
    ...options,
  });
  return { engine, directory, passkeys, codes, registrations, clock, sender: new FakeCodeSender() };
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
    serves: HOSTED,
    ...overrides,
  };
}
const registering = (built: Built, overrides: Partial<RoundContext> = {}) =>
  context(built, { flow: 'register', ...overrides });

function answer(step: StepName, fields: Record<string, unknown>): RoundAnswer {
  return { step: STEP_URNS[step], fields };
}

/** The transaction a result keeps, through its stored form; fails the test when it keeps none. */
function kept(result: RoundResult): SignInTransaction {
  if (result.transaction === null) throw new Error(`${result.kind} kept no transaction`);
  const read = readSignInTransaction(JSON.parse(JSON.stringify(result.transaction)));
  if (read === null) throw new Error('the kept transaction does not read back');
  return read;
}

function offerOf(result: RoundResult): StepOffer {
  if (result.kind !== 'step') throw new Error(`a ${result.kind}, not a step`);
  return result.offer;
}

function paramsOf(result: RoundResult, step: StepName): unknown {
  const offer = offerOf(result);
  const offered = [offer.current, ...offer.alternatives].find((entry) => entry.step === step);
  if (offered === undefined) throw new Error(`${step} was not offered`);
  return offered.params;
}

const creation = (result: RoundResult, credential = NEW_PASSKEY, userVerified = true) =>
  answer('webauthn_create', {
    webauthn_response: fakeRegistration(credential, paramsOf(result, 'webauthn_create'), {
      userVerified,
    }),
  });

const assertion = (result: RoundResult, credential = NEW_PASSKEY) =>
  answer('webauthn_get', {
    webauthn_response: fakeAssertion(credential, paramsOf(result, 'webauthn_get')),
  });

const confirmation = answer('recovery_codes', { acknowledged: true });

/** The codes a `recovery_codes` step showed. */
function shownCodes(result: RoundResult): readonly string[] {
  if (result.kind !== 'step' || result.offer.current.step !== 'recovery_codes') {
    throw new Error('no set shown');
  }
  return (result.personal as { codes: readonly string[] }).codes;
}

/** A set for the passkey-only account, as its registration issued it, confirmed. */
async function seededCodes(built: Built): Promise<readonly string[]> {
  const set = await built.codes.replace({ realmId: REALM, userId: PASSKEY_USER });
  await built.codes.confirm({ realmId: REALM, userId: PASSKEY_USER, setId: set.setId });
  return set.codes;
}

describe('a registration by passkey', () => {
  it('offers a passkey first, preferred, with the address beside it and no account named', async () => {
    const built = build();
    const result = await built.engine.advance(null, null, registering(built));
    expect(result).toMatchObject({
      kind: 'step',
      offer: {
        current: { step: 'webauthn_create', params: { optional: false } },
        alternatives: [{ step: 'identifier' }],
        required: false,
      },
      personal: {
        user: { name: MEMORY_PASSKEY_ACCOUNT_NAME, displayName: MEMORY_PASSKEY_ACCOUNT_NAME },
        excludeCredentials: [],
      },
    });
    expect(result.kind === 'step' && 'identifier' in result.personal).toBe(false);
    const transaction = kept(result);
    expect(transaction.ceremony?.step).toBe('webauthn_create');
    expect(transaction.subject).toBeUndefined();
    expect(built.directory.reads).toEqual([]);
  });

  it('creates the account from the ceremony, with no address, and shows its codes before it completes', async () => {
    const built = build();
    const ctx = registering(built);
    const first = await built.engine.advance(null, null, ctx);
    const created = await built.engine.advance(kept(first), creation(first), ctx);

    expect(built.registrations.createdWithPasskey).toEqual([
      expect.objectContaining({ realmId: REALM, clientId: CLIENT, credentialId: NEW_PASSKEY }),
    ]);
    const userId = built.registrations.createdWithPasskey[0]?.userId;
    expect(built.registrations.created).toEqual([]);
    // The codes are owed before anything completes: no code is minted yet.
    expect(created).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'recovery_codes', params: { count: 10 } } },
    });
    expect(shownCodes(created)).toHaveLength(10);
    const transaction = kept(created);
    expect(transaction).toMatchObject({ subject: userId, flow: 'register' });
    expect(transaction.identifier).toBeUndefined();
    expect(transaction.authTime).toBeUndefined();
    expect(transaction.verified.map((step) => step.step)).toEqual(['webauthn_create']);
    expect(ctx.records).toContainEqual(
      expect.objectContaining({ outcome: 'passed', step: 'webauthn_create', userId })
    );
    // Nothing was mailed: the account has no address.
    expect(built.sender.sent).toEqual([]);

    const done = await built.engine.advance(transaction, confirmation, ctx);
    expect(done).toEqual({
      kind: 'complete',
      transaction: null,
      signIn: { subject: userId, registered: true },
    });
    expect(await built.codes.status({ realmId: REALM, userId: userId ?? '' })).toEqual({
      issued: true,
      unused: 10,
      confirmed: true,
    });
  });

  it('shows a new set, and completes nothing, while the codes are not confirmed', async () => {
    const built = build();
    const ctx = registering(built);
    const first = await built.engine.advance(null, null, ctx);
    const created = await built.engine.advance(kept(first), creation(first), ctx);
    const again = await built.engine.advance(kept(created), null, ctx);
    expect(offerOf(again).current.step).toBe('recovery_codes');
    expect(shownCodes(again)).not.toEqual(shownCodes(created));
    const done = await built.engine.advance(kept(again), confirmation, ctx);
    expect(done.kind).toBe('complete');
  });

  it('makes the codes findable by the code alone', async () => {
    const built = build();
    const ctx = registering(built);
    const first = await built.engine.advance(null, null, ctx);
    const created = await built.engine.advance(kept(first), creation(first), ctx);
    const userId = built.registrations.createdWithPasskey[0]?.userId;
    const [code] = shownCodes(created);
    expect(await built.codes.findAccount?.({ realmId: REALM, code: code ?? '' })).toEqual({
      userId,
    });
    expect(built.codes.store.rows.every((row) => row.lookupDigest !== null)).toBe(true);
  });

  it('refuses a registration without user verification, and creates nothing', async () => {
    const built = build();
    const ctx = registering(built);
    const first = await built.engine.advance(null, null, ctx);
    const refused = await built.engine.advance(
      kept(first),
      creation(first, NEW_PASSKEY, false),
      ctx
    );
    expect(refused).toMatchObject({
      kind: 'step',
      offer: {
        current: { step: 'webauthn_create', error: 'invalid_credentials' },
        alternatives: [{ step: 'identifier' }],
        required: false,
      },
    });
    // A new ceremony: the refused one was taken.
    expect(paramsOf(refused, 'webauthn_create')).not.toEqual(paramsOf(first, 'webauthn_create'));
    expect(built.registrations.createdWithPasskey).toEqual([]);
    expect(kept(refused).subject).toBeUndefined();
    expect(ctx.records).toContainEqual(
      expect.objectContaining({
        outcome: 'refused',
        step: 'webauthn_create',
        reason: 'invalid_credentials',
      })
    );
  });

  it('ends the transaction when the realm holds the credential by then', async () => {
    const built = build();
    const ctx = registering(built);
    const first = await built.engine.advance(null, null, ctx);
    const ended = await built.engine.advance(kept(first), creation(first, OLD_PASSKEY), ctx);
    expect(ended).toMatchObject({ kind: 'refused', reason: 'transaction_ended' });
    expect(built.registrations.createdWithPasskey).toEqual([]);
    expect(ctx.records).toContainEqual(
      expect.objectContaining({ step: 'webauthn_create', reason: 'registration_conflict' })
    );
  });

  it('is gated by the realm and the client, as a password registration is', async () => {
    const built = build();
    built.registrations.allows = false;
    const ctx = registering(built);
    const result = await built.engine.advance(null, null, ctx);
    expect(result).toMatchObject({
      kind: 'refused',
      reason: 'request_refused',
      code: REGISTRATION_NOT_ALLOWED,
    });
    expect(built.passkeys.calls).toEqual([]);
    // A gate closed after round 0 refuses the ceremony's answer too.
    built.registrations.allows = true;
    const first = await built.engine.advance(null, null, ctx);
    built.registrations.allows = false;
    const refused = await built.engine.advance(kept(first), creation(first), ctx);
    expect(refused).toMatchObject({ kind: 'refused', code: REGISTRATION_NOT_ALLOWED });
    expect(built.registrations.createdWithPasskey).toEqual([]);
  });

  it('asks for the address alone on a transport that cannot show the codes, or with no passkeys', async () => {
    for (const [built, serves] of [
      [build(), HOSTED.filter((step) => step !== 'recovery_codes')],
      [build(), HOSTED.filter((step) => step !== 'webauthn_create')],
      [build({ passkeys: undefined }), HOSTED],
    ] as const) {
      const result = await built.engine.advance(null, null, registering(built, { serves }));
      expect(offerOf(result)).toEqual({
        current: { step: 'identifier', params: {} },
        alternatives: [],
      });
      expect(built.passkeys.calls).toEqual([]);
    }
  });

  it('goes on with the address registration when the person gives an address instead', async () => {
    const built = build();
    const ctx = registering(built);
    const first = await built.engine.advance(null, null, ctx);
    const coded = await built.engine.advance(
      kept(first),
      answer('identifier', { login_hint: 'bob@example.com' }),
      ctx
    );
    expect(offerOf(coded).current.step).toBe('email_code');
    expect(built.sender.sent).toHaveLength(1);
    // The passkey's ceremony went with the address: the next round reads the
    // transaction back and goes on to the new password.
    expect(kept(coded).ceremony).toBeUndefined();
    const proved = await built.engine.advance(
      kept(coded),
      answer('email_code', { otp: built.sender.last }),
      ctx
    );
    expect(offerOf(proved).current.step).toBe('new_password');
  });

  it('signs in with the passkey later, and owes no new codes', async () => {
    const built = build();
    const ctx = registering(built);
    const first = await built.engine.advance(null, null, ctx);
    const created = await built.engine.advance(kept(first), creation(first), ctx);
    await built.engine.advance(kept(created), confirmation, ctx);
    const userId = built.registrations.createdWithPasskey[0]?.userId;

    const signIn = context(built);
    const offered = await built.engine.advance(null, null, signIn);
    const done = await built.engine.advance(kept(offered), assertion(offered), signIn);
    expect(done).toMatchObject({
      kind: 'complete',
      signIn: { subject: userId, amr: ['pop', 'mfa'] },
    });
    expect(done.kind === 'complete' && 'identifier' in done.signIn).toBe(false);
  });
});

describe('a recovery code before any first factor', () => {
  it('finds the passkey-only account, and binds a new passkey before the sign-in completes', async () => {
    const built = build();
    const [code] = await seededCodes(built);
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    expect(offerOf(first).alternatives.map((step) => step.step)).toContain('recovery_code');

    const rebind = await built.engine.advance(
      kept(first),
      answer('recovery_code', { recovery_code: code }),
      ctx
    );
    expect(rebind).toMatchObject({
      kind: 'step',
      offer: {
        current: { step: 'webauthn_create', params: { optional: false } },
        alternatives: [],
      },
      personal: { excludeCredentials: [{ id: OLD_PASSKEY }] },
    });
    const recovering = kept(rebind);
    expect(recovering).toMatchObject({ subject: PASSKEY_USER });
    expect(recovering.identifier).toBeUndefined();
    expect(built.codes.usedNotices).toEqual([{ realmId: REALM, userId: PASSKEY_USER }]);
    expect((await built.codes.status({ realmId: REALM, userId: PASSKEY_USER })).unused).toBe(9);

    const proof = await built.engine.advance(recovering, creation(rebind), ctx);
    expect(built.passkeys.passkeys.get(NEW_PASSKEY)).toMatchObject({
      userId: PASSKEY_USER,
      disabled: false,
    });
    // In place of the lost one: the account's other passkeys are disabled.
    expect(built.passkeys.calls).toContain('bind replacing');
    expect(built.passkeys.passkeys.get(OLD_PASSKEY)).toMatchObject({ disabled: true });
    expect(proof).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'webauthn_get' }, alternatives: [] },
    });

    built.clock.advance(60_000);
    const redeemedAt = recovering.authTime ?? 0;
    const done = await built.engine.advance(kept(proof), assertion(proof), ctx);
    expect(done).toMatchObject({
      kind: 'complete',
      signIn: { subject: PASSKEY_USER, amr: ['pop', 'mfa'] },
    });
    // auth_time is the assertion's, never the code's.
    expect(done.kind === 'complete' && (done.signIn.authTime ?? 0) > redeemedAt + 60_000).toBe(
      true
    );
    // No new set: the account keeps its other codes.
    expect((await built.codes.status({ realmId: REALM, userId: PASSKEY_USER })).unused).toBe(9);
    // No mailbox was proved and nothing was mailed.
    expect(built.sender.sent).toEqual([]);
  });

  it('refuses a wrong code the same way, and names nobody', async () => {
    const built = build();
    await seededCodes(built);
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const refused = await built.engine.advance(
      kept(first),
      answer('recovery_code', { recovery_code: 'aaaa-bbbb-cccc-dddd' }),
      ctx
    );
    expect(refused).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'recovery_code', error: 'invalid_credentials' } },
    });
    expect(kept(refused).subject).toBeUndefined();
    expect(ctx.records).toContainEqual({
      outcome: 'refused',
      step: 'recovery_code',
      reason: 'invalid_credentials',
    });
  });

  it('finds no account that holds an address, whatever its codes', async () => {
    const built = build();
    const set = await built.codes.replace({ realmId: REALM, userId: PASSWORD_USER });
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const refused = await built.engine.advance(
      kept(first),
      answer('recovery_code', { recovery_code: set.codes[0] }),
      ctx
    );
    expect(offerOf(refused).current).toMatchObject({
      step: 'recovery_code',
      error: 'invalid_credentials',
    });
    expect(built.codes.usedNotices).toEqual([]);
  });

  it('refuses a code whose account gained an address since its set was issued', async () => {
    const built = build();
    const [code] = await seededCodes(built);
    built.directory.accounts.set(`passkey:${PASSKEY_USER}`, {
      ...passkeyOnly(),
      password: passwordAccount(PASSKEY_USER, PASSWORD).password,
    });
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const refused = await built.engine.advance(
      kept(first),
      answer('recovery_code', { recovery_code: code }),
      ctx
    );
    expect(offerOf(refused).current).toMatchObject({ error: 'invalid_credentials' });
    expect(built.codes.usedNotices).toEqual([]);
  });

  it('ends the transaction when the new passkey comes more than 5 minutes after the code', async () => {
    const built = build();
    const [code] = await seededCodes(built);
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const rebind = await built.engine.advance(
      kept(first),
      answer('recovery_code', { recovery_code: code }),
      ctx
    );
    built.clock.advance(PASSKEY_BINDING_MAX_AUTH_AGE_MS + 1);
    const ended = await built.engine.advance(kept(rebind), creation(rebind), ctx);
    expect(ended).toMatchObject({ kind: 'refused', reason: 'transaction_ended' });
    expect(built.passkeys.passkeys.has(NEW_PASSKEY)).toBe(false);
    expect(ctx.records).toContainEqual(
      expect.objectContaining({ step: 'webauthn_create', reason: 'authentication_stale' })
    );
  });

  it("completes only with the account's own passkey", async () => {
    const built = build();
    const [code] = await seededCodes(built);
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const rebind = await built.engine.advance(
      kept(first),
      answer('recovery_code', { recovery_code: code }),
      ctx
    );
    const proof = await built.engine.advance(kept(rebind), creation(rebind), ctx);
    // Another account's passkey ends the transaction.
    built.passkeys.passkeys.set('credential-other', {
      id: 'credential-other',
      userId: PASSWORD_USER,
      disabled: false,
    });
    const ended = await built.engine.advance(
      kept(proof),
      assertion(proof, 'credential-other'),
      ctx
    );
    expect(ended).toMatchObject({ kind: 'refused', reason: 'transaction_ended' });
  });

  it('is never offered where the transport serves no recovery code, nor without a lookup', async () => {
    const fipa = build();
    const offered = await fipa.engine.advance(
      null,
      null,
      context(fipa, { serves: FIPA_STEP_NAMES })
    );
    expect(offerOf(offered).alternatives.map((step) => step.step)).not.toContain('recovery_code');

    const noLookup = build({
      recoveryCodes: createMemoryRecoveryCodes(Date.now, { noLookup: true }),
    });
    const plain = await noLookup.engine.advance(null, null, context(noLookup));
    expect(offerOf(plain).alternatives.map((step) => step.step)).not.toContain('recovery_code');
  });

  it("looks a code up by the realm's digest alone", async () => {
    const built = build();
    const [code] = await seededCodes(built);
    const normalized = (code ?? '').replaceAll('-', '');
    expect(
      built.codes.store.rows.some(
        (row) => row.lookupDigest === memoryLookupDigest(REALM, normalized)
      )
    ).toBe(true);
    expect(
      await built.codes.findAccount?.({
        realmId: '0199fa20-0000-7000-8000-00000000bbbb',
        code: code ?? '',
      })
    ).toBeNull();
  });
});
