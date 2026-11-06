import { STEP_URNS, type StepName } from '@qauth-labs/server-step-grammar';
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
import { createMemoryRecoveryCodes } from '../testing/memory-recovery-codes';
import { createMemoryTotp } from '../testing/memory-totp';
import { createProofOfWorkProvider } from './bot-challenge';
import { createSignInEngine, type SignInEngineDependencies } from './engine';
import type { Clock, SignInAccount, UpstreamProviderEntry } from './ports';
import type {
  RoundAnswer,
  RoundContext,
  RoundResult,
  UpstreamProof,
  UpstreamStarter,
} from './round';
import { createCaptchaStep } from './steps/captcha';
import type { AnyStepHandler } from './steps/handler';
import type { SignInTransaction } from './transaction';

/**
 * The `upstream` step (#639): the realm's upstream identity providers
 * offered beside the identifier step, a pick or the request's routing
 * parameter sending the browser to one, and its callback proving the
 * account, which ranks with the password (ADR-017 Decision 4, decided
 * 2026-10-23 in #810) before rule 8 goes on as after any first factor.
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'web-app';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const ADDRESS = 'alice@example.com';
const T0 = 1_800_000_000_000;
const CORP: UpstreamProviderEntry = { provider: 'oidc_corp', name: 'Example Corp' };
const PARTNER: UpstreamProviderEntry = { provider: 'oidc_partner', name: 'Partner SSO' };
const HIDDEN: UpstreamProviderEntry = { provider: 'oidc_staff', name: 'Example Corp Staff' };
const PROVIDER_URL = 'https://idp.example.com/authorize?state=s';
const PASSKEY_PARAMS = {
  challenge: 'C'.repeat(43),
  rpId: 'auth.example.com',
  userVerification: 'required',
};
const WEBAUTHN_RESPONSE = JSON.stringify({
  id: 'credential',
  rawId: 'credential',
  type: 'public-key',
  response: { clientDataJSON: 'e30', authenticatorData: 'AAAA', signature: 'AAAA' },
  clientExtensionResults: {},
});

function manualClock(start = T0): Clock {
  let now = start;
  return {
    now: () => now,
    sleep: async (ms) => {
      now += ms;
    },
  };
}

/** An account an upstream provider created: no password, verified unless said otherwise. */
function upstreamAccount(overrides: Partial<FakeAccount> = {}): FakeAccount {
  return {
    userId: USER,
    enabled: true,
    verified: true,
    admin: false,
    password: null,
    others: [],
    ...overrides,
  };
}

/** A passkey handler that proves `userId`, discoverable, as #651's will be. */
function fakePasskey(userId: string): AnyStepHandler {
  const handler = {
    step: 'webauthn_get',
    role: 'first_factor',
    factor: 'passkey',
    discoverable: true,
    usableBy: (account: SignInAccount) =>
      account.factors.some((bound) => bound.type === 'passkey' && !bound.disabled),
    params: () => PASSKEY_PARAMS,
    personal: () => ({}),
    verify: async () => ({
      kind: 'proved' as const,
      account: { userId, enabled: true, verified: true },
    }),
  };
  return handler as unknown as AnyStepHandler;
}

interface Built {
  readonly engine: ReturnType<typeof createSignInEngine>;
  readonly directory: FakeDirectory;
  readonly addresses: FakeAddresses;
  readonly policy: FakePolicy;
  readonly sender: FakeCodeSender;
  readonly offered: ReturnType<typeof vi.fn>;
}

function build(
  account: FakeAccount = upstreamAccount(),
  options: Partial<SignInEngineDependencies> & {
    readonly providers?: readonly UpstreamProviderEntry[];
  } = {}
): Built {
  const directory = new FakeDirectory(new Map([[`upstream:${USER}`, account]]));
  const addresses = new FakeAddresses(directory);
  const policy = new FakePolicy();
  const { providers = [CORP, PARTNER], ...rest } = options;
  const offered = vi.fn(async () => providers);
  const engine = createSignInEngine({
    accounts: directory,
    passwords: new FakePasswords(),
    policy,
    identifierDigest: fakeIdentifierDigest,
    requireVerifiedAccount: true,
    emailCodes: { digest: fakeEmailCodeDigest, addresses },
    upstream: { offered },
    clock: manualClock(),
    ...rest,
  });
  return { engine, directory, addresses, policy, sender: new FakeCodeSender(), offered };
}

type Ctx = RoundContext & {
  readonly records: ReturnType<typeof recordingAudit>['records'];
  readonly started: UpstreamProviderEntry[];
};

function context(
  built: Built,
  overrides: Partial<RoundContext> = {},
  outcome: Awaited<ReturnType<UpstreamStarter>> = { kind: 'started', redirectTo: PROVIDER_URL }
): Ctx {
  const audit = recordingAudit();
  const started: UpstreamProviderEntry[] = [];
  return {
    realm: { id: REALM },
    client: { id: CLIENT },
    audit: audit.sink,
    records: audit.records,
    sendCode: built.sender.send,
    startUpstream: async (provider) => {
      started.push(provider);
      return outcome;
    },
    started,
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

/** Round 0, then the pick of `provider`: the transaction the callback completes. */
async function picked(built: Built, ctx: Ctx, provider = CORP): Promise<SignInTransaction> {
  const first = await built.engine.advance(null, null, ctx);
  const pick = await built.engine.advance(
    kept(first),
    answer('upstream', { provider: provider.provider }),
    ctx
  );
  expect(pick.kind).toBe('upstream');
  return kept(pick);
}

const proof = (overrides: Partial<UpstreamProof> = {}): UpstreamProof => ({
  provider: CORP,
  account: { userId: USER, enabled: true, verified: true },
  address: ADDRESS,
  ...overrides,
});

describe('the upstream step offered (#639)', () => {
  it('lists the realm’s providers beside the identifier step, nobody named yet', async () => {
    const built = build();
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    expect(first).toMatchObject({
      kind: 'step',
      offer: {
        current: { step: 'identifier' },
        alternatives: [{ step: 'upstream', params: { providers: [CORP, PARTNER] } }],
      },
    });
    expect(built.offered).toHaveBeenCalledWith({ realmId: REALM, clientId: CLIENT });
    expect(ctx.started).toEqual([]);
  });

  it('is not offered without a starter, a provider, or a transport that serves it', async () => {
    const cases: [Built, Partial<RoundContext>][] = [
      [build(), { startUpstream: undefined }],
      [build(undefined, { providers: [] }), {}],
      [build(), { serves: ['identifier', 'password'] }],
    ];
    for (const [built, overrides] of cases) {
      const first = await built.engine.advance(null, null, context(built, overrides));
      expect(first).toMatchObject({
        kind: 'step',
        offer: { current: { step: 'identifier' }, alternatives: [] },
      });
    }
  });

  it('is not offered once an identifier names somebody', async () => {
    const built = build(passwordAccount(USER, 'correct horse battery staple'));
    const ctx = context(built, { loginHint: ADDRESS });
    const first = await built.engine.advance(null, null, ctx);
    expect(first).toMatchObject({ kind: 'step', offer: { current: { step: 'password' } } });
    expect(JSON.stringify(first)).not.toContain('upstream');
  });

  it('leaves out and reports a provider outside the step’s schema', async () => {
    const reported: string[] = [];
    const built = build(undefined, {
      providers: [{ provider: 'Not A Type', name: 'Bad' }, CORP] as UpstreamProviderEntry[],
      onUnavailable: (error) => reported.push(error.port),
    });
    const first = await built.engine.advance(null, null, context(built));
    expect(first).toMatchObject({
      kind: 'step',
      offer: { alternatives: [{ step: 'upstream', params: { providers: [CORP] } }] },
    });
    expect(reported).toEqual(['upstream']);
  });

  it('lists at most sixteen providers', async () => {
    const many = Array.from({ length: 20 }, (_, index) => ({
      provider: `oidc_p${index}`,
      name: `Provider ${index}`,
    }));
    const built = build(undefined, { providers: many });
    const first = await built.engine.advance(null, null, context(built));
    if (first.kind !== 'step') throw new Error('not a step');
    expect(first.offer.alternatives[0]?.params).toEqual({ providers: many.slice(0, 16) });
  });

  it('refuses a directory that answers no list as a store fault', async () => {
    const built = build(undefined, { providers: 'nope' as unknown as UpstreamProviderEntry[] });
    const first = await built.engine.advance(null, null, context(built));
    expect(first).toMatchObject({ kind: 'refused', reason: 'unavailable' });
  });
});

describe('picking an upstream provider (#639)', () => {
  it('starts the provider picked and keeps which one may complete the step', async () => {
    const built = build();
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const pick = await built.engine.advance(
      kept(first),
      answer('upstream', { provider: 'oidc_partner' }),
      ctx
    );
    expect(pick).toMatchObject({
      kind: 'upstream',
      provider: 'oidc_partner',
      redirectTo: PROVIDER_URL,
      offer: { current: { step: 'identifier' } },
    });
    expect(kept(pick).upstream).toEqual({ provider: 'oidc_partner' });
    expect(kept(pick).subject).toBeUndefined();
    expect(ctx.started).toEqual([PARTNER]);
  });

  it('refuses a provider the step did not list, starting none', async () => {
    const built = build();
    const ctx = context(built);
    const first = await built.engine.advance(null, null, ctx);
    const pick = await built.engine.advance(
      kept(first),
      answer('upstream', { provider: 'oidc_staff' }),
      ctx
    );
    expect(pick).toMatchObject({ kind: 'refused', reason: 'invalid_answer' });
    expect(ctx.started).toEqual([]);
    expect(ctx.records).toContainEqual({
      outcome: 'refused',
      step: 'upstream',
      reason: 'invalid_answer',
    });
  });

  it('offers the step again with provider_unavailable when the provider cannot start', async () => {
    const built = build();
    const ctx = context(built, {}, { kind: 'unavailable' });
    const first = await built.engine.advance(null, null, ctx);
    const pick = await built.engine.advance(
      kept(first),
      answer('upstream', { provider: 'oidc_corp' }),
      ctx
    );
    expect(pick).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'upstream', error: 'provider_unavailable' } },
    });
    expect(kept(pick).upstream).toBeUndefined();
    expect(ctx.records).toContainEqual({
      outcome: 'refused',
      step: 'upstream',
      reason: 'provider_unavailable',
    });
  });

  it('starts the routed provider at round 0, a hidden one included, and never later', async () => {
    const built = build();
    const ctx = context(built, { upstreamRoute: HIDDEN });
    const routed = await built.engine.advance(null, null, ctx);
    expect(routed).toMatchObject({
      kind: 'upstream',
      provider: 'oidc_staff',
      // The way back lists only the providers the realm shows.
      offer: {
        current: { step: 'identifier' },
        alternatives: [{ step: 'upstream', params: { providers: [CORP, PARTNER] } }],
      },
    });
    expect(kept(routed).upstream).toEqual({ provider: 'oidc_staff' });

    const later = await built.engine.advance(kept(routed), null, ctx);
    expect(later).toMatchObject({ kind: 'step', offer: { current: { step: 'identifier' } } });
    expect(ctx.started).toEqual([HIDDEN]);
  });
});

describe('the upstream provider’s callback (#639)', () => {
  it('completes an account without a passkey through the provider alone, with no amr', async () => {
    const built = build();
    const ctx = context(built);
    const done = await built.engine.completeUpstream(await picked(built, ctx), proof(), ctx);
    expect(done).toMatchObject({
      kind: 'complete',
      signIn: { subject: USER, amr: [] },
    });
    if (done.kind !== 'complete') throw new Error('not complete');
    expect(done.signIn.identifier).toBeUndefined();
    expect(ctx.records).toContainEqual({ outcome: 'passed', step: 'upstream', userId: USER });
  });

  it('completes the callback when a bot challenge came due after the pick: the proof is not thrown away (#643)', async () => {
    let due = false;
    const built = build(upstreamAccount(), {
      steps: [createCaptchaStep(createProofOfWorkProvider({ difficulty: () => 4 }))],
      hooks: { botChallenge: async () => ({ kind: due ? 'due' : 'not_due' }) },
    });
    const ctx = context(built);
    const transaction = await picked(built, ctx);
    const other = await picked(built, ctx);
    due = true;
    const done = await built.engine.completeUpstream(transaction, proof(), ctx);
    expect(done).toMatchObject({ kind: 'complete', signIn: { subject: USER } });
    // A round that carries no proof meets the challenge as any other.
    expect(await built.engine.advance(other, null, ctx)).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'captcha' } },
    });
  });

  it('asks an account with a passkey for it, MFA off: upstream ranks below a passkey', async () => {
    const account = upstreamAccount({ others: [{ type: 'passkey', disabled: false }] });
    const built = build(account, { steps: [fakePasskey(USER)] });
    const ctx = context(built);
    const next = await built.engine.completeUpstream(await picked(built, ctx), proof(), ctx);
    expect(next).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'webauthn_get' }, alternatives: [] },
    });
    expect(kept(next).subject).toBe(USER);
    const done = await built.engine.advance(
      kept(next),
      answer('webauthn_get', { webauthn_response: WEBAUTHN_RESPONSE }),
      ctx
    );
    expect(done).toMatchObject({ kind: 'complete', signIn: { subject: USER } });
  });

  it('never completes a passkey account the transport cannot ask for its passkey', async () => {
    const account = upstreamAccount({ others: [{ type: 'passkey', disabled: true }] });
    const built = build(account);
    const ctx = context(built);
    const next = await built.engine.completeUpstream(await picked(built, ctx), proof(), ctx);
    expect(next).toMatchObject({ kind: 'redirect', reason: 'step_not_available' });
  });

  it('applies the MFA policy as after any first factor', async () => {
    const built = build();
    built.policy.policy = { realm: 'required', client: 'off' };
    const ctx = context(built);
    const next = await built.engine.completeUpstream(await picked(built, ctx), proof(), ctx);
    // No second factor is bound and none can be set up here: the sign-in cannot complete.
    expect(next.kind).not.toBe('complete');
  });

  it('draws no TOTP secret for an upstream sign-in under an MFA policy (#653)', async () => {
    const clock = manualClock();
    const totp = createMemoryTotp(clock);
    const built = build(upstreamAccount(), {
      clock,
      totp,
      recoveryCodes: createMemoryRecoveryCodes(clock.now),
    });
    built.policy.policy = { realm: 'required', client: 'off' };
    const ctx = context(built);
    const next = await built.engine.completeUpstream(await picked(built, ctx), proof(), ctx);
    // The set-up proves a password first (ADR-017 Decision 8): an account
    // with no password is sent on, and binds nothing it could not use.
    expect(next).toMatchObject({ kind: 'redirect', reason: 'step_not_available' });
    expect(totp.sealed).toEqual([]);
    expect(totp.rows.size).toBe(0);
  });

  it.each([
    ['another provider', proof({ provider: PARTNER })],
    ['a provider outside the step’s list', proof({ provider: HIDDEN })],
  ])('refuses the proof of %s, naming nobody', async (_name, other) => {
    const built = build();
    const ctx = context(built);
    const transaction = await picked(built, ctx);
    const refused = await built.engine.completeUpstream(transaction, other, ctx);
    expect(refused).toMatchObject({ kind: 'refused', reason: 'invalid_answer' });
    expect(kept(refused).subject).toBeUndefined();
    expect(ctx.records).toContainEqual({
      outcome: 'refused',
      step: 'upstream',
      reason: 'invalid_answer',
    });
  });

  it('refuses a proof no pick sent, or one already taken', async () => {
    const built = build();
    const ctx = context(built);
    expect(await built.engine.completeUpstream(null, proof(), ctx)).toMatchObject({
      kind: 'refused',
      reason: 'invalid_answer',
    });
    const first = await built.engine.advance(null, null, ctx);
    expect(await built.engine.completeUpstream(kept(first), proof(), ctx)).toMatchObject({
      kind: 'refused',
      reason: 'invalid_answer',
    });
    const done = await built.engine.completeUpstream(await picked(built, ctx), proof(), ctx);
    expect(done.kind).toBe('complete');
  });

  it('refuses a disabled account', async () => {
    const built = build();
    const ctx = context(built);
    const refused = await built.engine.completeUpstream(
      await picked(built, ctx),
      proof({ account: { userId: USER, enabled: false, verified: true } }),
      ctx
    );
    expect(refused).toMatchObject({ kind: 'refused', reason: 'invalid_answer' });
    expect(ctx.records).toContainEqual({
      outcome: 'refused',
      step: 'upstream',
      reason: 'account_disabled',
    });
  });

  it('verifies the address of an account the provider did not vouch for, inline', async () => {
    const built = build(upstreamAccount({ verified: false }));
    const ctx = context(built);
    const next = await built.engine.completeUpstream(
      await picked(built, ctx),
      proof({ account: { userId: USER, enabled: true, verified: false } }),
      ctx
    );
    expect(next).toMatchObject({
      kind: 'step',
      offer: { current: { step: 'email_code', params: { purpose: 'verify_account' } } },
      personal: { identifier: ADDRESS },
    });
    expect(built.sender.sent).toMatchObject([{ address: ADDRESS }]);
    const done = await built.engine.advance(
      kept(next),
      answer('email_code', { otp: built.sender.last }),
      ctx
    );
    expect(done).toMatchObject({ kind: 'complete', signIn: { subject: USER } });
    expect(built.addresses.calls).toEqual([
      { realmId: REALM, userId: USER, identifier: ADDRESS, upstream: 'oidc_corp' },
    ]);
  });

  it('cannot verify an account the provider gave no address for', async () => {
    const built = build(upstreamAccount({ verified: false }));
    const ctx = context(built);
    const next = await built.engine.completeUpstream(
      await picked(built, ctx),
      proof({ account: { userId: USER, enabled: true, verified: false }, address: undefined }),
      ctx
    );
    expect(next).toMatchObject({ kind: 'redirect', reason: 'step_not_available' });
    expect(built.sender.sent).toEqual([]);
  });
});
