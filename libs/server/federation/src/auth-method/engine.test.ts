import { describe, expect, it, vi } from 'vitest';

import {
  createSampleAuthMethod,
  SAMPLE_CONFIG,
  sampleProviderEgress,
} from '../../testing/sample-auth-method.fixture';
import type { AuthMethod, AuthMethodContext } from './auth-method.interface';
import { createAuthMethodContext } from './context';
import { MAX_UPSTREAM_TRANSACTION_BYTES } from './contract';
import { completeUpstreamStep, startUpstreamStep, upstreamBindingMatches } from './engine';
import { AuthMethodFaultError } from './errors';

const log = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };

/** A binding: 22 base64url characters and more. */
const BINDING = 'b1nd1ng-0f-th1s-st4rt_xyz';

function contextOf<TConfig>(method: AuthMethod<TConfig>): AuthMethodContext<TConfig> {
  return createAuthMethodContext(method, {
    config: SAMPLE_CONFIG,
    origin: 'https://auth.example.com',
    realmName: 'acme',
    realmId: '0190a5c4-0000-7000-8000-000000000001',
    providerId: method.type,
    signerCaller: 'api',
    egress: { request: async (request) => sampleProviderEgress(request) },
    signer: {
      signClientAssertion: async () => 'a.b.c',
      getUpstreamJwks: async () => ({ keys: [] }),
    },
    log,
  });
}

/** The sample method with `start` or `verify`/`extractAttributes` replaced. */
function withMembers(members: Partial<Record<'start' | 'verify' | 'extractAttributes', unknown>>) {
  return { ...createSampleAuthMethod(), ...members } as unknown as AuthMethod;
}

describe('startUpstreamStep', () => {
  it("answers the method's redirect and a frozen copy of its transaction", async () => {
    const method = createSampleAuthMethod();
    const start = await startUpstreamStep(method, contextOf(method), { uiLocales: [] });

    const url = new URL(start.redirectTo);
    expect(url.origin + url.pathname).toBe(SAMPLE_CONFIG.authorizationEndpoint);
    expect(url.searchParams.get('redirect_uri')).toBe(
      'https://auth.example.com/upstream/oidc_sample/callback'
    );
    expect(url.searchParams.get('state')).toBe((start.transaction as { state: string }).state);
    expect(start.binding).toBe(url.searchParams.get('state'));
    expect(Object.isFrozen(start)).toBe(true);
    expect(Object.isFrozen(start.transaction)).toBe(true);
  });

  it('answers the redirect as parsed, so what is sent is what was checked', async () => {
    const method = withMembers({
      start: async () => ({
        redirectTo: ' https://provider.example/authorize?q=a b\n',
        transaction: {},
        binding: BINDING,
      }),
    });
    const start = await startUpstreamStep(method, contextOf(method), { uiLocales: [] });
    expect(start.redirectTo).toBe('https://provider.example/authorize?q=a%20b');
  });

  it.each([
    ['http://provider.example/authorize', 'a redirect that is not https'],
    ['https://user:pass@provider.example/authorize', 'a redirect with credentials'],
    ['https://provider.example/authorize#state=x', 'a redirect with a fragment'],
    ['/authorize', 'a redirect that is not an absolute URL'],
    ['javascript:alert(1)', 'a redirect that is not https'],
    [`https://provider.example/?q=${'a'.repeat(8192)}`, 'a redirect longer than 8192 characters'],
    [42, 'a redirect that is not a string'],
  ])('refuses the redirect %j', async (redirectTo, problem) => {
    const method = withMembers({ start: async () => ({ redirectTo, transaction: {} }) });
    await expect(startUpstreamStep(method, contextOf(method), { uiLocales: [] })).rejects.toThrow(
      new AuthMethodFaultError('oidc_sample', `start() answered ${problem}`)
    );
  });

  it.each([
    ['a Date', { at: new Date() }],
    ['a function', { f: () => 1 }],
    ['a class instance', { map: new Map() }],
    ['NaN', { n: Number.NaN }],
    ['undefined', undefined],
    ['null', null],
    ['a string', 'state-value'],
    ['a list', ['state-value']],
    ['a symbol key', { [Symbol('k')]: 1 }],
    ['a nesting deeper than 16', JSON.parse('['.repeat(20) + ']'.repeat(20))],
    ['more than the cap', { state: 'x'.repeat(MAX_UPSTREAM_TRANSACTION_BYTES) }],
  ])('refuses a transaction holding %s', async (_label, transaction) => {
    const method = withMembers({
      start: async () => ({ redirectTo: 'https://provider.example/authorize', transaction }),
    });
    await expect(startUpstreamStep(method, contextOf(method), { uiLocales: [] })).rejects.toThrow(
      AuthMethodFaultError
    );
  });

  it('checks the cap again on the redirect as parsed, which percent-encodes', async () => {
    const method = withMembers({
      start: async () => ({
        redirectTo: `https://provider.example/?q=${'é'.repeat(4000)}`,
        transaction: {},
      }),
    });
    await expect(startUpstreamStep(method, contextOf(method), { uiLocales: [] })).rejects.toThrow(
      'start() answered a redirect longer than 8192 characters'
    );
  });

  it.each([
    ['missing', undefined],
    ['not a string', 42],
    ['shorter than 22 characters', 'x'.repeat(21)],
    ['longer than 512 characters', 'x'.repeat(513)],
    ['outside base64url', `${'x'.repeat(21)}+`],
  ])('refuses a binding that is %s', async (_label, binding) => {
    const method = withMembers({
      start: async () => ({
        redirectTo: 'https://provider.example/authorize',
        transaction: {},
        binding,
      }),
    });
    await expect(startUpstreamStep(method, contextOf(method), { uiLocales: [] })).rejects.toThrow(
      'start() answered a binding that is not 22 to 512 base64url characters'
    );
  });

  it("lets start()'s own rejection through unchanged", async () => {
    const failure = new Error('discovery failed');
    const method = withMembers({ start: async () => Promise.reject(failure) });
    await expect(startUpstreamStep(method, contextOf(method), { uiLocales: [] })).rejects.toBe(
      failure
    );
  });
});

describe('upstreamBindingMatches', () => {
  it('matches only the same binding, as one string', () => {
    expect(upstreamBindingMatches(BINDING, BINDING)).toBe(true);
    for (const presented of [undefined, '', BINDING.toUpperCase(), `${BINDING}x`, [BINDING]]) {
      expect(upstreamBindingMatches(BINDING, presented)).toBe(false);
    }
    // An expected value that is no binding never matches, not even itself.
    expect(upstreamBindingMatches('', '')).toBe(false);
    expect(upstreamBindingMatches('short', 'short')).toBe(false);
  });
});

describe('completeUpstreamStep', () => {
  /** Run the sample's callback for a fresh start, and hand its outcome on. */
  async function signedIn(method = createSampleAuthMethod()) {
    const context = contextOf(method);
    const start = await startUpstreamStep(method, context, { uiLocales: [] });
    const state = new URL(start.redirectTo).searchParams.get('state') ?? '';
    const route = method.routes.find((r) => r.kind === 'callback');
    if (route?.kind !== 'callback') throw new Error('no callback route');
    return route.handle(
      {
        method: 'GET',
        query: { code: 'code-for-person', state },
        form: {},
        transaction: start.transaction,
      },
      context
    );
  }

  it('turns a result into a checked identity and its attributes', async () => {
    const method = createSampleAuthMethod();
    const completion = await completeUpstreamStep(method, await signedIn(method));

    expect(completion).toEqual({
      kind: 'identity',
      identity: {
        externalSub: 'person',
        assuranceLevel: 'low',
        rawClaims: { sub: 'person', email: 'person@example.com', email_verified: true },
      },
      attributes: [
        {
          source: 'oidc_sample',
          attrKey: 'email',
          attrValue: 'person@example.com',
          verified: true,
        },
      ],
    });
    expect(Object.isFrozen(completion)).toBe(true);
    const identity = (completion as { identity: { rawClaims: object } }).identity;
    expect(Object.isFrozen(identity.rawClaims)).toBe(true);
  });

  it('keeps tab and line breaks in an attribute value, as a postal address holds them', async () => {
    const method = createSampleAuthMethod();
    const extract = method.extractAttributes.bind(method);
    const lenient = withMembers({
      verify: method.verify.bind(method),
      extractAttributes: (identity: Parameters<typeof extract>[0]) =>
        extract(identity).map((attribute) => ({ ...attribute, attrValue: 'Street 1\r\n\tCity' })),
    });
    await expect(completeUpstreamStep(lenient, await signedIn(method))).resolves.toMatchObject({
      kind: 'identity',
    });
  });

  it('passes declined and failed outcomes through', async () => {
    const method = createSampleAuthMethod();
    await expect(completeUpstreamStep(method, { kind: 'declined' })).resolves.toEqual({
      kind: 'declined',
    });
    await expect(
      completeUpstreamStep(method, { kind: 'failed', reason: 'transaction_mismatch' })
    ).resolves.toEqual({ kind: 'failed', reason: 'transaction_mismatch' });
  });

  it.each([
    ['nothing', undefined],
    ['an unknown kind', { kind: 'signed_in', identity: {} }],
    ['a reason outside the closed set', { kind: 'failed', reason: 'because' }],
    ['a result kind with no result', { kind: 'result' }],
  ])('treats %s as a fault of the method', async (_label, outcome) => {
    await expect(completeUpstreamStep(createSampleAuthMethod(), outcome)).rejects.toThrow(
      AuthMethodFaultError
    );
  });

  it('ends a step whose outcome is a fault the route mount caught with that fault', async () => {
    const method = createSampleAuthMethod();
    const own = new AuthMethodFaultError('oidc_sample', 'the callback route threw', {
      cause: new Error('boom'),
    });
    await expect(completeUpstreamStep(method, own)).rejects.toBe(own);
    // A fault naming another method is still a fault, of this one.
    const other = new AuthMethodFaultError('oidc_other', 'the callback route threw');
    await expect(completeUpstreamStep(method, other)).rejects.toThrow(
      'AuthMethod oidc_sample: the callback answered a fault of another method'
    );
  });

  it('ends as verification_refused when verify() rejects, keeping the cause for the log', async () => {
    const method = createSampleAuthMethod();
    // A result the callback never produced: the sample's verify() refuses it.
    const completion = await completeUpstreamStep(method, {
      kind: 'result',
      result: { sub: 'forged', email: 'x@example.com', emailVerified: true },
    });
    expect(completion).toMatchObject({ kind: 'failed', reason: 'verification_refused' });
    expect((completion as { cause?: unknown }).cause).toBeInstanceOf(Error);
  });

  it.each([
    ['an empty externalSub', { externalSub: '', assuranceLevel: 'low', rawClaims: {} }],
    ['a long externalSub', { externalSub: 's'.repeat(256), assuranceLevel: 'low', rawClaims: {} }],
    ['a control character', { externalSub: 'a\u0000b', assuranceLevel: 'low', rawClaims: {} }],
    ['an unknown level', { externalSub: 's', assuranceLevel: 'maximal', rawClaims: {} }],
    ['claims that are a list', { externalSub: 's', assuranceLevel: 'low', rawClaims: [] }],
    [
      'claims holding a function',
      { externalSub: 's', assuranceLevel: 'low', rawClaims: { f: () => 1 } },
    ],
    [
      'claims holding a BigInt',
      { externalSub: 's', assuranceLevel: 'low', rawClaims: { n: BigInt(1) } },
    ],
    [
      'claims over the cap',
      { externalSub: 's', assuranceLevel: 'low', rawClaims: { big: 'x'.repeat(64 * 1024) } },
    ],
    ['no object', 'person'],
  ])('refuses an identity with %s', async (_label, identity) => {
    const method = withMembers({ verify: async () => identity });
    await expect(completeUpstreamStep(method, { kind: 'result', result: {} })).rejects.toThrow(
      AuthMethodFaultError
    );
  });

  it.each([
    ['another source, one that outranks every other', { source: 'wallet' }],
    ['the self_reported source', { source: 'self_reported' }],
    ['a key outside its pattern', { attrKey: 'Email' }],
    ['a value that is not a string', { attrValue: 1 }],
    ['a long value', { attrValue: 'v'.repeat(8193) }],
    ['a NUL in its value', { attrValue: `a${String.fromCharCode(0)}b` }],
    ['an escape in its value', { attrValue: `a${String.fromCharCode(0x1b)}[31m` }],
    ['a verified flag that is not a boolean', { verified: 'yes' }],
    ['an invalid expiry', { expiresAt: new Date(Number.NaN) }],
  ])('refuses an attribute with %s', async (_label, change) => {
    const method = createSampleAuthMethod();
    const extract = method.extractAttributes.bind(method);
    const broken = withMembers({
      verify: method.verify.bind(method),
      extractAttributes: (identity: Parameters<typeof extract>[0]) =>
        extract(identity).map((attribute) => ({ ...attribute, ...change })),
    });
    await expect(completeUpstreamStep(broken, await signedIn(method))).rejects.toThrow(
      AuthMethodFaultError
    );
  });

  it('builds the checked list itself, so a species cannot add unchecked attributes', async () => {
    const method = createSampleAuthMethod();
    const smuggled = {
      source: 'wallet',
      attrKey: 'email',
      attrValue: 'x@example.com',
      verified: true,
    };
    // `map` builds its result through `constructor[Symbol.species]` and then
    // writes only the indexes it mapped: a species that hands back a longer
    // list slips its extra members past every check.
    class Smuggling extends Array<unknown> {
      static override get [Symbol.species](): ArrayConstructor {
        return function () {
          return [undefined, smuggled];
        } as unknown as ArrayConstructor;
      }
    }
    const broken = withMembers({
      verify: method.verify.bind(method),
      extractAttributes: () =>
        Smuggling.from([
          { source: 'oidc_sample', attrKey: 'email', attrValue: 'p@example.com', verified: true },
        ]),
    });
    const completion = await completeUpstreamStep(broken, await signedIn(method));
    const attributes = (completion as { attributes: readonly unknown[] }).attributes;
    expect(Object.getPrototypeOf(attributes)).toBe(Array.prototype);
    expect(Object.isFrozen(attributes)).toBe(true);
    expect(attributes).toEqual([
      { source: 'oidc_sample', attrKey: 'email', attrValue: 'p@example.com', verified: true },
    ]);
  });

  it("keeps a copy of an attribute's expiry, never the method's Date", async () => {
    const method = createSampleAuthMethod();
    const expiresAt = new Date('2030-01-01T00:00:00Z');
    const extract = method.extractAttributes.bind(method);
    const dated = withMembers({
      verify: method.verify.bind(method),
      extractAttributes: (identity: Parameters<typeof extract>[0]) =>
        extract(identity).map((attribute) => ({ ...attribute, expiresAt })),
    });
    const completion = await completeUpstreamStep(dated, await signedIn(method));
    const [attribute] = (completion as { attributes: readonly { expiresAt?: Date }[] }).attributes;
    expect(attribute.expiresAt).not.toBe(expiresAt);
    expiresAt.setUTCFullYear(2100);
    expect(attribute.expiresAt?.toISOString()).toBe('2030-01-01T00:00:00.000Z');
  });

  it.each([
    ['an externalSub', { externalSub: 'sub-\uD800', assuranceLevel: 'low', rawClaims: {} }],
    ['an externalSub', { externalSub: '\uDC00-sub', assuranceLevel: 'low', rawClaims: {} }],
  ])(
    'refuses %s with a lone surrogate, which Postgres would store as U+FFFD',
    async (_l, identity) => {
      const method = withMembers({ verify: async () => identity });
      await expect(completeUpstreamStep(method, { kind: 'result', result: {} })).rejects.toThrow(
        AuthMethodFaultError
      );
    }
  );

  it('refuses an attribute value with a lone surrogate, and keeps one with a surrogate pair', async () => {
    const method = createSampleAuthMethod();
    const extract = method.extractAttributes.bind(method);
    const withValue = (attrValue: string) =>
      withMembers({
        verify: method.verify.bind(method),
        extractAttributes: (identity: Parameters<typeof extract>[0]) =>
          extract(identity).map((attribute) => ({ ...attribute, attrValue })),
      });
    await expect(
      completeUpstreamStep(withValue('Name \uD83D'), await signedIn(method))
    ).rejects.toThrow(AuthMethodFaultError);
    await expect(
      completeUpstreamStep(withValue('Name \uD83D\uDE00'), await signedIn(method))
    ).resolves.toMatchObject({ kind: 'identity' });
  });

  describe('the assurance ceiling', () => {
    /** The sample, with verify() resolving `level` for its own results. */
    function claiming(sample: ReturnType<typeof createSampleAuthMethod>, level: string) {
      return withMembers({
        verify: async (input: unknown) => ({
          ...(await sample.verify(input)),
          assuranceLevel: level,
        }),
        extractAttributes: sample.extractAttributes.bind(sample),
      });
    }
    const levelOf = (completion: unknown) =>
      (completion as { identity: { assuranceLevel: string } }).identity.assuranceLevel;

    it('lowers a method that claims high to low when the caller names no ceiling', async () => {
      const sample = createSampleAuthMethod();
      const completion = await completeUpstreamStep(
        claiming(sample, 'high'),
        await signedIn(sample)
      );
      expect(levelOf(completion)).toBe('low');
    });

    it.each([
      ['high', 'substantial', 'substantial'],
      ['high', 'high', 'high'],
      ['substantial', 'high', 'substantial'],
      ['low', 'high', 'low'],
    ] as const)(
      'resolves a claimed %s under the ceiling %s as %s',
      async (claimed, maxAssurance, expected) => {
        const sample = createSampleAuthMethod();
        const completion = await completeUpstreamStep(
          claiming(sample, claimed),
          await signedIn(sample),
          { maxAssurance }
        );
        expect(levelOf(completion)).toBe(expected);
      }
    );

    it('refuses a ceiling that is not an assurance level', async () => {
      await expect(
        completeUpstreamStep(
          createSampleAuthMethod(),
          { kind: 'declined' },
          {
            maxAssurance: 'maximal' as never,
          }
        )
      ).rejects.toThrow(TypeError);
    });
  });

  it('treats a throwing extractAttributes() as a fault', async () => {
    const method = createSampleAuthMethod();
    const broken = withMembers({
      verify: method.verify.bind(method),
      extractAttributes: () => {
        throw new Error('boom');
      },
    });
    await expect(completeUpstreamStep(broken, await signedIn(method))).rejects.toThrow(
      'AuthMethod oidc_sample: extractAttributes() threw'
    );
  });
});
