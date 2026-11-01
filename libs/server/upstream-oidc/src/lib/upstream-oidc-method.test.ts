import { createHash } from 'node:crypto';

import {
  type AuthMethod,
  type AuthMethodBounceRoute,
  type AuthMethodCallbackRoute,
  authMethodParameters,
  completeUpstreamStep,
  startUpstreamStep,
  type UpstreamStart,
} from '@qauth-labs/server-federation';
import { checkAuthMethod } from '@qauth-labs/server-federation/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createFakeProvider,
  type FakeClientAuthentication,
  type FakeProvider,
  type FakeSignIn,
} from '../testing/fake-provider';
import { TEST_ORIGIN, TEST_REALM_ID, type TestHost, testHost } from '../testing/test-host';
import type { UpstreamOidcConfig } from './config';
import {
  createUpstreamOidcMethod,
  UPSTREAM_DISCOVERY_FAILURE_TTL_MS,
  UPSTREAM_OIDC_TYPE_PATTERN,
  upstreamOidcRedirectUri,
  type UpstreamOidcTransaction,
} from './upstream-oidc-method';

/**
 * The generic upstream OIDC client as an AuthMethod (#601), against a fake
 * provider, through the real context adapter (`createAuthMethodContext`) and
 * the real engine checks (`startUpstreamStep`, `completeUpstreamStep`).
 */

const ISSUER = 'https://idp.example.com';
const TYPE = 'oidc_corp';
const CLIENT_ID = 'qauth-client';
const CLIENT_SECRET = 'a-client-secret-of-some-length';
const REDIRECT_URI = `${TEST_ORIGIN}/upstream/${TYPE}/callback`;
const PERSON: FakeSignIn = {
  sub: 'user-1',
  claims: { email: 'ada@example.com', email_verified: true, name: 'Ada' },
  userinfo: { given_name: 'Ada', name: 'Ada from userinfo', email: 'other@example.com' },
};

function configFor(
  method: FakeClientAuthentication,
  overrides: Partial<Record<keyof UpstreamOidcConfig, unknown>> = {},
  issuer = ISSUER
) {
  return {
    issuer,
    clientId: CLIENT_ID,
    clientAuthentication:
      method === 'private_key_jwt' ? { method } : { method, clientSecret: CLIENT_SECRET },
    ...overrides,
  };
}

interface Setup {
  readonly provider: FakeProvider;
  readonly method: AuthMethod<UpstreamOidcConfig, UpstreamOidcTransaction>;
  readonly host: TestHost<UpstreamOidcConfig>;
}

async function setup(
  authentication: FakeClientAuthentication = 'client_secret_basic',
  overrides: Partial<Record<keyof UpstreamOidcConfig, unknown>> = {},
  options: { type?: string; issuer?: string; issParameter?: boolean } = {}
): Promise<Setup> {
  const type = options.type ?? TYPE;
  const issuer = options.issuer ?? ISSUER;
  const provider = await createFakeProvider({
    issuer,
    ...(options.issParameter === undefined ? {} : { issParameter: options.issParameter }),
  });
  const method = createUpstreamOidcMethod({ type, display: { name: 'Example Corp' } });
  const host = await testHost(method, configFor(authentication, overrides, issuer), provider, {
    signerClientId: CLIENT_ID,
  });
  provider.register({
    clientId: CLIENT_ID,
    method: authentication,
    clientSecret: CLIENT_SECRET,
    redirectUris: [`${TEST_ORIGIN}/upstream/${type}/callback`],
    assertionKeys: async () => host.upstreamJwks,
  });
  return { provider, method, host };
}

function callbackRoute(method: AuthMethod): AuthMethodCallbackRoute {
  const route = method.routes.find((r) => r.kind === 'callback' && r.method === 'GET');
  return route as AuthMethodCallbackRoute;
}

function bounceRoute(method: AuthMethod): AuthMethodBounceRoute {
  const route = method.routes.find((r) => r.kind === 'bounce');
  return route as AuthMethodBounceRoute;
}

/** Run the GET callback as the host would, with `transaction` taken. */
function callback(
  { method, host }: Pick<Setup, 'method' | 'host'>,
  query: Record<string, string | readonly string[]>,
  transaction: unknown
) {
  return callbackRoute(method).handle(
    {
      method: 'GET',
      query: authMethodParameters(query),
      form: authMethodParameters(undefined),
      transaction,
    },
    host.context
  );
}

async function signIn(s: Setup, person: FakeSignIn = PERSON) {
  const start = await startUpstreamStep(s.method, { uiLocales: ['en', 'tr-TR'] }, s.host.context);
  const response = s.provider.authorize(new URL(start.redirectTo), person);
  const outcome = await callback(s, response, start.transaction);
  return { start, response, outcome };
}

const s256 = (verifier: string) =>
  createHash('sha256').update(verifier, 'ascii').digest('base64url');

describe('createUpstreamOidcMethod', () => {
  it('takes only an oidc_<alias> type', () => {
    for (const type of ['oidc_corp', 'oidc_x1', 'oidc_corp_eu']) {
      expect(UPSTREAM_OIDC_TYPE_PATTERN.test(type)).toBe(true);
      expect(() => createUpstreamOidcMethod({ type, display: { name: 'x' } })).not.toThrow();
    }
    for (const type of ['oidc_', 'corp', 'oidc_Corp', 'oidc_https://idp', 'oidc:corp', 'oidc_-x']) {
      expect(() => createUpstreamOidcMethod({ type, display: { name: 'x' } })).toThrow(TypeError);
    }
  });

  it('names one callback per provider, under the fixed /upstream/<type> prefix', () => {
    const method = createUpstreamOidcMethod({ type: TYPE, display: { name: 'Example Corp' } });
    expect(method.id).toBe('oidc');
    expect(method.routes.map((route) => `${route.method} ${route.path} ${route.kind}`)).toEqual([
      'GET /callback callback',
      'POST /callback bounce',
    ]);
    expect(upstreamOidcRedirectUri(TEST_ORIGIN, TYPE)).toBe(REDIRECT_URI);
    expect(upstreamOidcRedirectUri(TEST_ORIGIN, 'oidc_other')).not.toBe(REDIRECT_URI);
    expect(() => upstreamOidcRedirectUri(`${TEST_ORIGIN}/x`, TYPE)).toThrow(TypeError);
  });
});

describe('start()', () => {
  it('sends the browser to the authorization endpoint with state, nonce and PKCE S256', async () => {
    const s = await setup();
    const start = await startUpstreamStep(s.method, { uiLocales: ['en', 'x y'] }, s.host.context);
    const url = new URL(start.redirectTo);
    const transaction = start.transaction;

    expect(`${url.origin}${url.pathname}`).toBe(s.provider.authorizationEndpoint);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'openid email profile',
      state: transaction.state,
      nonce: transaction.nonce,
      code_challenge: s256(transaction.codeVerifier),
      code_challenge_method: 'S256',
      ui_locales: 'en',
    });
    expect(start.binding).toBe(transaction.state);
    expect(transaction).toMatchObject({
      v: 1,
      type: TYPE,
      issuer: ISSUER,
      redirectUri: REDIRECT_URI,
    });
    // 32 random bytes each.
    for (const value of [transaction.state, transaction.nonce, transaction.codeVerifier]) {
      expect(value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    }
  });

  it('answers a fresh state, nonce and verifier at every start', async () => {
    const s = await setup();
    const starts: UpstreamStart<UpstreamOidcTransaction>[] = [];
    for (let i = 0; i < 3; i += 1) {
      starts.push(await startUpstreamStep(s.method, { uiLocales: [] }, s.host.context));
    }
    for (const member of ['state', 'nonce', 'codeVerifier'] as const) {
      expect(new Set(starts.map((start) => start.transaction[member])).size).toBe(3);
    }
  });

  it('asks for form_post when the config says so', async () => {
    const s = await setup('client_secret_basic', { responseMode: 'form_post' });
    const start = await startUpstreamStep(s.method, { uiLocales: [] }, s.host.context);
    expect(new URL(start.redirectTo).searchParams.get('response_mode')).toBe('form_post');
  });

  it('keeps the authorization endpoint query and replaces the parameters it sets itself', async () => {
    const s = await setup('client_secret_basic', {
      endpoints: {
        authorization: `${ISSUER}/authorize?tenant=t1&state=stale`,
        token: `${ISSUER}/token`,
        jwks: `${ISSUER}/jwks`,
      },
    });
    const start = await startUpstreamStep(s.method, { uiLocales: [] }, s.host.context);
    const url = new URL(start.redirectTo);
    expect(url.searchParams.get('tenant')).toBe('t1');
    expect(url.searchParams.getAll('state')).toEqual([start.transaction.state]);
  });

  it('rejects when discovery fails, so the engine never sends the browser anywhere', async () => {
    const s = await setup();
    s.provider.tamper.discovery = { issuer: 'https://evil.example.com' };
    await expect(startUpstreamStep(s.method, { uiLocales: [] }, s.host.context)).rejects.toThrow(
      /issuer/
    );
  });

  describe('discovery calls, which anyone who opens the sign-in page causes', () => {
    afterEach(() => {
      vi.useRealTimers();
    });

    const discoveryCalls = (s: Setup) =>
      s.host.egressCalls.filter((call) => call.purpose === 'upstream-discovery').length;

    /** Discovery fails while `down.value` is set: the provider cannot be reached. */
    function withOutage(s: Setup) {
      const down = { value: true };
      const realAnswer = s.provider.answer.bind(s.provider);
      (s.provider as { answer: FakeProvider['answer'] }).answer = async (request) => {
        if (down.value && request.url.endsWith('/.well-known/openid-configuration')) {
          throw new Error('egress failed: connect timeout');
        }
        return realAnswer(request);
      };
      return down;
    }

    const start = (s: Setup) => startUpstreamStep(s.method, { uiLocales: [] }, s.host.context);

    it('shares one call among concurrent starts', async () => {
      const s = await setup();
      await Promise.all([start(s), start(s), start(s), start(s)]);
      expect(discoveryCalls(s)).toBe(1);
    });

    it('shares one failed call among concurrent starts while the provider is down', async () => {
      const s = await setup();
      withOutage(s);
      const outcomes = await Promise.allSettled([start(s), start(s), start(s), start(s)]);
      expect(outcomes.map((outcome) => outcome.status)).toEqual(Array(4).fill('rejected'));
      expect(discoveryCalls(s)).toBe(1);
    });

    it('answers a failed discovery from the cache for 30 seconds, then reads again', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const s = await setup();
      const down = withOutage(s);
      await expect(start(s)).rejects.toMatchObject({ reason: 'upstream_unavailable' });
      expect(UPSTREAM_DISCOVERY_FAILURE_TTL_MS).toBe(30_000);
      vi.setSystemTime(Date.now() + UPSTREAM_DISCOVERY_FAILURE_TTL_MS - 1);
      for (let i = 0; i < 3; i += 1) {
        await expect(start(s)).rejects.toMatchObject({ reason: 'upstream_unavailable' });
      }
      expect(discoveryCalls(s)).toBe(1);

      // The provider is back; the next start after the 30 seconds reads it.
      down.value = false;
      vi.setSystemTime(Date.now() + 2);
      await expect(start(s)).resolves.toMatchObject({ redirectTo: expect.any(String) });
      expect(discoveryCalls(s)).toBe(2);
    });
  });
});

describe('the callback', () => {
  it.each(['client_secret_basic', 'client_secret_post', 'private_key_jwt'] as const)(
    'signs a person in with the code, PKCE and %s',
    async (authentication) => {
      const s = await setup(authentication, { fetchUserinfo: true });
      const { start, outcome } = await signIn(s);
      expect(outcome.kind).toBe('result');

      const completion = await completeUpstreamStep(s.method, outcome);
      expect(completion.kind).toBe('identity');
      if (completion.kind !== 'identity') return;
      expect(completion.identity.externalSub).toBe('user-1');
      expect(completion.identity.assuranceLevel).toBe('low');
      // The ID token's claims win over userinfo's; userinfo fills the rest.
      expect(completion.identity.rawClaims).toMatchObject({
        iss: ISSUER,
        sub: 'user-1',
        aud: CLIENT_ID,
        email: 'ada@example.com',
        name: 'Ada',
        given_name: 'Ada',
      });
      expect(completion.attributes).toEqual([
        { source: TYPE, attrKey: 'email', attrValue: 'ada@example.com', verified: true },
        { source: TYPE, attrKey: 'name', attrValue: 'Ada', verified: false },
        { source: TYPE, attrKey: 'given_name', attrValue: 'Ada', verified: false },
      ]);

      const [form] = s.provider.tokenRequests;
      expect(form.get('grant_type')).toBe('authorization_code');
      expect(form.get('redirect_uri')).toBe(REDIRECT_URI);
      expect(s256(form.get('code_verifier') ?? '')).toBe(
        new URL(start.redirectTo).searchParams.get('code_challenge')
      );
      const tokenCall = s.host.egressCalls.find((call) => call.purpose === 'upstream-token');
      const authorization = tokenCall?.headers?.['authorization'];
      if (authentication === 'client_secret_basic') {
        expect(authorization).toBe(
          `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`
        );
        expect(form.has('client_secret')).toBe(false);
      } else {
        expect(authorization).toBeUndefined();
      }
      if (authentication === 'client_secret_post') {
        expect(form.get('client_secret')).toBe(CLIENT_SECRET);
      }
      if (authentication === 'private_key_jwt') {
        expect(form.get('client_assertion')).toBe(s.host.signedAssertions[0]);
        expect(form.has('client_secret')).toBe(false);
        expect(s.provider.assertions).toHaveLength(1);
      }
    }
  );

  it('has the signer role sign the private_key_jwt assertion; the method never sees a key', async () => {
    const s = await setup('private_key_jwt');
    await signIn(s);
    expect(s.host.signerCalls).toEqual([
      {
        operation: 'signClientAssertion',
        caller: 'api',
        realmId: TEST_REALM_ID,
        providerId: TYPE,
        request: {
          realmId: TEST_REALM_ID,
          providerId: TYPE,
          audience: ISSUER,
          algorithm: 'RS256',
          claims: expect.objectContaining({
            jti: expect.stringMatching(/^[A-Za-z0-9_-]{22}$/),
            exp: expect.any(Number),
            iat: expect.any(Number),
          }),
        },
      },
    ]);
    const claims = s.host.signerCalls[0].request?.['claims'] as Record<string, number>;
    expect(claims['exp'] - claims['iat']).toBe(60);
    // What the method holds: a signer of two operations, and no key material.
    expect(Object.keys(s.host.context.signer).sort()).toEqual([
      'getUpstreamJwks',
      'signClientAssertion',
    ]);
    expect(JSON.stringify(s.host.context.config)).not.toMatch(/"d"|PRIVATE KEY|privateKey/);
    // The provider verified the assertion with the signer's public key alone.
    expect(s.provider.assertions[0]).toMatchObject({ iss: CLIENT_ID, sub: CLIENT_ID, aud: ISSUER });
  });

  it('asks the signer role for the configured assertion algorithm', async () => {
    const s = await setup('private_key_jwt', {
      clientAuthentication: { method: 'private_key_jwt', signingAlgorithm: 'ES256' },
    });
    const { outcome } = await signIn(s);
    expect(outcome.kind).toBe('result');
    expect(s.host.signerCalls).toHaveLength(1);
    // The request the signer received, not the JWT header: the test signer
    // signs with its own key whatever it is asked.
    expect(s.host.signerCalls[0].request?.['algorithm']).toBe('ES256');
  });

  it('asks the egress client to follow no redirect on every call', async () => {
    const s = await setup('client_secret_post', { fetchUserinfo: true });
    await signIn(s);
    expect(s.host.egressCalls.map((call) => call.purpose)).toEqual([
      'upstream-discovery',
      'upstream-token',
      'upstream-jwks',
      'upstream-userinfo',
    ]);
    for (const call of s.host.egressCalls) {
      expect(call.limits).toEqual({ maxRedirects: 0 });
      expect(call.realm).toBe('acme');
    }
  });

  it('sends every discovered URL as remote_document, which the allowlist never opens', async () => {
    const s = await setup('client_secret_post', { fetchUserinfo: true });
    await signIn(s);
    const sources = Object.fromEntries(s.host.egressCalls.map((c) => [c.purpose, c.source]));
    expect(sources).toEqual({
      'upstream-discovery': 'admin',
      'upstream-token': 'remote_document',
      'upstream-jwks': 'remote_document',
      'upstream-userinfo': 'remote_document',
    });
  });

  it('sends endpoints set by hand as admin, and reads no discovery document', async () => {
    const s = await setup('client_secret_post', {
      fetchUserinfo: true,
      endpoints: {
        authorization: `${ISSUER}/authorize`,
        token: `${ISSUER}/token`,
        jwks: `${ISSUER}/jwks`,
        userinfo: `${ISSUER}/userinfo`,
        issParameterSupported: true,
      },
    });
    const { outcome } = await signIn(s);
    expect(outcome.kind).toBe('result');
    expect(s.host.egressCalls.map((call) => [call.purpose, call.source])).toEqual([
      ['upstream-token', 'admin'],
      ['upstream-jwks', 'admin'],
      ['upstream-userinfo', 'admin'],
    ]);
  });

  it('ends as declined when the person declines at the provider', async () => {
    const s = await setup();
    const start = await startUpstreamStep(s.method, { uiLocales: [] }, s.host.context);
    const outcome = await callback(
      s,
      { error: 'access_denied', state: start.transaction.state, iss: ISSUER },
      start.transaction
    );
    expect(outcome).toEqual({ kind: 'declined' });
    expect(s.provider.tokenRequests).toHaveLength(0);
  });

  it.each([
    ['another provider error', { error: 'server_error' }, 'provider_error'],
    ['no code', {}, 'invalid_response'],
    ['a repeated code', { code: ['a', 'b'] }, 'invalid_response'],
    ['a code the provider never issued', { code: 'forged' }, 'provider_error'],
  ] as const)('ends as failed for %s', async (_name, extra, reason) => {
    const s = await setup();
    const start = await startUpstreamStep(s.method, { uiLocales: [] }, s.host.context);
    const outcome = await callback(
      s,
      { state: start.transaction.state, iss: ISSUER, ...extra },
      start.transaction
    );
    expect(outcome).toEqual({ kind: 'failed', reason });
  });

  it('refuses a state that is not the transaction’s, before it spends the code', async () => {
    const s = await setup();
    const start = await startUpstreamStep(s.method, { uiLocales: [] }, s.host.context);
    const response = s.provider.authorize(new URL(start.redirectTo), PERSON);
    const outcome = await callback(s, { ...response, state: 'A'.repeat(43) }, start.transaction);
    expect(outcome).toEqual({ kind: 'failed', reason: 'transaction_mismatch' });
    expect(s.provider.tokenRequests).toHaveLength(0);
  });

  it('reads one sign-in as one result: a second callback with the same code fails', async () => {
    const s = await setup();
    const { start, response, outcome } = await signIn(s);
    expect(outcome.kind).toBe('result');
    const again = await callback(s, response, start.transaction);
    expect(again).toEqual({ kind: 'failed', reason: 'provider_error' });
  });

  it('logs a refusal with its reason, never the code, the token or the secret', async () => {
    const s = await setup('client_secret_post');
    s.provider.tamper.idTokenClaims = { nonce: 'not-the-nonce' };
    const { response, outcome } = await signIn(s);
    expect(outcome).toEqual({ kind: 'failed', reason: 'invalid_response' });
    const lines = JSON.stringify(s.host.logLines);
    expect(lines).toContain('nonce');
    expect(lines).not.toContain(response['code'] as string);
    expect(lines).not.toContain(CLIENT_SECRET);
    expect(s.host.logLines).toEqual([
      expect.objectContaining({
        level: 'warn',
        fields: {
          authMethod: expect.objectContaining({ provider: TYPE, reason: 'invalid_response' }),
        },
      }),
    ]);
  });

  describe('userinfo', () => {
    it('refuses a userinfo answer for another sub', async () => {
      const s = await setup('client_secret_basic', { fetchUserinfo: true });
      const realAnswer = s.provider.answer.bind(s.provider);
      (s.provider as { answer: FakeProvider['answer'] }).answer = async (request) => {
        const answer = await realAnswer(request);
        if (!request.url.endsWith('/userinfo')) return answer;
        return { ...answer, body: Buffer.from(JSON.stringify({ sub: 'someone-else' })) };
      };
      const { outcome } = await signIn(s);
      expect(outcome).toEqual({ kind: 'failed', reason: 'invalid_response' });
    });

    it('takes a value and its verified flag from the same source', async () => {
      const s = await setup('client_secret_basic', { fetchUserinfo: true });
      // The ID token's email is unverified; userinfo vouches for another one.
      const { outcome } = await signIn(s, {
        sub: 'user-1',
        claims: { email: 'ada@example.com', phone_number: '+90 555 000 0000' },
        userinfo: {
          email: 'other@example.com',
          email_verified: true,
          phone_number_verified: true,
        },
      });
      const completion = await completeUpstreamStep(s.method, outcome);
      if (completion.kind !== 'identity') throw new Error(completion.kind);
      expect(completion.identity.rawClaims).not.toHaveProperty('email_verified');
      expect(completion.identity.rawClaims).not.toHaveProperty('phone_number_verified');
      expect(completion.attributes).toEqual(
        expect.arrayContaining([
          { source: TYPE, attrKey: 'email', attrValue: 'ada@example.com', verified: false },
          { source: TYPE, attrKey: 'phone_number', attrValue: '+90 555 000 0000', verified: false },
        ])
      );
    });

    it('takes both from userinfo when the ID token carries no such value', async () => {
      const s = await setup('client_secret_basic', { fetchUserinfo: true });
      const { outcome } = await signIn(s, {
        sub: 'user-1',
        claims: { email_verified: false },
        userinfo: { email: 'ada@example.com', email_verified: true },
      });
      const completion = await completeUpstreamStep(s.method, outcome);
      if (completion.kind !== 'identity') throw new Error(completion.kind);
      expect(completion.attributes).toContainEqual({
        source: TYPE,
        attrKey: 'email',
        attrValue: 'ada@example.com',
        verified: true,
      });
    });

    it('takes the protocol claims from the ID token alone, never from userinfo', async () => {
      const s = await setup('client_secret_basic', { fetchUserinfo: true });
      // The ID token carries no acr, amr, auth_time or sid; userinfo,
      // unsigned, offers them and every other ID-token-only claim.
      const offered = {
        iss: 'https://evil.example.com',
        aud: 'another-client',
        azp: 'another-client',
        exp: 4102444800,
        iat: 1,
        nbf: 1,
        jti: 'from-userinfo',
        nonce: 'from-userinfo',
        at_hash: 'from-userinfo',
        c_hash: 'from-userinfo',
        s_hash: 'from-userinfo',
        acr: 'urn:example:loa:high',
        amr: ['hwk', 'mfa'],
        auth_time: 1,
        sid: 'from-userinfo',
        cnf: { jkt: 'from-userinfo' },
      };
      const { outcome } = await signIn(s, {
        sub: 'user-1',
        claims: { name: 'Ada' },
        userinfo: { ...offered, given_name: 'Ada' },
      });
      const completion = await completeUpstreamStep(s.method, outcome);
      if (completion.kind !== 'identity') throw new Error(completion.kind);
      const claims = completion.identity.rawClaims;
      for (const name of ['acr', 'amr', 'auth_time', 'sid', 'azp', 'nbf', 'jti', 'cnf']) {
        expect(claims, name).not.toHaveProperty(name);
      }
      for (const name of ['at_hash', 'c_hash', 's_hash']) {
        expect(claims, name).not.toHaveProperty(name);
      }
      // The ID token's own, checked values stay.
      expect(claims).toMatchObject({ iss: ISSUER, sub: 'user-1', aud: CLIENT_ID, name: 'Ada' });
      expect(claims['nonce']).not.toBe('from-userinfo');
      expect(claims['exp']).not.toBe(offered.exp);
      expect(claims['iat']).not.toBe(offered.iat);
      // A profile claim from userinfo is still taken.
      expect(claims['given_name']).toBe('Ada');
    });

    it('is not read unless the config asks for it', async () => {
      const s = await setup();
      const { outcome } = await signIn(s);
      expect(outcome.kind).toBe('result');
      expect(s.host.egressCalls.map((call) => call.purpose)).not.toContain('upstream-userinfo');
    });
  });
});

describe('the iss response parameter (RFC 9207)', () => {
  it('refuses a response that names another issuer', async () => {
    const s = await setup();
    const start = await startUpstreamStep(s.method, { uiLocales: [] }, s.host.context);
    const response = s.provider.authorize(new URL(start.redirectTo), PERSON);
    const outcome = await callback(
      s,
      { ...response, iss: 'https://other.example.com' },
      start.transaction
    );
    expect(outcome).toEqual({ kind: 'failed', reason: 'invalid_response' });
    expect(s.provider.tokenRequests).toHaveLength(0);
  });

  it('refuses a response without iss from a provider that says it sends one', async () => {
    const s = await setup();
    const start = await startUpstreamStep(s.method, { uiLocales: [] }, s.host.context);
    const withoutIss = { ...s.provider.authorize(new URL(start.redirectTo), PERSON) };
    delete withoutIss['iss'];
    expect(await callback(s, withoutIss, start.transaction)).toEqual({
      kind: 'failed',
      reason: 'invalid_response',
    });
  });

  it('takes a response without iss from a provider that does not send one', async () => {
    const s = await setup('client_secret_basic', {}, { issParameter: false });
    const { response, outcome } = await signIn(s);
    expect(response).not.toHaveProperty('iss');
    expect(outcome.kind).toBe('result');
  });
});

describe('mix-up defence: a response for provider A at provider B’s callback', () => {
  async function twoProviders() {
    const a = await setup(
      'client_secret_basic',
      {},
      { type: 'oidc_a', issuer: 'https://a.example.com' }
    );
    const b = await setup(
      'client_secret_basic',
      {},
      { type: 'oidc_b', issuer: 'https://b.example.com' }
    );
    return { a, b };
  }

  it('is refused with A’s transaction: B holds no transaction of A’s', async () => {
    const { a, b } = await twoProviders();
    const start = await startUpstreamStep(a.method, { uiLocales: [] }, a.host.context);
    const response = a.provider.authorize(new URL(start.redirectTo), PERSON);
    // As if the host had handed B's handler what A started.
    const outcome = await callback(b, response, start.transaction);
    expect(outcome).toEqual({ kind: 'failed', reason: 'transaction_mismatch' });
    expect(a.provider.tokenRequests).toHaveLength(0);
    expect(b.provider.tokenRequests).toHaveLength(0);
  });

  it('is refused when A and B are two aliases of one issuer', async () => {
    const a = await setup('client_secret_basic', {}, { type: 'oidc_a' });
    const b = await setup('client_secret_basic', {}, { type: 'oidc_b' });
    const start = await startUpstreamStep(a.method, { uiLocales: [] }, a.host.context);
    const response = a.provider.authorize(new URL(start.redirectTo), PERSON);
    expect(await callback(b, response, start.transaction)).toEqual({
      kind: 'failed',
      reason: 'transaction_mismatch',
    });
    // The provider and the callback both name A; either refuses it on its own.
    expect(
      await callback(b, response, {
        ...start.transaction,
        redirectUri: b.host.context.routeUrl('/callback'),
      })
    ).toEqual({ kind: 'failed', reason: 'transaction_mismatch' });
    expect(b.provider.tokenRequests).toHaveLength(0);
  });

  it('is refused with B’s own transaction when the response names A as its issuer', async () => {
    const { a, b } = await twoProviders();
    const startA = await startUpstreamStep(a.method, { uiLocales: [] }, a.host.context);
    const startB = await startUpstreamStep(b.method, { uiLocales: [] }, b.host.context);
    const response = a.provider.authorize(new URL(startA.redirectTo), PERSON);
    const outcome = await callback(
      b,
      { ...response, state: startB.transaction.state },
      startB.transaction
    );
    expect(outcome).toEqual({ kind: 'failed', reason: 'invalid_response' });
    expect(a.provider.tokenRequests).toHaveLength(0);
    expect(b.provider.tokenRequests).toHaveLength(0);
  });

  it('never sends A’s code to A: B redeems it at its own token endpoint, which refuses it', async () => {
    const a = await setup(
      'client_secret_basic',
      {},
      { type: 'oidc_a', issuer: 'https://a.example.com', issParameter: false }
    );
    const b = await setup(
      'client_secret_basic',
      {},
      { type: 'oidc_b', issuer: 'https://b.example.com', issParameter: false }
    );
    const startA = await startUpstreamStep(a.method, { uiLocales: [] }, a.host.context);
    const startB = await startUpstreamStep(b.method, { uiLocales: [] }, b.host.context);
    const response = a.provider.authorize(new URL(startA.redirectTo), PERSON);
    const outcome = await callback(
      b,
      { ...response, state: startB.transaction.state },
      startB.transaction
    );
    expect(outcome).toEqual({ kind: 'failed', reason: 'provider_error' });
    expect(a.provider.tokenRequests).toHaveLength(0);
    expect(b.provider.tokenRequests).toHaveLength(1);
  });
});

describe('form_post', () => {
  it('bounces the provider’s POST to the GET callback with the response’s own parameters', async () => {
    const method = createUpstreamOidcMethod({ type: TYPE, display: { name: 'Example Corp' } });
    const bounce = await bounceRoute(method).handle({
      method: 'POST',
      query: authMethodParameters(undefined),
      form: authMethodParameters({
        code: 'the-code',
        state: 's'.repeat(43),
        iss: ISSUER,
        error_description: 'kept',
        repeated: 'dropped',
        extra: 'dropped',
      }),
    });
    expect(bounce).toEqual({
      to: '/callback',
      query: { code: 'the-code', state: 's'.repeat(43), iss: ISSUER, error_description: 'kept' },
    });
  });

  it('carries a repeated response parameter on as an empty value, so the GET callback refuses it', async () => {
    const method = createUpstreamOidcMethod({ type: TYPE, display: { name: 'Example Corp' } });
    const bounce = await bounceRoute(method).handle({
      method: 'POST',
      query: authMethodParameters(undefined),
      form: authMethodParameters({ code: ['a', 'b'], state: 's'.repeat(43) }),
    });
    expect(bounce.query).toEqual({ code: '', state: 's'.repeat(43) });
  });

  it('keeps a repeated error, so a valid code beside it is not redeemed', async () => {
    const method = createUpstreamOidcMethod({ type: TYPE, display: { name: 'Example Corp' } });
    const bounce = await bounceRoute(method).handle({
      method: 'POST',
      query: authMethodParameters(undefined),
      form: authMethodParameters({
        code: 'the-code',
        state: 's'.repeat(43),
        error: ['access_denied', 'server_error'],
        iss: [ISSUER, ISSUER],
      }),
    });
    expect(bounce.query).toEqual({ code: 'the-code', state: 's'.repeat(43), error: '', iss: '' });
  });
});

describe('verify()', () => {
  it('accepts a result of its own callback once, and nothing else', async () => {
    const s = await setup();
    const { outcome } = await signIn(s);
    const result = (outcome as { result: unknown }).result;
    await expect(s.method.verify(structuredClone(result))).rejects.toThrow();
    await expect(
      s.method.verify({ externalSub: 'user-1', assuranceLevel: 'high', rawClaims: {} })
    ).rejects.toThrow();
    const identity = await s.method.verify(result);
    expect(identity.externalSub).toBe('user-1');
    await expect(s.method.verify(result)).rejects.toThrow();
  });
});

describe('the contract test kit', () => {
  it.each(['client_secret_basic', 'client_secret_post', 'private_key_jwt'] as const)(
    'passes with %s',
    async (authentication) => {
      const provider = await createFakeProvider({ issuer: ISSUER });
      provider.register({
        clientId: CLIENT_ID,
        method: authentication,
        clientSecret: CLIENT_SECRET,
        redirectUris: [`https://realm.kit.invalid/upstream/${TYPE}/callback`],
        // The kit's signer hands back a stand-in assertion; the provider
        // trusts it here, since the kit has no keys to sign with.
        trustAssertion: (assertion) => assertion.split('.').length === 3,
      });
      const report = await checkAuthMethod(
        createUpstreamOidcMethod({ type: TYPE, display: { name: 'Example Corp' } }),
        {
          config: configFor(authentication),
          egress: (request) => provider.answer(request),
          callback: (url) => ({
            path: '/callback',
            method: 'GET',
            query: provider.authorize(url, PERSON),
          }),
          declined: (url) => ({
            path: '/callback',
            method: 'GET',
            query: {
              error: 'access_denied',
              state: url.searchParams.get('state') ?? '',
              iss: ISSUER,
            },
          }),
        }
      );
      expect(report.checks).toContain('pkce');
      expect(report.checks).toContain('declined');
    }
  );
});
