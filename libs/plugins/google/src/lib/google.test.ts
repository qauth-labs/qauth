import { checkAuthMethod } from '@qauth-labs/plugin-sdk/testing';
import {
  type AuthMethod,
  type AuthMethodCallbackRoute,
  authMethodParameters,
  completeUpstreamStep,
  loadAuthMethodPlugins,
  rankAttributeSource,
  startUpstreamStep,
  type VerifiedIdentity,
} from '@qauth-labs/server-federation';
import {
  createFakeProvider,
  type FakeSignIn,
} from '@qauth-labs/server-upstream-oidc/src/testing/fake-provider';
import { TEST_ORIGIN, testHost } from '@qauth-labs/server-upstream-oidc/src/testing/test-host';
import { describe, expect, it } from 'vitest';

import * as plugin from '../index';
import {
  createGoogleMethod,
  GOOGLE_ISSUER,
  GOOGLE_PLUGIN_TYPE,
  googleConfigSchema,
  googleRedirectUri,
} from './google';

/** The Google sign-in plugin (#671): a preset on the generic upstream OIDC client. */

const PACKAGE = '@qauth-labs/plugin-google';
const CLIENT_ID = '1234-qauth.apps.googleusercontent.com';
const CLIENT_SECRET = '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th';
const CONFIG = { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET };
const KIT_CALLBACK = 'https://realm.kit.invalid/upstream/google/callback';
const PERSON: FakeSignIn = {
  sub: '110169484474386276334',
  claims: {
    email: 'ada@example.com',
    email_verified: true,
    name: 'Ada Lovelace',
    given_name: 'Ada',
    family_name: 'Lovelace',
    hd: 'example.com',
  },
};

async function googleProvider() {
  const provider = await createFakeProvider({
    issuer: GOOGLE_ISSUER,
    algorithm: 'RS256',
    issParameter: false,
  });
  provider.register({
    clientId: CLIENT_ID,
    method: 'client_secret_post',
    clientSecret: CLIENT_SECRET,
    redirectUris: [googleRedirectUri(TEST_ORIGIN), KIT_CALLBACK],
  });
  return provider;
}

async function signIn(person: FakeSignIn = PERSON) {
  const provider = await googleProvider();
  const method = createGoogleMethod();
  const host = await testHost(method, CONFIG, provider, {
    secrets: new Map([['clientSecret', CLIENT_SECRET]]),
  });
  const start = await startUpstreamStep(method, { uiLocales: [] }, host.context);
  const callback = method.routes.find(
    (route) => route.kind === 'callback' && route.method === 'GET'
  ) as AuthMethodCallbackRoute;
  const outcome = await callback.handle(
    {
      method: 'GET',
      query: authMethodParameters(provider.authorize(new URL(start.redirectTo), person)),
      form: authMethodParameters(undefined),
      transaction: start.transaction,
    },
    host.context as never
  );
  return { provider, method, host, start, outcome };
}

async function identityOf(method: AuthMethod, outcome: unknown): Promise<VerifiedIdentity> {
  const completion = await completeUpstreamStep(method, outcome as never);
  expect(completion.kind).toBe('identity');
  return (completion as { identity: VerifiedIdentity }).identity;
}

describe('the Google plugin (#671)', () => {
  it('loads from the first-party list as a plugin with a write-only client secret', async () => {
    const loaded = await loadAuthMethodPlugins({
      packages: [PACKAGE],
      pluginApiEnabled: false,
      firstParty: [PACKAGE],
      importPackage: async () => plugin,
    });
    expect(loaded.installed).toEqual([
      expect.objectContaining({
        package: PACKAGE,
        firstParty: true,
        id: 'google',
        type: GOOGLE_PLUGIN_TYPE,
        secretPaths: ['clientSecret'],
      }),
    ]);
  });

  // Acceptance: the contract test kit passes.
  it('passes the contract test kit', async () => {
    const provider = await googleProvider();
    const report = await checkAuthMethod(createGoogleMethod(), {
      config: CONFIG,
      egress: (request) => provider.answer(request),
      callback: (url) => ({
        path: '/callback',
        method: 'GET',
        query: provider.authorize(url, PERSON),
      }),
      declined: (url) => ({
        path: '/callback',
        method: 'GET',
        query: { error: 'access_denied', state: url.searchParams.get('state') ?? '' },
      }),
    });
    expect(report.checks).toEqual(
      expect.arrayContaining(['static', 'config-schema', 'pkce', 'declined', 'secrets-not-logged'])
    );
  });

  it('asks Google for openid, email and profile, and redeems the code with the secret in the body', async () => {
    const { provider, start } = await signIn();
    const url = new URL(start.redirectTo);
    expect(`${url.origin}${url.pathname}`).toBe(provider.authorizationEndpoint);
    expect(url.searchParams.get('scope')).toBe('openid email profile');
    expect(url.searchParams.get('redirect_uri')).toBe(`${TEST_ORIGIN}/upstream/google/callback`);
    const [form] = provider.tokenRequests;
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.get('client_secret')).toBe(CLIENT_SECRET);
  });

  it('maps the email as verified when email_verified says so, and keeps hd unverified', async () => {
    const { method, outcome } = await signIn();
    const identity = await identityOf(method, outcome);
    expect(identity.externalSub).toBe(PERSON.sub);
    expect(method.extractAttributes(identity)).toEqual([
      { source: 'google', attrKey: 'email', attrValue: 'ada@example.com', verified: true },
      { source: 'google', attrKey: 'name', attrValue: 'Ada Lovelace', verified: false },
      { source: 'google', attrKey: 'given_name', attrValue: 'Ada', verified: false },
      { source: 'google', attrKey: 'family_name', attrValue: 'Lovelace', verified: false },
      { source: 'google', attrKey: 'hd', attrValue: 'example.com', verified: false },
    ]);
  });

  it.each([
    ['false', false],
    ['the string "true"', 'true'],
    ['absent', undefined],
  ])('keeps the email unverified when email_verified is %s', async (_case, flag) => {
    const { method, outcome } = await signIn({
      sub: 'user-2',
      claims: { email: 'bob@example.com', email_verified: flag },
    });
    const attributes = method.extractAttributes(await identityOf(method, outcome));
    expect(attributes).toEqual([
      { source: 'google', attrKey: 'email', attrValue: 'bob@example.com', verified: false },
    ]);
  });

  it("refuses a discovery document that names an endpoint off Google's origins", async () => {
    const provider = await googleProvider();
    provider.tamper.discovery = { token_endpoint: 'https://token.example.com/token' };
    const method = createGoogleMethod();
    const host = await testHost(method, CONFIG, provider, {
      secrets: new Map([['clientSecret', CLIENT_SECRET]]),
    });
    await expect(startUpstreamStep(method, { uiLocales: [] }, host.context)).rejects.toThrow(
      /off the preset's origins/
    );
  });

  it('lets an admin set the client and nothing else', () => {
    expect(googleConfigSchema.safeParse(CONFIG).success).toBe(true);
    for (const extra of [
      { issuer: 'https://idp.example.com' },
      { scopes: ['openid'] },
      { endpoints: {} },
    ]) {
      expect(createGoogleMethod().configSchema.safeParse({ ...CONFIG, ...extra }).success).toBe(
        false
      );
    }
    expect(createGoogleMethod().configSchema.safeParse({ clientId: CLIENT_ID }).success).toBe(
      false
    );
  });

  it("ranks its attributes with an oidc_ provider's in claim resolution", () => {
    expect(rankAttributeSource(GOOGLE_PLUGIN_TYPE)).toBe(rankAttributeSource('oidc_example'));
  });

  it('names the redirect URI to register at Google', () => {
    expect(googleRedirectUri('https://auth.example.com')).toBe(
      'https://auth.example.com/upstream/google/callback'
    );
    expect(() => googleRedirectUri('https://auth.example.com/realm')).toThrow(TypeError);
  });
});
