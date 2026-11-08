import { checkAuthMethod } from '@qauth-labs/plugin-sdk/testing';
import {
  type AuthMethod,
  type AuthMethodBounceRoute,
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
import { createLocalJWKSet, decodeProtectedHeader, type JSONWebKeySet, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';

import * as plugin from '../index';
import {
  APPLE_ISSUER,
  APPLE_PLUGIN_TYPE,
  appleRedirectUri,
  appleUserName,
  createAppleMethod,
  isApplePrivateRelay,
} from './apple';

/**
 * The Sign in with Apple plugin (#671): a client secret the signer role
 * signs, a `form_post` response, the name that arrives once in its `user`
 * member, and private relay addresses.
 */

const PACKAGE = '@qauth-labs/plugin-apple';
const SERVICES_ID = 'com.example.signin';
const TEAM_ID = 'A1B2C3D4E5';
const KIT_CALLBACK = 'https://realm.kit.invalid/upstream/apple/callback';
/** The stand-in assertion the contract kit's signer hands back. */
const KIT_ASSERTION = 'eyJhbGciOiJSUzI1NiJ9.eyJraXQiOnRydWV9.a2l0';
const USER = JSON.stringify({
  name: { firstName: 'Ada', lastName: 'Lovelace' },
  email: 'ada@example.com',
});
const PERSON: FakeSignIn = {
  sub: '001234.0a1b2c3d4e5f60718293a4b5c6d7e8f9.1234',
  claims: { email: 'ada@example.com', email_verified: 'true', is_private_email: 'false' },
};

async function appleProvider() {
  const provider = await createFakeProvider({
    issuer: APPLE_ISSUER,
    algorithm: 'RS256',
    issParameter: false,
    tokenEndpointAuthMethods: ['client_secret_post'],
  });
  return provider;
}

/** A host whose signer role signs as the Services ID for the Team ID. */
async function appleHost(config: Record<string, unknown> = {}) {
  const provider = await appleProvider();
  const method = createAppleMethod();
  const host = await testHost(method, { clientId: SERVICES_ID, ...config }, provider, {
    signerClientId: SERVICES_ID,
    signerAssertionIssuer: TEAM_ID,
  });
  provider.register({
    clientId: SERVICES_ID,
    method: 'signed_client_secret',
    secretIssuer: TEAM_ID,
    redirectUris: [appleRedirectUri(TEST_ORIGIN)],
    assertionKeys: async () => host.upstreamJwks,
  });
  return { provider, method, host };
}

function routes(method: AuthMethod) {
  return {
    callback: method.routes.find(
      (route) => route.kind === 'callback' && route.method === 'GET'
    ) as AuthMethodCallbackRoute,
    bounce: method.routes.find(
      (route) => route.kind === 'bounce' && route.method === 'POST'
    ) as AuthMethodBounceRoute,
  };
}

/** The person signs in; Apple posts the response, which the bounce carries to the GET callback. */
async function formPostSignIn(
  setup: Awaited<ReturnType<typeof appleHost>>,
  person: FakeSignIn = PERSON,
  /** The `user` member, or `null` for a response without one (every sign-in but the first). */
  user: string | null = USER
) {
  const { provider, method, host } = setup;
  const start = await startUpstreamStep(method, { uiLocales: [] }, host.context);
  const response = provider.authorize(new URL(start.redirectTo), person);
  const bounce = await routes(method).bounce.handle({
    method: 'POST',
    query: authMethodParameters(undefined),
    form: authMethodParameters(user === null ? response : { ...response, user }),
  });
  const outcome = await routes(method).callback.handle(
    {
      method: 'GET',
      query: authMethodParameters(Object.fromEntries(new URLSearchParams(bounce.query))),
      form: authMethodParameters(undefined),
      transaction: start.transaction,
    },
    host.context as never
  );
  return { start, bounce, outcome };
}

async function identityOf(method: AuthMethod, outcome: unknown): Promise<VerifiedIdentity> {
  const completion = await completeUpstreamStep(method, outcome as never);
  expect(completion.kind).toBe('identity');
  return (completion as { identity: VerifiedIdentity }).identity;
}

describe('the Apple plugin (#671)', () => {
  it('loads from the first-party list as a plugin with no secret member', async () => {
    const loaded = await loadAuthMethodPlugins({
      packages: [PACKAGE],
      pluginApiEnabled: false,
      firstParty: [PACKAGE],
      importPackage: async () => plugin,
    });
    expect(loaded.installed).toEqual([
      expect.objectContaining({ id: 'apple', type: APPLE_PLUGIN_TYPE, secretPaths: [] }),
    ]);
  });

  // Acceptance: the contract test kit passes.
  it('passes the contract test kit, its response arriving as a form_post', async () => {
    const provider = await appleProvider();
    provider.register({
      clientId: SERVICES_ID,
      method: 'signed_client_secret',
      redirectUris: [KIT_CALLBACK],
      trustAssertion: (assertion) => assertion === KIT_ASSERTION,
    });
    const report = await checkAuthMethod(createAppleMethod(), {
      config: { clientId: SERVICES_ID },
      egress: (request) => provider.answer(request),
      callback: (url) => ({
        path: '/callback',
        method: 'POST',
        form: { ...provider.authorize(url, PERSON), user: USER },
      }),
      declined: (url) => ({
        path: '/callback',
        method: 'POST',
        form: { error: 'access_denied', state: url.searchParams.get('state') ?? '' },
      }),
    });
    expect(report.checks).toEqual(
      expect.arrayContaining(['static', 'config-schema', 'pkce', 'declined'])
    );
  });

  it('asks for the name and email by form_post', async () => {
    const { method, host } = await appleHost();
    const start = await startUpstreamStep(method, { uiLocales: [] }, host.context);
    const url = new URL(start.redirectTo);
    expect(url.searchParams.get('scope')).toBe('openid name email');
    expect(url.searchParams.get('response_mode')).toBe('form_post');
    expect(url.searchParams.get('client_id')).toBe(SERVICES_ID);
  });

  // Acceptance: the client secret JWT has the expected claims and a short
  // life, and is signed through the signer role.
  it('sends as client_secret a short-lived ES256 JWT the signer role signed', async () => {
    const setup = await appleHost();
    const before = Math.floor(Date.now() / 1000);
    const { outcome } = await formPostSignIn(setup);
    await identityOf(setup.method, outcome);

    const { provider, host } = setup;
    expect(host.signerCalls).toEqual([
      {
        operation: 'signClientAssertion',
        caller: 'api',
        realmId: expect.any(String),
        providerId: APPLE_PLUGIN_TYPE,
        request: expect.objectContaining({ audience: APPLE_ISSUER, algorithm: 'ES256' }),
      },
    ]);
    const [form] = provider.tokenRequests;
    expect(form.get('client_id')).toBe(SERVICES_ID);
    expect(form.has('client_assertion')).toBe(false);
    const secret = form.get('client_secret') ?? '';
    expect(secret).toBe(host.signedAssertions[0]);
    expect(decodeProtectedHeader(secret)).toMatchObject({ alg: 'ES256', kid: expect.any(String) });
    const { payload } = await jwtVerify(
      secret,
      createLocalJWKSet(host.upstreamJwks as JSONWebKeySet),
      { issuer: TEAM_ID, subject: SERVICES_ID, audience: APPLE_ISSUER }
    );
    expect(typeof payload.jti).toBe('string');
    expect(payload.iat).toBeGreaterThanOrEqual(before);
    expect((payload.exp as number) - (payload.iat as number)).toBeLessThanOrEqual(60);
  });

  it('takes the name from the user member, unverified, and the email as Apple verified it', async () => {
    const setup = await appleHost();
    const { bounce, outcome } = await formPostSignIn(setup);
    // The bounce carries the name on, never the address Apple repeats there.
    expect(JSON.parse(bounce.query['user'])).toEqual({
      name: { firstName: 'Ada', lastName: 'Lovelace' },
    });
    const identity = await identityOf(setup.method, outcome);
    expect(setup.method.extractAttributes(identity)).toEqual([
      { source: 'apple', attrKey: 'email', attrValue: 'ada@example.com', verified: true },
      { source: 'apple', attrKey: 'given_name', attrValue: 'Ada', verified: false },
      { source: 'apple', attrKey: 'family_name', attrValue: 'Lovelace', verified: false },
    ]);
  });

  it('has no name on a later sign-in, whose response carries no user member', async () => {
    const setup = await appleHost();
    const { outcome } = await formPostSignIn(setup, PERSON, null);
    const attributes = setup.method.extractAttributes(await identityOf(setup.method, outcome));
    expect(attributes.map((attribute) => attribute.attrKey)).toEqual(['email']);
  });

  it('drops a user member that is no JSON name, and keeps the sign-in', async () => {
    const setup = await appleHost();
    const { bounce, outcome } = await formPostSignIn(setup, PERSON, 'Ada Lovelace');
    expect(bounce.query).not.toHaveProperty('user');
    expect(outcome).toMatchObject({ kind: 'result' });
  });

  describe('a private relay address', () => {
    const relay: FakeSignIn = {
      sub: '001234.relay.5678',
      claims: {
        email: 'x7q2c9z8ab@privaterelay.appleid.com',
        email_verified: true,
        is_private_email: true,
      },
    };

    it('is kept apart from email, so it is never the address mailed, by default', async () => {
      const setup = await appleHost();
      const { outcome } = await formPostSignIn(setup, relay);
      const identity = await identityOf(setup.method, outcome);
      expect(identity.rawClaims).not.toHaveProperty('email');
      expect(setup.method.extractAttributes(identity)).toEqual([
        {
          source: 'apple',
          attrKey: 'private_relay_email',
          attrValue: 'x7q2c9z8ab@privaterelay.appleid.com',
          verified: false,
        },
        { source: 'apple', attrKey: 'given_name', attrValue: 'Ada', verified: false },
        { source: 'apple', attrKey: 'family_name', attrValue: 'Lovelace', verified: false },
      ]);
    });

    it('is the email when the realm says the relay receives its mail', async () => {
      const setup = await appleHost({ privateRelayReceivesMail: true });
      const { outcome } = await formPostSignIn(setup, relay, null);
      const attributes = setup.method.extractAttributes(await identityOf(setup.method, outcome));
      expect(attributes).toEqual([
        {
          source: 'apple',
          attrKey: 'email',
          attrValue: 'x7q2c9z8ab@privaterelay.appleid.com',
          verified: true,
        },
      ]);
    });

    it.each([
      [{ is_private_email: true, email: 'a@example.com' }, true],
      [{ is_private_email: 'true', email: 'a@example.com' }, true],
      [{ email: 'A@PrivateRelay.AppleID.com' }, true],
      [{ is_private_email: 'false', email: 'a@example.com' }, false],
      [{ email: 'a@privaterelay.appleid.com.example.com' }, false],
    ])('is told by its flag or its domain (%o)', (claims, relayed) => {
      expect(isApplePrivateRelay(claims)).toBe(relayed);
    });
  });

  it.each([
    [
      '{"name":{"firstName":" Ada ","lastName":"Lovelace"}}',
      { firstName: 'Ada', lastName: 'Lovelace' },
    ],
    ['{"name":{"firstName":"Ada"}}', { firstName: 'Ada' }],
    ['{"name":{"firstName":"","lastName":"  "}}', undefined],
    ['{"name":{"firstName":"A\\u0000da"}}', undefined],
    [`{"name":{"firstName":"${'a'.repeat(257)}"}}`, undefined],
    ['{"name":"Ada"}', undefined],
    ['{"email":"ada@example.com"}', undefined],
    ['not json', undefined],
  ])('reads the name of the user member %s', (value, name) => {
    expect(appleUserName(value)).toEqual(name);
  });

  it("ranks its attributes with an oidc_ provider's in claim resolution", () => {
    expect(rankAttributeSource(APPLE_PLUGIN_TYPE)).toBe(rankAttributeSource('oidc_example'));
  });

  it('refuses a config with a client secret or a key', () => {
    const schema = createAppleMethod().configSchema;
    expect(schema.safeParse({ clientId: SERVICES_ID }).success).toBe(true);
    expect(schema.safeParse({ clientId: SERVICES_ID, clientSecret: 'x'.repeat(20) }).success).toBe(
      false
    );
    expect(schema.safeParse({ clientId: SERVICES_ID, privateKey: 'x'.repeat(20) }).success).toBe(
      false
    );
  });
});
