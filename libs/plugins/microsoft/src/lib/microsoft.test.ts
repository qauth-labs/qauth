import { checkAuthMethod } from '@qauth-labs/plugin-sdk/testing';
import {
  type AuthMethod,
  type AuthMethodCallbackRoute,
  authMethodParameters,
  completeUpstreamStep,
  loadAuthMethodPlugins,
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
  createMicrosoftMethod,
  MICROSOFT_ISSUER_TEMPLATE,
  MICROSOFT_PLUGIN_TYPE,
  microsoftIssuer,
  microsoftRedirectUri,
} from './microsoft';

/**
 * The Microsoft sign-in plugin (#671): a fixed tenant, the multi-tenant
 * endpoints and their issuer template, and an email that is unverified
 * unless the token says its domain is.
 */

const PACKAGE = '@qauth-labs/plugin-microsoft';
const CLIENT_ID = '6731de76-14a6-49ae-97bc-6eba6914391e';
const CLIENT_SECRET = 'a-microsoft-client-secret-of-some-length';
const TENANT = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a';
const OTHER_TENANT = '9122040d-6c67-4c5b-b112-36a304b66dad';
const KIT_CALLBACK = 'https://realm.kit.invalid/upstream/microsoft/callback';

const configFor = (tenant: string) => ({
  tenant,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
});

const person = (tenant: string, claims: Record<string, unknown> = {}): FakeSignIn => ({
  sub: 'AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ',
  claims: {
    iss: microsoftIssuer(tenant),
    tid: tenant,
    email: 'ada@contoso.example',
    name: 'Ada Lovelace',
    preferred_username: 'ada@contoso.example',
    ...claims,
  },
});

/** A provider at the issuer `tenant` makes: a tenant's own, or a multi-tenant endpoint's. */
async function microsoftProvider(tenant: string) {
  const multiTenant = tenant === 'common' || tenant === 'organizations';
  const provider = await createFakeProvider({
    issuer: microsoftIssuer(tenant),
    algorithm: 'RS256',
    issParameter: false,
    ...(multiTenant ? { documentIssuer: MICROSOFT_ISSUER_TEMPLATE } : {}),
  });
  provider.register({
    clientId: CLIENT_ID,
    method: 'client_secret_post',
    clientSecret: CLIENT_SECRET,
    redirectUris: [microsoftRedirectUri(TEST_ORIGIN), KIT_CALLBACK],
  });
  return provider;
}

async function signIn(tenant: string, signedIn: FakeSignIn) {
  const provider = await microsoftProvider(tenant);
  const method = createMicrosoftMethod();
  const host = await testHost(method, configFor(tenant), provider, {
    secrets: new Map([['clientSecret', CLIENT_SECRET]]),
  });
  const start = await startUpstreamStep(method, { uiLocales: [] }, host.context);
  const callback = method.routes.find(
    (route) => route.kind === 'callback' && route.method === 'GET'
  ) as AuthMethodCallbackRoute;
  const outcome = await callback.handle(
    {
      method: 'GET',
      query: authMethodParameters(provider.authorize(new URL(start.redirectTo), signedIn)),
      form: authMethodParameters(undefined),
      transaction: start.transaction,
    },
    host.context as never
  );
  return { provider, method, outcome };
}

async function identityOf(method: AuthMethod, outcome: unknown): Promise<VerifiedIdentity> {
  const completion = await completeUpstreamStep(method, outcome as never);
  expect(completion.kind).toBe('identity');
  return (completion as { identity: VerifiedIdentity }).identity;
}

describe('the Microsoft plugin (#671)', () => {
  it('loads from the first-party list as a plugin with a write-only client secret', async () => {
    const loaded = await loadAuthMethodPlugins({
      packages: [PACKAGE],
      pluginApiEnabled: false,
      firstParty: [PACKAGE],
      importPackage: async () => plugin,
    });
    expect(loaded.installed).toEqual([
      expect.objectContaining({
        id: 'microsoft',
        type: MICROSOFT_PLUGIN_TYPE,
        secretPaths: ['clientSecret'],
      }),
    ]);
  });

  // Acceptance: the contract test kit passes.
  it.each([TENANT, 'organizations'])(
    'passes the contract test kit with tenant %s',
    async (tenant) => {
      const provider = await microsoftProvider(tenant);
      const report = await checkAuthMethod(createMicrosoftMethod(), {
        config: configFor(tenant),
        egress: (request) => provider.answer(request),
        callback: (url) => ({
          path: '/callback',
          method: 'GET',
          query: provider.authorize(url, person(tenant === TENANT ? TENANT : OTHER_TENANT)),
        }),
        declined: (url) => ({
          path: '/callback',
          method: 'GET',
          query: { error: 'access_denied', state: url.searchParams.get('state') ?? '' },
        }),
      });
      expect(report.checks).toEqual(
        expect.arrayContaining([
          'static',
          'config-schema',
          'pkce',
          'declined',
          'secrets-not-logged',
        ])
      );
    }
  );

  describe('with a fixed tenant', () => {
    it("reads the tenant's own v2.0 endpoints and accepts its tokens", async () => {
      const { provider, method, outcome } = await signIn(TENANT, person(TENANT));
      expect(provider.requests[0].url).toBe(
        `https://login.microsoftonline.com/${TENANT}/v2.0/.well-known/openid-configuration`
      );
      const identity = await identityOf(method, outcome);
      expect(identity.rawClaims['iss']).toBe(microsoftIssuer(TENANT));
    });

    // Acceptance: a token from another tenant than the configured one is refused.
    it('refuses a token another tenant issued', async () => {
      const { outcome } = await signIn(TENANT, person(OTHER_TENANT));
      expect(outcome).toEqual({ kind: 'failed', reason: 'invalid_response' });
    });
  });

  describe('with the multi-tenant endpoints', () => {
    // Acceptance: a multi-tenant token with a matching issuer template is accepted.
    it.each(['organizations', 'common'])(
      "accepts through %s a token whose issuer is the template with the token's tid",
      async (endpoint) => {
        const { method, outcome } = await signIn(endpoint, person(OTHER_TENANT));
        const identity = await identityOf(method, outcome);
        expect(identity.rawClaims).toMatchObject({
          iss: microsoftIssuer(OTHER_TENANT),
          tid: OTHER_TENANT,
        });
      }
    );

    it.each([
      ['names another tenant than its tid', { iss: microsoftIssuer(TENANT), tid: OTHER_TENANT }],
      ['is the multi-tenant endpoint', { iss: microsoftIssuer('organizations'), tid: TENANT }],
      ['carries no tid', { tid: undefined }],
      ['is on another host', { iss: `https://login.example.com/${TENANT}/v2.0`, tid: TENANT }],
    ])('refuses a token whose issuer %s', async (_case, claims) => {
      const { outcome } = await signIn('organizations', person(TENANT, claims));
      expect(outcome).toEqual({ kind: 'failed', reason: 'invalid_response' });
    });

    it('refuses a discovery document that names a single issuer', async () => {
      const provider = await microsoftProvider('organizations');
      provider.tamper.discovery = { issuer: microsoftIssuer('organizations') };
      const method = createMicrosoftMethod();
      const host = await testHost(method, configFor('organizations'), provider, {
        secrets: new Map([['clientSecret', CLIENT_SECRET]]),
      });
      await expect(startUpstreamStep(method, { uiLocales: [] }, host.context)).rejects.toThrow(
        /issuer/
      );
    });
  });

  // Acceptance: the email attribute is unverified by default.
  it('keeps the email unverified by default, even beside email_verified', async () => {
    const { method, outcome } = await signIn(TENANT, person(TENANT, { email_verified: true }));
    expect(method.extractAttributes(await identityOf(method, outcome))).toEqual([
      { source: 'microsoft', attrKey: 'email', attrValue: 'ada@contoso.example', verified: false },
      { source: 'microsoft', attrKey: 'name', attrValue: 'Ada Lovelace', verified: false },
      {
        source: 'microsoft',
        attrKey: 'preferred_username',
        attrValue: 'ada@contoso.example',
        verified: false,
      },
      { source: 'microsoft', attrKey: 'tid', attrValue: TENANT, verified: false },
    ]);
  });

  it.each([
    [true, true],
    ['true', false],
    [1, false],
  ])(
    'marks the email verified only when xms_edov is the boolean true (%s)',
    async (flag, verified) => {
      const { method, outcome } = await signIn(TENANT, person(TENANT, { xms_edov: flag }));
      const [email] = method.extractAttributes(await identityOf(method, outcome));
      expect(email).toMatchObject({ attrKey: 'email', verified });
    }
  );

  it.each([
    ['consumers', 'consumers'],
    ['a tenant id in upper case', TENANT.toUpperCase()],
    ['a domain name', 'contoso.onmicrosoft.com'],
    ['a path', `${TENANT}/x`],
  ])('refuses %s as the tenant', (_case, tenant) => {
    expect(createMicrosoftMethod().configSchema.safeParse(configFor(tenant)).success).toBe(false);
  });

  it('asks for the secret again when the tenant changes', () => {
    const method = createMicrosoftMethod();
    const destination = (tenant: string) =>
      method.secretDestination?.(method.configSchema.parse(configFor(tenant)));
    expect(destination(TENANT)).not.toBe(destination(OTHER_TENANT));
    expect(destination('organizations')).not.toBe(destination('common'));
  });

  it('names the redirect URI to register for the app registration', () => {
    expect(microsoftRedirectUri('https://auth.example.com')).toBe(
      'https://auth.example.com/upstream/microsoft/callback'
    );
  });
});
