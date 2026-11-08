import {
  type AuthMethod,
  type AuthMethodBounceRoute,
  type AuthMethodCallbackRoute,
  authMethodParameters,
  completeUpstreamStep,
  startUpstreamStep,
  type VerifiedIdentity,
} from '@qauth-labs/server-federation';
import { decodeProtectedHeader } from 'jose';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { createFakeProvider, type FakeSignIn } from '../testing/fake-provider';
import { TEST_ORIGIN, testHost } from '../testing/test-host';
import { upstreamClaimIsTrue } from './attributes';
import { upstreamOidcConfigSchema } from './config';
import { isTenantIssuer, tenantIssuerOf } from './id-token';
import { upstreamOidcRedirectUri } from './upstream-oidc-method';
import {
  createUpstreamOidcPresetMethod,
  type UpstreamOidcPresetOptions,
} from './upstream-oidc-preset';

/**
 * What a preset may set beyond the generic client's config (#671): a client
 * secret the signer role signs, a multi-tenant issuer template, response
 * members its callback reads, claims of its own and its attribute rules.
 */

const ORIGIN = 'https://idp.example.com';
const CLIENT_ID = 'qauth-client';
const CLIENT_SECRET = 'a-preset-client-secret-of-some-length';
const TYPE = 'hooked_idp';
const CALLBACK = `${TEST_ORIGIN}/upstream/${TYPE}/callback`;

const plainSchema = z.strictObject({
  clientId: z.string().min(1).max(255),
  clientSecret: z.string().min(1).max(1024).meta({ writeOnly: true }),
});
type PlainConfig = z.output<typeof plainSchema>;
const PLAIN_CONFIG: PlainConfig = { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET };

function preset<TConfig>(
  options: Partial<UpstreamOidcPresetOptions<TConfig>> &
    Pick<UpstreamOidcPresetOptions<TConfig>, 'configSchema' | 'upstreamConfig'>
): AuthMethod<TConfig> {
  return createUpstreamOidcPresetMethod({
    id: 'hooked-idp',
    type: TYPE,
    display: { name: 'Hooked IdP' },
    origins: [ORIGIN],
    ...options,
  }) as AuthMethod<TConfig>;
}

function routes(method: AuthMethod) {
  return {
    callback: method.routes.find(
      (route) => route.kind === 'callback' && route.method === 'GET'
    ) as AuthMethodCallbackRoute,
    bounce: method.routes.find((route) => route.kind === 'bounce') as AuthMethodBounceRoute,
  };
}

/** Start, sign `person` in at the provider and run the GET callback with `extra` in the query. */
async function signIn(
  method: AuthMethod,
  host: Awaited<ReturnType<typeof testHost>>,
  provider: Awaited<ReturnType<typeof createFakeProvider>>,
  person: FakeSignIn,
  extra: Record<string, string> = {}
) {
  const start = await startUpstreamStep(method, { uiLocales: [] }, host.context);
  const response = { ...provider.authorize(new URL(start.redirectTo), person), ...extra };
  const outcome = await routes(method).callback.handle(
    {
      method: 'GET',
      query: authMethodParameters(response),
      form: authMethodParameters(undefined),
      transaction: start.transaction,
    },
    host.context as never
  );
  return { start, outcome, completion: await completeUpstreamStep(method, outcome) };
}

function identityOf(completion: unknown): VerifiedIdentity {
  expect(completion).toMatchObject({ kind: 'identity' });
  return (completion as { identity: VerifiedIdentity }).identity;
}

describe('a signed client secret (#671)', () => {
  const signedSchema = z.strictObject({ clientId: z.string().min(1).max(255) });
  const signedPreset = () =>
    preset({
      configSchema: signedSchema,
      upstreamConfig: (config: z.output<typeof signedSchema>) => ({
        issuer: ORIGIN,
        clientId: config.clientId,
        clientAuthentication: { method: 'signed_client_secret' },
        responseMode: 'form_post',
      }),
    });

  async function signedHost(tokenEndpointAuthMethods = ['client_secret_post']) {
    const provider = await createFakeProvider({
      issuer: ORIGIN,
      issParameter: false,
      tokenEndpointAuthMethods,
    });
    const method = signedPreset();
    const host = await testHost(method, { clientId: CLIENT_ID }, provider, {
      signerClientId: CLIENT_ID,
      signerAssertionIssuer: 'TEAM123456',
    });
    provider.register({
      clientId: CLIENT_ID,
      method: 'signed_client_secret',
      secretIssuer: 'TEAM123456',
      redirectUris: [CALLBACK],
      assertionKeys: async () => host.upstreamJwks,
    });
    return { provider, method, host };
  }

  it('sends, as client_secret, a short-lived JWT the signer role signed with ES256', async () => {
    const { provider, method, host } = await signedHost();
    const { completion } = await signIn(method, host, provider, { sub: 'user-1' });
    expect(identityOf(completion).externalSub).toBe('user-1');

    expect(host.signerCalls).toEqual([
      expect.objectContaining({
        operation: 'signClientAssertion',
        caller: 'api',
        providerId: TYPE,
        request: expect.objectContaining({ audience: ORIGIN, algorithm: 'ES256' }),
      }),
    ]);
    const form = provider.tokenRequests[0];
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.get('client_secret')).toBe(host.signedAssertions[0]);
    expect(form.has('client_assertion')).toBe(false);
    expect(decodeProtectedHeader(host.signedAssertions[0]).alg).toBe('ES256');
    const [claims] = provider.assertions;
    expect(claims).toMatchObject({ iss: 'TEAM123456', sub: CLIENT_ID, aud: ORIGIN });
    expect(typeof claims['jti']).toBe('string');
    expect((claims['exp'] as number) - (claims['iat'] as number)).toBeLessThanOrEqual(60);
  });

  it('is refused at discovery by a provider that takes no client_secret_post', async () => {
    const { provider, method, host } = await signedHost(['client_secret_basic']);
    await expect(startUpstreamStep(method, { uiLocales: [] }, host.context)).rejects.toThrow(
      /client_secret_post/
    );
    expect(provider.tokenRequests).toEqual([]);
  });

  it("is no method of the generic client's config, which a realm's admin writes", () => {
    const result = upstreamOidcConfigSchema.safeParse({
      issuer: ORIGIN,
      clientId: CLIENT_ID,
      clientAuthentication: { method: 'signed_client_secret' },
    });
    expect(result.success).toBe(false);
  });
});

describe('a multi-tenant issuer template (#671)', () => {
  const TEMPLATE = `${ORIGIN}/{tenantid}/v2.0`;
  const COMMON = `${ORIGIN}/common/v2.0`;
  const TENANT_A = '11111111-1111-4111-8111-111111111111';
  const TENANT_B = '22222222-2222-4222-8222-222222222222';
  const tenantPreset = (template = TEMPLATE, origins = [ORIGIN]) =>
    preset({
      origins,
      configSchema: plainSchema,
      upstreamConfig: (config: PlainConfig) => ({
        issuer: COMMON,
        tenantIssuer: { template, tenantClaim: 'tid' },
        clientId: config.clientId,
        clientAuthentication: { method: 'client_secret_post', clientSecret: config.clientSecret },
      }),
    });

  async function tenantHost(issParameter = false) {
    const provider = await createFakeProvider({
      issuer: COMMON,
      documentIssuer: TEMPLATE,
      issParameter,
    });
    const method = tenantPreset();
    const host = await testHost(method, PLAIN_CONFIG, provider, {
      secrets: new Map([['clientSecret', CLIENT_SECRET]]),
    });
    provider.register({
      clientId: CLIENT_ID,
      method: 'client_secret_post',
      clientSecret: CLIENT_SECRET,
      redirectUris: [CALLBACK],
    });
    return { provider, method, host };
  }

  const tenantIssuer = (tenant: string) => `${ORIGIN}/${tenant}/v2.0`;

  it("accepts a token whose issuer is the template with the token's own tenant", async () => {
    const { provider, method, host } = await tenantHost();
    const { completion } = await signIn(method, host, provider, {
      sub: 'user-a',
      claims: { iss: tenantIssuer(TENANT_A), tid: TENANT_A },
    });
    expect(identityOf(completion).rawClaims).toMatchObject({
      iss: tenantIssuer(TENANT_A),
      tid: TENANT_A,
    });
  });

  it.each([
    ['names another tenant than its tid', { iss: tenantIssuer(TENANT_B), tid: TENANT_A }],
    ['carries no tid', { iss: tenantIssuer(TENANT_A) }],
    ['is the template itself', { iss: TEMPLATE, tid: TENANT_A }],
    ['is the common endpoint', { iss: COMMON, tid: TENANT_A }],
    ['has a tid that reaches past its segment', { iss: `${ORIGIN}/a/b/v2.0`, tid: 'a/b' }],
  ])('refuses a token whose issuer %s', async (_name, claims) => {
    const { provider, method, host } = await tenantHost();
    const { outcome } = await signIn(method, host, provider, { sub: 'user-a', claims });
    expect(outcome).toEqual({ kind: 'failed', reason: 'invalid_response' });
  });

  it('refuses a response whose iss parameter is on another host (RFC 9207)', async () => {
    const { provider, method, host } = await tenantHost(true);
    const { outcome } = await signIn(
      method,
      host,
      provider,
      { sub: 'user-a', claims: { iss: tenantIssuer(TENANT_A), tid: TENANT_A } },
      { iss: `https://evil.example.com/${TENANT_A}/v2.0` }
    );
    expect(outcome).toEqual({ kind: 'failed', reason: 'invalid_response' });
  });

  it('refuses a discovery document that names no template', async () => {
    const { provider, method, host } = await tenantHost();
    provider.tamper.discovery = { issuer: COMMON };
    await expect(startUpstreamStep(method, { uiLocales: [] }, host.context)).rejects.toThrow(
      /issuer/
    );
  });

  it("refuses a template off the preset's origins, or with the tenant in its host", () => {
    expect(
      tenantPreset('https://elsewhere.example.com/{tenantid}/v2.0').configSchema.safeParse(
        PLAIN_CONFIG
      ).success
    ).toBe(false);
    expect(
      tenantPreset('https://{tenantid}.example.com/v2.0', [
        'https://tenant.example.com',
        ORIGIN,
      ]).configSchema.safeParse(PLAIN_CONFIG).success
    ).toBe(false);
    expect(
      tenantPreset(`${ORIGIN}/{tenantid}/{tenantid}`).configSchema.safeParse(PLAIN_CONFIG).success
    ).toBe(false);
  });

  it('matches a tenant id only within its own path segment', () => {
    const template = { template: TEMPLATE, tenantClaim: 'tid' };
    expect(tenantIssuerOf(template, { tid: TENANT_A })).toBe(tenantIssuer(TENANT_A));
    expect(tenantIssuerOf(template, { tid: '../x' })).toBeUndefined();
    expect(tenantIssuerOf(template, { tid: 7 })).toBeUndefined();
    expect(isTenantIssuer(template, tenantIssuer(TENANT_A))).toBe(true);
    expect(isTenantIssuer(template, `${ORIGIN}//v2.0`)).toBe(false);
    expect(isTenantIssuer(template, `${ORIGIN}/a%2Fb/v2.0`)).toBe(false);
    expect(isTenantIssuer(template, `${ORIGIN}/a/b/v2.0`)).toBe(false);
  });
});

describe('response members and identity claims (#671)', () => {
  const memberPreset = (
    identityClaims?: UpstreamOidcPresetOptions<PlainConfig>['identityClaims']
  ) =>
    preset({
      configSchema: plainSchema,
      upstreamConfig: (config: PlainConfig) => ({
        issuer: ORIGIN,
        clientId: config.clientId,
        clientAuthentication: { method: 'client_secret_post', clientSecret: config.clientSecret },
        responseMode: 'form_post',
      }),
      responseMembers: { user: (value) => (value.startsWith('{') ? value : undefined) },
      identityClaims:
        identityClaims ??
        (({ response }) => ({
          nickname: response['user'] === undefined ? undefined : JSON.parse(response['user']).n,
          sub: 'forged',
          iss: 'https://forged.example.com',
          email: undefined,
        })),
    });

  async function memberHost(
    identityClaims?: UpstreamOidcPresetOptions<PlainConfig>['identityClaims']
  ) {
    const provider = await createFakeProvider({ issuer: ORIGIN });
    const method = memberPreset(identityClaims);
    const host = await testHost(method, PLAIN_CONFIG, provider, {
      secrets: new Map([['clientSecret', CLIENT_SECRET]]),
    });
    provider.register({
      clientId: CLIENT_ID,
      method: 'client_secret_post',
      clientSecret: CLIENT_SECRET,
      redirectUris: [CALLBACK],
    });
    return { provider, method, host };
  }

  it('carries a member through the form_post bounce, and dropped what its map refuses', async () => {
    const method = memberPreset();
    const bounce = await routes(method).bounce.handle({
      method: 'POST',
      query: authMethodParameters(undefined),
      form: authMethodParameters({
        code: 'c',
        state: 's',
        user: '{"n":"Ada"}',
        other: 'x',
      }),
    });
    expect(bounce).toEqual({
      to: '/callback',
      query: { code: 'c', state: 's', user: '{"n":"Ada"}' },
    });
    const refused = await routes(method).bounce.handle({
      method: 'POST',
      query: authMethodParameters(undefined),
      form: authMethodParameters({ code: 'c', state: 's', user: 'plain' }),
    });
    expect(refused.query).toEqual({ code: 'c', state: 's' });
    const long = await routes(method).bounce.handle({
      method: 'POST',
      query: authMethodParameters(undefined),
      form: authMethodParameters({ code: 'c', state: 's', user: `{${'x'.repeat(1100)}}` }),
    });
    expect(long.query).toEqual({ code: 'c', state: 's' });
  });

  it("sets the preset's claims over the provider's, never sub or iss", async () => {
    const { provider, method, host } = await memberHost();
    const { completion } = await signIn(
      method,
      host,
      provider,
      { sub: 'user-1', claims: { email: 'ada@example.com', email_verified: true } },
      { user: '{"n":"Ada"}' }
    );
    const identity = identityOf(completion);
    expect(identity.externalSub).toBe('user-1');
    expect(identity.rawClaims).toMatchObject({ sub: 'user-1', iss: ORIGIN, nickname: 'Ada' });
    expect(identity.rawClaims).not.toHaveProperty('email');
    expect(method.extractAttributes(identity).map((attribute) => attribute.attrKey)).toEqual([
      'nickname',
    ]);
  });

  it('never sets a claim the provider vouches for, or its flag, from the preset', async () => {
    const { provider, method, host } = await memberHost(({ response }) => ({
      email: response['user'] === undefined ? undefined : JSON.parse(response['user']).email,
      email_verified: true,
      phone_number: '+15550100',
      phone_number_verified: true,
    }));
    const { completion } = await signIn(
      method,
      host,
      provider,
      { sub: 'user-1', claims: { email: 'ada@example.com', email_verified: true } },
      { user: '{"email":"mallory@example.com"}' }
    );
    const identity = identityOf(completion);
    expect(identity.rawClaims).toMatchObject({ email: 'ada@example.com', email_verified: true });
    expect(identity.rawClaims).not.toHaveProperty('phone_number');
    expect(identity.rawClaims).not.toHaveProperty('phone_number_verified');
  });

  it('fails the callback when the identity claims throw', async () => {
    const { provider, method, host } = await memberHost(() => {
      throw new Error('broken');
    });
    const { outcome } = await signIn(method, host, provider, { sub: 'user-1' });
    expect(outcome).toEqual({ kind: 'failed', reason: 'invalid_response' });
  });

  it('refuses response members that name a protocol parameter', () => {
    expect(() =>
      preset({
        configSchema: plainSchema,
        upstreamConfig: () => ({}) as never,
        responseMembers: { code: (value) => value },
      })
    ).toThrow(TypeError);
  });
});

describe("a preset's attribute rules (#671)", () => {
  it('maps only the claims its rules name, verified only as they say', async () => {
    const provider = await createFakeProvider({ issuer: ORIGIN });
    const method = preset({
      configSchema: plainSchema,
      upstreamConfig: (config: PlainConfig) => ({
        issuer: ORIGIN,
        clientId: config.clientId,
        clientAuthentication: { method: 'client_secret_post', clientSecret: config.clientSecret },
      }),
      attributes: [
        { claim: 'email', verified: (claims) => upstreamClaimIsTrue(claims, 'domain_verified') },
        { claim: 'hd' },
        { claim: 'org', attribute: 'organization' },
      ],
    });
    const host = await testHost(method, PLAIN_CONFIG, provider, {
      secrets: new Map([['clientSecret', CLIENT_SECRET]]),
    });
    provider.register({
      clientId: CLIENT_ID,
      method: 'client_secret_post',
      clientSecret: CLIENT_SECRET,
      redirectUris: [CALLBACK],
    });
    const { completion } = await signIn(method, host, provider, {
      sub: 'user-1',
      claims: {
        email: 'ada@example.com',
        email_verified: true,
        hd: 'example.com',
        org: 'Example',
        name: 'Ada',
      },
    });
    expect(method.extractAttributes(identityOf(completion))).toEqual([
      { source: TYPE, attrKey: 'email', attrValue: 'ada@example.com', verified: false },
      { source: TYPE, attrKey: 'hd', attrValue: 'example.com', verified: false },
      { source: TYPE, attrKey: 'organization', attrValue: 'Example', verified: false },
    ]);
  });
});

describe('the redirect URI of a preset (#671)', () => {
  it("is its own type's callback on the realm host", () => {
    expect(upstreamOidcRedirectUri(TEST_ORIGIN, 'acme_idp')).toBe(
      `${TEST_ORIGIN}/upstream/acme_idp/callback`
    );
    expect(() => upstreamOidcRedirectUri(TEST_ORIGIN, 'Acme_idp')).toThrow(TypeError);
  });
});
