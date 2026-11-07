import { checkAuthMethod } from '@qauth-labs/plugin-sdk/testing';
import {
  type AuthMethod,
  type AuthMethodCallbackRoute,
  AuthMethodConfigError,
  authMethodParameters,
  AuthMethodPluginError,
  authMethodSecretPaths,
  completeUpstreamStep,
  configSpellsMemberOf,
  loadAuthMethodPlugins,
  parseAuthMethodConfig,
  startUpstreamStep,
  withConfigMembers,
  withoutConfigMembers,
} from '@qauth-labs/server-federation';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  EXAMPLE_PRESET_ID,
  EXAMPLE_PRESET_ISSUER,
  EXAMPLE_PRESET_PACKAGE,
  EXAMPLE_PRESET_SECRET_PATH,
  EXAMPLE_PRESET_TYPE,
  examplePresetMethod,
  examplePresetPackage,
} from '../testing/example-preset';
import {
  createFakeProvider,
  type FakeClientAuthentication,
  type FakeSignIn,
} from '../testing/fake-provider';
import { type HostEgressCall, TEST_ORIGIN, testHost } from '../testing/test-host';
import { createUpstreamOidcMethod } from './upstream-oidc-method';
import { createUpstreamOidcPresetMethod } from './upstream-oidc-preset';

/**
 * A preset plugin on the generic upstream OpenID Connect client (#951): its
 * own id, type and config, loaded by the plugin loader as any plugin, its
 * client secret write-only, and the secret bound to the preset's provider.
 */

const CLIENT_ID = 'qauth-client';
// Characters that encode, so each spelling of it on the wire differs.
const CLIENT_SECRET = 'a-preset/client+secret of=some&length';
const CALLBACK = `${TEST_ORIGIN}/upstream/${EXAMPLE_PRESET_TYPE}/callback`;
const PERSON: FakeSignIn = {
  sub: 'user-1',
  claims: { email: 'ada@example.com', email_verified: true, name: 'Ada' },
};

function presetConfig(method: FakeClientAuthentication = 'client_secret_basic') {
  return {
    clientId: CLIENT_ID,
    clientAuthentication:
      method === 'private_key_jwt' ? { method } : { method, clientSecret: CLIENT_SECRET },
  };
}

/** An importer over named modules, as the loader's test support takes it. */
function importer(modules: Readonly<Record<string, unknown>>) {
  return async (name: string) => {
    if (Object.hasOwn(modules, name)) return modules[name];
    const error = new Error(`Cannot find package '${name}' imported from /app/main.js`);
    (error as NodeJS.ErrnoException).code = 'ERR_MODULE_NOT_FOUND';
    throw error;
  };
}

/** Every spelling of the client secret a call could carry it in. */
function secretSpellings(secret: string): string[] {
  const form = (value: string) => new URLSearchParams([['v', value]]).toString().slice(2);
  const base64 = (value: string) => Buffer.from(value, 'utf8').toString('base64');
  return [
    secret,
    encodeURIComponent(secret),
    form(secret),
    base64(secret),
    base64(`${CLIENT_ID}:${secret}`),
    base64(`${form(CLIENT_ID)}:${form(secret)}`),
  ];
}

/** An egress call as text, its body read as UTF-8. */
function callText(call: HostEgressCall): string {
  const body =
    call.body === undefined
      ? ''
      : typeof call.body === 'string'
        ? call.body
        : Buffer.from(call.body).toString('utf8');
  return JSON.stringify({ ...call, body });
}

/** A preset whose mapping a test chooses, on the example's provider. */
function presetWith<TConfig>(
  configSchema: z.ZodType<TConfig>,
  upstreamConfig: (config: TConfig) => unknown
): AuthMethod<TConfig> {
  return createUpstreamOidcPresetMethod({
    id: 'buggy-idp',
    type: 'buggy_idp',
    display: { name: 'Buggy IdP' },
    origins: [EXAMPLE_PRESET_ISSUER],
    configSchema,
    upstreamConfig: upstreamConfig as never,
  }) as AuthMethod<TConfig>;
}

describe('a preset plugin through the plugin loader (#951)', () => {
  // Acceptance: a preset plugin built on the generic client loads from the
  // first-party list with PLUGIN_API_ENABLED off.
  it('loads from the first-party list with the plugin API off, its secret member read', async () => {
    const loaded = await loadAuthMethodPlugins({
      packages: [EXAMPLE_PRESET_PACKAGE],
      pluginApiEnabled: false,
      firstParty: [EXAMPLE_PRESET_PACKAGE],
      importPackage: importer({ [EXAMPLE_PRESET_PACKAGE]: examplePresetPackage() }),
    });
    expect(loaded.skipped).toEqual([]);
    expect(loaded.installed).toHaveLength(1);
    expect(loaded.installed[0]).toMatchObject({
      package: EXAMPLE_PRESET_PACKAGE,
      firstParty: true,
      id: EXAMPLE_PRESET_ID,
      type: EXAMPLE_PRESET_TYPE,
      secretPaths: [EXAMPLE_PRESET_SECRET_PATH],
    });
  });

  it('is never imported off the first-party list while the plugin API is off', async () => {
    let imported = false;
    const loaded = await loadAuthMethodPlugins({
      packages: [EXAMPLE_PRESET_PACKAGE],
      pluginApiEnabled: false,
      firstParty: [],
      importPackage: async () => {
        imported = true;
        return examplePresetPackage();
      },
    });
    expect(imported).toBe(false);
    expect(loaded.installed).toEqual([]);
    expect(loaded.skipped).toEqual([{ package: EXAMPLE_PRESET_PACKAGE, reason: 'plugin-api-off' }]);
  });

  it("reads the generic client's own secret member now, and still refuses the client as a plugin", async () => {
    const generic = createUpstreamOidcMethod({ type: 'oidc_corp', display: { name: 'Corp' } });
    expect(authMethodSecretPaths(generic)).toEqual(['clientAuthentication.clientSecret']);
    const refusal = await loadAuthMethodPlugins({
      packages: ['@example/generic'],
      pluginApiEnabled: false,
      firstParty: ['@example/generic'],
      importPackage: importer({ '@example/generic': { authMethod: generic } }),
    }).catch((error: unknown) => error);
    expect(refusal).toBeInstanceOf(AuthMethodPluginError);
    // Only the reserved names: the secret inside the union no longer fails it.
    expect((refusal as AuthMethodPluginError).problems).toEqual([
      expect.stringMatching(/its id oidc is the generic upstream OpenID Connect client's/),
      expect.stringMatching(/its type oidc_corp is in the generic upstream OpenID Connect/),
    ]);
  });
});

describe('the contract test kit (#951)', () => {
  // Acceptance: it passes the contract kit.
  it.each(['client_secret_basic', 'client_secret_post', 'private_key_jwt'] as const)(
    'passes with %s',
    async (authentication) => {
      const provider = await createFakeProvider({ issuer: EXAMPLE_PRESET_ISSUER });
      provider.register({
        clientId: CLIENT_ID,
        method: authentication,
        clientSecret: CLIENT_SECRET,
        redirectUris: [`https://realm.kit.invalid/upstream/${EXAMPLE_PRESET_TYPE}/callback`],
        // The kit's signer hands back a stand-in assertion.
        trustAssertion: (assertion) => assertion.split('.').length === 3,
      });
      const report = await checkAuthMethod(examplePresetMethod(), {
        config: presetConfig(authentication),
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
            iss: EXAMPLE_PRESET_ISSUER,
          },
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
});

describe('a sign-in through a preset (#951)', () => {
  async function presetHost(
    authentication: FakeClientAuthentication = 'client_secret_basic',
    config: unknown = presetConfig(authentication)
  ) {
    const provider = await createFakeProvider({ issuer: EXAMPLE_PRESET_ISSUER });
    const method = examplePresetMethod();
    const secrets = new Map<string, string>(
      authentication === 'private_key_jwt' ? [] : [[EXAMPLE_PRESET_SECRET_PATH, CLIENT_SECRET]]
    );
    const host = await testHost(method, config, provider, {
      signerClientId: CLIENT_ID,
      secrets,
    });
    provider.register({
      clientId: CLIENT_ID,
      method: authentication,
      clientSecret: CLIENT_SECRET,
      redirectUris: [CALLBACK],
      assertionKeys: async () => host.upstreamJwks,
    });
    return { provider, method, host };
  }

  function callbackRoute(method: AuthMethod): AuthMethodCallbackRoute {
    return method.routes.find(
      (route) => route.kind === 'callback' && route.method === 'GET'
    ) as AuthMethodCallbackRoute;
  }

  it("answers on the preset's own callback and signs the person in at its provider", async () => {
    const { provider, method, host } = await presetHost();
    expect(method.id).toBe(EXAMPLE_PRESET_ID);
    expect(method.type).toBe(EXAMPLE_PRESET_TYPE);

    const start = await startUpstreamStep(method, { uiLocales: [] }, host.context);
    const url = new URL(start.redirectTo);
    expect(`${url.origin}${url.pathname}`).toBe(provider.authorizationEndpoint);
    expect(url.searchParams.get('redirect_uri')).toBe(CALLBACK);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(start.transaction).toMatchObject({
      v: 1,
      type: EXAMPLE_PRESET_TYPE,
      issuer: EXAMPLE_PRESET_ISSUER,
      redirectUri: CALLBACK,
    });

    const outcome = await callbackRoute(method).handle(
      {
        method: 'GET',
        query: authMethodParameters(provider.authorize(url, PERSON)),
        form: authMethodParameters(undefined),
        transaction: start.transaction,
      },
      host.context
    );
    const completion = await completeUpstreamStep(method, outcome);
    expect(completion.kind).toBe('identity');
    const identity = (completion as { identity: { externalSub: string; rawClaims: object } })
      .identity;
    expect(identity.externalSub).toBe('user-1');
    expect(identity.rawClaims).toMatchObject({ iss: EXAMPLE_PRESET_ISSUER, sub: 'user-1' });
    expect(method.extractAttributes(identity as never)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          attrKey: 'email',
          attrValue: 'ada@example.com',
          source: EXAMPLE_PRESET_TYPE,
          verified: true,
        }),
      ])
    );
  });

  // Acceptance: its client secret is write-only end to end.
  it.each(['client_secret_basic', 'client_secret_post'] as const)(
    'sends the secret with %s only to the token endpoint, never in a log line or an egress label',
    async (authentication) => {
      const { provider, method, host } = await presetHost(authentication);
      const start = await startUpstreamStep(method, { uiLocales: [] }, host.context);
      // A refused callback logs: its line must not carry the secret either.
      await callbackRoute(method).handle(
        {
          method: 'GET',
          query: authMethodParameters({ state: 'x'.repeat(43) }),
          form: authMethodParameters(undefined),
          transaction: start.transaction,
        },
        host.context
      );
      await callbackRoute(method).handle(
        {
          method: 'GET',
          query: authMethodParameters(provider.authorize(new URL(start.redirectTo), PERSON)),
          form: authMethodParameters(undefined),
          transaction: start.transaction,
        },
        host.context
      );
      const spellings = secretSpellings(CLIENT_SECRET);
      const withSecret = host.egressCalls.filter((call) =>
        spellings.some((spelling) => callText(call).includes(spelling))
      );
      expect(withSecret.map((call) => call.url)).toEqual([provider.tokenEndpoint]);
      expect(provider.tokenRequests).toHaveLength(1);
      expect(host.logLines.length).toBeGreaterThan(0);
      for (const line of host.logLines) {
        const text = JSON.stringify(line);
        for (const spelling of spellings) expect(text).not.toContain(spelling);
      }
      for (const call of host.egressCalls) {
        expect(`${call.purpose} ${call.source}`).not.toContain(CLIENT_SECRET);
      }
    }
  );

  it('stores the secret apart from the plain members, and refuses it spelled among them', () => {
    const [path] = authMethodSecretPaths(examplePresetMethod());
    expect(path).toBe(EXAMPLE_PRESET_SECRET_PATH);
    const config = presetConfig('client_secret_post');
    const plain = withoutConfigMembers(config, [path]);
    expect(JSON.stringify(plain)).not.toContain(CLIENT_SECRET);
    expect(configSpellsMemberOf(config, [path])).toBe(true);
    expect(configSpellsMemberOf({ 'clientAuthentication.clientSecret': 'x' }, [path])).toBe(true);
    expect(configSpellsMemberOf(plain, [path])).toBe(false);
    // Put back from the secret store, the config parses again.
    const opened = withConfigMembers(plain, new Map([[path, CLIENT_SECRET]]));
    expect(parseAuthMethodConfig(examplePresetMethod(), opened)).toEqual({
      ...config,
      formPost: false,
    });
  });

  it('reaches its provider as a remote document: the egress allowlist never opens a private address for it', async () => {
    const { provider, method, host } = await presetHost();
    const start = await startUpstreamStep(method, { uiLocales: [] }, host.context);
    const outcome = await callbackRoute(method).handle(
      {
        method: 'GET',
        query: authMethodParameters(provider.authorize(new URL(start.redirectTo), PERSON)),
        form: authMethodParameters(undefined),
        transaction: start.transaction,
      },
      host.context
    );
    expect((outcome as { kind: string }).kind).toBe('result');
    // Discovery, the code exchange and the key set: every call of a sign-in.
    expect(host.egressCalls.map((call) => call.url)).toEqual(
      expect.arrayContaining([provider.discoveryUrl, provider.tokenEndpoint, provider.jwksUri])
    );
    expect(new Set(host.egressCalls.map((call) => call.source))).toEqual(
      new Set(['remote_document'])
    );
  });

  it.each<[string, Record<string, unknown>]>([
    ['token endpoint', { token_endpoint: 'https://tokens.attacker.example/token' }],
    ['authorization endpoint', { authorization_endpoint: 'https://attacker.example/authorize' }],
    ['JWKS URI', { jwks_uri: 'https://attacker.example/jwks' }],
    ['userinfo endpoint', { userinfo_endpoint: 'https://attacker.example/userinfo' }],
  ])(
    'refuses a discovery document that names its %s off the origins, and never calls it',
    async (name, discovery) => {
      const { provider, method, host } = await presetHost();
      provider.tamper.discovery = discovery;
      await expect(startUpstreamStep(method, { uiLocales: [] }, host.context)).rejects.toThrow(
        `the provider names its ${name} off the preset's origins`
      );
      expect(host.egressCalls.map((call) => call.url)).toEqual([provider.discoveryUrl]);
    }
  );

  it('refuses at the callback a discovery document that moved its token endpoint off the origins', async () => {
    const { provider, method, host } = await presetHost();
    const start = await startUpstreamStep(method, { uiLocales: [] }, host.context);
    // Another method of the same preset, as after a restart: it reads the
    // document again, which now sends the code, and the secret, elsewhere.
    const restarted = examplePresetMethod();
    provider.tamper.discovery = { token_endpoint: 'https://tokens.attacker.example/token' };
    const outcome = await callbackRoute(restarted).handle(
      {
        method: 'GET',
        query: authMethodParameters(provider.authorize(new URL(start.redirectTo), PERSON)),
        form: authMethodParameters(undefined),
        transaction: start.transaction,
      },
      host.context
    );
    expect(outcome).toEqual({ kind: 'failed', reason: 'invalid_response' });
    expect(provider.tokenRequests).toEqual([]);
    for (const call of host.egressCalls) {
      expect(new URL(call.url).origin).toBe(EXAMPLE_PRESET_ISSUER);
      for (const spelling of secretSpellings(CLIENT_SECRET)) {
        expect(callText(call)).not.toContain(spelling);
      }
    }
  });

  it('signs a client assertion for the preset as its provider', async () => {
    const { provider, method, host } = await presetHost('private_key_jwt');
    const start = await startUpstreamStep(method, { uiLocales: [] }, host.context);
    const outcome = await callbackRoute(method).handle(
      {
        method: 'GET',
        query: authMethodParameters(provider.authorize(new URL(start.redirectTo), PERSON)),
        form: authMethodParameters(undefined),
        transaction: start.transaction,
      },
      host.context
    );
    expect((outcome as { kind: string }).kind).toBe('result');
    expect(host.signerCalls.filter((call) => call.operation === 'signClientAssertion')).toEqual([
      expect.objectContaining({ caller: 'api', providerId: EXAMPLE_PRESET_TYPE }),
    ]);
  });

  it("refuses another method's transaction at its callback", async () => {
    const { provider, method, host } = await presetHost();
    const start = await startUpstreamStep(method, { uiLocales: [] }, host.context);
    const outcome = await callbackRoute(method).handle(
      {
        method: 'GET',
        query: authMethodParameters(provider.authorize(new URL(start.redirectTo), PERSON)),
        form: authMethodParameters(undefined),
        transaction: { ...start.transaction, type: 'oidc_corp' },
      },
      host.context
    );
    expect(outcome).toEqual({ kind: 'failed', reason: 'transaction_mismatch' });
  });
});

describe("the secret bound to the preset's provider (#951)", () => {
  const withDomain = z.strictObject({
    domain: z.string().min(1),
    clientId: z.string().min(1),
    clientSecret: z.string().min(1).meta({ writeOnly: true }),
  });
  type WithDomain = z.output<typeof withDomain>;

  const fromDomain = (config: WithDomain) => ({
    issuer: `https://${config.domain}`,
    clientId: config.clientId,
    clientAuthentication: { method: 'client_secret_basic', clientSecret: config.clientSecret },
  });

  it('takes a config whose provider is on its origins', () => {
    const method = presetWith(withDomain, fromDomain);
    expect(
      parseAuthMethodConfig(method, {
        domain: 'idp.example.com',
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
      })
    ).toMatchObject({ domain: 'idp.example.com' });
  });

  it('refuses a config that sends the provider, and the secret with it, to another host', () => {
    const method = presetWith(withDomain, fromDomain);
    const refusal = (() => {
      try {
        parseAuthMethodConfig(method, {
          domain: 'attacker.example',
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
        });
      } catch (error) {
        return error;
      }
      return undefined;
    })();
    expect(refusal).toBeInstanceOf(AuthMethodConfigError);
    expect(JSON.stringify(refusal)).not.toContain(CLIENT_SECRET);
    expect(String((refusal as Error).message)).not.toContain(CLIENT_SECRET);
  });

  it('refuses an endpoint set by hand off its origins, the issuer on them', () => {
    const schema = z.strictObject({ clientSecret: z.string().min(1).meta({ writeOnly: true }) });
    const method = presetWith(schema, (config: z.output<typeof schema>) => ({
      issuer: EXAMPLE_PRESET_ISSUER,
      clientId: CLIENT_ID,
      clientAuthentication: { method: 'client_secret_post', clientSecret: config.clientSecret },
      endpoints: {
        authorization: `${EXAMPLE_PRESET_ISSUER}/authorize`,
        token: 'https://tokens.attacker.example/token',
        jwks: `${EXAMPLE_PRESET_ISSUER}/jwks`,
      },
    }));
    expect(() => parseAuthMethodConfig(method, { clientSecret: CLIENT_SECRET })).toThrow(
      AuthMethodConfigError
    );
  });

  it('refuses a client secret taken from a member that is not secret, which would be stored in the clear', () => {
    const schema = z.strictObject({ clientId: z.string(), clientSecret: z.string().min(1) });
    const method = presetWith(schema, (config: z.output<typeof schema>) => ({
      issuer: EXAMPLE_PRESET_ISSUER,
      clientId: config.clientId,
      clientAuthentication: { method: 'client_secret_basic', clientSecret: config.clientSecret },
    }));
    expect(authMethodSecretPaths(method)).toEqual([]);
    expect(() =>
      parseAuthMethodConfig(method, { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET })
    ).toThrow(AuthMethodConfigError);
  });

  it.each<[string, string, (config: WithDomain) => unknown]>([
    [
      'the client id',
      'clientId',
      (config) => ({
        ...fromDomain(config),
        clientId: `${config.clientId}.${config.clientSecret}`,
      }),
    ],
    [
      "the issuer's path",
      'issuer',
      (config) => ({
        ...fromDomain(config),
        issuer: `https://${config.domain}/${config.clientSecret}`,
      }),
    ],
    [
      'a scope',
      'scopes.1',
      (config) => ({ ...fromDomain(config), scopes: ['openid', config.clientSecret] }),
    ],
  ])(
    "refuses a secret member's value in %s, which would go out in the clear",
    (_case, at, mapping) => {
      const method = presetWith(withDomain, mapping);
      const secret = 'secret-value-of-the-member';
      const config = { domain: 'idp.example.com', clientId: CLIENT_ID, clientSecret: secret };
      expect(() => parseAuthMethodConfig(method, config)).toThrow(AuthMethodConfigError);
      // The schema's own issue names where, never the value.
      const parsed = method.configSchema.safeParse(config);
      expect(parsed.success ? [] : parsed.error.issues.map((issue) => issue.message)).toEqual([
        `the provider config carries the value of a secret member at ${at}, which would be sent in the clear`,
      ]);
      expect(() => parseAuthMethodConfig(method, config)).not.toThrow(secret);
      // The same mapping without the secret in it parses.
      expect(parseAuthMethodConfig(presetWith(withDomain, fromDomain), config)).toEqual(config);
    }
  );

  it('refuses a config whose provider config does not parse, or whose mapping throws', () => {
    const schema = z.strictObject({ clientId: z.string() });
    const noOpenid = presetWith(schema, (config: z.output<typeof schema>) => ({
      issuer: EXAMPLE_PRESET_ISSUER,
      clientId: config.clientId,
      clientAuthentication: { method: 'private_key_jwt' },
      scopes: ['email'],
    }));
    expect(() => parseAuthMethodConfig(noOpenid, { clientId: CLIENT_ID })).toThrow(
      AuthMethodConfigError
    );
    const throwing = presetWith(schema, () => {
      throw new Error(`a mapping bug near ${CLIENT_SECRET}`);
    });
    // The mapping's own error, which may hold a value, is not passed on.
    expect(() => parseAuthMethodConfig(throwing, { clientId: CLIENT_ID })).toThrow(
      AuthMethodConfigError
    );
    expect(() => parseAuthMethodConfig(throwing, { clientId: CLIENT_ID })).not.toThrow(
      CLIENT_SECRET
    );
  });
});

describe('createUpstreamOidcPresetMethod (#951)', () => {
  const base = {
    id: 'example-idp',
    type: 'example_idp',
    display: { name: 'Example IdP' },
    origins: [EXAMPLE_PRESET_ISSUER],
    configSchema: z.strictObject({ clientId: z.string() }),
    upstreamConfig: (config: { clientId: string }) => ({
      issuer: EXAMPLE_PRESET_ISSUER,
      clientId: config.clientId,
      clientAuthentication: { method: 'private_key_jwt' as const },
    }),
  };

  it.each<[string, Record<string, unknown>]>([
    ["the generic client's id", { id: 'oidc' }],
    ['an id outside the contract', { id: 'Example IdP' }],
    ["a type in the generic client's namespace", { type: 'oidc_example' }],
    ['a type outside the contract', { type: 'example-idp' }],
    ['no origins', { origins: [] }],
    ['an http origin', { origins: ['http://idp.example.com'] }],
    ['an origin with a path', { origins: ['https://idp.example.com/tenant'] }],
    ['an origin list that is no list', { origins: 'https://idp.example.com' }],
    ['a mapping that is no function', { upstreamConfig: 'issuer' }],
  ])('refuses %s', (_case, change) => {
    expect(() => createUpstreamOidcPresetMethod({ ...base, ...change } as never)).toThrow(
      TypeError
    );
  });

  it('builds a method of its own id, type and config', () => {
    const method = createUpstreamOidcPresetMethod(base);
    expect(method).toMatchObject({ id: 'example-idp', type: 'example_idp' });
    expect(method.routes.map((route) => `${route.method} ${route.path} ${route.kind}`)).toEqual([
      'GET /callback callback',
      'POST /callback bounce',
    ]);
    expect(parseAuthMethodConfig(method, { clientId: CLIENT_ID })).toEqual({ clientId: CLIENT_ID });
  });
});
