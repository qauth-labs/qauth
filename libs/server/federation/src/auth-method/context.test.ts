import { afterEach, describe, expect, it, vi } from 'vitest';

import { createSampleAuthMethod, SAMPLE_CONFIG } from '../../testing/sample-auth-method.fixture';
import { type AuthMethodContextParts, createAuthMethodContext } from './context';
import { AuthMethodConfigError } from './errors';

/**
 * What a method is handed (ADR-019 Decision 12): its config, the egress client,
 * the signer role and a logger. These tests hand the builder objects shaped like
 * the WHOLE ones a host has (an egress client that takes a realm and caps, a
 * signer whose calls name caller, realm and provider, with decrypt beside them,
 * a logger with `child`) and check that only the contract's members come out,
 * with the realm, the provider and the caller fixed by the host.
 */
function hostObjects() {
  const egress = {
    request: vi.fn(async (_request: unknown) => ({
      status: 200,
      headers: {},
      body: new Uint8Array(),
      url: 'https://provider.example/token',
    })),
    validateDestination: vi.fn(),
    counts: vi.fn(),
  };
  const signer = {
    signClientAssertion: vi.fn(async (_caller: string, _request: unknown) => 'a.b.c'),
    getUpstreamJwks: vi.fn(async (_caller: string, _realmId: string, _providerId: string) => ({
      keys: [{ kty: 'RSA' }],
    })),
    decrypt: vi.fn(),
    encrypt: vi.fn(),
    signJws: vi.fn(),
    getCookieSecrets: vi.fn(),
  };
  const log = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: vi.fn(),
    pool: { query: vi.fn() },
  };
  return { egress, signer, log };
}

function parts(overrides: Partial<AuthMethodContextParts> = {}) {
  const host = hostObjects();
  const all = {
    config: SAMPLE_CONFIG,
    origin: 'https://auth.example.com',
    realmName: 'acme',
    realmId: '0190a5c4-0000-7000-8000-000000000001',
    providerId: 'oidc_sample',
    signerCaller: 'api',
    ...host,
    ...overrides,
  };
  return { host, parts: all };
}

describe('createAuthMethodContext', () => {
  it('hands a method exactly its config, egress, signer, logger and route URLs', () => {
    const { parts: given } = parts();
    const context = createAuthMethodContext(createSampleAuthMethod(), given);

    expect(Object.keys(context).sort()).toEqual(['config', 'egress', 'log', 'routeUrl', 'signer']);
    expect(Object.keys(context.egress)).toEqual(['request']);
    expect(Object.keys(context.signer).sort()).toEqual(['getUpstreamJwks', 'signClientAssertion']);
    expect(Object.keys(context.log).sort()).toEqual(['debug', 'error', 'info', 'warn']);
    for (const value of [context, context.egress, context.signer, context.log]) {
      expect(Object.isFrozen(value)).toBe(true);
      expect(value).not.toHaveProperty('decrypt');
      expect(value).not.toHaveProperty('child');
      expect(value).not.toHaveProperty('pool');
      expect(value).not.toHaveProperty('validateDestination');
    }
  });

  it("passes on only the contract's egress members and adds the realm itself", async () => {
    const { host, parts: given } = parts();
    const context = createAuthMethodContext(createSampleAuthMethod(), given);
    // A method that tries to pick another realm, lift the caps or add a member.
    await context.egress.request({
      method: 'POST',
      url: 'https://provider.example/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'code=x',
      purpose: 'upstream-token',
      source: 'admin',
      realm: 'other-realm',
      limits: { maxResponseBytes: 1e12 },
      extra: true,
    } as never);

    expect(host.egress.request).toHaveBeenCalledTimes(1);
    expect(host.egress.request.mock.calls[0]).toEqual([
      {
        method: 'POST',
        url: 'https://provider.example/token',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'code=x',
        purpose: 'upstream-token',
        source: 'admin',
        realm: 'acme',
      },
    ]);
  });

  it('refuses an egress method or source the contract does not name, without calling out', async () => {
    const { host, parts: given } = parts();
    const context = createAuthMethodContext(createSampleAuthMethod(), given);
    const base = { url: 'https://provider.example/', purpose: 'upstream-token' };
    await expect(
      context.egress.request({ ...base, method: 'DELETE', source: 'admin' } as never)
    ).rejects.toThrow(TypeError);
    await expect(
      context.egress.request({ ...base, method: 'GET', source: 'client' } as never)
    ).rejects.toThrow(TypeError);
    await expect(
      context.egress.request({ ...base, method: 'GET', source: 'end_user' } as never)
    ).rejects.toThrow(TypeError);
    expect(host.egress.request).not.toHaveBeenCalled();
  });

  it('signs for this realm, this provider and the host caller role only', async () => {
    const { host, parts: given } = parts();
    const context = createAuthMethodContext(createSampleAuthMethod(), given);
    await context.signer.signClientAssertion({
      audience: 'https://provider.example',
      claims: { exp: 1, jti: 'j' },
      algorithm: 'ES256',
      realmId: 'other-realm',
      providerId: 'other-provider',
    } as never);
    await (context.signer.getUpstreamJwks as (...args: unknown[]) => Promise<unknown>)(
      'local',
      'other-realm',
      'other-provider'
    );

    expect(host.signer.signClientAssertion.mock.calls[0]).toEqual([
      'api',
      {
        realmId: '0190a5c4-0000-7000-8000-000000000001',
        providerId: 'oidc_sample',
        audience: 'https://provider.example',
        claims: { exp: 1, jti: 'j', iat: expect.any(Number) },
        algorithm: 'ES256',
      },
    ]);
    expect(host.signer.getUpstreamJwks.mock.calls[0]).toEqual([
      'api',
      '0190a5c4-0000-7000-8000-000000000001',
      'oidc_sample',
    ]);
    await expect(
      context.signer.signClientAssertion({ audience: 'x', claims: {}, algorithm: 'HS256' } as never)
    ).rejects.toThrow(TypeError);
  });

  describe('client assertions', () => {
    const NOW = 1_800_000_000;
    afterEach(() => {
      vi.useRealTimers();
    });

    async function signed(claims: Record<string, unknown>) {
      vi.useFakeTimers();
      vi.setSystemTime(NOW * 1000);
      const { host, parts: given } = parts();
      const context = createAuthMethodContext(createSampleAuthMethod(), given);
      await context.signer.signClientAssertion({ audience: 'https://provider.example', claims });
      return (host.signer.signClientAssertion.mock.calls[0][1] as { claims: unknown }).claims;
    }

    it('lowers an exp past five minutes from now to five minutes from now', async () => {
      expect(await signed({ exp: NOW + 86_400, jti: 'j' })).toEqual({
        exp: NOW + 300,
        jti: 'j',
        iat: NOW,
      });
      expect(await signed({ exp: NOW + 120, jti: 'j' })).toEqual({
        exp: NOW + 120,
        jti: 'j',
        iat: NOW,
      });
    });

    it('sets iat when the claims carry none, and keeps a past one', async () => {
      expect(await signed({ exp: NOW + 60, jti: 'j', iat: NOW - 5 })).toEqual({
        exp: NOW + 60,
        jti: 'j',
        iat: NOW - 5,
      });
    });

    it('refuses an iat that is not a time or lies in the future, without signing', async () => {
      vi.useFakeTimers();
      vi.setSystemTime(NOW * 1000);
      const { host, parts: given } = parts();
      const context = createAuthMethodContext(createSampleAuthMethod(), given);
      for (const iat of ['now', Number.NaN, NOW + 3600]) {
        await expect(
          context.signer.signClientAssertion({
            audience: 'https://provider.example',
            claims: { exp: NOW + 60, jti: 'j', iat },
          })
        ).rejects.toThrow(TypeError);
      }
      await expect(
        context.signer.signClientAssertion({ audience: 'x', claims: null as never })
      ).rejects.toThrow(TypeError);
      expect(host.signer.signClientAssertion).not.toHaveBeenCalled();
    });
  });

  describe('the egress source', () => {
    async function sentSource(url: string, source: 'operator' | 'admin' | 'remote_document') {
      const { host, parts: given } = parts();
      const context = createAuthMethodContext(createSampleAuthMethod(), given);
      await context.egress.request({ method: 'GET', url, purpose: 'upstream-discovery', source });
      return (host.egress.request.mock.calls[0][0] as { source: string }).source;
    }

    it.each(['operator', 'admin'] as const)(
      'keeps %s for a URL on the origin of a URL the config holds',
      async (source) => {
        // SAMPLE_CONFIG names https://provider.example/authorize and /token.
        expect(await sentSource('https://provider.example/.well-known/jwks.json', source)).toBe(
          source
        );
      }
    );

    it.each(['operator', 'admin'] as const)(
      'sends %s for any other destination as remote_document, which the allowlist never covers',
      async (source) => {
        for (const url of [
          'https://internal.corp.example/metadata',
          'https://provider.example:8443/token',
          'http://provider.example/token',
          'not a url',
        ]) {
          expect(await sentSource(url, source)).toBe('remote_document');
        }
      }
    );

    it('keeps remote_document as it is', async () => {
      expect(await sentSource('https://provider.example/jwks', 'remote_document')).toBe(
        'remote_document'
      );
    });
  });

  describe('the logger', () => {
    it('logs through the four levels with a message and the fields nested under authMethod', () => {
      const { host, parts: given } = parts();
      const context = createAuthMethodContext(createSampleAuthMethod(), given);
      (context.log.warn as (...args: unknown[]) => void)({ a: 1 }, 'message', 'extra');
      expect(host.log.warn.mock.calls[0]).toEqual([{ authMethod: { a: 1 } }, 'message']);
    });

    it("never lets a method overwrite the host's fields of the line", () => {
      const { host, parts: given } = parts();
      const context = createAuthMethodContext(createSampleAuthMethod(), given);
      context.log.info({ reqId: 'forged', realm: 'other', msg: 'x' }, 'calling');
      const [fields] = host.log.info.mock.calls[0] as [Record<string, unknown>];
      expect(Object.keys(fields)).toEqual(['authMethod']);
    });

    it('redacts secrets at any depth, whatever their case', () => {
      const { host, parts: given } = parts();
      const context = createAuthMethodContext(createSampleAuthMethod(), given);
      const secrets = {
        code: 'secret-code-1',
        verifier: 'secret-verifier-2',
        clientSecret: 'secret-client-3',
        idToken: 'secret-id-token-4',
        accessToken: 'secret-access-5',
        refreshToken: 'secret-refresh-6',
        nonce: 'secret-nonce-7',
        password: 'secret-password-8',
        assertion: 'secret-assertion-9',
        nested: 'secret-access-10',
      };
      context.log.error(
        {
          code: secrets.code,
          request: {
            form: {
              Code_Verifier: secrets.verifier,
              client_secret: secrets.clientSecret,
              grant_type: 'authorization_code',
            },
            answers: [
              {
                id_token: secrets.idToken,
                access_token: secrets.accessToken,
                refresh_token: secrets.refreshToken,
              },
            ],
          },
          NONCE: secrets.nonce,
          password: secrets.password,
          client_assertion: secrets.assertion,
          err: Object.assign(new Error('token call failed'), {
            body: { access_token: secrets.nested },
          }),
        },
        'token call failed'
      );
      const [fields] = host.log.error.mock.calls[0] as [{ authMethod: Record<string, unknown> }];
      const line = JSON.stringify(fields);
      for (const secret of Object.values(secrets)) expect(line).not.toContain(secret);
      expect(fields.authMethod['request']).toEqual({
        form: {
          Code_Verifier: '[Redacted]',
          client_secret: '[Redacted]',
          grant_type: 'authorization_code',
        },
        answers: [
          { id_token: '[Redacted]', access_token: '[Redacted]', refresh_token: '[Redacted]' },
        ],
      });
      expect(fields.authMethod['err']).toMatchObject({
        type: 'Error',
        message: 'token call failed',
        body: { access_token: '[Redacted]' },
      });
    });

    it('copies a cycle and a deep nesting without throwing', () => {
      const { host, parts: given } = parts();
      const context = createAuthMethodContext(createSampleAuthMethod(), given);
      const cyclic: Record<string, unknown> = { name: 'loop' };
      cyclic['self'] = cyclic;
      let deep: Record<string, unknown> = { code: 'deep-code' };
      for (let i = 0; i < 20; i += 1) deep = { inner: deep };
      context.log.debug({ cyclic, deep }, 'shapes');
      const line = JSON.stringify(host.log.debug.mock.calls[0][0]);
      expect(line).toContain('[Circular]');
      expect(line).toContain('[Truncated]');
      expect(line).not.toContain('deep-code');
    });
  });

  it('parses the config with the method schema, and freezes a copy', () => {
    const config = { ...SAMPLE_CONFIG, unknownMember: 'dropped' };
    const { parts: given } = parts({ config });
    const context = createAuthMethodContext(createSampleAuthMethod(), given);
    expect(context.config).toEqual(SAMPLE_CONFIG);
    expect(Object.isFrozen(context.config)).toBe(true);
    expect(Object.isFrozen(config)).toBe(false);
  });

  it.each([
    ['a Map', new Map([['k', 'v']])],
    ['a Set', new Set(['v'])],
    ['a Date', new Date()],
    ['a class instance', new (class Settings {})()],
  ])('refuses a parsed config holding %s, which does not freeze', (_label, value) => {
    const method = {
      ...createSampleAuthMethod(),
      configSchema: { safeParse: () => ({ success: true, data: { nested: { value } } }) },
    } as unknown as Parameters<typeof createAuthMethodContext>[0];
    const { parts: given } = parts();
    try {
      createAuthMethodContext(method, given);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AuthMethodConfigError);
      expect((error as AuthMethodConfigError).issues).toEqual([
        'nested.value: not plain data (a Map, Set, Date or class instance does not freeze)',
      ]);
    }
  });

  it('refuses a config the schema refuses, naming members and never their values', () => {
    const { parts: given } = parts({
      config: { ...SAMPLE_CONFIG, clientSecret: '', tokenEndpoint: 'not a url' },
    });
    try {
      createAuthMethodContext(createSampleAuthMethod(), given);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AuthMethodConfigError);
      expect((error as AuthMethodConfigError).issues).toEqual([
        'tokenEndpoint: invalid_format',
        'clientSecret: too_small',
      ]);
      expect(JSON.stringify(error)).not.toContain('not a url');
    }
  });

  it("builds route URLs under the method's prefix on the realm origin, and nowhere else", () => {
    const { parts: given } = parts();
    const context = createAuthMethodContext(createSampleAuthMethod({ type: 'oidc_corp' }), given);
    expect(context.routeUrl('/callback')).toBe(
      'https://auth.example.com/upstream/oidc_corp/callback'
    );
    // A path the method does not declare is refused too, however well formed:
    // a redirect_uri must name a route that is mounted.
    for (const path of ['/../oauth/token', 'callback', '//evil.example', '/%2e%2e', '/other']) {
      expect(() => context.routeUrl(path)).toThrow(TypeError);
    }
  });

  it('refuses an origin that is not a bare origin', () => {
    for (const origin of [
      'https://auth.example.com/',
      'https://auth.example.com/x',
      'auth.example.com',
    ]) {
      const { parts: given } = parts({ origin });
      expect(() => createAuthMethodContext(createSampleAuthMethod(), given)).toThrow();
    }
  });
});
