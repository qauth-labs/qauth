import { describe, expect, it, vi } from 'vitest';

import { createSampleAuthMethod, SAMPLE_CONFIG } from '../../testing/sample-auth-method.fixture';
import { createAuthMethodContext } from './context';
import { AuthMethodConfigError } from './errors';

/**
 * What a method is handed (ADR-019 Decision 12): its config, the egress client,
 * the signer role and a logger. These tests hand the builder the WHOLE objects a
 * host has (an egress client with its checks and counters, a signer with
 * decrypt and the cookie secrets, a logger with `child`, and stray handles) and
 * check that only the contract's members come out.
 */
function wholeObjects() {
  const egress = {
    request: vi.fn(async () => ({ status: 200, headers: {}, body: new Uint8Array(), url: 'x' })),
    validateDestination: vi.fn(),
    counts: vi.fn(),
  };
  const signer = {
    signClientAssertion: vi.fn(async () => 'a.b.c'),
    getUpstreamJwks: vi.fn(async () => ({ keys: [] })),
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

describe('createAuthMethodContext', () => {
  it('hands a method exactly its config, egress, signer, logger and route URLs', () => {
    const { egress, signer, log } = wholeObjects();
    const context = createAuthMethodContext(createSampleAuthMethod(), {
      config: SAMPLE_CONFIG,
      origin: 'https://auth.example.com',
      egress,
      signer,
      log,
    });

    expect(Object.keys(context).sort()).toEqual(['config', 'egress', 'log', 'routeUrl', 'signer']);
    expect(Object.keys(context.egress)).toEqual(['request']);
    expect(Object.keys(context.signer).sort()).toEqual(['getUpstreamJwks', 'signClientAssertion']);
    expect(Object.keys(context.log).sort()).toEqual(['debug', 'error', 'info', 'warn']);
    // Nothing reachable through the copies: no decrypt, no child logger, no pool.
    for (const value of [context, context.egress, context.signer, context.log]) {
      expect(Object.isFrozen(value)).toBe(true);
      expect(value).not.toHaveProperty('decrypt');
      expect(value).not.toHaveProperty('child');
      expect(value).not.toHaveProperty('pool');
      expect(value).not.toHaveProperty('validateDestination');
    }
  });

  it('calls through to the objects it was given', async () => {
    const { egress, signer, log } = wholeObjects();
    const context = createAuthMethodContext(createSampleAuthMethod(), {
      config: SAMPLE_CONFIG,
      origin: 'https://auth.example.com',
      egress,
      signer,
      log,
    });
    await context.egress.request({
      method: 'GET',
      url: 'https://provider.example/.well-known/openid-configuration',
      purpose: 'upstream-discovery',
      source: 'admin',
    });
    await context.signer.signClientAssertion({ audience: 'https://provider.example', claims: {} });
    context.log.warn({ a: 1 }, 'message');

    expect(egress.request).toHaveBeenCalledTimes(1);
    expect(signer.signClientAssertion).toHaveBeenCalledTimes(1);
    expect(log.warn).toHaveBeenCalledWith({ a: 1 }, 'message');
  });

  it('parses the config with the method schema and freezes it', () => {
    const { egress, signer, log } = wholeObjects();
    const context = createAuthMethodContext(createSampleAuthMethod(), {
      config: { ...SAMPLE_CONFIG, unknownMember: 'dropped' },
      origin: 'https://auth.example.com',
      egress,
      signer,
      log,
    });
    expect(context.config).toEqual(SAMPLE_CONFIG);
    expect(Object.isFrozen(context.config)).toBe(true);
  });

  it('refuses a config the schema refuses, naming members and never their values', () => {
    const { egress, signer, log } = wholeObjects();
    try {
      createAuthMethodContext(createSampleAuthMethod(), {
        config: { ...SAMPLE_CONFIG, clientSecret: '', tokenEndpoint: 'not a url' },
        origin: 'https://auth.example.com',
        egress,
        signer,
        log,
      });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AuthMethodConfigError);
      const issues = (error as AuthMethodConfigError).issues;
      expect(issues).toEqual(['tokenEndpoint: invalid_format', 'clientSecret: too_small']);
      expect(JSON.stringify(error)).not.toContain('not a url');
    }
  });

  it("builds route URLs under the method's prefix on the realm origin, and nowhere else", () => {
    const { egress, signer, log } = wholeObjects();
    const context = createAuthMethodContext(createSampleAuthMethod({ type: 'oidc_corp' }), {
      config: SAMPLE_CONFIG,
      origin: 'https://auth.example.com',
      egress,
      signer,
      log,
    });
    expect(context.routeUrl('/callback')).toBe(
      'https://auth.example.com/upstream/oidc_corp/callback'
    );
    for (const path of ['/../oauth/token', 'callback', '//evil.example', '/%2e%2e']) {
      expect(() => context.routeUrl(path)).toThrow(TypeError);
    }
  });

  it('refuses an origin that is not a bare origin', () => {
    const { egress, signer, log } = wholeObjects();
    for (const origin of [
      'https://auth.example.com/',
      'https://auth.example.com/x',
      'auth.example.com',
    ]) {
      expect(() =>
        createAuthMethodContext(createSampleAuthMethod(), {
          config: SAMPLE_CONFIG,
          origin,
          egress,
          signer,
          log,
        })
      ).toThrow();
    }
  });
});
