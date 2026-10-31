import { describe, expect, it } from 'vitest';

import {
  CONFIG_KEY_REGISTRY,
  type EnvDeprecationWarning,
  KeyAliasConflictError,
  readConfiguredEnv,
} from '../registry';
import { authEnvSchema } from './auth';

/**
 * REQUIRE_VERIFIED_ACCOUNT replaced REQUIRE_EMAIL_VERIFIED on 2026-10-09.
 *
 * Email is a user attribute, not the trust gate; the gate is a verified
 * account. The old name stays a working alias through the 1.x deprecation
 * window. These tests pin the alias, its boot warning, and the refusal when
 * the two names disagree.
 *
 * The alias is the configuration key registry's (`applyKeyAliases`), applied
 * before `authEnvSchema` sees the environment, exactly as the auth server
 * reads it.
 */
type Resolution =
  | {
      readonly ok: true;
      readonly requireVerifiedAccount: boolean;
      readonly deprecation: EnvDeprecationWarning | undefined;
    }
  | { readonly ok: false; readonly message: string };

function resolve(raw: Record<string, string | undefined>): Resolution {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (value !== undefined) env[key] = value;
  }
  try {
    const configured = readConfiguredEnv(CONFIG_KEY_REGISTRY, env);
    return {
      ok: true,
      requireVerifiedAccount: configured.parse(authEnvSchema).REQUIRE_VERIFIED_ACCOUNT,
      deprecation: configured.deprecations[0],
    };
  } catch (error) {
    if (!(error instanceof KeyAliasConflictError)) throw error;
    return { ok: false, message: error.message };
  }
}

describe('authEnvSchema verified-account flags', () => {
  const parse = (name: 'REQUIRE_VERIFIED_ACCOUNT' | 'REQUIRE_EMAIL_VERIFIED', raw?: string) =>
    readConfiguredEnv(CONFIG_KEY_REGISTRY, raw === undefined ? {} : { [name]: raw }).parse(
      authEnvSchema
    ).REQUIRE_VERIFIED_ACCOUNT;

  it.each(['REQUIRE_VERIFIED_ACCOUNT', 'REQUIRE_EMAIL_VERIFIED'] as const)(
    '%s parses "true" and "false" strictly (not the z.coerce.boolean footgun)',
    (name) => {
      expect(parse(name, 'true')).toBe(true);
      expect(parse(name, 'false')).toBe(false);
    }
  );

  it.each(['REQUIRE_VERIFIED_ACCOUNT', 'REQUIRE_EMAIL_VERIFIED'] as const)(
    '%s reads unset and blank as "not set", which is the default, true',
    (name) => {
      // Blank is what `${VAR:-}` in docker-compose.yml expands to.
      expect(parse(name)).toBe(true);
      expect(parse(name, '')).toBe(true);
      expect(parse(name, '   ')).toBe(true);
    }
  );

  it.each(['REQUIRE_VERIFIED_ACCOUNT', 'REQUIRE_EMAIL_VERIFIED'] as const)(
    '%s rejects a value other than true or false',
    (name) => {
      expect(() => parse(name, '0')).toThrow(new RegExp(name));
      expect(() => parse(name, 'TRUE')).toThrow(new RegExp(name));
    }
  );
});

describe('the REQUIRE_EMAIL_VERIFIED alias', () => {
  // Default true since 2026-10-19 (ANT-2026-SPEMY9GU): with the gate off,
  // registering an address and then logging in with the chosen password told
  // a free address (200) from a registered one (401).
  it('defaults to true with no warning when neither name is set', () => {
    expect(resolve({})).toEqual({
      ok: true,
      requireVerifiedAccount: true,
      deprecation: undefined,
    });
  });

  it('defaults to true when both names are forwarded blank, as docker-compose.yml does', () => {
    expect(resolve({ REQUIRE_VERIFIED_ACCOUNT: '', REQUIRE_EMAIL_VERIFIED: '' })).toEqual({
      ok: true,
      requireVerifiedAccount: true,
      deprecation: undefined,
    });
  });

  it.each([
    ['true', true],
    ['false', false],
  ])('uses REQUIRE_VERIFIED_ACCOUNT=%s on its own, with no warning', (raw, expected) => {
    expect(resolve({ REQUIRE_VERIFIED_ACCOUNT: raw })).toEqual({
      ok: true,
      requireVerifiedAccount: expected,
      deprecation: undefined,
    });
  });

  it.each([
    ['true', true],
    ['false', false],
  ])('honours the deprecated REQUIRE_EMAIL_VERIFIED=%s on its own', (raw, expected) => {
    const resolution = resolve({ REQUIRE_EMAIL_VERIFIED: raw });

    expect(resolution.ok).toBe(true);
    expect(resolution.ok && resolution.requireVerifiedAccount).toBe(expected);
  });

  it('warns at boot when only the deprecated name is set', () => {
    const resolution = resolve({ REQUIRE_EMAIL_VERIFIED: 'true' });

    expect(resolution.ok && resolution.deprecation).toEqual({
      variable: 'REQUIRE_EMAIL_VERIFIED',
      replacement: 'REQUIRE_VERIFIED_ACCOUNT',
      message: expect.stringMatching(/deprecated.*Rename it to REQUIRE_VERIFIED_ACCOUNT/),
    });
  });

  it.each(['true', 'false'])(
    'accepts both names set to the same value (%s), and still warns about the old one',
    (raw) => {
      const resolution = resolve({ REQUIRE_VERIFIED_ACCOUNT: raw, REQUIRE_EMAIL_VERIFIED: raw });

      expect(resolution.ok && resolution.requireVerifiedAccount).toBe(raw === 'true');
      expect(resolution.ok && resolution.deprecation).toMatchObject({
        variable: 'REQUIRE_EMAIL_VERIFIED',
        message: expect.stringMatching(/Remove REQUIRE_EMAIL_VERIFIED/),
      });
    }
  );

  it.each([
    ['true', 'false'],
    ['false', 'true'],
  ])(
    'refuses REQUIRE_VERIFIED_ACCOUNT=%s with REQUIRE_EMAIL_VERIFIED=%s, naming both',
    (current, alias) => {
      const resolution = resolve({
        REQUIRE_VERIFIED_ACCOUNT: current,
        REQUIRE_EMAIL_VERIFIED: alias,
      });

      expect(resolution.ok).toBe(false);
      expect(!resolution.ok && resolution.message).toContain(
        `REQUIRE_VERIFIED_ACCOUNT=${current} and REQUIRE_EMAIL_VERIFIED=${alias} disagree`
      );
    }
  );

  it('treats a blank deprecated name as unset, so compose forwarding it cannot conflict', () => {
    expect(resolve({ REQUIRE_VERIFIED_ACCOUNT: 'true', REQUIRE_EMAIL_VERIFIED: '' })).toEqual({
      ok: true,
      requireVerifiedAccount: true,
      deprecation: undefined,
    });
  });
});

/**
 * How many OAuth clients one developer account may own. `GET /api/clients`
 * returns all of them in one response, so with no ceiling a self-registered
 * account could store enough rows to run the process out of heap.
 */
describe('authEnvSchema MAX_CLIENTS_PER_DEVELOPER', () => {
  const parse = (raw?: string) =>
    authEnvSchema.parse(raw === undefined ? {} : { MAX_CLIENTS_PER_DEVELOPER: raw })
      .MAX_CLIENTS_PER_DEVELOPER;

  it('defaults to 100', () => {
    expect(parse()).toBe(100);
  });

  it('accepts a positive integer', () => {
    expect(parse('1')).toBe(1);
    expect(parse('5000')).toBe(5000);
  });

  it('refuses zero, a negative, a fraction or a non-number, so it can never mean "no limit"', () => {
    for (const raw of ['0', '-1', '1.5', 'unlimited']) {
      expect(() => parse(raw), raw).toThrow();
    }
  });
});

/**
 * DEFAULT_DYNAMIC_REGISTRATION_SCOPES seeds a realm's dynamic registration
 * allowlist, which may never hold a scope in the reserved `qauth:` namespace
 * (#507, ADR-019 Decision 7).
 */
describe('authEnvSchema DEFAULT_DYNAMIC_REGISTRATION_SCOPES', () => {
  const parse = (raw?: string) =>
    authEnvSchema.parse(raw === undefined ? {} : { DEFAULT_DYNAMIC_REGISTRATION_SCOPES: raw })
      .DEFAULT_DYNAMIC_REGISTRATION_SCOPES;

  it('defaults to the OIDC core scopes', () => {
    expect(parse()).toEqual(['openid', 'profile', 'email', 'offline_access']);
  });

  it('splits on spaces and commas', () => {
    expect(parse('openid, mcp:read  mcp:write')).toEqual(['openid', 'mcp:read', 'mcp:write']);
  });

  // Other servers' scopes that look administrative are ordinary scopes.
  it('accepts admin: scopes and scopes that only contain "qauth"', () => {
    expect(parse('openid admin:read admin:org example:qauth qauthx:read')).toEqual([
      'openid',
      'admin:read',
      'admin:org',
      'example:qauth',
      'qauthx:read',
    ]);
  });

  it.each([
    'openid qauth:admin:read',
    'qauth:admin:write',
    'openid,qauth:admin:security',
    'QAUTH:admin:read',
    'qauth:custom',
  ])('refuses the boot for %j, naming the reserved scope', (raw) => {
    const result = authEnvSchema.safeParse({ DEFAULT_DYNAMIC_REGISTRATION_SCOPES: raw });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toMatch(
      /^DEFAULT_DYNAMIC_REGISTRATION_SCOPES lists "[^"]+": the "qauth:" scope namespace is reserved/
    );
  });
});

/**
 * SESSION_LAST_SEEN_INTERVAL (ADR-019 Decision 3, issue #469): how often, at
 * most, a browser session's `last_seen_at` is written. One minute by default,
 * as ADR-019 decides; the operator may change it.
 */
describe('authEnvSchema SESSION_LAST_SEEN_INTERVAL', () => {
  const parse = (raw?: string) =>
    authEnvSchema.parse(raw === undefined ? {} : { SESSION_LAST_SEEN_INTERVAL: raw })
      .SESSION_LAST_SEEN_INTERVAL;

  it('defaults to 60 seconds', () => {
    expect(parse()).toBe(60);
  });

  it('accepts whole seconds from 1 to a day', () => {
    expect(parse('1')).toBe(1);
    expect(parse('300')).toBe(300);
    expect(parse('86400')).toBe(86_400);
  });

  it('refuses zero, a negative, a fraction, more than a day or a non-number', () => {
    for (const raw of ['0', '-1', '1.5', '86401', 'often']) {
      expect(() => parse(raw), raw).toThrow();
    }
  });
});

/**
 * INTERACTION_TTL (ADR-019 Decision 6, issue #592): how long an interaction
 * of the Interaction API lives. Thirty minutes by default, as the issue
 * decides; the operator may change it within a minute and two hours.
 */
describe('authEnvSchema INTERACTION_TTL', () => {
  const parse = (raw?: string) =>
    authEnvSchema.parse(raw === undefined ? {} : { INTERACTION_TTL: raw }).INTERACTION_TTL;

  it('defaults to 30 minutes', () => {
    expect(parse()).toBe(1800);
  });

  it('accepts whole seconds from a minute to two hours', () => {
    expect(parse('60')).toBe(60);
    expect(parse('900')).toBe(900);
    expect(parse('7200')).toBe(7200);
  });

  it('refuses less than a minute, more than two hours, a fraction or a non-number', () => {
    for (const raw of ['0', '59', '-60', '90.5', '7201', 'long']) {
      expect(() => parse(raw), raw).toThrow();
    }
  });
});

/**
 * The ID-JAG issuer key cache and its two bounds (#433, ADR-011 §4). The cache
 * TTL has a hard ceiling of an hour, as `CIMD_CACHE_MAX_TTL` is for CIMD, and a
 * larger value fails validation instead of being clamped. The refresh cooldown
 * and the negative cache are short, and neither can be switched off.
 */
describe('authEnvSchema ID-JAG issuer key cache', () => {
  const parse = (key: string, raw?: string) =>
    (authEnvSchema.parse(raw === undefined ? {} : { [key]: raw }) as Record<string, unknown>)[key];

  it('defaults to a 5-minute cache, a 30-second cooldown and a 30-second negative cache', () => {
    expect(parse('ID_JAG_JWKS_CACHE_TTL')).toBe(300);
    expect(parse('ID_JAG_JWKS_REFRESH_COOLDOWN')).toBe(30);
    expect(parse('ID_JAG_JWKS_NEGATIVE_CACHE_TTL')).toBe(30);
  });

  it('accepts a cache TTL from 0 up to the one-hour ceiling', () => {
    expect(parse('ID_JAG_JWKS_CACHE_TTL', '0')).toBe(0);
    expect(parse('ID_JAG_JWKS_CACHE_TTL', '3600')).toBe(3600);
  });

  it('refuses a cache TTL above the ceiling, rather than clamping it', () => {
    for (const raw of ['3601', '86400', '-1', '1.5', 'forever']) {
      expect(() => parse('ID_JAG_JWKS_CACHE_TTL', raw), raw).toThrow();
    }
  });

  it.each(['ID_JAG_JWKS_REFRESH_COOLDOWN', 'ID_JAG_JWKS_NEGATIVE_CACHE_TTL'])(
    '%s accepts whole seconds from 1 to 300 and refuses 0, so it cannot be switched off',
    (key) => {
      expect(parse(key, '1')).toBe(1);
      expect(parse(key, '300')).toBe(300);
      for (const raw of ['0', '-1', '1.5', '301', 'off']) {
        expect(() => parse(key, raw), raw).toThrow();
      }
    }
  );
});
