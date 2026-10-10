import { describe, expect, it } from 'vitest';

import { authEnvSchema, resolveRequireVerifiedAccount } from './auth';

/**
 * REQUIRE_VERIFIED_ACCOUNT replaced REQUIRE_EMAIL_VERIFIED on 2026-10-09.
 *
 * Email is a user attribute, not the trust gate; the gate is a verified
 * account. The old name stays a working alias through the 1.x deprecation
 * window. These tests pin the alias, its boot warning, and the refusal when
 * the two names disagree.
 */
function resolve(raw: Record<string, string | undefined>) {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (value !== undefined) env[key] = value;
  }
  return resolveRequireVerifiedAccount(authEnvSchema.parse(env));
}

describe('authEnvSchema verified-account flags', () => {
  const parse = (name: 'REQUIRE_VERIFIED_ACCOUNT' | 'REQUIRE_EMAIL_VERIFIED', raw?: string) =>
    authEnvSchema.parse(raw === undefined ? {} : { [name]: raw })[name];

  it.each(['REQUIRE_VERIFIED_ACCOUNT', 'REQUIRE_EMAIL_VERIFIED'] as const)(
    '%s parses "true" and "false" strictly (not the z.coerce.boolean footgun)',
    (name) => {
      expect(parse(name, 'true')).toBe(true);
      expect(parse(name, 'false')).toBe(false);
    }
  );

  it.each(['REQUIRE_VERIFIED_ACCOUNT', 'REQUIRE_EMAIL_VERIFIED'] as const)(
    '%s reads unset and blank as "not set"',
    (name) => {
      // Blank is what `${VAR:-}` in docker-compose.yml expands to.
      expect(parse(name)).toBeUndefined();
      expect(parse(name, '')).toBeUndefined();
      expect(parse(name, '   ')).toBeUndefined();
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

describe('resolveRequireVerifiedAccount', () => {
  it('defaults to false with no warning when neither name is set', () => {
    expect(resolve({})).toEqual({
      ok: true,
      requireVerifiedAccount: false,
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
