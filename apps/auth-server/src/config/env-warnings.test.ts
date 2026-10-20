import { CONFIG_KEY_REGISTRY } from '@qauth-labs/server-config';
import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * The boot warnings `env.ts` collects for `main.ts` to log (ADR-018 §5): an
 * experimental key or value that is set. The deprecated-name warnings are
 * pinned in `env.test.ts`.
 *
 * The static import above also loads the library before the first case, so
 * that case's `import('./env')` does not pay for transforming it.
 */

const BASE: Record<string, string> = {
  NODE_ENV: 'development',
  DATABASE_URL: 'postgresql://u:p@localhost:5431/qauth',
  EMAIL_FROM_ADDRESS: 'noreply@example.com',
  EMAIL_BASE_URL: 'http://localhost:3000',
  JWT_ISSUER: 'http://localhost:3000',
  JWT_PRIVATE_KEY:
    '-----BEGIN PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlBgkqhkiG9w0BBw0BAgMEBQQE\nBicqAwQBZw==\n-----END PRIVATE KEY-----',
};

function setEnv(overrides: Record<string, string | undefined>) {
  for (const [key, value] of Object.entries({ ...BASE, ...overrides })) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  vi.resetModules();
}

beforeEach(() => {
  setEnv({
    OID4VP_VERIFIER_PROFILE: undefined,
    REQUIRE_EMAIL_VERIFIED: undefined,
    SESSION_COOKIE_SECRET: undefined,
  });
});

describe('experimental boot warnings', () => {
  it('come from the registry, which marks oid4vp-1.0-base experimental (ADR-018 §4)', () => {
    expect(
      CONFIG_KEY_REGISTRY.find((key) => key.name === 'OID4VP_VERIFIER_PROFILE')?.experimentalValues
    ).toEqual(['oid4vp-1.0-base']);
  });

  it('warns when OID4VP_VERIFIER_PROFILE is set to the experimental oid4vp-1.0-base', async () => {
    setEnv({ OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' });
    const mod = await import('./env');

    expect(mod.envExperimentalWarnings).toEqual([
      {
        variable: 'OID4VP_VERIFIER_PROFILE',
        message: expect.stringMatching(/^OID4VP_VERIFIER_PROFILE=oid4vp-1\.0-base is experimental/),
      },
    ]);
  });

  it.each([
    ['haip-1.0', 'haip-1.0'],
    ['unset', undefined],
  ])('stays quiet when OID4VP_VERIFIER_PROFILE is %s', async (_label, profile) => {
    setEnv({ OID4VP_VERIFIER_PROFILE: profile });
    const mod = await import('./env');

    expect(mod.envExperimentalWarnings).toEqual([]);
  });

  it('never carries a secret value', async () => {
    setEnv({
      OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
      REQUIRE_EMAIL_VERIFIED: 'true',
      SESSION_COOKIE_SECRET: 'a-strong-secret-of-at-least-32-characters-xxxxxxxxxxxxxxx',
    });
    const mod = await import('./env');
    const bootLog = JSON.stringify([...mod.envDeprecationWarnings, ...mod.envExperimentalWarnings]);

    expect(mod.envDeprecationWarnings).toHaveLength(1);
    expect(mod.envExperimentalWarnings).toHaveLength(1);
    expect(bootLog).not.toContain('a-strong-secret');
    expect(bootLog).not.toContain('postgresql://u:p@');
    expect(bootLog).not.toContain('BEGIN PRIVATE KEY');
  });
});
