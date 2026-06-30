import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Env-schema parsing tests for config fields added in the env-hardening
 * batch. Covers the REQUIRE_EMAIL_VERIFIED `z.coerce.boolean()` footgun
 * (F-08), the SESSION_COOKIE_SECRET production guard (F-12), and the
 * ENABLE_SWAGGER default (F-07). Without these, a future refactor could
 * silently re-introduce the bug.
 */

const JWT_PRIVATE_KEY =
  '-----BEGIN PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlBgkqhkiG9w0BBw0BAgMEBQQE\nBicqAwQBZw==\n-----END PRIVATE KEY-----';

const PROD_SECRET = 'a-strong-secret-of-at-least-32-characters-xxxxxxxxxxxxxxx';

const BASE: Record<string, string | undefined> = {
  DATABASE_URL: 'postgresql://u:p@localhost:5431/qauth',
  EMAIL_FROM_ADDRESS: 'noreply@example.com',
  EMAIL_BASE_URL: 'http://localhost:3000',
  JWT_ISSUER: 'http://localhost:3000',
  JWT_PRIVATE_KEY,
};

function setEnv(overrides: Record<string, string | undefined>) {
  // Clear env, then re-apply the merged map via isStubbed process.env.
  // Avoid Object.defineProperty on process.env (Node rejects non-enumerable).
  for (const k of Object.keys(process.env)) {
    if (!(k in BASE) && !(k in overrides)) continue;
    delete process.env[k];
  }
  for (const [k, v] of Object.entries({ ...BASE, ...overrides })) {
    if (v === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = v;
    }
  }
  vi.resetModules();
}

beforeEach(() => {
  setEnv({ NODE_ENV: 'development' });
});

describe('REQUIRE_EMAIL_VERIFIED parsing (F-08 footgun guard)', () => {
  it('"false" string → false (NOT true — the z.coerce.boolean footgun)', async () => {
    setEnv({ NODE_ENV: 'development', REQUIRE_EMAIL_VERIFIED: 'false' });
    const mod = await import('./env');
    expect(mod.env.REQUIRE_EMAIL_VERIFIED).toBe(false);
  });

  it('rejects a non-true/false value (strict enum, not silent coercion)', async () => {
    setEnv({ NODE_ENV: 'development', REQUIRE_EMAIL_VERIFIED: '0' });
    await expect(import('./env')).rejects.toThrow(/REQUIRE_EMAIL_VERIFIED/);
  });

  it('"true" string → true', async () => {
    setEnv({ NODE_ENV: 'development', REQUIRE_EMAIL_VERIFIED: 'true' });
    const mod = await import('./env');
    expect(mod.env.REQUIRE_EMAIL_VERIFIED).toBe(true);
  });

  it('unset → false (MVP default preserves behavior)', async () => {
    setEnv({ NODE_ENV: 'development', REQUIRE_EMAIL_VERIFIED: undefined });
    const mod = await import('./env');
    expect(mod.env.REQUIRE_EMAIL_VERIFIED).toBe(false);
  });
});

describe('SESSION_COOKIE_SECRET production guard (F-12)', () => {
  it('rejects the dev default when NODE_ENV=production', async () => {
    setEnv({ NODE_ENV: 'production', SESSION_COOKIE_SECRET: undefined });
    await expect(import('./env')).rejects.toThrow(/SESSION_COOKIE_SECRET/);
  });

  it('accepts the dev default when NODE_ENV=development', async () => {
    setEnv({ NODE_ENV: 'development', SESSION_COOKIE_SECRET: undefined });
    const mod = await import('./env');
    expect(mod.env.SESSION_COOKIE_SECRET.length).toBeGreaterThanOrEqual(32);
  });

  it('accepts a strong secret when NODE_ENV=production', async () => {
    setEnv({ NODE_ENV: 'production', SESSION_COOKIE_SECRET: PROD_SECRET });
    const mod = await import('./env');
    expect(mod.env.SESSION_COOKIE_SECRET).toBe(PROD_SECRET);
  });
});

describe('ENABLE_SWAGGER defaults (F-07)', () => {
  it('defaults to true in development', async () => {
    setEnv({ NODE_ENV: 'development', ENABLE_SWAGGER: undefined });
    const mod = await import('./env');
    expect(mod.env.ENABLE_SWAGGER).toBe(true);
  });

  it('defaults to false in production', async () => {
    setEnv({
      NODE_ENV: 'production',
      ENABLE_SWAGGER: undefined,
      SESSION_COOKIE_SECRET: PROD_SECRET,
    });
    const mod = await import('./env');
    expect(mod.env.ENABLE_SWAGGER).toBe(false);
  });

  it('"true" string → true even in production (explicit opt-in)', async () => {
    setEnv({
      NODE_ENV: 'production',
      ENABLE_SWAGGER: 'true',
      SESSION_COOKIE_SECRET: PROD_SECRET,
    });
    const mod = await import('./env');
    expect(mod.env.ENABLE_SWAGGER).toBe(true);
  });

  it('"false" string → false in development (explicit opt-out)', async () => {
    setEnv({ NODE_ENV: 'development', ENABLE_SWAGGER: 'false' });
    const mod = await import('./env');
    expect(mod.env.ENABLE_SWAGGER).toBe(false);
  });
});
