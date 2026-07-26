import { VERIFIER_PROFILE_IDS } from '@qauth-labs/fastify-plugin-federation';
import { federationEnvSchema } from '@qauth-labs/server-config';
import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Env-schema parsing tests for config fields added in the env-hardening
 * batch. Covers the REQUIRE_EMAIL_VERIFIED `z.coerce.boolean()` footgun
 * (F-08), the SESSION_COOKIE_SECRET production guard (F-12), and the
 * ENABLE_SWAGGER default (F-07). Without these, a future refactor could
 * silently re-introduce the bug.
 *
 * It is also where the OID4VP_VERIFIER_PROFILE ↔ VerifierProfile cross-lib pin
 * lives (#299) — see the last describe block for why this file, of all files.
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

/**
 * Cross-lib pin: `OID4VP_VERIFIER_PROFILE` ↔ the shipped VerifierProfile table
 * (#299).
 *
 * `server-config` spells its enum out as a literal instead of importing
 * `VerifierProfileId`, because config is the workspace's lowest layer and must
 * not depend on `server-federation` — a deployment that only wants a database
 * URL should not pull in OID4VP. The price of that layering is a duplicated
 * list, and a duplicated list drifts: adding `haip-1.1` to the profile table
 * without widening the enum ships a profile no operator can select, and the
 * symptom is a `ZodError` that takes the whole process down at boot on a value
 * the release notes say is valid.
 *
 * `apps/auth-server` is the only place the two lists are simultaneously visible.
 * It composes `federationEnvSchema.shape` into its env, and it reaches the
 * profile table through `@qauth-labs/fastify-plugin-federation` (app code may
 * not import `scope:server` libs beyond `server-config`, so the plugin
 * re-exports `VERIFIER_PROFILE_IDS` for exactly this purpose). Neither lib's own
 * test can see the other list, so neither of them fails when the two drift.
 * This one does.
 */
describe('OID4VP_VERIFIER_PROFILE ↔ VERIFIER_PROFILE_IDS cross-lib pin (#299)', () => {
  /**
   * The values the env schema actually accepts, read off the schema's own
   * refusal rather than its internals.
   *
   * Zod v4 reports an unmatched enum as an `invalid_value` issue carrying the
   * full option list, which is the accepted set BY CONSTRUCTION — no reaching
   * into `_zod.def`, and no second transcription of the list inside this test
   * that could itself drift.
   */
  function acceptedProfileValues(): readonly string[] {
    const result = federationEnvSchema.safeParse({
      OID4VP_VERIFIER_PROFILE: '__not-a-verifier-profile__',
    });

    expect(result.success).toBe(false);
    const issue = result.error?.issues.find(
      (candidate) => candidate.path[0] === 'OID4VP_VERIFIER_PROFILE'
    );
    expect(issue?.code).toBe('invalid_value');

    return issue !== undefined && issue.code === 'invalid_value'
      ? issue.values.map((value) => String(value))
      : [];
  }

  it('accepts exactly the shipped profile ids — no more, no fewer', () => {
    // Fails in BOTH drift directions: a profile added to the table but not to
    // the enum (unselectable), and an enum value with no profile behind it
    // (accepted at parse time, then refused at boot as "no profile selected").
    expect([...acceptedProfileValues()].sort()).toEqual([...VERIFIER_PROFILE_IDS].sort());
  });

  it.each(VERIFIER_PROFILE_IDS)('parses %s and hands it back unchanged', (profileId) => {
    // The pin above compares lists; this proves the enum genuinely accepts each
    // id and does not normalise, alias or default it into something the
    // federation gate would then fail to recognise.
    const parsed = federationEnvSchema.parse({ OID4VP_VERIFIER_PROFILE: profileId });

    expect(parsed.OID4VP_VERIFIER_PROFILE).toBe(profileId);
  });
});
