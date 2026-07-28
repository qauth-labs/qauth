import {
  ACR_VALUE_STYLES,
  ATTACK_POTENTIAL_RESISTANCE_ORDER,
  DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL,
  SUBJECT_RESOLUTION_STRATEGY_IDS,
  VERIFIER_PROFILE_IDS,
} from '@qauth-labs/fastify-plugin-federation';
import {
  assuranceEnvSchema,
  federationEnvSchema,
  keyAttestationEnvSchema,
} from '@qauth-labs/server-config';
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
 * `OID4VP_TRUSTED_ISSUERS` reaches the running server (#236).
 *
 * The variable existed in `server-config`'s schema but was never spread into
 * this app's env, never listed in `.env.example` and never forwarded by
 * `docker-compose.yml` — so an operator could configure a per-realm issuer
 * allowlist, restart, and have the server read an empty map: every realm
 * trusting nobody, with the configuration apparently accepted. These tests pin
 * the wiring, including the "blank means unset" handling that keeps the
 * `${VAR:-}` compose form from taking a deployment down at boot.
 */
describe('OID4VP_TRUSTED_ISSUERS reaches the app env (#236)', () => {
  it('unset → an empty map, not undefined (fail-closed: no realm trusts anyone)', async () => {
    setEnv({ NODE_ENV: 'development', OID4VP_TRUSTED_ISSUERS: undefined });
    const mod = await import('./env');

    expect(mod.env.OID4VP_TRUSTED_ISSUERS).toEqual({});
  });

  it.each([
    ['an empty string', ''],
    ['whitespace', '   '],
  ])('%s is read as unset and does NOT fail the boot', async (_label, raw) => {
    // This is what `${OID4VP_TRUSTED_ISSUERS:-}` in docker-compose.yml expands
    // to. `parseEnv` validates the whole composed env in one `.parse()` at
    // module import, so throwing here would take down password login,
    // /authorize and /token for a deployment with no interest in wallets.
    setEnv({ NODE_ENV: 'development', OID4VP_TRUSTED_ISSUERS: raw });
    const mod = await import('./env');

    expect(mod.env.OID4VP_TRUSTED_ISSUERS).toEqual({});
  });

  it('a configured allowlist arrives as a per-realm map', async () => {
    setEnv({
      NODE_ENV: 'development',
      OID4VP_TRUSTED_ISSUERS: '{"master":["https://issuer.example"],"acme":[]}',
    });
    const mod = await import('./env');

    expect(mod.env.OID4VP_TRUSTED_ISSUERS).toEqual({
      master: ['https://issuer.example'],
      acme: [],
    });
  });

  it.each([
    ['malformed JSON', '{not json'],
    ['a bare array with no realm to attach trust to', '["https://issuer.example"]'],
    ['a plain-http issuer', '{"master":["http://issuer.example"]}'],
  ])('fails the boot on %s rather than degrading to "trusts nothing"', async (_label, raw) => {
    // "Trusts nothing" is also the legitimate default, so a typo that degraded
    // to it silently would be indistinguishable from a correct empty config.
    setEnv({ NODE_ENV: 'development', OID4VP_TRUSTED_ISSUERS: raw });

    await expect(import('./env')).rejects.toThrow(/OID4VP_TRUSTED_ISSUERS/);
  });
});

/**
 * `OID4VP_ISSUER_ASSURANCE` and `ACR_VALUE_STYLE` reach the running server
 * (#237).
 *
 * Same wiring pin as `OID4VP_TRUSTED_ISSUERS` above, and for the same failure:
 * a variable that exists in `server-config`'s schema but is never spread into
 * this app's env is configuration an operator can write, restart, and have the
 * server ignore — here the symptom would be an ID token that silently never
 * carries an `acr` claim.
 */
describe('OID4VP_ISSUER_ASSURANCE / ACR_VALUE_STYLE reach the app env (#237)', () => {
  /**
   * `setEnv` only deletes keys it is told about, so every wallet-federation
   * variable this block does not set has to be cleared EXPLICITLY — otherwise a
   * deliberately-invalid `OID4VP_TRUSTED_ISSUERS` left behind by the previous
   * describe fails this block's imports for a reason that has nothing to do
   * with assurance.
   */
  function setAssuranceEnv(overrides: Record<string, string | undefined>) {
    setEnv({
      NODE_ENV: 'development',
      OID4VP_TRUSTED_ISSUERS: undefined,
      OID4VP_ISSUER_ASSURANCE: undefined,
      ACR_VALUE_STYLE: undefined,
      ...overrides,
    });
  }

  it('unset → an empty map, not undefined (fail-closed: no realm assures anyone)', async () => {
    setAssuranceEnv({});
    const mod = await import('./env');

    expect(mod.env.OID4VP_ISSUER_ASSURANCE).toEqual({});
  });

  it.each([
    ['an empty string', ''],
    ['whitespace', '   '],
  ])('%s is read as unset and does NOT fail the boot', async (_label, raw) => {
    setAssuranceEnv({ OID4VP_ISSUER_ASSURANCE: raw });
    const mod = await import('./env');

    expect(mod.env.OID4VP_ISSUER_ASSURANCE).toEqual({});
  });

  it('a configured policy arrives as a per-realm, per-issuer map', async () => {
    setAssuranceEnv({
      OID4VP_ISSUER_ASSURANCE: '{"master":{"https://issuer.example":{"level":"high"}}}',
    });
    const mod = await import('./env');

    expect(mod.env.OID4VP_ISSUER_ASSURANCE).toEqual({
      master: { 'https://issuer.example': { level: 'high' } },
    });
  });

  it.each([
    ['malformed JSON', '{not json'],
    ['a bare array with no realm to attach a policy to', '["https://issuer.example"]'],
    ['a plain-http issuer', '{"master":{"http://issuer.example":{"level":"high"}}}'],
    ['a level of low', '{"master":{"https://issuer.example":{"level":"low"}}}'],
  ])('fails the boot on %s rather than degrading to "assures nothing"', async (_label, raw) => {
    setAssuranceEnv({ OID4VP_ISSUER_ASSURANCE: raw });

    await expect(import('./env')).rejects.toThrow(/OID4VP_ISSUER_ASSURANCE/);
  });

  it('ACR_VALUE_STYLE defaults to the eIDAS URI form', async () => {
    setAssuranceEnv({});
    const mod = await import('./env');

    expect(mod.env.ACR_VALUE_STYLE).toBe('eidas-uri');
  });

  it('ACR_VALUE_STYLE accepts an explicit vocabulary', async () => {
    setAssuranceEnv({ ACR_VALUE_STYLE: 'loa-name' });
    const mod = await import('./env');

    expect(mod.env.ACR_VALUE_STYLE).toBe('loa-name');
  });

  it('ACR_VALUE_STYLE fails the boot on an unknown vocabulary', async () => {
    setAssuranceEnv({ ACR_VALUE_STYLE: 'eidas-saml' });

    await expect(import('./env')).rejects.toThrow(/ACR_VALUE_STYLE/);
  });
});

/**
 * Cross-lib pin: `ACR_VALUE_STYLE` ↔ the shipped `acr` vocabularies (#237).
 *
 * Identical layering problem to the profile pin below: `server-config` spells
 * the enum out as a literal because it may not depend on `server-federation`,
 * and a duplicated list drifts. A vocabulary added to the federation table but
 * not to the enum is one no operator can select; an enum value with no table
 * behind it silently renders as the default. This app is the only place both
 * lists are visible at once.
 */
describe('ACR_VALUE_STYLE ↔ ACR_VALUE_STYLES cross-lib pin (#237)', () => {
  function acceptedStyles(): readonly string[] {
    const result = assuranceEnvSchema.safeParse({ ACR_VALUE_STYLE: '__not-an-acr-style__' });

    expect(result.success).toBe(false);
    const issue = result.error?.issues.find((candidate) => candidate.path[0] === 'ACR_VALUE_STYLE');
    expect(issue?.code).toBe('invalid_value');

    return issue !== undefined && issue.code === 'invalid_value'
      ? issue.values.map((value) => String(value))
      : [];
  }

  it('accepts exactly the shipped vocabularies — no more, no fewer', () => {
    expect([...acceptedStyles()].sort()).toEqual([...ACR_VALUE_STYLES].sort());
  });

  it.each(ACR_VALUE_STYLES)('parses %s and hands it back unchanged', (style) => {
    expect(assuranceEnvSchema.parse({ ACR_VALUE_STYLE: style }).ACR_VALUE_STYLE).toBe(style);
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

/**
 * Cross-lib pin: `OID4VP_SUBJECT_RESOLUTION` ↔ the shipped strategy table
 * (#300).
 *
 * The same drift hazard as the profile pin above, with one extra edge that makes
 * it worth its own block. The enum deliberately accepts strategies a deployment
 * may NOT select — `session-binding`, `key-thumbprint` and `rp-pseudonym` — so
 * that the refusal an operator sees is
 * `assertSubjectResolutionStrategySelectable`'s explanation of the actual gate
 * (ADR-009 §§3–5) rather than a `ZodError` listing strings. A future edit that
 * "tidies" the enum down to the selectable ids would silently replace a useful
 * message with a useless one, and this pin fails when it does.
 */
describe('OID4VP_SUBJECT_RESOLUTION ↔ SUBJECT_RESOLUTION_STRATEGY_IDS cross-lib pin (#300)', () => {
  function acceptedStrategyValues(): readonly string[] {
    const result = federationEnvSchema.safeParse({
      OID4VP_SUBJECT_RESOLUTION: '__not-a-subject-resolution-strategy__',
    });

    expect(result.success).toBe(false);
    const issue = result.error?.issues.find(
      (candidate) => candidate.path[0] === 'OID4VP_SUBJECT_RESOLUTION'
    );
    expect(issue?.code).toBe('invalid_value');

    return issue !== undefined && issue.code === 'invalid_value'
      ? issue.values.map((value) => String(value))
      : [];
  }

  it('accepts exactly the strategies ADR-009 names — reserved ones included', () => {
    expect([...acceptedStrategyValues()].sort()).toEqual(
      [...SUBJECT_RESOLUTION_STRATEGY_IDS].sort()
    );
  });

  it.each(SUBJECT_RESOLUTION_STRATEGY_IDS)('parses %s and hands it back unchanged', (strategy) => {
    const parsed = federationEnvSchema.parse({ OID4VP_SUBJECT_RESOLUTION: strategy });

    expect(parsed.OID4VP_SUBJECT_RESOLUTION).toBe(strategy);
  });

  it('treats a blank value as unset, not as a bad value', () => {
    // `${OID4VP_SUBJECT_RESOLUTION:-}` is how an orchestrator materialises an
    // absent variable. Unset means "use the profile default", which is a real
    // answer — unlike OID4VP_VERIFIER_PROFILE, where unset is a refusal.
    expect(
      federationEnvSchema.parse({ OID4VP_SUBJECT_RESOLUTION: '   ' }).OID4VP_SUBJECT_RESOLUTION
    ).toBeUndefined();
  });

  it('splits and trims the binding claim list, and refuses an entry with whitespace', () => {
    expect(
      federationEnvSchema.parse({ OID4VP_SUBJECT_BINDING_CLAIMS: ' family_name , given_name ' })
        .OID4VP_SUBJECT_BINDING_CLAIMS
    ).toEqual(['family_name', 'given_name']);

    expect(
      federationEnvSchema.safeParse({ OID4VP_SUBJECT_BINDING_CLAIMS: 'family name' }).success
    ).toBe(false);
  });
});

/**
 * The cross-lib pin three schemas' TSDoc promises (#308/#379).
 *
 * `server-config` DUPLICATES two `server-federation` vocabularies as Zod enums —
 * `AttackPotentialResistance` (OID4VCI Appendix D §D.2) in both
 * `schemas/assurance.ts` and `schemas/key-attestation.ts`, and
 * `AssuredKeyStorage` in `schemas/assurance.ts` — rather than importing them,
 * because config is the lowest server layer and carries no dependency on
 * `server-federation`. Those three TSDoc blocks each say the duplication is
 * "pinned by `apps/auth-server`'s `src/config/env.test.ts`".
 *
 * This is that pin. Without it the claim was decoration: a grade added to the
 * §D.2 order would be accepted by `translateKeyStorageAssurance` and REJECTED by
 * the env schema, so an operator could write the new grade, fail the boot, and
 * find nothing in either library that said the two disagreed.
 *
 * Asserted behaviourally rather than by comparing arrays: what matters is not
 * that two lists look alike but that a grade the runtime understands is a grade
 * an operator can actually configure.
 */
describe('the §D.2 vocabulary agrees across server-config and server-federation (#308/#379)', () => {
  it('accepts every grade the runtime orders, in OID4VP_ATTESTING_ISSUERS', () => {
    for (const grade of ATTACK_POTENTIAL_RESISTANCE_ORDER) {
      const parsed = keyAttestationEnvSchema.parse({
        OID4VP_ATTESTING_ISSUERS: JSON.stringify({ 'https://pid.issuer.example': grade }),
      });

      expect(parsed.OID4VP_ATTESTING_ISSUERS).toEqual({ 'https://pid.issuer.example': grade });
    }
  });

  it('accepts every grade the runtime orders, as an OID4VP_ISSUER_ASSURANCE floor', () => {
    for (const grade of ATTACK_POTENTIAL_RESISTANCE_ORDER) {
      const parsed = assuranceEnvSchema.parse({
        OID4VP_ISSUER_ASSURANCE: JSON.stringify({
          master: {
            'https://issuer.example': {
              level: 'high',
              requiresKeyStorage: 'hardware',
              requiresKeyStorageAttackPotential: grade,
            },
          },
        }),
      });

      expect(
        parsed.OID4VP_ISSUER_ASSURANCE?.['master']?.['https://issuer.example']
          ?.requiresKeyStorageAttackPotential
      ).toBe(grade);
    }
  });

  it('the default floor is a grade the env schema accepts', () => {
    // `DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL` is what an entry gets when it
    // states no floor. If config could not express it, an operator could never
    // write the default down explicitly to see what they were already getting.
    expect(ATTACK_POTENTIAL_RESISTANCE_ORDER).toContain(DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL);

    const parsed = keyAttestationEnvSchema.parse({
      OID4VP_ATTESTING_ISSUERS: JSON.stringify({
        'https://pid.issuer.example': DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL,
      }),
    });

    expect(parsed.OID4VP_ATTESTING_ISSUERS).toBeDefined();
  });

  it('rejects a grade the runtime does not order', () => {
    // The other direction: config must not accept a value the runtime would
    // then fail to recognise, which fails closed to "no assurance" silently.
    expect(
      keyAttestationEnvSchema.safeParse({
        OID4VP_ATTESTING_ISSUERS: '{"https://pid.issuer.example":"iso_18045_beyond-high"}',
      }).success
    ).toBe(false);
  });
});

/**
 * `OID4VP_ATTESTING_ISSUERS` reaches the app env (#308/#379).
 *
 * The same wiring pin `OID4VP_TRUSTED_ISSUERS` and `OID4VP_ISSUER_ASSURANCE`
 * already carry, and for the same failure: a variable that exists in
 * `server-config`'s schema but is never spread into this app's env is
 * configuration an operator can write, restart, and have the server ignore.
 * Here the symptom is silent rather than loud — every credential resolves to
 * `assurance: 'none'`, so an entry demanding hardware key storage grants `'low'`
 * to a wallet that satisfies it.
 */
describe('OID4VP_ATTESTING_ISSUERS reaches the app env (#308/#379)', () => {
  /**
   * `setEnv` only deletes keys it is told about, so every wallet-federation
   * variable this block does not set must be cleared EXPLICITLY — including
   * `ACR_VALUE_STYLE`, which the assurance block above leaves behind and which
   * fails this block's import for a reason that has nothing to do with
   * attesting issuers. The same footgun that block documents.
   */
  function setAttestingEnv(overrides: Record<string, string | undefined>) {
    setEnv({
      NODE_ENV: 'development',
      OID4VP_TRUSTED_ISSUERS: undefined,
      OID4VP_ISSUER_ASSURANCE: undefined,
      OID4VP_ATTESTING_ISSUERS: undefined,
      ACR_VALUE_STYLE: undefined,
      ...overrides,
    });
  }

  it('unset → nothing recorded, and the boot still succeeds', async () => {
    setAttestingEnv({});
    const mod = await import('./env');

    expect(mod.env.OID4VP_ATTESTING_ISSUERS).toEqual({});
  });

  it('a configured map arrives as issuer → grade', async () => {
    setAttestingEnv({
      OID4VP_ATTESTING_ISSUERS: '{"https://pid.issuer.example":"iso_18045_high"}',
    });
    const mod = await import('./env');

    expect(mod.env.OID4VP_ATTESTING_ISSUERS).toEqual({
      'https://pid.issuer.example': 'iso_18045_high',
    });
  });
});
