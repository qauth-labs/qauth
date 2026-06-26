import { describe, expect, it } from 'vitest';

import {
  type Environment,
  ENVIRONMENT_PROFILES,
  ENVIRONMENTS,
  parseEnvironment,
  resolveAccessTokenLifespanSeconds,
  resolveEnvironmentPolicy,
  resolveRateLimitMax,
  stricterEnvironment,
} from './environment-policy';

describe('environment-policy — parseEnvironment (fail-safe)', () => {
  it('returns the value for each known environment', () => {
    for (const env of ENVIRONMENTS) {
      expect(parseEnvironment(env)).toBe(env);
    }
  });

  it('fails safe to production for unknown / empty / null / undefined', () => {
    expect(parseEnvironment('prod')).toBe('production');
    expect(parseEnvironment('PRODUCTION')).toBe('production');
    expect(parseEnvironment('')).toBe('production');
    expect(parseEnvironment(null)).toBe('production');
    expect(parseEnvironment(undefined)).toBe('production');
    // never silently downgrades to a laxer profile
    expect(parseEnvironment('dev')).toBe('production');
  });
});

describe('environment-policy — stricterEnvironment (ceiling ordering)', () => {
  it('production beats staging beats development', () => {
    expect(stricterEnvironment('development', 'production')).toBe('production');
    expect(stricterEnvironment('production', 'development')).toBe('production');
    expect(stricterEnvironment('development', 'staging')).toBe('staging');
    expect(stricterEnvironment('staging', 'production')).toBe('production');
  });

  it('is idempotent for equal inputs', () => {
    for (const env of ENVIRONMENTS) {
      expect(stricterEnvironment(env, env)).toBe(env);
    }
  });
});

describe('environment-policy — ENVIRONMENT_PROFILES table (ADR-008 §5)', () => {
  it('development relaxes the security-relevant knobs', () => {
    const dev = ENVIRONMENT_PROFILES.development;
    expect(dev).toMatchObject({
      environment: 'development',
      staticApiKeysAllowed: true,
      localhostRedirectAllowed: true,
      pkceRequired: false,
      accessTokenLifespanTier: 'long',
      refreshRotationRequired: false,
      rateLimitTier: 'lenient',
      openDynamicRegistration: true,
      agentStepUpEnforced: false,
      t3SecurityEnforced: false,
    });
  });

  it('staging keeps production-grade security, relaxing only operational knobs', () => {
    const staging = ENVIRONMENT_PROFILES.staging;
    const prod = ENVIRONMENT_PROFILES.production;
    // Security knobs match production exactly.
    expect(staging.staticApiKeysAllowed).toBe(false);
    expect(staging.localhostRedirectAllowed).toBe(false);
    expect(staging.pkceRequired).toBe(true);
    expect(staging.refreshRotationRequired).toBe(true);
    expect(staging.openDynamicRegistration).toBe(false);
    expect(staging.agentStepUpEnforced).toBe(true);
    expect(staging.t3SecurityEnforced).toBe(true);
    // The ONLY relaxations vs production are operational conveniences.
    expect(staging.rateLimitTier).toBe('lenient');
    expect(prod.rateLimitTier).toBe('strict');
  });

  it('production is the strict baseline (every security knob hardened)', () => {
    expect(ENVIRONMENT_PROFILES.production).toMatchObject({
      environment: 'production',
      staticApiKeysAllowed: false,
      localhostRedirectAllowed: false,
      pkceRequired: true,
      accessTokenLifespanTier: 'short',
      refreshRotationRequired: true,
      rateLimitTier: 'strict',
      openDynamicRegistration: false,
      agentStepUpEnforced: true,
      t3SecurityEnforced: true,
    });
  });

  it('is frozen against mutation', () => {
    expect(Object.isFrozen(ENVIRONMENT_PROFILES)).toBe(true);
    expect(Object.isFrozen(ENVIRONMENT_PROFILES.development)).toBe(true);
  });
});

describe('environment-policy — resolveEnvironmentPolicy (effective profile)', () => {
  it('unset client + unset realm → production (default-deny / fail-safe)', () => {
    expect(resolveEnvironmentPolicy({}, {}).environment).toBe('production');
    expect(resolveEnvironmentPolicy(null, null).environment).toBe('production');
    expect(resolveEnvironmentPolicy(undefined, undefined).environment).toBe('production');
  });

  it('realm ceiling caps a laxer client: realm=production forces client=development to production', () => {
    const policy = resolveEnvironmentPolicy(
      { environment: 'development' },
      { maxEnvironmentLaxity: 'production' }
    );
    expect(policy).toBe(ENVIRONMENT_PROFILES.production);
    expect(policy.environment).toBe('production');
    expect(policy.staticApiKeysAllowed).toBe(false);
  });

  it('a development client under a development realm gets the development profile', () => {
    const policy = resolveEnvironmentPolicy(
      { environment: 'development' },
      { maxEnvironmentLaxity: 'development' }
    );
    expect(policy).toBe(ENVIRONMENT_PROFILES.development);
    expect(policy.staticApiKeysAllowed).toBe(true);
  });

  it('staging effective keeps strict security (client=staging, realm=staging)', () => {
    const policy = resolveEnvironmentPolicy(
      { environment: 'staging' },
      { maxEnvironmentLaxity: 'staging' }
    );
    expect(policy.environment).toBe('staging');
    expect(policy.pkceRequired).toBe(true);
    expect(policy.t3SecurityEnforced).toBe(true);
    expect(policy.staticApiKeysAllowed).toBe(false);
  });

  it('a staging realm caps a development client at staging (still strict security)', () => {
    const policy = resolveEnvironmentPolicy(
      { environment: 'development' },
      { maxEnvironmentLaxity: 'staging' }
    );
    expect(policy.environment).toBe('staging');
    expect(policy.staticApiKeysAllowed).toBe(false);
    expect(policy.pkceRequired).toBe(true);
  });

  it('a stricter client is honoured even under a laxer realm ceiling', () => {
    // Client self-declaring production while realm permits development:
    // the STRICTER (production) wins — narrowing one's own privilege is safe.
    const policy = resolveEnvironmentPolicy(
      { environment: 'production' },
      { maxEnvironmentLaxity: 'development' }
    );
    expect(policy.environment).toBe('production');
  });

  it('unknown / null values on either side fail safe to production', () => {
    expect(
      resolveEnvironmentPolicy({ environment: 'bogus' }, { maxEnvironmentLaxity: 'development' })
        .environment
    ).toBe('production');
    expect(
      resolveEnvironmentPolicy({ environment: 'development' }, { maxEnvironmentLaxity: 'nonsense' })
        .environment
    ).toBe('production');
    expect(
      resolveEnvironmentPolicy({ environment: null }, { maxEnvironmentLaxity: null }).environment
    ).toBe('production');
  });

  it('returns a profile for every (client, realm) environment pairing', () => {
    for (const clientEnv of ENVIRONMENTS) {
      for (const realmEnv of ENVIRONMENTS) {
        const policy = resolveEnvironmentPolicy(
          { environment: clientEnv },
          { maxEnvironmentLaxity: realmEnv }
        );
        const expected: Environment = stricterEnvironment(clientEnv, realmEnv);
        expect(policy).toBe(ENVIRONMENT_PROFILES[expected]);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Tier → concrete-value mappers (ADR-008 §5, #197). These are the single place
// a tier label is turned into a number; checkpoints call them rather than
// re-deriving `dev ? x : y`.
// ---------------------------------------------------------------------------

describe('environment-policy — resolveAccessTokenLifespanSeconds (#197)', () => {
  const config = { shortSeconds: 900, longSeconds: 28800 };

  it('maps the short tier (staging/production) to the baseline lifespan', () => {
    expect(resolveAccessTokenLifespanSeconds('short', config)).toBe(900);
  });

  it('maps the long tier (development) to the dev-convenience lifespan', () => {
    expect(resolveAccessTokenLifespanSeconds('long', config)).toBe(28800);
  });

  it('a production-effective policy always resolves the short baseline', () => {
    const policy = resolveEnvironmentPolicy(
      { environment: 'development' },
      { maxEnvironmentLaxity: 'production' }
    );
    expect(resolveAccessTokenLifespanSeconds(policy.accessTokenLifespanTier, config)).toBe(900);
  });

  it('only a development-effective policy gets the longer lifespan', () => {
    const dev = resolveEnvironmentPolicy(
      { environment: 'development' },
      { maxEnvironmentLaxity: 'development' }
    );
    const staging = resolveEnvironmentPolicy(
      { environment: 'staging' },
      { maxEnvironmentLaxity: 'staging' }
    );
    expect(resolveAccessTokenLifespanSeconds(dev.accessTokenLifespanTier, config)).toBe(28800);
    expect(resolveAccessTokenLifespanSeconds(staging.accessTokenLifespanTier, config)).toBe(900);
  });
});

describe('environment-policy — resolveRateLimitMax (#197)', () => {
  const config = { lenientMax: 600, strictMax: 60 };

  it('maps the strict tier (production) to the tight cap', () => {
    expect(resolveRateLimitMax('strict', config)).toBe(60);
  });

  it('maps the lenient tier (development/staging) to the relaxed cap', () => {
    expect(resolveRateLimitMax('lenient', config)).toBe(600);
  });

  it('a production realm forces the strict cap even for a development client', () => {
    const policy = resolveEnvironmentPolicy(
      { environment: 'development' },
      { maxEnvironmentLaxity: 'production' }
    );
    expect(resolveRateLimitMax(policy.rateLimitTier, config)).toBe(60);
  });
});

// ---------------------------------------------------------------------------
// HARD FLOORS (ADR-008 §5, #197): the resolver must NEVER relax these, in any
// environment. The profile carries no field that could turn them off; this test
// pins that contract so a future profile-table edit cannot smuggle one in.
// ---------------------------------------------------------------------------

describe('environment-policy — hard floors never relax (#197)', () => {
  it('development relaxes ONLY the ADR-sanctioned knobs; no security floor is exposed', () => {
    const dev = ENVIRONMENT_PROFILES.development;

    // The exhaustive set of fields the profile is ALLOWED to carry. If a new
    // field is added it must be listed here deliberately — a floor (hashed
    // secrets, audience binding, signature/issuer validation, confidential-only
    // grants) must NEVER become a profile knob, so it must never appear.
    expect(Object.keys(dev).sort()).toEqual(
      [
        'accessTokenLifespanTier',
        'agentStepUpEnforced',
        'environment',
        'localhostRedirectAllowed',
        'openDynamicRegistration',
        'pkceRequired',
        'rateLimitTier',
        'refreshRotationRequired',
        'staticApiKeysAllowed',
        't3SecurityEnforced',
      ].sort()
    );

    // No floor-shaped key exists on ANY profile (a resolver can't disable them).
    for (const env of ENVIRONMENTS) {
      const keys = Object.keys(ENVIRONMENT_PROFILES[env]);
      for (const forbidden of [
        'hashClientSecret',
        'audienceBindingEnforced',
        'verifyTokenSignature',
        'verifyIssuer',
        'allowPublicConfidentialGrants',
      ]) {
        expect(keys).not.toContain(forbidden);
      }
    }
  });

  it('the difference between development and production is EXACTLY the sanctioned knobs', () => {
    const dev = ENVIRONMENT_PROFILES.development;
    const prod = ENVIRONMENT_PROFILES.production;
    const differing = (Object.keys(prod) as (keyof typeof prod)[]).filter(
      (k) => k !== 'environment' && dev[k] !== prod[k]
    );
    // Every relaxation development makes is one of these eight ADR-008 §5 rows.
    expect(differing.sort()).toEqual(
      [
        'accessTokenLifespanTier',
        'agentStepUpEnforced',
        'localhostRedirectAllowed',
        'openDynamicRegistration',
        'pkceRequired',
        'rateLimitTier',
        'refreshRotationRequired',
        'staticApiKeysAllowed',
        't3SecurityEnforced',
      ].sort()
    );
  });
});
