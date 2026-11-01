import { describe, expect, expectTypeOf, it, vi } from 'vitest';
import { z } from 'zod';

import { policyField } from './field';
import {
  defaultsFromEnv,
  diffPolicies,
  parseRealmPolicies,
  REALM_POLICY_REGISTRY,
  type RealmPolicies,
  type RealmPoliciesRepresentation,
  registerPolicyGroup,
  toJsonSchema,
  toRealmPoliciesRepresentation,
} from './realm-policies';
import { PolicySeedError, PolicyValidationError } from './registry';
import { REALM_POLICY_SCHEMA_VERSION } from './version';

/**
 * The defaults of the issue's table (#514), as a realm whose environment sets
 * none of the seed keys gets them. One row differs from the table on purpose:
 * `accounts.requireVerifiedAccount` is `true`, the default of
 * `REQUIRE_VERIFIED_ACCOUNT` since 2026-10-19, so a seeded realm is never
 * looser than the server is today. `mail.smtp.secure` is `true`, the default
 * of `SMTP_SECURE`, where the table says "none" for the SMTP settings.
 */
const TABLE_DEFAULTS: RealmPolicies = {
  tokens: {
    accessTokenLifespanSeconds: 900,
    developmentAccessTokenLifespanSeconds: 28800,
    refreshTokenLifespanSeconds: 604800,
    adminAccessTokenLifespanSeconds: 600,
  },
  accounts: { requireVerifiedAccount: true },
  password: { minScore: 2 },
  bruteForce: { enabled: true, maxAttempts: 5, windowSeconds: 900, lockoutSeconds: 900 },
  registration: {
    dynamicRegistrationAllowedScopes: ['openid', 'profile', 'email', 'offline_access'],
    cimd: { enabled: true, trustPolicy: 'accept-any-https', trustedDomains: [] },
  },
  mail: {
    provider: 'mock',
    fromAddress: null,
    fromName: 'QAuth',
    smtp: { host: null, port: null, secure: true, user: null },
    resend: {},
    verificationTokenExpirySeconds: 86400,
    invalidateExistingTokensOnResend: true,
  },
  posture: { maxEnvironmentLaxity: 'production' },
  admin: { twoAdminMandatoryOperations: [], workloadIssuers: [] },
};

/** The default policies with `patch` merged in, one group deep. */
function withPolicies(patch: Record<string, Record<string, unknown>>): Record<string, unknown> {
  const document: Record<string, unknown> = structuredClone(TABLE_DEFAULTS);
  for (const [group, members] of Object.entries(patch)) {
    document[group] = { ...(document[group] as object), ...members };
  }
  return document;
}

/** Trusted domains the type accepts, as a writer may send them, and those it refuses. */
const DOMAINS = {
  accepted: [
    'example.com',
    'auth.eu.example.co.uk',
    '*.example.com',
    'Login.Example.ORG',
    'xn--bcher-kva.example',
    '1password.com',
    `${'a'.repeat(63)}.com`,
  ],
  refused: [
    'com',
    '*.com',
    'a..b',
    'a.-b',
    '-a.com',
    'a-.com',
    '.example.com',
    'example.com.',
    '*.',
    '**.example.com',
    'example.com/path',
    '192.168.0.1',
    '*.10.0.0.1',
    '[::1]',
    '::1',
    `${'a'.repeat(64)}.com`,
  ],
};
const ISSUERS = {
  accepted: ['https://ci.example.com', 'https://ci.example.com:8443/oidc'],
  refused: [
    'https:ci.example.com',
    'https:/ci.example.com',
    'HTTPS://ci.example.com',
    'http://ci.example.com',
  ],
};

describe('the schema version', () => {
  it('is a release candidate of version 1 until QAuth 1.0.0 (ADR-018 §5)', () => {
    expect(REALM_POLICY_SCHEMA_VERSION).toMatch(/^1-rc\.\d+$/);
    expect(REALM_POLICY_REGISTRY.version).toBe(REALM_POLICY_SCHEMA_VERSION);
    expect(toJsonSchema()['x-qauth-schema-version']).toBe(REALM_POLICY_SCHEMA_VERSION);
  });
});

describe('diffPolicies', () => {
  // Acceptance criterion of #514.
  it('marks lowering password.minScore as a loosening security change', () => {
    const diff = diffPolicies(TABLE_DEFAULTS, withPolicies({ password: { minScore: 1 } }));
    expect(diff.changes).toEqual([
      {
        path: 'password.minScore',
        before: 2,
        after: 1,
        direction: 'loosening',
        class: 'security',
        effects: ['credential-path'],
        secret: false,
        environmentBound: false,
      },
    ]);
    expect(diff.class).toBe('security');
    expect(diff.effects).toEqual(['credential-path']);
  });

  // Acceptance criterion of #514.
  it('marks raising password.minScore as a tightening write change', () => {
    const diff = diffPolicies(TABLE_DEFAULTS, withPolicies({ password: { minScore: 4 } }));
    expect(diff.changes).toEqual([
      expect.objectContaining({
        path: 'password.minScore',
        direction: 'tightening',
        class: 'write',
        effects: [],
      }),
    ]);
    expect(diff.class).toBe('write');
    expect(diff.effects).toEqual([]);
  });

  // Acceptance criterion of #514.
  it('marks a change of mail.fromAddress as a security change in both directions', () => {
    const set = withPolicies({ mail: { fromAddress: 'noreply@example.com' } });
    const other = withPolicies({ mail: { fromAddress: 'auth@example.org' } });
    for (const [before, after] of [
      [TABLE_DEFAULTS, set],
      [set, TABLE_DEFAULTS],
      [set, other],
      [other, set],
    ]) {
      const { changes, class: changeClass } = diffPolicies(before, after);
      expect(changes).toEqual([
        expect.objectContaining({
          path: 'mail.fromAddress',
          direction: 'neutral',
          class: 'security',
          effects: ['credential-path'],
          environmentBound: true,
        }),
      ]);
      expect(changeClass).toBe('security');
    }
  });

  it('lists no change for equal documents, and reads a missing member as its default', () => {
    expect(diffPolicies(TABLE_DEFAULTS, structuredClone(TABLE_DEFAULTS)).changes).toEqual([]);
    expect(diffPolicies({}, TABLE_DEFAULTS).changes).toEqual([]);
    expect(diffPolicies({}, { password: { minScore: 1 } }).changes).toEqual([
      expect.objectContaining({ path: 'password.minScore', before: 2, after: 1 }),
    ]);
  });

  it('compares a set as a set: another order of the same entries is no change', () => {
    const reordered = withPolicies({
      registration: {
        dynamicRegistrationAllowedScopes: ['offline_access', 'email', 'profile', 'openid'],
        cimd: TABLE_DEFAULTS.registration.cimd,
      },
    });
    expect(diffPolicies(TABLE_DEFAULTS, reordered).changes).toEqual([]);
  });

  it('counts an added registration scope as a loosening and a removed one as a tightening', () => {
    const scopes = (list: string[]) =>
      withPolicies({
        registration: {
          dynamicRegistrationAllowedScopes: list,
          cimd: TABLE_DEFAULTS.registration.cimd,
        },
      });
    const added = diffPolicies(
      TABLE_DEFAULTS,
      scopes(['openid', 'profile', 'email', 'offline_access', 'notes:read'])
    );
    expect(added.changes[0]).toMatchObject({
      direction: 'loosening',
      class: 'security',
      effects: ['token-content'],
    });
    const removed = diffPolicies(TABLE_DEFAULTS, scopes(['openid']));
    expect(removed.changes[0]).toMatchObject({ direction: 'tightening', class: 'write' });
    // One added and one removed: an added scope can reach a token, so it loosens.
    const swapped = diffPolicies(
      TABLE_DEFAULTS,
      scopes(['openid', 'profile', 'email', 'notes:read'])
    );
    expect(swapped.changes[0]).toMatchObject({ direction: 'loosening', class: 'security' });
  });

  // #508's rule for realms.policies.update: lengthening a token lifetime is
  // posture-loosening, shortening one is a write.
  it('counts a longer token lifetime as posture-loosening and a shorter one as a write', () => {
    for (const field of [
      'accessTokenLifespanSeconds',
      'developmentAccessTokenLifespanSeconds',
      'refreshTokenLifespanSeconds',
      'adminAccessTokenLifespanSeconds',
    ] as const) {
      const current = TABLE_DEFAULTS.tokens[field];
      const longer = diffPolicies(
        TABLE_DEFAULTS,
        withPolicies({ tokens: { [field]: current + 60 } })
      );
      expect(longer.changes).toEqual([
        expect.objectContaining({
          path: `tokens.${field}`,
          direction: 'loosening',
          class: 'security',
          effects: ['posture-loosening'],
        }),
      ]);
      const shorter = diffPolicies(
        TABLE_DEFAULTS,
        withPolicies({ tokens: { [field]: current - 60 } })
      );
      expect(shorter.changes).toEqual([
        expect.objectContaining({ direction: 'tightening', class: 'write', effects: [] }),
      ]);
    }
  });

  it('counts loosening the environment posture as posture-loosening, and tightening it as a write', () => {
    const staging = withPolicies({ posture: { maxEnvironmentLaxity: 'staging' } });
    const development = withPolicies({ posture: { maxEnvironmentLaxity: 'development' } });
    expect(diffPolicies(TABLE_DEFAULTS, staging).changes[0]).toMatchObject({
      direction: 'loosening',
      class: 'security',
      effects: ['posture-loosening'],
    });
    expect(diffPolicies(development, staging).changes[0]).toMatchObject({
      direction: 'tightening',
      class: 'write',
    });
  });

  it('counts every change of the two-admin set as a security change, an added entry included', () => {
    const one = withPolicies({ admin: { twoAdminMandatoryOperations: ['users.passkeys.delete'] } });
    expect(diffPolicies(TABLE_DEFAULTS, one).changes[0]).toMatchObject({
      direction: 'tightening',
      class: 'security',
      effects: ['administration'],
    });
    expect(diffPolicies(one, TABLE_DEFAULTS).changes[0]).toMatchObject({
      direction: 'loosening',
      class: 'security',
      effects: ['administration'],
    });
  });

  it('counts the verified-account switch, brute force, CIMD and mail links by their direction', () => {
    const cimd = (changes: Record<string, unknown>) => ({
      registration: {
        ...TABLE_DEFAULTS.registration,
        cimd: { ...TABLE_DEFAULTS.registration.cimd, ...changes },
      },
    });
    const cases: Array<[Record<string, Record<string, unknown>>, string, string, string]> = [
      [
        { accounts: { requireVerifiedAccount: false } },
        'accounts.requireVerifiedAccount',
        'loosening',
        'security',
      ],
      [{ bruteForce: { enabled: false } }, 'bruteForce.enabled', 'loosening', 'security'],
      [{ bruteForce: { maxAttempts: 10 } }, 'bruteForce.maxAttempts', 'loosening', 'security'],
      [{ bruteForce: { maxAttempts: 3 } }, 'bruteForce.maxAttempts', 'tightening', 'write'],
      [{ bruteForce: { windowSeconds: 60 } }, 'bruteForce.windowSeconds', 'loosening', 'security'],
      [{ bruteForce: { windowSeconds: 3600 } }, 'bruteForce.windowSeconds', 'tightening', 'write'],
      [
        { bruteForce: { lockoutSeconds: 60 } },
        'bruteForce.lockoutSeconds',
        'loosening',
        'security',
      ],
      [
        { bruteForce: { lockoutSeconds: 3600 } },
        'bruteForce.lockoutSeconds',
        'tightening',
        'write',
      ],
      [cimd({ trustPolicy: 'allowlist' }), 'registration.cimd.trustPolicy', 'tightening', 'write'],
      [cimd({ enabled: false }), 'registration.cimd.enabled', 'tightening', 'write'],
      [
        cimd({ trustedDomains: ['*.example.com'] }),
        'registration.cimd.trustedDomains',
        'loosening',
        'security',
      ],
      [
        { mail: { verificationTokenExpirySeconds: 172800 } },
        'mail.verificationTokenExpirySeconds',
        'loosening',
        'security',
      ],
      [
        { mail: { verificationTokenExpirySeconds: 3600 } },
        'mail.verificationTokenExpirySeconds',
        'tightening',
        'write',
      ],
      [
        { mail: { invalidateExistingTokensOnResend: false } },
        'mail.invalidateExistingTokensOnResend',
        'loosening',
        'write',
      ],
    ];
    for (const [patch, path, direction, changeClass] of cases) {
      const { changes } = diffPolicies(TABLE_DEFAULTS, withPolicies(patch));
      expect(
        changes.map((change) => [change.path, change.direction, change.class]),
        path
      ).toEqual([[path, direction, changeClass]]);
    }
    // And back again: each change reversed moves the other way.
    const allowlist = withPolicies(cimd({ trustPolicy: 'allowlist', enabled: false }));
    expect(
      diffPolicies(allowlist, TABLE_DEFAULTS).changes.map((change) => [
        change.path,
        change.direction,
        change.class,
      ])
    ).toEqual([
      ['registration.cimd.enabled', 'loosening', 'security'],
      ['registration.cimd.trustPolicy', 'loosening', 'security'],
    ]);
  });

  it('reads -0 as 0, as JSON does', () => {
    const zero = withPolicies({ password: { minScore: 0 } });
    expect(diffPolicies(zero, withPolicies({ password: { minScore: -0 } })).changes).toEqual([]);
  });

  it('gives a mixed change the strictest class and every effect, in the list order', () => {
    const diff = diffPolicies(
      TABLE_DEFAULTS,
      withPolicies({
        tokens: { accessTokenLifespanSeconds: 300 },
        posture: { maxEnvironmentLaxity: 'development' },
        password: { minScore: 0 },
      })
    );
    expect(diff.changes.map((change) => [change.path, change.class])).toEqual([
      ['tokens.accessTokenLifespanSeconds', 'write'],
      ['password.minScore', 'security'],
      ['posture.maxEnvironmentLaxity', 'security'],
    ]);
    expect(diff.class).toBe('security');
    expect(diff.effects).toEqual(['credential-path', 'posture-loosening']);
  });

  it('records a secret being set as a security change without its value', () => {
    const secret = 'smtp-password-value';
    const after = withPolicies({
      mail: { smtp: { ...TABLE_DEFAULTS.mail.smtp, password: secret } },
    });
    const diff = diffPolicies(TABLE_DEFAULTS, after);
    expect(diff.changes).toEqual([
      {
        path: 'mail.smtp.password',
        before: false,
        after: true,
        direction: 'neutral',
        class: 'security',
        effects: ['credential-path'],
        secret: true,
        environmentBound: true,
      },
    ]);
    expect(JSON.stringify(diff)).not.toContain(secret);
    // A write that leaves the secret out leaves it as it is.
    expect(
      diffPolicies(TABLE_DEFAULTS, TABLE_DEFAULTS, { setSecrets: ['mail.smtp.password'] }).changes
    ).toEqual([]);
  });

  it('records a secret given again as a security change, so the diff never confirms a guess', () => {
    const after = withPolicies({
      mail: { smtp: { ...TABLE_DEFAULTS.mail.smtp, password: 'p4ss' } },
    });
    expect(
      diffPolicies(TABLE_DEFAULTS, after, { setSecrets: ['mail.smtp.password'] })
    ).toMatchObject({
      changes: [{ path: 'mail.smtp.password', before: true, after: true, class: 'security' }],
      class: 'security',
    });
    // The stored document holds no secret, so `before` cannot carry one to
    // compare with; it is refused without the value.
    let caught: unknown;
    try {
      diffPolicies(after, after);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(PolicyValidationError);
    expect(JSON.stringify((caught as PolicyValidationError).issues)).not.toContain('p4ss');
  });

  it('records a replaced and a cleared secret with what the secret store says was set', () => {
    const after = withPolicies({
      mail: { smtp: { ...TABLE_DEFAULTS.mail.smtp, password: 'new-password-value' } },
    });
    expect(
      diffPolicies(TABLE_DEFAULTS, after, { setSecrets: ['mail.smtp.password'] }).changes
    ).toEqual([
      expect.objectContaining({
        path: 'mail.smtp.password',
        before: true,
        after: true,
        class: 'security',
      }),
    ]);

    // null clears a secret.
    const cleared = diffPolicies(
      TABLE_DEFAULTS,
      withPolicies({ mail: { resend: { apiKey: null } } }),
      {
        setSecrets: ['mail.resend.apiKey'],
      }
    );
    expect(cleared.changes).toEqual([
      {
        path: 'mail.resend.apiKey',
        before: true,
        after: false,
        direction: 'neutral',
        class: 'security',
        effects: ['credential-path'],
        secret: true,
        environmentBound: true,
      },
    ]);
    // Clearing counts even when the caller does not say the secret was set.
    const unset = diffPolicies(
      TABLE_DEFAULTS,
      withPolicies({ mail: { smtp: { ...TABLE_DEFAULTS.mail.smtp, password: null } } })
    );
    expect(unset.changes).toEqual([
      expect.objectContaining({ path: 'mail.smtp.password', before: false, after: false }),
    ]);
    expect(unset.class).toBe('security');
  });

  it('keeps a secret the write leaves out, and changes nothing when a representation is sent back', () => {
    const setSecrets = ['mail.smtp.password'];
    expect(diffPolicies(TABLE_DEFAULTS, TABLE_DEFAULTS, { setSecrets }).changes).toEqual([]);
    const representation = toRealmPoliciesRepresentation(TABLE_DEFAULTS, setSecrets);
    expect(representation.mail.smtp.passwordSet).toBe(true);
    expect(diffPolicies(TABLE_DEFAULTS, representation, { setSecrets }).changes).toEqual([]);
    // A flag that says otherwise sets and clears nothing either.
    const flipped = {
      ...representation,
      mail: {
        ...representation.mail,
        smtp: { ...representation.mail.smtp, passwordSet: false },
        resend: { apiKeySet: true },
      },
    };
    expect(diffPolicies(TABLE_DEFAULTS, flipped, { setSecrets }).changes).toEqual([]);
    // The write drops the flag, so what it parses to holds none.
    expect(REALM_POLICY_REGISTRY.parse(flipped, 'input')).toEqual(
      REALM_POLICY_REGISTRY.parse(TABLE_DEFAULTS, 'input')
    );
  });

  it('refuses a path that is not a secret, without echoing it', () => {
    for (const options of [
      { setSecrets: ['hunter2-secret'] },
      { setSecrets: ['mail.fromAddress'] },
    ]) {
      let caught: unknown;
      try {
        diffPolicies(TABLE_DEFAULTS, TABLE_DEFAULTS, options);
      } catch (error) {
        caught = error;
      }
      expect((caught as Error).message).toMatch(/not a secret field/);
      expect((caught as Error).message).not.toMatch(/hunter2|fromAddress/);
    }
  });

  it('refuses a document with an unknown member, naming its path and not its value', () => {
    let caught: unknown;
    try {
      diffPolicies(TABLE_DEFAULTS, { password: { minScore: 2, minLength: 'hunter2-hunter2' } });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(PolicyValidationError);
    const issues = (caught as PolicyValidationError).issues;
    expect(issues.map((issue) => issue.path)).toEqual(['password']);
    expect(JSON.stringify(issues)).toContain('minLength');
    expect(JSON.stringify(issues)).not.toContain('hunter2');
  });
});

describe('defaultsFromEnv', () => {
  // Acceptance criterion of #514.
  it('of an empty environment equals the defaults of the table', () => {
    expect(defaultsFromEnv({})).toEqual(TABLE_DEFAULTS);
  });

  it('reads raw environment strings as the environment writes them', () => {
    const policies = defaultsFromEnv({
      ACCESS_TOKEN_LIFESPAN: '300',
      REQUIRE_VERIFIED_ACCOUNT: 'false',
      FAILED_LOGIN_TRACKING_ENABLED: '0',
      DEFAULT_DYNAMIC_REGISTRATION_SCOPES: 'openid, profile  email',
      CIMD_TRUSTED_DOMAINS: '',
      CIMD_TRUST_POLICY: 'allowlist',
      EMAIL_PROVIDER: 'smtp',
      EMAIL_FROM_ADDRESS: 'noreply@example.com',
      SMTP_PORT: '587',
      SMTP_HOST: '   ',
    });
    expect(policies.tokens.accessTokenLifespanSeconds).toBe(300);
    expect(policies.accounts.requireVerifiedAccount).toBe(false);
    expect(policies.bruteForce.enabled).toBe(false);
    expect(policies.registration.dynamicRegistrationAllowedScopes).toEqual([
      'openid',
      'profile',
      'email',
    ]);
    expect(policies.registration.cimd.trustedDomains).toEqual([]);
    expect(policies.registration.cimd.trustPolicy).toBe('allowlist');
    expect(policies.mail).toMatchObject({
      provider: 'smtp',
      fromAddress: 'noreply@example.com',
      smtp: { port: 587, host: null },
    });
  });

  it('reads numbers as the env schemas do, and a set listed with a repeat as the set', () => {
    const policies = defaultsFromEnv({
      ACCESS_TOKEN_LIFESPAN: '1e3',
      REFRESH_TOKEN_LIFESPAN: '0x10',
      FAILED_LOGIN_MAX_ATTEMPTS: '+5',
      DEFAULT_DYNAMIC_REGISTRATION_SCOPES: 'openid openid profile',
      CIMD_TRUSTED_DOMAINS: 'Example.com example.com *.Example.org',
    });
    expect(policies.tokens.accessTokenLifespanSeconds).toBe(1000);
    expect(policies.tokens.refreshTokenLifespanSeconds).toBe(16);
    expect(policies.bruteForce.maxAttempts).toBe(5);
    expect(policies.registration.dynamicRegistrationAllowedScopes).toEqual(['openid', 'profile']);
    expect(policies.registration.cimd.trustedDomains).toEqual(['example.com', '*.example.org']);
  });

  it('takes values the env schema already parsed as they are', () => {
    const policies = defaultsFromEnv({
      ACCESS_TOKEN_LIFESPAN: 300,
      REQUIRE_VERIFIED_ACCOUNT: false,
      CIMD_TRUSTED_DOMAINS: ['example.com', '*.example.org'],
      SMTP_PORT: undefined,
    });
    expect(policies.tokens.accessTokenLifespanSeconds).toBe(300);
    expect(policies.accounts.requireVerifiedAccount).toBe(false);
    expect(policies.registration.cimd.trustedDomains).toEqual(['example.com', '*.example.org']);
    expect(policies.mail.smtp.port).toBeNull();
  });

  it('reads a deprecated key name as its current one, as the server does', () => {
    expect(
      defaultsFromEnv({ REQUIRE_EMAIL_VERIFIED: 'false' }).accounts.requireVerifiedAccount
    ).toBe(false);
    expect(
      defaultsFromEnv({ REQUIRE_EMAIL_VERIFIED: 'false', REQUIRE_VERIFIED_ACCOUNT: 'false' })
        .accounts.requireVerifiedAccount
    ).toBe(false);
    expect(() =>
      defaultsFromEnv({ REQUIRE_EMAIL_VERIFIED: 'false', REQUIRE_VERIFIED_ACCOUNT: 'true' })
    ).toThrow(/REQUIRE_EMAIL_VERIFIED/);
  });

  it('refuses a raw value the server refuses, which it would otherwise seed', () => {
    for (const env of [
      { REQUIRE_VERIFIED_ACCOUNT: '0' },
      { CIMD_ENABLED: '1' },
      { SMTP_SECURE: ' true ' },
      { ACCESS_TOKEN_LIFESPAN: '' },
      { CIMD_TRUST_POLICY: ' ' },
    ]) {
      expect(() => defaultsFromEnv(env), JSON.stringify(env)).toThrow(PolicySeedError);
    }
    // Blank is unset where the server reads it so, never the weakest score.
    expect(defaultsFromEnv({ PASSWORD_MIN_SCORE: '' }).password.minScore).toBe(2);
    expect(defaultsFromEnv({ REQUIRE_VERIFIED_ACCOUNT: ' ' }).accounts.requireVerifiedAccount).toBe(
      true
    );
  });

  it('never seeds a secret into the document', () => {
    const policies = defaultsFromEnv({ SMTP_PASSWORD: 'p4ss', RESEND_API_KEY: 're_key' });
    expect(JSON.stringify(policies)).not.toMatch(/p4ss|re_key/);
    expect(
      REALM_POLICY_REGISTRY.secretSeedsFromEnv({ SMTP_PASSWORD: 'p4ss', RESEND_API_KEY: ' ' })
    ).toEqual(new Map([['mail.smtp.password', 'p4ss']]));
  });

  it('refuses a value its field refuses, naming the key and the field but not the value', () => {
    for (const env of [
      { PASSWORD_MIN_SCORE: '5' },
      { ACCESS_TOKEN_LIFESPAN: 'soon' },
      { DEFAULT_DYNAMIC_REGISTRATION_SCOPES: 'openid qauth:admin:read' },
      { DEFAULT_DYNAMIC_REGISTRATION_SCOPES: 'openid QAuth:Admin:Security' },
      { EMAIL_FROM_NAME: 'QAuth\r\nBcc: someone@example.com' },
      { CIMD_TRUSTED_DOMAINS: 'example.com/path' },
      { ACCESS_TOKEN_LIFESPAN: 'Infinity' },
    ]) {
      const [key, value] = Object.entries(env)[0];
      let caught: unknown;
      try {
        defaultsFromEnv(env);
      } catch (error) {
        caught = error;
      }
      expect(caught, key).toBeInstanceOf(PolicySeedError);
      expect((caught as PolicySeedError).key).toBe(key);
      expect((caught as Error).message).not.toContain(value);
    }
  });

  it('leaves the fields that no key seeds at their defaults', () => {
    const policies = defaultsFromEnv({
      ADMIN_ACCESS_TOKEN_LIFESPAN: '900',
      MAX_ENVIRONMENT_LAXITY: 'development',
    });
    expect(policies.tokens.adminAccessTokenLifespanSeconds).toBe(600);
    expect(policies.posture.maxEnvironmentLaxity).toBe('production');
  });
});

describe('parseRealmPolicies', () => {
  it('fills a stored document that predates a field with its default', () => {
    expect(parseRealmPolicies({})).toEqual(TABLE_DEFAULTS);
    expect(parseRealmPolicies({ tokens: { accessTokenLifespanSeconds: 300 } }).tokens).toEqual({
      ...TABLE_DEFAULTS.tokens,
      accessTokenLifespanSeconds: 300,
    });
  });

  it('refuses a secret value, which the document never holds', () => {
    expect(() => parseRealmPolicies({ mail: { smtp: { password: 'p4ss' } } })).toThrow(
      PolicyValidationError
    );
  });

  it('accepts a trusted domain of two labels or more, stored in lower case', () => {
    expect(
      parseRealmPolicies({ registration: { cimd: { trustedDomains: DOMAINS.accepted } } })
        .registration.cimd.trustedDomains
    ).toEqual(DOMAINS.accepted.map((domain) => domain.toLowerCase()));
  });

  it('refuses a trusted domain that is a bare top-level domain, an IP literal or not a host', () => {
    for (const domain of DOMAINS.refused) {
      expect(
        () => parseRealmPolicies({ registration: { cimd: { trustedDomains: [domain] } } }),
        domain
      ).toThrow(PolicyValidationError);
    }
  });

  it('accepts an https issuer with a path', () => {
    const issuers = ['https://ci.example.com', 'https://ci.example.com/oidc/realm-1'];
    expect(
      parseRealmPolicies({ admin: { workloadIssuers: issuers } }).admin.workloadIssuers
    ).toEqual(issuers);
  });

  it('bounds the token lifetimes: a day for an access token, 90 days for a refresh token', () => {
    const atBounds = parseRealmPolicies({
      tokens: {
        accessTokenLifespanSeconds: 86_400,
        developmentAccessTokenLifespanSeconds: 86_400,
        refreshTokenLifespanSeconds: 7_776_000,
      },
    }).tokens;
    expect(atBounds).toMatchObject({
      accessTokenLifespanSeconds: 86_400,
      developmentAccessTokenLifespanSeconds: 86_400,
      refreshTokenLifespanSeconds: 7_776_000,
    });
    // A row written by hand with a lifetime of years is refused, as any value
    // the schema refuses: the realm's requests fail rather than issue it.
    for (const tokens of [
      { accessTokenLifespanSeconds: 86_401 },
      { accessTokenLifespanSeconds: 315_360_000 },
      { developmentAccessTokenLifespanSeconds: 86_401 },
      { refreshTokenLifespanSeconds: 7_776_001 },
    ]) {
      expect(() => parseRealmPolicies({ tokens }), JSON.stringify(tokens)).toThrow(
        PolicyValidationError
      );
    }
  });

  it('refuses values outside the bounds the issue sets', () => {
    for (const document of [
      { tokens: { adminAccessTokenLifespanSeconds: 901 } },
      { password: { minScore: -1 } },
      { mail: { verificationTokenExpirySeconds: 3599 } },
      { posture: { maxEnvironmentLaxity: 'test' } },
      { admin: { workloadIssuers: ['http://ci.example.com'] } },
      { admin: { workloadIssuers: ['https://'] } },
      { admin: { workloadIssuers: ['https://user:pass@ci.example.com'] } },
      { admin: { workloadIssuers: ['https://ci.example.com?audience=x'] } },
      { admin: { workloadIssuers: ['https://ci.example.com#f'] } },
      ...ISSUERS.refused.map((issuer) => ({ admin: { workloadIssuers: [issuer] } })),
      { admin: { twoAdminMandatoryOperations: ['users'] } },
      { registration: { dynamicRegistrationAllowedScopes: ['openid', 'openid'] } },
    ]) {
      expect(() => parseRealmPolicies(document), JSON.stringify(document)).toThrow(
        PolicyValidationError
      );
    }
  });
});

describe('the representation', () => {
  it('shows a secret only as <name>Set and never copies its value', () => {
    const document = withPolicies({
      mail: { smtp: { ...TABLE_DEFAULTS.mail.smtp, password: 'p4ss' } },
    });
    const representation = toRealmPoliciesRepresentation(document, ['mail.smtp.password']);
    expect(representation.mail.smtp).toEqual({
      host: null,
      port: null,
      secure: true,
      user: null,
      passwordSet: true,
    });
    expect(representation.mail.resend).toEqual({ apiKeySet: false });
    expect(JSON.stringify(representation)).not.toContain('p4ss');
    expect(representation.tokens).toEqual(TABLE_DEFAULTS.tokens);
  });

  it('never fills a missing member with its default, which could show a loosened realm as strict', () => {
    const loosened = toRealmPoliciesRepresentation(
      withPolicies({ accounts: { requireVerifiedAccount: false } })
    );
    const schema = REALM_POLICY_REGISTRY.schema('representation');
    expect(schema.parse(loosened)).toEqual(loosened);
    const withoutAccounts: Record<string, unknown> = { ...loosened };
    delete withoutAccounts['accounts'];
    expect(schema.safeParse(withoutAccounts).success).toBe(false);
    expect(
      schema.safeParse({ ...loosened, bruteForce: { ...loosened.bruteForce, enabled: undefined } })
        .success
    ).toBe(false);
  });

  it('refuses to flag a path that is not a secret field', () => {
    expect(() => toRealmPoliciesRepresentation(TABLE_DEFAULTS, ['mail.fromAddress'])).toThrow(
      /not a secret field/
    );
  });

  it('strips a member it does not name when it serialises', () => {
    const representation = toRealmPoliciesRepresentation(TABLE_DEFAULTS);
    const parsed = REALM_POLICY_REGISTRY.schema('representation').parse({
      ...representation,
      mail: { ...representation.mail, smtp: { ...representation.mail.smtp, password: 'p4ss' } },
    });
    expect(JSON.stringify(parsed)).not.toContain('p4ss');
  });
});

describe('toJsonSchema', () => {
  const properties = (schema: Record<string, unknown>, ...path: string[]) => {
    let node = schema;
    for (const segment of path) {
      node = (node['properties'] as Record<string, Record<string, unknown>>)[segment];
    }
    return node['properties'] as Record<string, Record<string, unknown>>;
  };

  // Acceptance criterion of #514.
  it('leaves a secret field out of the representation and shows it as ...Set', () => {
    const representation = toJsonSchema('representation');
    const smtp = properties(representation, 'mail', 'smtp');
    expect(smtp).not.toHaveProperty('password');
    expect(smtp['passwordSet']).toMatchObject({ type: 'boolean', readOnly: true });
    const resend = properties(representation, 'mail', 'resend');
    expect(resend).not.toHaveProperty('apiKey');
    expect(resend['apiKeySet']).toMatchObject({ type: 'boolean', readOnly: true });
    const mail = (representation['properties'] as Record<string, unknown>)['mail'];
    expect(JSON.stringify(mail)).not.toMatch(/"(password|apiKey)"/);
  });

  it('makes a secret field write-only in the input and leaves it out of the document', () => {
    const smtp = properties(toJsonSchema('input'), 'mail', 'smtp');
    expect(smtp['password']).toMatchObject({
      anyOf: [expect.objectContaining({ type: 'string' }), { type: 'null' }],
      writeOnly: true,
      description: expect.stringContaining('null clears it'),
    });
    // The representation's flag is accepted in a write, read-only.
    expect(smtp['passwordSet']).toMatchObject({ type: 'boolean', readOnly: true });
    const document = toJsonSchema('document');
    expect(properties(document, 'mail', 'smtp')).not.toHaveProperty('password');
    expect(properties(document, 'mail', 'smtp')).not.toHaveProperty('passwordSet');
  });

  it("carries each field's sentence, default and annotations", () => {
    const minScore = properties(toJsonSchema('document'), 'password')['minScore'];
    expect(minScore).toMatchObject({
      type: 'integer',
      minimum: 0,
      maximum: 4,
      default: 2,
      description: expect.stringMatching(/\.$/),
      'x-qauth-policy': {
        docs: 'https://docs.qauth.dev/reference/realm-policies/#password',
        seedEnv: 'PASSWORD_MIN_SCORE',
        direction: 'higher-is-stricter',
        securityWhen: 'loosening',
        effects: ['credential-path'],
        secret: false,
        environmentBound: false,
      },
    });
    const laxity = properties(toJsonSchema('document'), 'posture')['maxEnvironmentLaxity'];
    expect(laxity['x-qauth-policy']).toMatchObject({
      direction: 'ordered',
      order: ['development', 'staging', 'production'],
    });
    const scopes = properties(toJsonSchema('input'), 'registration')[
      'dynamicRegistrationAllowedScopes'
    ];
    expect(scopes['uniqueItems']).toBe(true);
  });

  it('refuses unknown members in the document and the input, and stays open in the representation', () => {
    expect(toJsonSchema('document')['additionalProperties']).toBe(false);
    expect(properties(toJsonSchema('input'), 'mail')).toBeDefined();
    expect(
      (toJsonSchema('input')['properties'] as Record<string, Record<string, unknown>>)['mail'][
        'additionalProperties'
      ]
    ).toBe(false);
    expect(toJsonSchema('representation')).not.toHaveProperty('additionalProperties');
    expect(JSON.stringify(toJsonSchema('representation'))).not.toContain(
      '"additionalProperties":false'
    );
  });

  it('gives a pattern that accepts what the input accepts, for the trusted domains and the issuers', () => {
    const input = toJsonSchema('input');
    const cases = [
      [
        properties(input, 'registration', 'cimd')['trustedDomains'],
        DOMAINS,
        (value: string[]) => ({
          registration: { cimd: { trustedDomains: value } },
        }),
      ],
      [
        properties(input, 'admin')['workloadIssuers'],
        ISSUERS,
        (value: string[]) => ({
          admin: { workloadIssuers: value },
        }),
      ],
    ] as const;
    for (const [property, samples, document] of cases) {
      const pattern = new RegExp((property['items'] as { pattern: string }).pattern);
      for (const sample of [...samples.accepted, ...samples.refused]) {
        const accepted = REALM_POLICY_REGISTRY.schema('input').safeParse(
          document([sample])
        ).success;
        expect(pattern.test(sample), sample).toBe(accepted);
      }
    }
  });

  it('is plain JSON', () => {
    for (const view of ['document', 'input', 'representation'] as const) {
      const schema = toJsonSchema(view);
      expect(JSON.parse(JSON.stringify(schema))).toEqual(schema);
      expect(schema['$schema']).toBe('https://json-schema.org/draft/2020-12/schema');
    }
  });
});

describe('the TypeScript types', () => {
  it('leave a secret out of the document and show it as <name>Set in the representation', () => {
    expectTypeOf<RealmPolicies['mail']['smtp']>().not.toHaveProperty('password');
    expectTypeOf<RealmPolicies['mail']['smtp']>()
      .toHaveProperty('port')
      .toEqualTypeOf<number | null>();
    expectTypeOf<RealmPoliciesRepresentation['mail']['smtp']>()
      .toHaveProperty('passwordSet')
      .toEqualTypeOf<boolean>();
    expectTypeOf<RealmPoliciesRepresentation['mail']['resend']>().toEqualTypeOf<{
      apiKeySet: boolean;
    }>();
    expectTypeOf<RealmPolicies['registration']['dynamicRegistrationAllowedScopes']>().toEqualTypeOf<
      string[]
    >();
    expectTypeOf<RealmPolicies['posture']['maxEnvironmentLaxity']>().toEqualTypeOf<
      'development' | 'staging' | 'production'
    >();
  });
});

describe('registerPolicyGroup on the shared registry', () => {
  const lifetime = () =>
    policyField(z.number().int().positive(), {
      seedEnv: null,
      default: 60,
      direction: 'lower-is-stricter',
      securityWhen: 'loosening',
      effects: ['posture-loosening'],
      secret: false,
      environmentBound: false,
      doc: { summary: 'A setting for this test.', link: 'https://docs.qauth.dev/reference/' },
    });

  it('refuses a group that clashes with a built-in one in the shared registry', () => {
    expect(() => registerPolicyGroup('tokens', { idTokenLifespanSeconds: lifetime() })).toThrow(
      /already registered/
    );
    expect(() => registerPolicyGroup('bruteforce', { delaySeconds: lifetime() })).toThrow(
      /differs only in case from the registered group "bruteForce"/
    );
    expect(REALM_POLICY_REGISTRY.field('tokens.idTokenLifespanSeconds')).toBeUndefined();
  });

  it('adds a valid group, which the other wrappers then read', async () => {
    // A fresh copy of the module, so the group stays out of the registry the
    // other tests read.
    vi.resetModules();
    const fresh = await import('./realm-policies');
    fresh.registerPolicyGroup('testOnlyGroup', { delaySeconds: lifetime() });
    expect(fresh.REALM_POLICY_REGISTRY.field('testOnlyGroup.delaySeconds')?.field.default).toBe(60);
    expect(fresh.parseRealmPolicies({})).toEqual({
      ...TABLE_DEFAULTS,
      testOnlyGroup: { delaySeconds: 60 },
    });
    expect(
      fresh
        .diffPolicies({}, { testOnlyGroup: { delaySeconds: 120 } })
        .changes.map((change) => [change.path, change.class])
    ).toEqual([['testOnlyGroup.delaySeconds', 'security']]);
    expect(REALM_POLICY_REGISTRY.field('testOnlyGroup.delaySeconds')).toBeUndefined();
  });
});
