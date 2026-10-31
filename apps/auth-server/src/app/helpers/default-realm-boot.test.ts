import {
  RealmPolicySeedRefusedError,
  type RealmPolicySeedReport,
} from '@qauth-labs/fastify-plugin-realm-policy';
import { BadRequestError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

import {
  bootDefaultRealm,
  type DefaultRealmBootDependencies,
  DefaultRealmBootError,
  defaultRealmIssuerFrom,
  EMAIL_BASE_URL_IGNORED_WARNING,
  emailBaseUrlWarning,
  JWT_ISSUER_PATH_WARNING,
  JWT_ISSUER_TRAILING_SLASH_WARNING,
  seedKeyIgnoredWarning,
  seedKeyStillAppliedNote,
} from './default-realm-boot';
import type { RealmRow } from './request-realm';

/**
 * The default realm's boot step (#484), without a database: how `JWT_ISSUER`
 * becomes the stored issuer and primary host, and what the boot logs. The
 * steps against a real Postgres are in `default-realm-boot.integration.test.ts`.
 */

describe('emailBaseUrlWarning (#490)', () => {
  it('says nothing when EMAIL_BASE_URL is unset, the key being optional', () => {
    expect(emailBaseUrlWarning(undefined, 'https://auth.example.com')).toBe(undefined);
  });

  it('says nothing when EMAIL_BASE_URL is the issuer, a trailing slash aside', () => {
    expect(emailBaseUrlWarning('https://auth.example.com', 'https://auth.example.com')).toBe(
      undefined
    );
    expect(emailBaseUrlWarning('https://auth.example.com/', 'https://auth.example.com')).toBe(
      undefined
    );
    expect(emailBaseUrlWarning('https://auth.example.com', 'https://auth.example.com/')).toBe(
      undefined
    );
  });

  it('warns when the mailed links move from EMAIL_BASE_URL to the issuer', () => {
    expect(emailBaseUrlWarning('https://qauth.dev', 'https://auth.qauth.dev')).toBe(
      EMAIL_BASE_URL_IGNORED_WARNING
    );
    expect(emailBaseUrlWarning('https://auth.example.com/app', 'https://auth.example.com')).toBe(
      EMAIL_BASE_URL_IGNORED_WARNING
    );
  });
});

describe('defaultRealmIssuerFrom', () => {
  it('stores https://auth.example.com:8443/ as https://auth.example.com:8443 on the host auth.example.com', () => {
    expect(defaultRealmIssuerFrom('https://auth.example.com:8443/')).toEqual({
      issuer: 'https://auth.example.com:8443',
      host: 'auth.example.com',
      warnings: [JWT_ISSUER_TRAILING_SLASH_WARNING],
    });
  });

  it('keeps an origin with no trailing slash as it is, with no warning', () => {
    expect(defaultRealmIssuerFrom('https://auth.example.com')).toEqual({
      issuer: 'https://auth.example.com',
      host: 'auth.example.com',
      warnings: [],
    });
  });

  it('keeps a path, takes only the host for routing, and warns', () => {
    expect(defaultRealmIssuerFrom('https://example.com/auth')).toEqual({
      issuer: 'https://example.com/auth',
      host: 'example.com',
      warnings: [JWT_ISSUER_PATH_WARNING],
    });
  });

  it('warns twice for a path with a trailing slash, and drops the slash', () => {
    expect(defaultRealmIssuerFrom('https://example.com/auth/')).toEqual({
      issuer: 'https://example.com/auth',
      host: 'example.com',
      warnings: [JWT_ISSUER_TRAILING_SLASH_WARNING, JWT_ISSUER_PATH_WARNING],
    });
  });

  it('keeps the issuer as written and writes the host in stored form', () => {
    expect(defaultRealmIssuerFrom('http://LocalHost:3000')).toMatchObject({
      issuer: 'http://LocalHost:3000',
      host: 'localhost',
    });
  });

  it.each(['https://127.0.0.1:3000', 'https://[::1]'])(
    'refuses %s, whose host can be no primary host, naming JWT_ISSUER',
    (jwtIssuer) => {
      expect(() => defaultRealmIssuerFrom(jwtIssuer)).toThrow(DefaultRealmBootError);
      expect(() => defaultRealmIssuerFrom(jwtIssuer)).toThrow(
        `The host of JWT_ISSUER "${jwtIssuer}" cannot be the default realm's primary host`
      );
    }
  );
});

/** A realm row as the repository returns it. */
function realmRow(overrides: Partial<RealmRow> = {}): RealmRow {
  return {
    id: '019a0000-0000-7000-8000-000000000001',
    name: 'master',
    enabled: true,
    issuer: null,
    isOperator: false,
    webauthnRpId: null,
    webauthnRpIdLockedAt: null,
    policiesVersion: 1,
    ...overrides,
  } as RealmRow;
}

/**
 * The boot step's dependencies over an empty database: the realm is created,
 * and the transaction runs its callback with a stand-in handle.
 */
function emptyDatabase(): {
  deps: DefaultRealmBootDependencies;
  warn: ReturnType<typeof vi.fn>;
  info: ReturnType<typeof vi.fn>;
} {
  const created = realmRow({ issuer: 'https://auth.example.com' });
  const realms = {
    lockProvisioning: vi.fn(async () => undefined),
    findByName: vi.fn(async () => undefined),
    findByHost: vi.fn(async () => undefined),
    findOperator: vi.fn(async () => undefined),
    createWithPrimaryHost: vi.fn(async () => ({
      realm: created,
      host: { host: 'auth.example.com', realmId: created.id, kind: 'primary', createdAt: 0 },
    })),
    update: vi.fn(async (_id: string, data: Partial<RealmRow>) => ({ ...created, ...data })),
    setOperator: vi.fn(async (_id: string, isOperator: boolean) => ({ ...created, isOperator })),
    setWebAuthnRpId: vi.fn(async (_id: string, webauthnRpId: string | null) => ({
      ...created,
      webauthnRpId,
    })),
    addEndpointHost: vi.fn(async (realmId: string, host: string) => ({
      host,
      realmId,
      kind: 'endpoint',
      createdAt: 0,
    })),
  };
  const warn = vi.fn();
  const info = vi.fn();
  const deps = {
    db: { transaction: async (run: (tx: unknown) => Promise<unknown>) => run({}) },
    realms,
    // A new realm got its policies when it was created: nothing to fill.
    policies: {
      seedRealms: vi.fn(async (): Promise<RealmPolicySeedReport> => ({
        filled: [],
        completed: [],
        skipped: [],
      })),
    },
    log: { warn, info },
  } as unknown as DefaultRealmBootDependencies;
  return { deps, warn, info };
}

describe('bootDefaultRealm logging', () => {
  const settings = { realmName: 'master', endpointHosts: ['auth-server'] };

  it('logs a warning for a trailing slash', async () => {
    const { deps, warn } = emptyDatabase();

    await bootDefaultRealm(deps, { ...settings, jwtIssuer: 'https://auth.example.com/' });

    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      { variable: 'JWT_ISSUER', issuer: 'https://auth.example.com/' },
      JWT_ISSUER_TRAILING_SLASH_WARNING
    );
  });

  it('logs a warning for a path', async () => {
    const { deps, warn } = emptyDatabase();

    await bootDefaultRealm(deps, { ...settings, jwtIssuer: 'https://auth.example.com/qauth' });

    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      { variable: 'JWT_ISSUER', issuer: 'https://auth.example.com/qauth' },
      JWT_ISSUER_PATH_WARNING
    );
  });

  it('logs no warning for an origin', async () => {
    const { deps, warn } = emptyDatabase();

    await bootDefaultRealm(deps, { ...settings, jwtIssuer: 'https://auth.example.com' });

    expect(warn).not.toHaveBeenCalled();
  });

  it('logs one line with the realm name, issuer, host, operator flag and passkey RP ID', async () => {
    const { deps, info } = emptyDatabase();

    await bootDefaultRealm(deps, { ...settings, jwtIssuer: 'https://auth.example.com' });

    expect(info).toHaveBeenCalledTimes(1);
    expect(info).toHaveBeenCalledWith(
      {
        realm: 'master',
        issuer: 'https://auth.example.com',
        host: 'auth.example.com',
        operator: true,
        endpointHostsAdded: ['auth-server'],
        passkeyRpId: 'auth.example.com',
        passkeyRpIdLocked: false,
        policiesVersion: 1,
      },
      'default realm ready'
    );
  });

  it('takes the provisioning lock before it reads a realm', async () => {
    const { deps } = emptyDatabase();
    const realms = deps.realms as unknown as Record<string, ReturnType<typeof vi.fn>>;

    await bootDefaultRealm(deps, { ...settings, jwtIssuer: 'https://auth.example.com' });

    expect(realms['lockProvisioning'].mock.invocationCallOrder[0]).toBeLessThan(
      realms['findByName'].mock.invocationCallOrder[0]
    );
  });
});

describe('bootDefaultRealm and the passkey RP ID (#467, #553)', () => {
  const settings = {
    realmName: 'master',
    jwtIssuer: 'https://auth.example.com',
    endpointHosts: [],
  };
  const LOCKED_AT = 1_790_000_000_000;

  /**
   * The dependencies over a database whose default realm already exists, with
   * the RP ID its row stores and, once a passkey is enrolled, its lock time.
   */
  function existingRealm(webauthnRpId: string | null, webauthnRpIdLockedAt: number | null) {
    const { deps, warn, info } = emptyDatabase();
    const realm = realmRow({
      issuer: 'https://auth.example.com',
      isOperator: true,
      webauthnRpId,
      webauthnRpIdLockedAt,
    });
    Object.assign(deps.realms, {
      findByName: vi.fn(async () => realm),
      findByHost: vi.fn(async () => ({
        realm,
        host: { host: 'auth.example.com', realmId: realm.id, kind: 'primary', createdAt: 0 },
      })),
      assignIssuer: vi.fn(async () => ({
        realm,
        host: { host: 'auth.example.com', realmId: realm.id, kind: 'primary', createdAt: 0 },
      })),
    });
    return { deps, warn, info };
  }

  it("uses the realm's host when WEBAUTHN_RP_ID is unset, and logs it", async () => {
    const { deps, info, warn } = emptyDatabase();

    const result = await bootDefaultRealm(deps, settings);

    expect(result.relyingParty).toMatchObject({ rpId: 'auth.example.com', scope: 'realm-host' });
    expect(warn).not.toHaveBeenCalled();
    expect(info).toHaveBeenCalledWith(
      expect.objectContaining({ passkeyRpId: 'auth.example.com', passkeyRpIdLocked: false }),
      'default realm ready'
    );
  });

  it('warns at boot for a parent-domain RP ID the operator opted into', async () => {
    const { deps, warn } = emptyDatabase();

    await bootDefaultRealm(deps, {
      ...settings,
      passkeys: { rpId: 'example.com', allowParentDomainRpId: true },
    });

    expect(warn).toHaveBeenCalledWith(
      { variable: 'WEBAUTHN_RP_ID', rpId: 'example.com' },
      expect.stringContaining('every host under "example.com" can ask for assertions')
    );
  });

  it('refuses a parent domain without the opt-in, before it touches the database', async () => {
    const { deps } = emptyDatabase();

    const boot = bootDefaultRealm(deps, {
      ...settings,
      passkeys: { rpId: 'example.com', allowParentDomainRpId: false },
    });

    await expect(boot).rejects.toThrow(DefaultRealmBootError);
    await expect(boot).rejects.toThrow('Set WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN=true to opt in');
    expect(deps.realms.lockProvisioning).not.toHaveBeenCalled();
  });

  it('stores an opted-in parent domain on the realm row while no passkey has locked it', async () => {
    const { deps } = existingRealm(null, null);

    const result = await bootDefaultRealm(deps, {
      ...settings,
      passkeys: { rpId: 'example.com', allowParentDomainRpId: true },
    });

    expect(deps.realms.setWebAuthnRpId).toHaveBeenCalledWith(
      '019a0000-0000-7000-8000-000000000001',
      'example.com',
      {}
    );
    expect(result.realm.webauthnRpId).toBe('example.com');
  });

  it('stores NULL when WEBAUTHN_RP_ID goes back to the realm host before any passkey', async () => {
    const { deps } = existingRealm('example.com', null);

    const result = await bootDefaultRealm(deps, settings);

    expect(deps.realms.setWebAuthnRpId).toHaveBeenCalledWith(
      '019a0000-0000-7000-8000-000000000001',
      null,
      {}
    );
    expect(result.realm.webauthnRpId).toBeNull();
  });

  it('writes nothing when the row already holds the configured RP ID', async () => {
    const { deps } = existingRealm(null, null);

    await bootDefaultRealm(deps, {
      ...settings,
      passkeys: { rpId: 'auth.example.com', allowParentDomainRpId: false },
    });

    expect(deps.realms.setWebAuthnRpId).not.toHaveBeenCalled();
  });

  it('boots when the configured RP ID is the one the realm is locked to, and writes nothing', async () => {
    const { deps, info } = existingRealm(null, LOCKED_AT);

    await expect(bootDefaultRealm(deps, settings)).resolves.toBeDefined();
    expect(deps.realms.setWebAuthnRpId).not.toHaveBeenCalled();
    expect(info).toHaveBeenCalledWith(
      expect.objectContaining({ passkeyRpId: 'auth.example.com', passkeyRpIdLocked: true }),
      'default realm ready'
    );
  });

  it('reads a locked row that spells out the realm host as the realm host', async () => {
    const { deps } = existingRealm('auth.example.com', LOCKED_AT);

    await expect(bootDefaultRealm(deps, settings)).resolves.toBeDefined();
    expect(deps.realms.setWebAuthnRpId).not.toHaveBeenCalled();
  });

  it('refuses to boot when WEBAUTHN_RP_ID differs from the locked RP ID, explaining why and what to set', async () => {
    const { deps } = existingRealm(null, LOCKED_AT);

    const boot = bootDefaultRealm(deps, {
      ...settings,
      passkeys: { rpId: 'example.com', allowParentDomainRpId: true },
    });

    await expect(boot).rejects.toThrow(DefaultRealmBootError);
    await expect(boot).rejects.toThrow(
      'The default realm "master" has passkeys bound to the RP ID "auth.example.com", but WEBAUTHN_RP_ID gives "example.com".'
    );
    await expect(boot).rejects.toThrow('would orphan every passkey');
    await expect(boot).rejects.toThrow('Unset WEBAUTHN_RP_ID, or set it to "auth.example.com".');
  });

  it('names the parent domain to keep when the lock is a parent domain', async () => {
    const { deps } = existingRealm('example.com', LOCKED_AT);

    await expect(bootDefaultRealm(deps, settings)).rejects.toThrow(
      'Set WEBAUTHN_RP_ID to "example.com" and keep WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN=true.'
    );
  });

  it('explains the lock when a first enrolment on another node took it during the boot', async () => {
    const { deps } = existingRealm(null, null);
    const lockedMeanwhile = realmRow({
      issuer: 'https://auth.example.com',
      isOperator: true,
      webauthnRpIdLockedAt: LOCKED_AT,
    });
    Object.assign(deps.realms, {
      setWebAuthnRpId: vi.fn(async () => {
        throw new BadRequestError("Realm's passkey RP ID is locked by its first passkey enrolment");
      }),
      findById: vi.fn(async () => lockedMeanwhile),
    });

    await expect(
      bootDefaultRealm(deps, {
        ...settings,
        passkeys: { rpId: 'example.com', allowParentDomainRpId: true },
      })
    ).rejects.toThrow(
      'The default realm "master" has passkeys bound to the RP ID "auth.example.com", but WEBAUTHN_RP_ID gives "example.com".'
    );
  });
});

describe('bootDefaultRealm and the realm policies (#516)', () => {
  const REALM_ID = '019a0000-0000-7000-8000-000000000001';
  const NOTHING: RealmPolicySeedReport = { filled: [], completed: [], skipped: [] };
  const settings = {
    realmName: 'master',
    jwtIssuer: 'https://auth.example.com',
    endpointHosts: [],
    seedKeysSet: [
      {
        key: 'ACCESS_TOKEN_LIFESPAN',
        path: 'tokens.accessTokenLifespanSeconds',
        readFromRealmRow: false,
      },
      {
        key: 'DEFAULT_DYNAMIC_REGISTRATION_SCOPES',
        path: 'registration.dynamicRegistrationAllowedScopes',
        readFromRealmRow: true,
      },
      { key: 'PASSWORD_MIN_SCORE', path: 'password.minScore', readFromRealmRow: true },
    ],
  };

  /** The dependencies over a database whose default realm exists. */
  function existingRealm(report: RealmPolicySeedReport) {
    const { deps, warn, info } = emptyDatabase();
    const realm = realmRow({ issuer: 'https://auth.example.com', isOperator: true });
    const filledRealm = { ...realm, policiesVersion: 2 };
    Object.assign(deps.realms, {
      findByName: vi.fn(async () => realm),
      findByHost: vi.fn(async () => ({
        realm,
        host: { host: 'auth.example.com', realmId: realm.id, kind: 'primary', createdAt: 0 },
      })),
      assignIssuer: vi.fn(async () => ({
        realm,
        host: { host: 'auth.example.com', realmId: realm.id, kind: 'primary', createdAt: 0 },
      })),
      findById: vi.fn(async () => filledRealm),
    });
    vi.mocked(deps.policies.seedRealms).mockResolvedValue(report);
    return { deps, warn, info, realm };
  }

  /** The lines about seed keys, as `[fields, message]`. */
  function seedKeyLines(log: ReturnType<typeof vi.fn>): unknown[][] {
    return log.mock.calls.filter(([fields]) => typeof fields?.variable === 'string');
  }

  /** The variables of the lines about seed keys. */
  function variablesOf(log: ReturnType<typeof vi.fn>): string[] {
    return seedKeyLines(log).map(([fields]) => (fields as { variable: string }).variable);
  }

  it('fills the policies in the provisioning transaction, after the realm exists', async () => {
    const { deps } = emptyDatabase();
    const tx = { transaction: 'provisioning' };
    deps.db.transaction = (async (run: (handle: unknown) => Promise<unknown>) =>
      run(tx)) as typeof deps.db.transaction;
    const realms = deps.realms as unknown as Record<string, ReturnType<typeof vi.fn>>;

    await bootDefaultRealm(deps, settings);

    expect(deps.policies.seedRealms).toHaveBeenCalledWith(tx);
    expect(vi.mocked(deps.policies.seedRealms).mock.invocationCallOrder[0]).toBeGreaterThan(
      realms['createWithPrimaryHost'].mock.invocationCallOrder[0]
    );
  });

  it('names no seed key for a realm this boot created, which they seeded', async () => {
    const { deps, warn, info } = emptyDatabase();

    const result = await bootDefaultRealm(deps, settings);

    expect(result.created).toBe(true);
    expect(seedKeyLines(warn)).toEqual([]);
    expect(seedKeyLines(info)).toEqual([]);
  });

  it('warns once for each set key whose policy the server reads from the realm row', async () => {
    const { deps, warn } = existingRealm(NOTHING);

    const result = await bootDefaultRealm(deps, settings);

    expect(result.created).toBe(false);
    expect(seedKeyLines(warn)).toEqual([
      [
        {
          variable: 'DEFAULT_DYNAMIC_REGISTRATION_SCOPES',
          realm: 'master',
          policy: 'registration.dynamicRegistrationAllowedScopes',
        },
        seedKeyIgnoredWarning(
          'DEFAULT_DYNAMIC_REGISTRATION_SCOPES',
          'master',
          'registration.dynamicRegistrationAllowedScopes'
        ),
      ],
      [
        { variable: 'PASSWORD_MIN_SCORE', realm: 'master', policy: 'password.minScore' },
        seedKeyIgnoredWarning('PASSWORD_MIN_SCORE', 'master', 'password.minScore'),
      ],
    ]);
    expect(seedKeyIgnoredWarning('PASSWORD_MIN_SCORE', 'master', 'password.minScore')).toBe(
      'PASSWORD_MIN_SCORE only seeds new realms and is ignored: the realm "master" already has its policies, and its password.minScore stays as stored'
    );
  });

  it('says a key whose policy is not read from the row yet still applies, and does not warn', async () => {
    const { deps, warn, info } = existingRealm(NOTHING);

    await bootDefaultRealm(deps, settings);

    expect(variablesOf(warn)).not.toContain('ACCESS_TOKEN_LIFESPAN');
    expect(seedKeyLines(info)).toEqual([
      [
        {
          variable: 'ACCESS_TOKEN_LIFESPAN',
          realm: 'master',
          policy: 'tokens.accessTokenLifespanSeconds',
        },
        seedKeyStillAppliedNote(
          'ACCESS_TOKEN_LIFESPAN',
          'master',
          'tokens.accessTokenLifespanSeconds'
        ),
      ],
    ]);
    expect(
      seedKeyStillAppliedNote(
        'ACCESS_TOKEN_LIFESPAN',
        'master',
        'tokens.accessTokenLifespanSeconds'
      )
    ).toBe(
      'ACCESS_TOKEN_LIFESPAN only seeds new realms and is ignored by the stored policies of the realm "master", whose tokens.accessTokenLifespanSeconds stays as stored: a change of ACCESS_TOKEN_LIFESPAN never reaches it. The server still applies ACCESS_TOKEN_LIFESPAN to every realm until it reads that policy from the realm row, so keep it set; once it does, the stored tokens.accessTokenLifespanSeconds applies and ACCESS_TOKEN_LIFESPAN is ignored, so change the stored policy along with ACCESS_TOKEN_LIFESPAN'
    );
  });

  it('names no seed key when this boot filled the realm, and says it filled it', async () => {
    const { deps, warn, info, realm } = existingRealm({
      ...NOTHING,
      filled: [{ realmId: REALM_ID, realmName: 'master' }],
    });

    const result = await bootDefaultRealm(deps, settings);

    expect(seedKeyLines(warn)).toEqual([]);
    expect(seedKeyLines(info)).toEqual([]);
    expect(info).toHaveBeenCalledWith(
      { realm: 'master', realmId: realm.id },
      'realm policies filled from the environment: the realm row owns them from now on'
    );
    // The row as the fill left it.
    expect(result.realm.policiesVersion).toBe(2);
  });

  it('names no seed key whose field this boot completed, and the others', async () => {
    const { deps, warn, info, realm } = existingRealm({
      ...NOTHING,
      completed: [{ realmId: REALM_ID, realmName: 'master', paths: ['password.minScore'] }],
    });

    await bootDefaultRealm(deps, settings);

    expect(variablesOf(warn)).toEqual(['DEFAULT_DYNAMIC_REGISTRATION_SCOPES']);
    expect(info).toHaveBeenCalledWith(
      { realm: 'master', realmId: realm.id, policies: ['password.minScore'] },
      'realm policies of this release filled from the environment'
    );
  });

  it('warns for a realm whose policies another schema version wrote, which it left as they are', async () => {
    const { deps, warn } = existingRealm({
      ...NOTHING,
      skipped: [{ realmId: REALM_ID, realmName: 'master', schemaVersion: '1-rc.7' }],
    });

    await bootDefaultRealm(deps, { ...settings, seedKeysSet: [] });

    expect(warn).toHaveBeenCalledWith(
      { realm: 'master', realmId: REALM_ID, schemaVersion: '1-rc.7' },
      'realm policies of another schema version left as they are: a node of this release does not complete them'
    );
  });

  it('names no seed key when the environment sets none', async () => {
    const { deps, warn, info } = existingRealm(NOTHING);

    await bootDefaultRealm(deps, { ...settings, seedKeysSet: [] });

    expect(seedKeyLines(warn)).toEqual([]);
    expect(seedKeyLines(info)).toEqual([]);
  });

  it('refuses the boot when stored values cannot be filled, naming the realm and the paths', async () => {
    const { deps } = existingRealm(NOTHING);
    vi.mocked(deps.policies.seedRealms).mockRejectedValue(
      new RealmPolicySeedRefusedError('master', [
        { path: 'registration.dynamicRegistrationAllowedScopes', message: 'is not valid' },
      ])
    );

    const refused = await bootDefaultRealm(deps, settings).catch((error: unknown) => error);

    expect(refused).toBeInstanceOf(DefaultRealmBootError);
    expect((refused as Error).message).toContain('"master"');
    expect((refused as Error).message).toContain('registration.dynamicRegistrationAllowedScopes');
  });
});
