import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { DbClient } from '../db';
import { REALM_POLICY_COLUMNS, realmPolicyRecord, splitRealmPolicies } from './realm-policy-record';
import {
  createRealmsRepository,
  type NewRealm,
  type Realm,
  type UpdateRealm,
} from './realms.repository';

/**
 * The two storage forms of a realm's policies (#516): four fields in the
 * columns that held them before the policies existed, every other one in
 * `realms.policies`. The policy store reads and writes one document; these
 * functions are where it is joined and split.
 */

/** A realm row as the repository returns it, with policies. */
function realmRow(overrides: Partial<Realm> = {}): Realm {
  return {
    id: '00000000-0000-7000-8000-000000000001',
    name: 'master',
    enabled: true,
    issuer: 'https://auth.example.com',
    isOperator: true,
    webauthnRpId: null,
    webauthnRpIdLockedAt: null,
    accessTokenLifespan: 600,
    refreshTokenLifespan: 86400,
    sslRequired: 'external',
    verifyEmail: true,
    registrationAllowed: false,
    loginWithEmailAllowed: true,
    duplicateEmailsAllowed: false,
    passwordPolicy: null,
    ssoIdleTimeout: null,
    ssoMaxLifespan: null,
    revokeRefreshToken: false,
    refreshTokenMaxReuse: 0,
    defaultLocale: null,
    supportedLocales: [],
    dynamicRegistrationAllowedScopes: ['openid'],
    maxEnvironmentLaxity: 'staging',
    userEventRetentionDays: 90,
    adminEventRetentionDays: 365,
    ssfTransmitterEnabled: false,
    policies: {
      tokens: { developmentAccessTokenLifespanSeconds: 3600 },
      password: { minScore: 3 },
    },
    policySchemaVersion: '1-rc.0',
    policiesVersion: 4,
    metadata: null,
    createdAt: 1,
    updatedAt: 1,
    ...overrides,
  };
}

interface CapturedQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

/** A `pg` client that records queries and answers each with no row. */
function createRecordingDb(): { db: DbClient; queries: CapturedQuery[] } {
  const queries: CapturedQuery[] = [];
  const client = {
    query: (config: { text?: string; values?: unknown[] } | string, values?: unknown[]) => {
      const text = typeof config === 'string' ? config : (config.text ?? '');
      const params = typeof config === 'string' ? (values ?? []) : (config.values ?? values ?? []);
      queries.push({ text, values: params });
      return Promise.resolve({ rows: [], rowCount: 0, fields: [], command: '', oid: 0 });
    },
  };
  return { db: drizzle(client as unknown as Pool) as unknown as DbClient, queries };
}

/** The value an INSERT into `realms` bound for one column. */
function insertedValue(query: CapturedQuery, column: string): unknown {
  const columns = /insert into "realms" \(([^)]*)\)/.exec(query.text)?.[1];
  if (columns === undefined) throw new Error(`not an insert into realms: ${query.text}`);
  const names = columns.split(', ').map((name) => name.replaceAll('"', ''));
  const values = /values \(([^)]*)\)/.exec(query.text)?.[1].split(', ') ?? [];
  const placeholder = values[names.indexOf(column)];
  if (placeholder === 'default') return 'default';
  const value = query.values[Number(placeholder?.slice(1)) - 1];
  return typeof value === 'string' && /^[[{]/.test(value) ? JSON.parse(value) : value;
}

/** A whole policy document, as `defaultsFromEnv` gives one. */
const SEED_DOCUMENT = {
  tokens: {
    accessTokenLifespanSeconds: 900,
    developmentAccessTokenLifespanSeconds: 28800,
    refreshTokenLifespanSeconds: 604800,
    adminAccessTokenLifespanSeconds: 600,
  },
  registration: {
    dynamicRegistrationAllowedScopes: ['openid', 'profile'],
    cimd: { enabled: true },
  },
  posture: { maxEnvironmentLaxity: 'production' },
  password: { minScore: 2 },
};

describe('REALM_POLICY_COLUMNS', () => {
  it('keeps exactly the four columns of the issue as storage of their fields', () => {
    expect(REALM_POLICY_COLUMNS.map(({ column, path }) => [column, path])).toEqual([
      ['accessTokenLifespan', 'tokens.accessTokenLifespanSeconds'],
      ['refreshTokenLifespan', 'tokens.refreshTokenLifespanSeconds'],
      ['dynamicRegistrationAllowedScopes', 'registration.dynamicRegistrationAllowedScopes'],
      ['maxEnvironmentLaxity', 'posture.maxEnvironmentLaxity'],
    ]);
  });
});

describe('realmPolicyRecord', () => {
  it('joins the members of realms.policies and the four columns into one document', () => {
    const record = realmPolicyRecord(realmRow());

    expect(record).toEqual({
      realmId: '00000000-0000-7000-8000-000000000001',
      realmName: 'master',
      version: 4,
      schemaVersion: '1-rc.0',
      document: {
        tokens: {
          developmentAccessTokenLifespanSeconds: 3600,
          accessTokenLifespanSeconds: 600,
          refreshTokenLifespanSeconds: 86400,
        },
        password: { minScore: 3 },
        registration: { dynamicRegistrationAllowedScopes: ['openid'] },
        posture: { maxEnvironmentLaxity: 'staging' },
      },
      keptOnFill: {},
    });
  });

  it('takes a column-backed field from its column, never from a member of the same path', () => {
    const record = realmPolicyRecord(
      realmRow({ policies: { posture: { maxEnvironmentLaxity: 'development' } } })
    );

    expect(record.document['posture']).toEqual({ maxEnvironmentLaxity: 'staging' });
  });

  it('copies the row, so a change of the record leaves the row as it was', () => {
    const row = realmRow();
    const record = realmPolicyRecord(row);
    (record.document['password'] as Record<string, unknown>)['minScore'] = 0;
    (
      (record.document['registration'] as Record<string, unknown>)[
        'dynamicRegistrationAllowedScopes'
      ] as string[]
    ).push('email');

    expect(row.policies).toEqual({
      tokens: { developmentAccessTokenLifespanSeconds: 3600 },
      password: { minScore: 3 },
    });
    expect(row.dynamicRegistrationAllowedScopes).toEqual(['openid']);
  });

  describe('a realm with no policies yet (counter 0)', () => {
    it('keeps the ceiling and a scope list that holds a scope, which the server read before', () => {
      const record = realmPolicyRecord(realmRow({ policies: {}, policiesVersion: 0 }));

      expect(record.keptOnFill).toEqual({
        registration: { dynamicRegistrationAllowedScopes: ['openid'] },
        posture: { maxEnvironmentLaxity: 'staging' },
      });
    });

    it('keeps no empty scope list, for which the server used DEFAULT_DYNAMIC_REGISTRATION_SCOPES', () => {
      const record = realmPolicyRecord(
        realmRow({ policies: {}, policiesVersion: 0, dynamicRegistrationAllowedScopes: [] })
      );

      expect(record.keptOnFill).toEqual({ posture: { maxEnvironmentLaxity: 'staging' } });
    });

    it('keeps no token lifetime: nothing read those columns, the server ran on the environment', () => {
      const record = realmPolicyRecord(realmRow({ policies: {}, policiesVersion: 0 }));

      expect(record.keptOnFill['tokens']).toBeUndefined();
    });
  });
});

describe('splitRealmPolicies', () => {
  it('puts the four fields in their columns and the rest in realms.policies', () => {
    expect(splitRealmPolicies(SEED_DOCUMENT)).toEqual({
      columns: {
        accessTokenLifespan: 900,
        refreshTokenLifespan: 604800,
        dynamicRegistrationAllowedScopes: ['openid', 'profile'],
        maxEnvironmentLaxity: 'production',
      },
      members: {
        tokens: {
          developmentAccessTokenLifespanSeconds: 28800,
          adminAccessTokenLifespanSeconds: 600,
        },
        registration: { cimd: { enabled: true } },
        password: { minScore: 2 },
      },
    });
  });

  it('round-trips through realmPolicyRecord', () => {
    const { columns, members } = splitRealmPolicies(SEED_DOCUMENT);
    const record = realmPolicyRecord(realmRow({ ...columns, policies: members }));

    expect(record.document).toEqual(SEED_DOCUMENT);
  });

  it('refuses a document without a column-backed field', () => {
    expect(() => splitRealmPolicies({ ...SEED_DOCUMENT, posture: {} })).toThrow(
      'The realm policy document has no value for posture.maxEnvironmentLaxity'
    );
  });

  it('leaves the document it split as it was', () => {
    const document = structuredClone(SEED_DOCUMENT);
    splitRealmPolicies(document);

    expect(document).toEqual(SEED_DOCUMENT);
  });
});

describe('createRealmsRepository — the policy seed (#516)', () => {
  const seeds = { policies: { document: SEED_DOCUMENT, schemaVersion: '1-rc.0' } };

  it('gives a new realm the seeded document, its schema version and counter 1', async () => {
    const { db, queries } = createRecordingDb();

    await createRealmsRepository(db, { seeds }).create({ name: 'seeded' });

    expect(insertedValue(queries[0], 'access_token_lifespan')).toBe(900);
    expect(insertedValue(queries[0], 'refresh_token_lifespan')).toBe(604800);
    expect(insertedValue(queries[0], 'dynamic_registration_allowed_scopes')).toEqual([
      'openid',
      'profile',
    ]);
    expect(insertedValue(queries[0], 'max_environment_laxity')).toBe('production');
    expect(insertedValue(queries[0], 'policies')).toEqual({
      tokens: {
        developmentAccessTokenLifespanSeconds: 28800,
        adminAccessTokenLifespanSeconds: 600,
      },
      registration: { cimd: { enabled: true } },
      password: { minScore: 2 },
    });
    expect(insertedValue(queries[0], 'policy_schema_version')).toBe('1-rc.0');
    expect(insertedValue(queries[0], 'policies_version')).toBe(1);
  });

  it('stores the seed of the four column-backed fields whatever the creator passes', async () => {
    const { db, queries } = createRecordingDb();
    // A caller the types do not bind: values the policy schema refuses, which
    // would make every later read of the realm's policies throw.
    const forged = {
      name: 'lax',
      accessTokenLifespan: 0,
      refreshTokenLifespan: 0,
      dynamicRegistrationAllowedScopes: ['openid', 'openid', 'a scope'],
      maxEnvironmentLaxity: 'development',
    } as unknown as NewRealm;

    await createRealmsRepository(db, { seeds }).create(forged);
    await createRealmsRepository(db).create(forged);

    expect(insertedValue(queries[0], 'access_token_lifespan')).toBe(900);
    expect(insertedValue(queries[0], 'refresh_token_lifespan')).toBe(604800);
    expect(insertedValue(queries[0], 'dynamic_registration_allowed_scopes')).toEqual([
      'openid',
      'profile',
    ]);
    expect(insertedValue(queries[0], 'max_environment_laxity')).toBe('production');
    expect(insertedValue(queries[0], 'policies_version')).toBe(1);
    // Without the policy seed, the column defaults, until the boot step fills them.
    for (const column of [
      'access_token_lifespan',
      'refresh_token_lifespan',
      'dynamic_registration_allowed_scopes',
      'max_environment_laxity',
    ]) {
      expect(insertedValue(queries[1], column), column).toBe('default');
    }
  });

  it('drops every policy column from a plain update, the four column-backed ones among them', async () => {
    const { db, queries } = createRecordingDb();

    // The recording database has no such realm, so the update finds none.
    await expect(
      createRealmsRepository(db).update('00000000-0000-7000-8000-000000000001', {
        enabled: false,
        accessTokenLifespan: 0,
        refreshTokenLifespan: 0,
        dynamicRegistrationAllowedScopes: ['qauth:admin:read'],
        maxEnvironmentLaxity: 'development',
        policies: { password: { minScore: 0 } },
        policySchemaVersion: '9',
        policiesVersion: 0,
      } as unknown as UpdateRealm)
    ).rejects.toThrow('not found');

    expect(queries).toHaveLength(1);
    expect(queries[0].text).toMatch(
      /^update "realms" set "enabled" = \$1, "updated_at" = \$2 where/
    );
  });

  it('leaves a realm without the policy seed with no policies (counter 0)', async () => {
    const { db, queries } = createRecordingDb();

    await createRealmsRepository(db).create({ name: 'plain' });

    expect(insertedValue(queries[0], 'policies')).toBe('default');
    expect(insertedValue(queries[0], 'policies_version')).toBe('default');
  });

  it('stores the seed whatever policies the creator passes, so nothing unparsed reaches realms.policies', async () => {
    const { db, queries } = createRecordingDb();
    const forged = {
      name: 'forged',
      policies: { mail: { smtp: { password: 'a-secret-value' } } },
      policySchemaVersion: '1-rc.9',
      policiesVersion: 7,
    } as unknown as NewRealm;

    await createRealmsRepository(db, { seeds }).create(forged);
    await createRealmsRepository(db).create(forged);

    expect(insertedValue(queries[0], 'policies')).toEqual(
      splitRealmPolicies(SEED_DOCUMENT).members
    );
    expect(insertedValue(queries[0], 'policy_schema_version')).toBe('1-rc.0');
    expect(insertedValue(queries[0], 'policies_version')).toBe(1);
    // Without the policy seed, the column defaults: no policies.
    expect(insertedValue(queries[1], 'policies')).toBe('default');
    expect(insertedValue(queries[1], 'policies_version')).toBe('default');
    expect(JSON.stringify(queries)).not.toContain('a-secret-value');
  });

  it('refuses at construction a seed that lacks a column-backed field', () => {
    const { db } = createRecordingDb();

    expect(() =>
      createRealmsRepository(db, {
        seeds: { policies: { document: { tokens: {} }, schemaVersion: '1-rc.0' } },
      })
    ).toThrow(TypeError);
  });

  it('writes policies only where the counter is still the expected one, one higher', async () => {
    const { db, queries } = createRecordingDb();

    const written = await createRealmsRepository(db).writePolicies(
      '00000000-0000-7000-8000-000000000001',
      { document: SEED_DOCUMENT, schemaVersion: '1-rc.0', expectedVersion: 3 }
    );

    expect(written).toBeUndefined();
    expect(queries[0].text).toMatch(
      /^update "realms" set .*"policies_version" = \$\d+.* where \("realms"."id" = \$\d+ and "realms"."policies_version" = \$\d+\) returning/
    );
    expect(queries[0].values).toContain(4);
    expect(queries[0].values.at(-1)).toBe(3);
  });

  it('refuses an expected counter that is not a whole number, 0 or more', async () => {
    const { db, queries } = createRecordingDb();
    const realms = createRealmsRepository(db);

    for (const expectedVersion of [-1, 1.5, Number.NaN]) {
      await expect(
        realms.writePolicies('id', {
          document: SEED_DOCUMENT,
          schemaVersion: '1-rc.0',
          expectedVersion,
        })
      ).rejects.toThrow(TypeError);
    }
    expect(queries).toHaveLength(0);
  });
});
