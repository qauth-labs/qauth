import { REALM_POLICY_COLUMNS, realmPolicyRecord, splitRealmPolicies } from '@qauth-labs/infra-db';
import { defaultsFromEnv, REALM_POLICY_REGISTRY } from '@qauth-labs/server-realm-policy';
import { describe, expect, it } from 'vitest';

/**
 * The contract between the policy schema and the realm row (#516): the
 * database library maps four fields to columns by path, and cannot import the
 * schema, so this test holds the two together.
 */
describe('the column-backed policy fields', () => {
  it('names four fields of the registry, none of them secret', () => {
    for (const { path } of REALM_POLICY_COLUMNS) {
      const entry = REALM_POLICY_REGISTRY.field(path);
      expect(entry, path).toBeDefined();
      expect(entry?.field.secret, path).toBe(false);
    }
    expect(REALM_POLICY_COLUMNS).toHaveLength(4);
  });

  it('round-trips a whole policy document through the columns and realms.policies', () => {
    const document = defaultsFromEnv({
      ACCESS_TOKEN_LIFESPAN: '300',
      REFRESH_TOKEN_LIFESPAN: '3600',
      DEFAULT_DYNAMIC_REGISTRATION_SCOPES: 'openid email',
    });
    const { columns, members } = splitRealmPolicies(document);

    expect(columns).toEqual({
      accessTokenLifespan: 300,
      refreshTokenLifespan: 3600,
      dynamicRegistrationAllowedScopes: ['openid', 'email'],
      maxEnvironmentLaxity: 'production',
    });
    const record = realmPolicyRecord({
      id: 'r',
      name: 'r',
      policiesVersion: 1,
      policySchemaVersion: REALM_POLICY_REGISTRY.version,
      policies: members,
      ...columns,
    } as Parameters<typeof realmPolicyRecord>[0]);
    expect(REALM_POLICY_REGISTRY.parse(record.document)).toEqual(document);
  });
});
