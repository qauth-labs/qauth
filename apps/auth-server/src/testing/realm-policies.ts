import {
  defaultsFromEnv,
  REALM_POLICY_SCHEMA_VERSION,
  type RealmPolicies,
  type RealmPolicySnapshot,
} from '@qauth-labs/fastify-plugin-realm-policy';
import { vi } from 'vitest';

import type { RealmRow } from '../app/helpers/request-realm';

/** Members to override in each group of a test realm's policies (#528). */
export type TestPolicyOverrides = {
  readonly [G in Exclude<keyof RealmPolicies, 'tokens'>]?: Partial<RealmPolicies[G]>;
};

/**
 * TEST SUPPORT — `fastify.policyStore` for a unit test's stub server (#527).
 * `ofRealm` hands out the policies of an empty environment
 * (`defaultsFromEnv({})`: 900 s access tokens, 8 h for a development client,
 * a week for a refresh token; verified accounts required, password score 2,
 * 5 failed sign-ins in 900 s lock for 900 s) with `tokens` and the members of
 * `groups` overridden (#528), for whatever row it is given, and counts its
 * calls. It makes no query, as the real one does not.
 */
export function testPolicyStore(
  tokens: Partial<RealmPolicies['tokens']> = {},
  groups: TestPolicyOverrides = {}
) {
  const defaults = defaultsFromEnv({});
  const policies = { ...defaults, tokens: { ...defaults.tokens, ...tokens } } as RealmPolicies;
  for (const [group, members] of Object.entries(groups)) {
    const name = group as keyof TestPolicyOverrides;
    (policies as Record<string, unknown>)[name] = { ...defaults[name], ...members };
  }
  return {
    ofRealm: vi.fn((row: RealmRow): RealmPolicySnapshot => ({
      realmId: row.id,
      version: row.policiesVersion ?? 0,
      hasPolicies: (row.policiesVersion ?? 0) > 0,
      schemaVersion: REALM_POLICY_SCHEMA_VERSION,
      policies,
    })),
    get: vi.fn(async () => {
      throw new Error('testPolicyStore: a token flow reads the row it loaded, never get()');
    }),
  };
}
