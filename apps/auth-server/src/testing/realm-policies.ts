import {
  defaultsFromEnv,
  REALM_POLICY_SCHEMA_VERSION,
  type RealmPolicies,
  type RealmPolicySnapshot,
} from '@qauth-labs/fastify-plugin-realm-policy';
import { vi } from 'vitest';

import type { RealmRow } from '../app/helpers/request-realm';

/**
 * TEST SUPPORT — `fastify.policyStore` for a unit test's stub server (#527).
 * `ofRealm` hands out the policies of an empty environment
 * (`defaultsFromEnv({})`: 900 s access tokens, 8 h for a development client,
 * a week for a refresh token) with `tokens` overridden, for whatever row it is
 * given, and counts its calls. It makes no query, as the real one does not.
 */
export function testPolicyStore(tokens: Partial<RealmPolicies['tokens']> = {}) {
  const defaults = defaultsFromEnv({});
  const policies: RealmPolicies = { ...defaults, tokens: { ...defaults.tokens, ...tokens } };
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
