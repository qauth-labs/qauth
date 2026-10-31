import { defaultsFromEnv, realmSecretPaths } from '@qauth-labs/fastify-plugin-realm-policy';
import { describe, expect, it, vi } from 'vitest';

import { testRealm } from '../../testing/request-realm';
import { dynamicRegistrationScopesOf, POLICIES_READ_FROM_REALM_ROW } from './realm-policy-readers';

/** A policy document's value at a dotted path, or `undefined`. */
function valueAt(document: unknown, path: string): unknown {
  return path
    .split('.')
    .reduce<unknown>(
      (node, segment) =>
        typeof node === 'object' && node !== null
          ? (node as Record<string, unknown>)[segment]
          : undefined,
      document
    );
}

describe('POLICIES_READ_FROM_REALM_ROW (#516)', () => {
  it('names fields of the realm policy document, none of them secret', () => {
    const document = defaultsFromEnv({});
    for (const path of POLICIES_READ_FROM_REALM_ROW) {
      expect(valueAt(document, path), path).not.toBeUndefined();
      expect(realmSecretPaths(), path).not.toContain(path);
    }
  });

  it('holds the two policies the server read from the row before #516', () => {
    expect([...POLICIES_READ_FROM_REALM_ROW].sort()).toEqual([
      'posture.maxEnvironmentLaxity',
      'registration.dynamicRegistrationAllowedScopes',
    ]);
  });
});

describe('dynamicRegistrationScopesOf (#516)', () => {
  const FILL = Object.freeze(['openid', 'profile']);
  const policies = () => ({
    ofRealm: vi.fn(
      () =>
        ({
          policies: { registration: { dynamicRegistrationAllowedScopes: FILL } },
        }) as never
    ),
  });

  it("reads the row's list of a realm that has its policies, even an empty one", () => {
    const store = policies();
    const realm = testRealm({ id: 'r', dynamicRegistrationAllowedScopes: [], policiesVersion: 4 });

    expect(dynamicRegistrationScopesOf(store, realm)).toEqual([]);
    expect(store.ofRealm).not.toHaveBeenCalled();
  });

  it('reads the list of the fill of a realm with no policies yet, as a copy', () => {
    const store = policies();
    const realm = testRealm({ id: 'r', dynamicRegistrationAllowedScopes: [], policiesVersion: 0 });

    const scopes = dynamicRegistrationScopesOf(store, realm);

    expect(scopes).toEqual(FILL);
    expect(store.ofRealm).toHaveBeenCalledWith(realm);
    scopes.push('email');
    expect(FILL).toEqual(['openid', 'profile']);
  });
});
