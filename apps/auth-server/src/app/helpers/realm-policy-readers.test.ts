import { defaultsFromEnv, realmSecretPaths } from '@qauth-labs/fastify-plugin-realm-policy';
import { describe, expect, it } from 'vitest';

import { POLICIES_READ_FROM_REALM_ROW } from './realm-policy-readers';

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
