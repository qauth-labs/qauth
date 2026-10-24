import { describe, expect, it } from 'vitest';

import * as custody from '../custody';
import * as publicEntry from '../index';

/**
 * The two entry points of `@qauth-labs/server-keys` (issue #464). The public
 * one holds the signer interface and public facts; everything that touches a
 * KEK or key material is in `custody`, which only the signer's wiring may
 * import (eslint.config.mjs).
 */
describe('package entry points', () => {
  it.each([
    'loadKekProvider',
    'createLocalKekProvider',
    'computeKekRef',
    'DEV_KEK_DEFAULT',
    'sealKeyMaterial',
    'openKeyMaterial',
    'encodeKeyAad',
    'generateKeyMaterial',
    'createKeyFactory',
    'createInProcessSigner',
    'runKekProviderContract',
    'prepareEnvironmentKeys',
    'bootRealmKeys',
  ])('keeps %s out of the public entry point and in custody', (name) => {
    expect(publicEntry).not.toHaveProperty(name);
    expect(custody).toHaveProperty(name);
  });

  it('shares no export between the two', () => {
    const shared = Object.keys(custody).filter((name) => Object.hasOwn(publicEntry, name));
    expect(shared).toEqual([]);
  });

  it('exports the signer interface facts publicly', () => {
    expect(publicEntry).toHaveProperty('SIGNER_OPERATIONS');
    expect(publicEntry).toHaveProperty('SIGNER_POLICY');
    expect(publicEntry).toHaveProperty('JWS_TYP_BY_PURPOSE');
    expect(publicEntry).toHaveProperty('isSignerError');
  });
});
