/**
 * The plugin meets the AuthMethod contract: `npm test` runs this with Node's
 * own test runner (`node --test`). The kit works in any runner.
 */
import { test } from 'node:test';

import { AUTH_METHOD_PLUGIN_EXPORT } from '@qauth-labs/plugin-sdk';
import { checkAuthMethod } from '@qauth-labs/plugin-sdk/testing';

import { scenario } from './fake-provider.js';
import * as plugin from './index.js';

test('the package exports its method as authMethod', () => {
  if (!(AUTH_METHOD_PLUGIN_EXPORT in plugin)) {
    throw new Error(`the package must export ${AUTH_METHOD_PLUGIN_EXPORT}`);
  }
});

test('the method meets the AuthMethod contract', async () => {
  // Rejects with an AuthMethodContractError that lists every failed check.
  await checkAuthMethod(plugin.authMethod, scenario);
});
