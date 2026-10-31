import { createKeyFactory, loadKekProvider } from '@qauth-labs/server-keys/custody';

import type { CreateRealmKeyDependencies } from '../lib/realm-keys';
import { createRepositoryKeyStore } from '../lib/repository-key-stores';
import {
  rotateTokenKeys,
  type TokenKeyRotation,
  type TokenKeyRotationOptions,
} from './key-rotation';

/**
 * TEST SUPPORT: rotate a realm's `token_signing` keys in the database, as
 * {@link rotateTokenKeys} describes, with the KEK the deployment's
 * environment names (issue #492). The auth server's E2E harness calls it for
 * a server it booted. Never exported from the package entry point.
 *
 * @throws the errors of `loadKekProvider` and of {@link rotateTokenKeys}
 */
export async function rotateRealmTokenKeys(
  deps: CreateRealmKeyDependencies,
  realmId: string,
  options: TokenKeyRotationOptions = {}
): Promise<TokenKeyRotation> {
  const kekProvider = await loadKekProvider({ env: deps.kekEnv, warn: deps.warn });
  try {
    const store = createRepositoryKeyStore(deps.db);
    const factory = createKeyFactory({
      store,
      kekProvider,
      enabledSignatureAlgorithms: deps.enabledSignatureAlgorithms,
      hybridSigning: deps.hybridSigning,
    });
    return await rotateTokenKeys(store, factory, realmId, options);
  } finally {
    await kekProvider.close?.();
  }
}
