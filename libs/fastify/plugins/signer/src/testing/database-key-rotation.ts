import type { DbClient } from '@qauth-labs/infra-db';
import {
  createKeyFactory,
  type KeyFactory,
  loadKekProvider,
  type RealmKeyBootStore,
} from '@qauth-labs/server-keys/custody';

import type { CreateRealmKeyDependencies } from '../lib/realm-keys';
import { createRepositoryKeyStore } from '../lib/repository-key-stores';
import {
  prepublishTokenKeys,
  rotateTokenKeys,
  type TokenKeyPrepublication,
  type TokenKeyPrepublicationOptions,
  type TokenKeyRotation,
  type TokenKeyRotationOptions,
} from './key-rotation';

/**
 * Run `work` with the deployment's key store and a key factory over the KEK
 * its environment names, and close the KEK provider afterwards.
 */
async function withKeyFactory<T>(
  deps: CreateRealmKeyDependencies,
  work: (store: RealmKeyBootStore<DbClient>, factory: KeyFactory<DbClient>) => Promise<T>
): Promise<T> {
  const kekProvider = await loadKekProvider({ env: deps.kekEnv, warn: deps.warn });
  try {
    const store = createRepositoryKeyStore(deps.db);
    const factory = createKeyFactory({
      store,
      kekProvider,
      enabledSignatureAlgorithms: deps.enabledSignatureAlgorithms,
      hybridSigning: deps.hybridSigning,
    });
    return await work(store, factory);
  } finally {
    await kekProvider.close?.();
  }
}

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
  return withKeyFactory(deps, (store, factory) =>
    rotateTokenKeys(store, factory, realmId, options)
  );
}

/**
 * TEST SUPPORT: publish a `next` `token_signing` key of a realm in the
 * database, as {@link prepublishTokenKeys} describes, with the KEK the
 * deployment's environment names (issue #494). The auth server's E2E harness
 * calls it for a server it booted. Never exported from the package entry
 * point.
 *
 * @throws the errors of `loadKekProvider` and of {@link prepublishTokenKeys}
 */
export async function prepublishRealmTokenKeys(
  deps: CreateRealmKeyDependencies,
  realmId: string,
  options: TokenKeyPrepublicationOptions = {}
): Promise<TokenKeyPrepublication> {
  return withKeyFactory(deps, (store, factory) =>
    prepublishTokenKeys(store, factory, realmId, options)
  );
}
