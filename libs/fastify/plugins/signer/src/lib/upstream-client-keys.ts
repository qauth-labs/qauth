import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import type { DbClient } from '@qauth-labs/infra-db';
import { KeyChangeRefusedError } from '@qauth-labs/server-keys';
import {
  type ActivatedKey,
  createKeyFactory,
  type KekProvider,
  type NewKeyStatus,
} from '@qauth-labs/server-keys/custody';

import { createRepositoryKeyStore } from './repository-key-stores';

/**
 * THE CLIENT-ASSERTION KEYS OF AN UPSTREAM PROVIDER, as the admin API manages
 * them (ADR-019 Decision 9, issue #1073): import a private key the provider
 * issued, such as Sign in with Apple's `.p8` key, as the realm's
 * `upstream_client_assertion` key for that provider, and switch to the
 * `next` one.
 *
 * The key is sealed under the KEK here, in the signer's wiring, the one
 * place besides the key library that holds the KEK: the admin API hands the
 * text over and keeps nothing of it, and no plugin ever sees it (ADR-019
 * Decision 12). Nothing here returns, throws or logs key material.
 */

/** The purpose every key here belongs to. */
const PURPOSE = 'upstream_client_assertion';

/** An algorithm a client-assertion key may have. */
export type UpstreamClientKeyAlgorithm = 'RS256' | 'ES256' | 'EdDSA';

/** Input of {@link UpstreamClientKeys.importKey}. */
export interface ImportUpstreamClientKeyInput {
  readonly realmId: string;
  /** The provider's AuthMethod type: the key's scope, as the signer names it. */
  readonly providerId: string;
  /** The algorithm the provider asks for; a key of another is refused. */
  readonly algorithm: UpstreamClientKeyAlgorithm;
  /** The provider's id of the key, kept as its `kid`. */
  readonly kid: string;
  /** The private key in PEM, unencrypted. */
  readonly privateKeyPem: string;
  /** An outer transaction to run in, such as the admin call's: the key commits with it. */
  readonly tx?: DbClient;
}

/** An imported key, as {@link UpstreamClientKeys.importKey} answers it: no material. */
export interface ImportedUpstreamClientKey {
  readonly kid: string;
  readonly algorithm: UpstreamClientKeyAlgorithm;
  /** `active` when it signs at once, `next` when it waits for a switch. */
  readonly status: NewKeyStatus;
}

/** Input of {@link UpstreamClientKeys.activate}. */
export interface ActivateUpstreamClientKeyInput {
  readonly realmId: string;
  readonly providerId: string;
  /** The `next` key to switch to. */
  readonly kid: string;
  /** An outer transaction to run in, such as the admin call's. */
  readonly tx?: DbClient;
}

/** A provider's client-assertion keys, managed through the signer's KEK. See the module comment. */
export interface UpstreamClientKeys {
  /**
   * Import the provider's key: the provider's active key when it has none of
   * the algorithm, its `next` key otherwise, under the realm's key lock.
   *
   * @throws as `KeyFactory.importKey`: `KeyCreationRefusedError` for a key,
   *   kid or KEK it refuses, `KeyIdConflictError` and `NextKeyConflictError`
   */
  importKey(input: ImportUpstreamClientKeyInput): Promise<ImportedUpstreamClientKey>;
  /**
   * Make the provider's `next` key `kid` its active key, and retire the
   * active key of its algorithm, under the realm's key lock, once the next
   * key's overlap has passed (`KeyFactory.activateNextKey`).
   *
   * @throws KeyChangeRefusedError (`NO_NEXT_KEY`) when `kid` is not the
   *   provider's `next` key, and as `KeyFactory.activateNextKey`
   */
  activate(input: ActivateUpstreamClientKeyInput): Promise<ActivatedKey>;
}

/** What {@link createUpstreamClientKeys} works with. */
export interface UpstreamClientKeysDependencies {
  readonly db: DbClient;
  readonly kekProvider: KekProvider;
  readonly enabledSignatureAlgorithms: readonly SignatureAlgorithm[];
  readonly hybridSigning: boolean;
}

/** The provider client-assertion keys over the database and the signer's KEK. */
export function createUpstreamClientKeys(deps: UpstreamClientKeysDependencies): UpstreamClientKeys {
  const store = createRepositoryKeyStore(deps.db);
  const factory = createKeyFactory({
    store,
    kekProvider: deps.kekProvider,
    enabledSignatureAlgorithms: deps.enabledSignatureAlgorithms,
    hybridSigning: deps.hybridSigning,
  });
  return Object.freeze({
    async importKey(input: ImportUpstreamClientKeyInput): Promise<ImportedUpstreamClientKey> {
      const created = await store.transaction(async (tx) => {
        await store.lockRealm(input.realmId, tx);
        return factory.importKey({
          realmId: input.realmId,
          purpose: PURPOSE,
          scopeId: input.providerId,
          algorithm: input.algorithm,
          kid: input.kid,
          privateKeyPem: input.privateKeyPem,
          tx,
        });
      }, input.tx);
      return Object.freeze({
        kid: created.kid,
        algorithm: created.algorithm as UpstreamClientKeyAlgorithm,
        status: created.status,
      });
    },

    async activate(input: ActivateUpstreamClientKeyInput): Promise<ActivatedKey> {
      return store.transaction(async (tx) => {
        await store.lockRealm(input.realmId, tx);
        const next = (
          await store.listByRealm(
            input.realmId,
            { purpose: PURPOSE, scopeId: input.providerId, status: 'next' },
            tx
          )
        ).find((key) => key.kid === input.kid);
        if (next === undefined) {
          throw new KeyChangeRefusedError(
            'NO_NEXT_KEY',
            'The provider holds no next key with the kid the request names'
          );
        }
        return factory.activateNextKey({
          realmId: input.realmId,
          purpose: PURPOSE,
          scopeId: input.providerId,
          algorithm: next.algorithm as UpstreamClientKeyAlgorithm,
          tx,
        });
      }, input.tx);
    },
  } satisfies UpstreamClientKeys);
}
