import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import { createRealmsRepository, type DbClient } from '@qauth-labs/infra-db';
import {
  isKeyPurpose,
  KEY_ALGORITHMS,
  type KeyAlgorithm,
  KeyCreationRefusedError,
} from '@qauth-labs/server-keys';
import {
  bootRealmKeys,
  type CreatedKey,
  createKeyFactory,
  type EnvironmentKeySettings,
  type KekEnv,
  type KekProvider,
  type KekWarning,
  loadKekProvider,
  type NewKeyStatus,
  type RealmKeysBootResult,
} from '@qauth-labs/server-keys/custody';
import type { FastifyBaseLogger } from 'fastify';

import { createRepositoryKeyStore } from './repository-key-stores';

/**
 * The realm keys' boot step and the operator's key creation, over the
 * database repositories (ADR-019 Decision 9, issue #485).
 *
 * Both need the KEK, so both live in the signer's wiring, the one project
 * besides `@qauth-labs/server-keys` that may import its `custody` entry point.
 */

/** What the key boot step reads, besides the database and the KEK. */
export interface RealmKeysBootSettings {
  /**
   * The realm whose keys the step imports and creates, by name: the default
   * realm (`DEFAULT_REALM_NAME`). Its own boot step creates it first.
   */
  readonly realmName: string;
  /**
   * The keys the deployment configured in variables, as the configuration
   * resolved them, with the names of the variables that set them. Pass the
   * ML-DSA-65 seed only with hybrid signing on.
   */
  readonly environmentKeys: EnvironmentKeySettings;
}

/** What the key boot step and key creation work with. */
export interface RealmKeysDependencies {
  readonly db: DbClient;
  readonly kekProvider: KekProvider;
  /** `cryptoEnv.enabledSignatureAlgorithms` (`SIGNING_ALGORITHM_MODE`). */
  readonly enabledSignatureAlgorithms: readonly SignatureAlgorithm[];
  /** `HYBRID_SIGNING_ENABLED`. */
  readonly hybridSigning: boolean;
}

/**
 * The message logged at every boot for a key variable whose key is in the
 * store. It names the variable, never its value.
 */
export function keyVariableWarning(variable: string): string {
  return `${variable} is no longer read: its key is in the realm's key store. Remove the variable.`;
}

/**
 * Run the key boot step for a realm named by `settings.realmName`: import
 * each configured key the realm's store lacks, create the standard keys it
 * still lacks, and an RS256 signing key on a fresh realm (`bootRealmKeys`).
 *
 * Then log one line with what was imported and generated, by `kid`, and one
 * warning per key variable that is still set: its key is in the store, so the
 * variable is no longer read and should be removed.
 *
 * @throws Error when the realm does not exist
 * @throws the errors of `bootRealmKeys`: an `InvalidConfigurationError` names
 *   the variables when a configured key cannot be imported, or when an import
 *   would use the published development KEK
 */
export async function bootRealmKeysByName(
  deps: RealmKeysDependencies & { readonly log: Pick<FastifyBaseLogger, 'info' | 'warn'> },
  settings: RealmKeysBootSettings
): Promise<RealmKeysBootResult> {
  const realm = await createRealmsRepository(deps.db).findByName(settings.realmName);
  if (realm === undefined) {
    throw new Error(
      `The realm "${settings.realmName}" does not exist, so its keys cannot be provisioned: the default realm's boot step creates it before the key step runs.`
    );
  }

  const result = await bootRealmKeys({
    store: createRepositoryKeyStore(deps.db),
    kekProvider: deps.kekProvider,
    enabledSignatureAlgorithms: deps.enabledSignatureAlgorithms,
    hybridSigning: deps.hybridSigning,
    realmId: realm.id,
    environmentKeys: settings.environmentKeys,
  });

  deps.log.info(
    {
      realm: realm.name,
      imported: result.imported.map(({ purpose, algorithm, kid, variables }) => ({
        purpose,
        algorithm,
        kid,
        variables,
      })),
      generated: result.generated.map(({ purpose, algorithm, kid, status }) => ({
        purpose,
        algorithm,
        kid,
        status,
      })),
    },
    'realm keys ready'
  );

  const variables = new Set(
    [...result.imported, ...result.alreadyStored].flatMap((key) => key.variables)
  );
  for (const variable of variables) {
    deps.log.warn({ variable, realm: realm.name }, keyVariableWarning(variable));
  }
  return result;
}

/** What {@link createRealmKey} works with: it loads the KEK provider itself. */
export interface CreateRealmKeyDependencies extends Omit<RealmKeysDependencies, 'kekProvider'> {
  /** The KEK provider's settings (`KEK_PROVIDER`, `KEK`, `KEK_PATH`, …, `NODE_ENV`). */
  readonly kekEnv: KekEnv;
  /** Receives the KEK provider's warnings, such as the development KEK fallback. */
  readonly warn: (warning: KekWarning) => void;
}

/** Input of {@link createRealmKey}: what the operator asked for. */
export interface CreateRealmKeyInput {
  /** The realm, by name. */
  readonly realmName: string;
  /** A key purpose, such as `token_signing`. */
  readonly purpose: string;
  /** One of the purpose's algorithms; its default when absent. */
  readonly algorithm?: string;
  /** The owner of a scoped key, for a scoped purpose only. */
  readonly scopeId?: string;
  /** `active` (the default) or `next`. */
  readonly status?: NewKeyStatus;
}

/**
 * Create one key for a realm, as an operator does with
 * `auth-server:keys:create` on a host that holds the KEK: for example an
 * RS256 `token_signing` key for an OpenID Foundation conformance run.
 *
 * The key is generated, sealed and stored under the realm's key lock, so it
 * never races a node's boot step. With hybrid signing on, an EdDSA
 * `token_signing` key comes with its ML-DSA-65 key.
 *
 * @returns the stored keys, with their `kid`s and public JWKs; never material
 * @throws Error when the realm does not exist
 * @throws KeyCreationRefusedError for an unknown purpose or algorithm, or one
 *   the deployment does not create (see `createKeyFactory`)
 * @throws ActiveKeyConflictError when the realm already has an active key of
 *   the purpose and algorithm: create the new one as `next`
 */
export async function createRealmKey(
  deps: CreateRealmKeyDependencies,
  input: CreateRealmKeyInput
): Promise<readonly CreatedKey[]> {
  const { purpose } = input;
  if (!isKeyPurpose(purpose)) {
    throw new KeyCreationRefusedError('UNKNOWN_PURPOSE', `Unknown key purpose '${purpose}'`);
  }
  const algorithm = resolveAlgorithm(input.algorithm);
  const kekProvider = await loadKekProvider({ env: deps.kekEnv, warn: deps.warn });
  const realm = await createRealmsRepository(deps.db).findByName(input.realmName);
  if (realm === undefined) {
    throw new Error(`The realm "${input.realmName}" does not exist`);
  }

  const store = createRepositoryKeyStore(deps.db);
  const factory = createKeyFactory({
    store,
    kekProvider,
    enabledSignatureAlgorithms: deps.enabledSignatureAlgorithms,
    hybridSigning: deps.hybridSigning,
  });
  return store.transaction(async (tx) => {
    await store.lockRealm(realm.id, tx);
    return factory.createKey({
      realmId: realm.id,
      purpose,
      ...(algorithm === undefined ? {} : { algorithm }),
      ...(input.scopeId === undefined ? {} : { scopeId: input.scopeId }),
      ...(input.status === undefined ? {} : { status: input.status }),
      tx,
    });
  });
}

function resolveAlgorithm(algorithm: string | undefined): KeyAlgorithm | undefined {
  if (algorithm === undefined) return undefined;
  if (!(KEY_ALGORITHMS as readonly string[]).includes(algorithm)) {
    throw new KeyCreationRefusedError(
      'ALGORITHM_NOT_ALLOWED',
      `Unknown key algorithm '${algorithm}' (known: ${KEY_ALGORITHMS.join(', ')})`
    );
  }
  return algorithm as KeyAlgorithm;
}
