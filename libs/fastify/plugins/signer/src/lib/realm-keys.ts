import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import { createRealmsRepository, type DbClient } from '@qauth-labs/infra-db';
import {
  isKeyPurpose,
  KEY_ALGORITHMS,
  type KeyAlgorithm,
  KeyCreationRefusedError,
  type KeyPurpose,
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
 *
 * Tokens are signed through the realm's key store (#491), so a token variable
 * is read only by the key boot step, where a new key in it replaces the stored
 * key until rotation through the store ships (#544, #551). The session cookie
 * is still signed with its variable until it moves onto the signer (#493), so
 * that variable stays set.
 */
export function keyVariableWarning(variable: string, purpose: KeyPurpose): string {
  return purpose === 'cookie_hmac'
    ? `${variable} is in the realm's key store, but the session cookie is still signed with the variable: keep it set until the upgrade guide says to remove it.`
    : `${variable} is in the realm's key store, which signs the tokens: the variable is read only at boot, where a new key in it replaces the stored key and unpublishes the old one at once. Remove it unless you may roll back to a release that signs with it.`;
}

/**
 * The message logged at boot for a key variable that held a new key, which
 * replaced the realm's active key of its algorithm. The log line carries the
 * new and the retired `kid`s.
 */
export function keyReplacedWarning(variables: readonly string[], algorithm: string): string {
  return `${variables.join(' and ')} held a new ${algorithm} key: the realm's key store now holds it as the active key, and retired and unpublished the key it replaced at once. Tokens that key signed no longer verify.`;
}

/**
 * The message logged at every boot for a key variable whose key the store
 * holds, but not as its active key: a key a replacement retired. The log line
 * carries both `kid`s.
 */
export function keyInactiveWarning(
  variables: readonly string[],
  algorithm: string,
  status: string
): string {
  return `${variables.join(' and ')} holds an ${algorithm} key the realm's key store holds as ${status}, not as its active key, and the store does not make it active again: once tokens are signed through the key store, its active key signs. Set the variable to the active key, or to a new key to replace it.`;
}

/**
 * Run the key boot step for a realm named by `settings.realmName`: import
 * each configured key the realm's store lacks, replacing the active key of its
 * algorithm, create the standard keys it still lacks, and an RS256 signing key
 * on a fresh realm (`bootRealmKeys`).
 *
 * Then log one line with what was imported and generated, by `kid`, one
 * warning per replaced key and per variable that holds a retired key, and one
 * warning per key variable that is still set: tokens and the session cookie
 * are still signed with it, so it stays set.
 *
 * @throws Error when the realm does not exist
 * @throws KeyCreationRefusedError (`HYBRID_PAIR_INCOMPLETE`) when hybrid
 *   signing is on and the realm's active token keys are half a pair: the
 *   ML-DSA-65 key is missing
 * @throws the errors of `bootRealmKeys`: an `InvalidConfigurationError` names
 *   the variables when a configured key cannot be imported, when an import
 *   would use the published development KEK, for half a hybrid pair, or for a
 *   new key under a stored key's configured `kid`
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

  let result: RealmKeysBootResult;
  try {
    result = await bootRealmKeys({
      store: createRepositoryKeyStore(deps.db),
      kekProvider: deps.kekProvider,
      enabledSignatureAlgorithms: deps.enabledSignatureAlgorithms,
      hybridSigning: deps.hybridSigning,
      realmId: realm.id,
      environmentKeys: settings.environmentKeys,
    });
  } catch (error) {
    // Hybrid signing on, and the realm's active token keys are an EdDSA key
    // without its ML-DSA-65 half: tokens would be signed classical-only, so
    // the boot is refused (#491). Say what the operator can do today, before
    // rotation through the store ships (#542).
    if (error instanceof KeyCreationRefusedError && error.reason === 'HYBRID_PAIR_INCOMPLETE') {
      throw new KeyCreationRefusedError(
        'HYBRID_PAIR_INCOMPLETE',
        `HYBRID_SIGNING_ENABLED=true needs the realm's token keys as a hybrid pair, but the realm "${realm.name}" holds an active EdDSA key without its ML-DSA-65 key. Set JWT_PRIVATE_KEY and JWT_MLDSA_PRIVATE_KEY to a new pair, which replaces the stored key at boot, or turn hybrid signing off.`
      );
    }
    throw error;
  }

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

  for (const { purpose, algorithm, kid, variables, retiredKids } of result.replaced) {
    deps.log.warn(
      { realm: realm.name, purpose, algorithm, kid, retiredKids, variables },
      keyReplacedWarning(variables, algorithm)
    );
  }
  for (const { purpose, algorithm, kid, status, activeKid, variables } of result.inactive) {
    deps.log.warn(
      { realm: realm.name, purpose, algorithm, kid, status, activeKid, variables },
      keyInactiveWarning(variables, algorithm, status)
    );
  }

  const variables = new Map<string, KeyPurpose>();
  for (const key of [...result.imported, ...result.alreadyStored, ...result.inactive]) {
    for (const variable of key.variables) variables.set(variable, key.purpose);
  }
  for (const [variable, purpose] of variables) {
    deps.log.warn({ variable, realm: realm.name }, keyVariableWarning(variable, purpose));
  }
  return result;
}

/**
 * Run the key boot step for the realm named by `settings.realmName`, as
 * {@link bootRealmKeysByName} does, loading the KEK provider from `kekEnv`
 * first: for a caller outside the signer's wiring, such as a test harness that
 * empties the database and runs the boot steps again, or that gives a second
 * realm its standard keys.
 *
 * @throws the errors of `loadKekProvider` and of {@link bootRealmKeysByName}
 */
export async function bootRealmKeysWithKekEnv(
  deps: CreateRealmKeyDependencies & { readonly log: Pick<FastifyBaseLogger, 'info' | 'warn'> },
  settings: RealmKeysBootSettings
): Promise<RealmKeysBootResult> {
  const kekProvider = await loadKekProvider({ env: deps.kekEnv, warn: deps.warn });
  return bootRealmKeysByName(
    {
      db: deps.db,
      kekProvider,
      enabledSignatureAlgorithms: deps.enabledSignatureAlgorithms,
      hybridSigning: deps.hybridSigning,
      log: deps.log,
    },
    settings
  );
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
  try {
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
    return await store.transaction(async (tx) => {
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
  } finally {
    await kekProvider.close?.();
  }
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
