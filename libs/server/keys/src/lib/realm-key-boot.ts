import { randomUUID } from 'node:crypto';

import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import type { JWK } from 'jose';

import { LOCAL_KEK_PROVIDER } from './default-kek-provider';
import { sealKeyMaterial } from './envelope';
import {
  type EnvironmentKey,
  type EnvironmentKeySettings,
  prepareEnvironmentKeys,
} from './environment-keys';
import type { KekProvider } from './kek-provider';
import { computeKekRef, DEV_KEK_DEFAULT } from './kek-sources';
import { KeyCreationRefusedError, KeyIdConflictError } from './key-creation-errors';
import { type CreatedKey, createKeyFactory, type KeyFactoryOptions } from './key-factory';
import { jwkThumbprintKid } from './key-generation';
import type { RealmKeyStore, StoredKeyStatus } from './key-store';
import { isRealmId } from './realm-id';

/**
 * A realm's key boot step (ADR-019 Decision 9 and its answer on existing
 * issuers, issue #485): import the keys the deployment configured in
 * environment variables, then create every standard key the realm still
 * lacks.
 *
 * It runs at every boot, on every node, for the default realm:
 *
 * 1. Under an advisory lock on the realm, so nodes that start together run it
 *    one at a time: the first imports and creates, the others find the keys.
 * 2. Each configured key the realm's store lacks is imported, as an `active`
 *    key. A signing key counts as stored when the realm has a published key
 *    with the same public key (RFC 7638 thumbprint), whatever its `kid`. The
 *    cookie secret is imported only into a realm with no `cookie_hmac` key.
 * 3. `provisionRealmKeys` creates the standard keys still missing:
 *    `event_signing` and `data_at_rest`, and `token_signing` and `cookie_hmac`
 *    on a fresh deployment.
 * 4. A fresh realm, one that had no `token_signing` key and imported none,
 *    also gets an RS256 `token_signing` key: OpenID Connect requires an OP to
 *    sign ID tokens with RS256.
 *
 * All of it is one transaction: every key or none. The step refuses, and
 * stores nothing, when:
 *
 * - a key must be imported and the KEK is the published development KEK: a
 *   real key wrapped with it would be as good as plaintext;
 * - a variable holds another key than the realm's active key of its
 *   algorithm: the store has held the realm's keys since the first boot after
 *   the upgrade, and a stored key changes by rotation, not through the
 *   variable;
 * - a variable holds a key the realm marked `compromised`;
 * - the ML-DSA-65 key would join an Ed25519 key stored without one: both keys
 *   of a hybrid pair are stored together (ADR-005).
 */

/** A published key as {@link RealmKeyBootStore.listPublicKeys} returns it. */
export interface StoredPublicKey {
  readonly kid: string;
  readonly purpose: string;
  readonly status: StoredKeyStatus;
  readonly publicJwk: Record<string, unknown>;
}

/** The store the boot step works through: the key factory's, plus a lock and the public keys. */
export interface RealmKeyBootStore<Tx> extends RealmKeyStore<Tx> {
  /**
   * Take the realm's key lock for the rest of `tx`: a transaction-level
   * advisory lock, so a second boot step for the realm waits until the first
   * commits or rolls back.
   */
  lockRealm(realmId: string, tx: Tx): Promise<void>;
  /** Every `realm_public_keys` row of the realm, whatever its status or window. */
  listPublicKeys(realmId: string, tx: Tx): Promise<readonly StoredPublicKey[]>;
}

/** Options of {@link bootRealmKeys}: the key factory's, the realm and the configured keys. */
export interface BootRealmKeysOptions<Tx> extends Omit<KeyFactoryOptions<Tx>, 'store'> {
  readonly store: RealmKeyBootStore<Tx>;
  /** The realm, a UUID. */
  readonly realmId: string;
  /**
   * The keys the deployment configured in variables. Pass `mlDsa` only with
   * hybrid signing on: the ML-DSA-65 key is stored only as the second key of
   * a hybrid pair.
   */
  readonly environmentKeys?: EnvironmentKeySettings;
}

/** What happened to one configured key. Never carries key material. */
export interface EnvironmentKeyOutcome {
  readonly purpose: EnvironmentKey['purpose'];
  readonly algorithm: EnvironmentKey['algorithm'];
  /** The `kid` of the stored key that holds it, or of the realm's cookie key. */
  readonly kid: string;
  /** The variables that set it. */
  readonly variables: readonly string[];
}

/** What {@link bootRealmKeys} did. */
export interface RealmKeysBootResult {
  /** The configured keys this boot imported. */
  readonly imported: readonly EnvironmentKeyOutcome[];
  /**
   * The configured keys the realm already held. For the cookie secret: the
   * realm already had a cookie key, which may not be this secret.
   */
  readonly alreadyStored: readonly EnvironmentKeyOutcome[];
  /** The keys this boot generated: the missing standard keys, and RS256 on a fresh realm. */
  readonly generated: readonly CreatedKey[];
}

/** The `kekRef` of the published development KEK. */
const DEVELOPMENT_KEK_REF = computeKekRef(Buffer.from(DEV_KEK_DEFAULT, 'base64'));

/**
 * Run the key boot step for one realm. See the module comment for the steps
 * and the refusals.
 *
 * @throws InvalidConfigurationError for a configured key that cannot be
 *   imported, or an import that would use the development KEK. The message
 *   names the variables; the details carry the stored `kid` where one is
 *   involved.
 * @throws KeyCreationRefusedError when the realm id is not a UUID, or when
 *   hybrid signing is on and the realm holds half a pair
 *   (`HYBRID_PAIR_INCOMPLETE`)
 * @throws KeyIdConflictError when a configured `kid` is already another key's
 */
export async function bootRealmKeys<Tx>(
  options: BootRealmKeysOptions<Tx>
): Promise<RealmKeysBootResult> {
  const { store, kekProvider } = options;
  if (!isRealmId(options.realmId)) {
    throw new KeyCreationRefusedError('INVALID_REALM_ID', 'A realm id is a UUID');
  }
  // The stored form, as the key factory writes it: the realm id is sealed into
  // each key's associated data.
  const realmId = options.realmId.toLowerCase();
  const now = options.now ?? Date.now;
  const settings = options.environmentKeys ?? {};
  if (settings.mlDsa !== undefined && options.hybridSigning !== true) {
    throw new InvalidConfigurationError(
      'The ML-DSA-65 key is imported only with HYBRID_SIGNING_ENABLED on: it is stored as the second key of a hybrid pair.'
    );
  }
  const factory = createKeyFactory({
    store,
    kekProvider,
    enabledSignatureAlgorithms: options.enabledSignatureAlgorithms,
    hybridSigning: options.hybridSigning,
    ...(options.federationOperator === undefined
      ? {}
      : { federationOperator: options.federationOperator }),
    now,
  });

  const keys = await prepareEnvironmentKeys(settings, {
    enabledSignatureAlgorithms: options.enabledSignatureAlgorithms,
  });
  try {
    return await store.transaction(async (tx) => {
      await store.lockRealm(realmId, tx);

      const tokenKeysBefore = await store.listByRealm(
        realmId,
        { purpose: 'token_signing', scopeId: null },
        tx
      );
      const { toImport, alreadyStored } = await sortEnvironmentKeys(store, realmId, keys, tx);
      if (toImport.length > 0 && (await usesDevelopmentKek(kekProvider))) {
        throw new InvalidConfigurationError(
          'Keys from the key variables must be imported into the key store, but no KEK is set: with KEK_PROVIDER=local, KEK or KEK_PATH wraps every stored key, and without one the keys would be wrapped with the published development KEK. Set KEK or KEK_PATH, for example to the output of `openssl rand -base64 32`, and boot again. See this error\'s "details" for the variables.',
          { variables: toImport.flatMap((key) => key.variables) }
        );
      }

      const imported = await importKeys(store, kekProvider, realmId, toImport, now(), tx);
      const generated = [...(await factory.provisionRealmKeys(realmId, { tx }))];
      const fresh =
        tokenKeysBefore.length === 0 && !toImport.some((key) => key.purpose === 'token_signing');
      if (fresh) {
        generated.push(
          ...(await factory.createKey({
            realmId,
            purpose: 'token_signing',
            algorithm: 'RS256',
            tx,
          }))
        );
      }
      return { imported, alreadyStored, generated };
    });
  } finally {
    for (const key of keys) key.material.fill(0);
  }
}

/** Whether the provider wraps with the published development KEK. */
async function usesDevelopmentKek(provider: KekProvider): Promise<boolean> {
  if (provider.name !== LOCAL_KEK_PROVIDER) return false;
  return (await provider.health()).kekRef === DEVELOPMENT_KEK_REF;
}

/** Split the configured keys into those to import and those the realm holds. */
async function sortEnvironmentKeys<Tx>(
  store: RealmKeyBootStore<Tx>,
  realmId: string,
  keys: readonly EnvironmentKey[],
  tx: Tx
): Promise<{ toImport: EnvironmentKey[]; alreadyStored: EnvironmentKeyOutcome[] }> {
  const toImport: EnvironmentKey[] = [];
  const alreadyStored: EnvironmentKeyOutcome[] = [];
  let published: { readonly key: StoredPublicKey; readonly thumbprint: string }[] | undefined;

  for (const key of keys) {
    if (key.purpose === 'cookie_hmac') {
      const stored = await store.listByRealm(
        realmId,
        { purpose: 'cookie_hmac', scopeId: null },
        tx
      );
      if (stored.length === 0) {
        toImport.push(key);
      } else {
        const current = stored.find((row) => row.status === 'active') ?? stored[0];
        alreadyStored.push(outcome(key, current.kid));
      }
      continue;
    }

    published ??= await thumbprintsOf(await store.listPublicKeys(realmId, tx));
    const match = published.find(
      ({ key: stored, thumbprint }) =>
        stored.purpose === key.purpose && thumbprint === key.thumbprint
    );
    if (match !== undefined) {
      if (match.key.status === 'compromised') {
        throw new InvalidConfigurationError(
          `${key.variables.join(' and ')} holds a key the realm marked compromised. Remove the variable.`,
          { variables: key.variables, realmId, kid: match.key.kid }
        );
      }
      alreadyStored.push(outcome(key, match.key.kid));
      continue;
    }

    const active = await store.listByRealm(
      realmId,
      { purpose: key.purpose, scopeId: null, status: 'active' },
      tx
    );
    const current = active.find((row) => row.algorithm === key.algorithm);
    if (current !== undefined) {
      throw new InvalidConfigurationError(
        `${key.variables.join(' and ')} holds another ${key.algorithm} key than the one the realm's key store holds. The store has held the realm's keys since the first boot after the upgrade, and a stored key is replaced by rotation, not through the variable. Put back the key the store holds (its kid is in this error's "details"), or remove the variable once nothing reads it.`,
        { variables: key.variables, realmId, kid: current.kid }
      );
    }
    toImport.push(key);
  }
  return { toImport, alreadyStored };
}

async function thumbprintsOf(
  keys: readonly StoredPublicKey[]
): Promise<{ readonly key: StoredPublicKey; readonly thumbprint: string }[]> {
  return Promise.all(
    keys.map(async (key) => ({ key, thumbprint: await jwkThumbprintKid(key.publicJwk as JWK) }))
  );
}

/**
 * Seal and store the keys to import, as `active` keys. The Ed25519 and
 * ML-DSA-65 keys share one `pair_id` when both are imported.
 */
async function importKeys<Tx>(
  store: RealmKeyBootStore<Tx>,
  kekProvider: KekProvider,
  realmId: string,
  keys: readonly EnvironmentKey[],
  at: number,
  tx: Tx
): Promise<EnvironmentKeyOutcome[]> {
  // ML-DSA-65 keys are configured only with hybrid signing on (see
  // `bootRealmKeys`), so one to import means the realm's pair is imported now:
  // its Ed25519 key must come with it.
  const ed25519 = keys.find((key) => key.algorithm === 'EdDSA');
  const mlDsa = keys.find((key) => key.algorithm === 'ML-DSA-65');
  if (mlDsa !== undefined && ed25519 === undefined) {
    throw new InvalidConfigurationError(
      `${mlDsa.variables.join(' and ')} holds an ML-DSA-65 key to import, but the realm's Ed25519 key is already stored without it. Both keys of a hybrid pair are stored together, so the ML-DSA-65 key cannot join the stored Ed25519 key; rotate the token-signing keys to a new pair.`,
      { variables: mlDsa.variables, realmId }
    );
  }
  const pairId = mlDsa !== undefined ? randomUUID() : null;

  const imported: EnvironmentKeyOutcome[] = [];
  for (const key of keys) {
    if ((await store.findByKid(realmId, key.kid, tx)) !== undefined) {
      throw new KeyIdConflictError(key.kid);
    }
    const sealed = await sealKeyMaterial(kekProvider, key.material, {
      realmId,
      purpose: key.purpose,
      scopeId: null,
      kid: key.kid,
      algorithm: key.algorithm,
    });
    const row = {
      realmId,
      purpose: key.purpose,
      scopeId: null,
      algorithm: key.algorithm,
      kid: key.kid,
      status: 'active' as const,
      pairId: key.algorithm === 'EdDSA' || key.algorithm === 'ML-DSA-65' ? pairId : null,
      ciphertext: sealed.ciphertext,
      iv: sealed.iv,
      wrappedDek: sealed.wrappedDek,
      kekRef: sealed.kekRef,
      aadVersion: sealed.aadVersion,
      activateAt: at,
    };
    if (key.publicJwk !== undefined) {
      await store.create({ key: { ...row, publishAt: at }, publicJwk: { ...key.publicJwk } }, tx);
    } else {
      await store.create({ key: { ...row, publishAt: null } }, tx);
    }
    imported.push(outcome(key, key.kid));
  }
  return imported;
}

function outcome(key: EnvironmentKey, kid: string): EnvironmentKeyOutcome {
  return Object.freeze({
    purpose: key.purpose,
    algorithm: key.algorithm,
    kid,
    variables: key.variables,
  });
}
