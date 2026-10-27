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
import {
  KeyChangeRefusedError,
  KeyCreationRefusedError,
  KeyIdConflictError,
} from './key-creation-errors';
import { type CreatedKey, createKeyFactory, type KeyFactoryOptions } from './key-factory';
import { jwkThumbprintKid } from './key-generation';
import { KEY_PURPOSES } from './key-purposes';
import type { RealmKeyStore, StoredKeyStatus, StoredKeySummary } from './key-store';
import { publicKeyIdentity } from './published-keys';
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
 * 3. A signing key the store lacks, while the realm has an active key of its
 *    algorithm, replaces that key: the stored key, and its hybrid partner, are
 *    retired and unpublished at once. Changing the variable is how a deployment
 *    replaces a signing key until rotation through the store ships (manual
 *    rotation #544, emergency retirement #551).
 * 4. `provisionRealmKeys` creates the standard keys still missing:
 *    `event_signing` and `data_at_rest`, and `token_signing` and `cookie_hmac`
 *    on a fresh deployment.
 * 5. A fresh realm, one that had no `token_signing` key and imported none,
 *    also gets an RS256 `token_signing` key: OpenID Connect requires an OP to
 *    sign ID tokens with RS256.
 *
 * A variable that holds a key the store keeps, but not as its active key (a
 * key a replacement retired), changes nothing: the step reports it in
 * `inactive`.
 *
 * All of it is one transaction: every key or none. The step refuses, and
 * stores nothing, when:
 *
 * - a key must be imported and the KEK is the published development KEK: a
 *   real key wrapped with it would be as good as plaintext;
 * - a variable holds a key the realm marked `compromised`;
 * - one key of the hybrid pair is new to the store and the other is not: both
 *   keys of a pair are stored, and replaced, together (ADR-005);
 * - a new key comes with a configured `kid` that is already another stored
 *   key's: a `kid` names one key.
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
  /**
   * Whether a realm other than `realmId` publishes a key whose public JWK has
   * every member of `identity` ({@link publicKeyIdentity}), whatever its
   * status or window.
   */
  anotherRealmPublishes(
    realmId: string,
    identity: Readonly<Record<string, string>>,
    tx: Tx
  ): Promise<boolean>;
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

/** A configured key that replaced the realm's active key of its algorithm. */
export interface ReplacedKeyOutcome extends EnvironmentKeyOutcome {
  /**
   * The stored keys this boot retired and unpublished for it: the key it
   * replaced, and that key's hybrid partner when the partner was not replaced
   * too.
   */
  readonly retiredKids: readonly string[];
}

/** A configured key the store holds, but not as its active key. */
export interface InactiveKeyOutcome extends EnvironmentKeyOutcome {
  /** The stored key's status: `retired`, or `next`. */
  readonly status: Exclude<StoredKeyStatus, 'active' | 'compromised'>;
  /** The realm's active key of the algorithm, or `null` when it has none. */
  readonly activeKid: string | null;
}

/** What {@link bootRealmKeys} did. */
export interface RealmKeysBootResult {
  /** The configured keys this boot imported, replacements included. */
  readonly imported: readonly EnvironmentKeyOutcome[];
  /** The imported keys that replaced a stored key, with the keys they retired. */
  readonly replaced: readonly ReplacedKeyOutcome[];
  /**
   * The configured keys the realm already held as active keys. For the cookie
   * secret: the realm already had a cookie key, which may not be this secret.
   */
  readonly alreadyStored: readonly EnvironmentKeyOutcome[];
  /** The configured keys the store holds, but not as its active key. Nothing changed for them. */
  readonly inactive: readonly InactiveKeyOutcome[];
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
 *   imported, an import that would use the development KEK, half a hybrid
 *   pair to import, or a new key whose configured `kid` is already another
 *   stored key's. The message names the variables; the details carry the
 *   stored `kid` where one is involved.
 * @throws KeyCreationRefusedError when the realm id is not a UUID, or when
 *   hybrid signing is on and the realm holds half a pair
 *   (`HYBRID_PAIR_INCOMPLETE`)
 * @throws KeyIdConflictError when a new key's thumbprint `kid` is already
 *   another key's
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
      const { pending, alreadyStored, inactive } = await sortEnvironmentKeys(
        store,
        realmId,
        keys,
        tx
      );
      const toImport = pending.map(({ key }) => key);
      checkHybridPair(realmId, keys, toImport);
      await refuseKeysOfAnotherRealm(store, realmId, toImport, tx);
      if (toImport.length > 0 && (await usesDevelopmentKek(kekProvider))) {
        throw new InvalidConfigurationError(
          'Keys from the key variables must be imported into the key store, but no KEK is set: with KEK_PROVIDER=local, KEK or KEK_PATH wraps every stored key, and without one the keys would be wrapped with the published development KEK. Set KEK or KEK_PATH, for example to the output of `openssl rand -base64 32`, and boot again. See this error\'s "details" for the variables.',
          { variables: toImport.flatMap((key) => key.variables) }
        );
      }

      const at = now();
      // Retire first: the one-active index allows no moment with two.
      const replaced = await retireReplacedKeys(store, realmId, pending, at, tx);
      const imported = await importKeys(store, kekProvider, realmId, toImport, at, tx);
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
      return { imported, replaced, alreadyStored, inactive, generated };
    });
  } finally {
    for (const key of keys) key.material.fill(0);
  }
}

/**
 * Refuse to import a configured key that another realm already publishes
 * (#491). A realm's tokens verify only with its own keys, and an issuer rule
 * that accepts another realm's issuer (the admin family's, #509) relies on no
 * two realms holding the same key: a shared key would let one realm's tokens
 * verify as the other's.
 */
async function refuseKeysOfAnotherRealm<Tx>(
  store: RealmKeyBootStore<Tx>,
  realmId: string,
  keys: readonly EnvironmentKey[],
  tx: Tx
): Promise<void> {
  for (const key of keys) {
    const identity = key.publicJwk === undefined ? undefined : publicKeyIdentity(key.publicJwk);
    if (identity === undefined) continue;
    if (await store.anotherRealmPublishes(realmId, identity, tx)) {
      throw new InvalidConfigurationError(
        `${key.variables.join(' and ')} holds a ${key.algorithm} key that another realm of this deployment already stores. Two realms never share a key: each realm's tokens must verify with its own keys only. Set a key of this realm's own, or unset the variable and let the realm keep or generate its own, and boot again.`,
        { variables: key.variables }
      );
    }
  }
}

/** Whether the provider wraps with the published development KEK. */
async function usesDevelopmentKek(provider: KekProvider): Promise<boolean> {
  if (provider.name !== LOCAL_KEK_PROVIDER) return false;
  return (await provider.health()).kekRef === DEVELOPMENT_KEK_REF;
}

/** A configured key to import, and the active key it replaces, if any. */
interface PendingImport {
  readonly key: EnvironmentKey;
  readonly replaces?: StoredKeySummary;
}

/**
 * Split the configured keys into those to import, with the active keys they
 * replace, those the realm holds as active keys, and those it holds otherwise.
 */
async function sortEnvironmentKeys<Tx>(
  store: RealmKeyBootStore<Tx>,
  realmId: string,
  keys: readonly EnvironmentKey[],
  tx: Tx
): Promise<{
  pending: PendingImport[];
  alreadyStored: EnvironmentKeyOutcome[];
  inactive: InactiveKeyOutcome[];
}> {
  const pending: PendingImport[] = [];
  const alreadyStored: EnvironmentKeyOutcome[] = [];
  const inactive: InactiveKeyOutcome[] = [];
  let published: { readonly key: StoredPublicKey; readonly thumbprint: string }[] | undefined;

  for (const key of keys) {
    if (key.purpose === 'cookie_hmac') {
      const stored = await store.listByRealm(
        realmId,
        { purpose: 'cookie_hmac', scopeId: null },
        tx
      );
      if (stored.length === 0) {
        pending.push({ key });
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
    const active = await store.listByRealm(
      realmId,
      { purpose: key.purpose, scopeId: null, status: 'active' },
      tx
    );
    const current = active.find((row) => row.algorithm === key.algorithm);
    if (match === undefined) {
      pending.push(current === undefined ? { key } : { key, replaces: current });
      continue;
    }

    const { status } = match.key;
    if (status === 'compromised') {
      throw new InvalidConfigurationError(
        `${key.variables.join(' and ')} holds a key the realm marked compromised. Remove the variable.`,
        { variables: key.variables, realmId, kid: match.key.kid }
      );
    }
    if (status === 'active') {
      alreadyStored.push(outcome(key, match.key.kid));
    } else {
      inactive.push(
        Object.freeze({ ...outcome(key, match.key.kid), status, activeKid: current?.kid ?? null })
      );
    }
  }
  return { pending, alreadyStored, inactive };
}

/**
 * Refuse half a hybrid pair to import. With hybrid signing on, both keys of
 * the pair are configured; the store holds them under one `pair_id`, so both
 * are new to it, or neither (ADR-005).
 */
function checkHybridPair(
  realmId: string,
  keys: readonly EnvironmentKey[],
  toImport: readonly EnvironmentKey[]
): void {
  const mlDsa = keys.find((key) => key.algorithm === 'ML-DSA-65');
  if (mlDsa === undefined) return;
  const ed25519 = keys.find((key) => key.algorithm === 'EdDSA');
  const mlDsaIsNew = toImport.includes(mlDsa);
  if (ed25519 !== undefined && toImport.includes(ed25519) === mlDsaIsNew) return;
  if (ed25519 === undefined) {
    if (!mlDsaIsNew) return;
    throw new InvalidConfigurationError(
      `${mlDsa.variables.join(' and ')} holds an ML-DSA-65 key to import, but no Ed25519 key comes with it: both keys of a hybrid pair are stored together.`,
      { variables: mlDsa.variables, realmId }
    );
  }
  const [fresh, kept] = mlDsaIsNew ? [mlDsa, ed25519] : [ed25519, mlDsa];
  throw new InvalidConfigurationError(
    `${fresh.variables.join(' and ')} holds a ${fresh.algorithm} key the realm's key store lacks, but ${kept.variables.join(' and ')} holds the ${kept.algorithm} key it already stores. Both keys of a hybrid pair are stored, and replaced, together: set ${kept.variables[0]} to a new key as well, and boot again.`,
    { variables: fresh.variables, realmId }
  );
}

/**
 * Retire the active keys the configured keys replace, with the hybrid partner
 * of each when the partner is not replaced too: a pair retires together
 * (ADR-005). A retired published key leaves its JWKS at once. The variable
 * change took it out of service, so no overlap applies; a deployment that
 * wants one waits for rotation through the store (#544).
 */
async function retireReplacedKeys<Tx>(
  store: RealmKeyBootStore<Tx>,
  realmId: string,
  pending: readonly PendingImport[],
  at: number,
  tx: Tx
): Promise<ReplacedKeyOutcome[]> {
  const replacedKids = new Set(pending.flatMap(({ replaces }) => replaces?.kid ?? []));
  const retired = new Set<string>();
  const replacements: ReplacedKeyOutcome[] = [];
  for (const { key, replaces } of pending) {
    if (replaces === undefined) continue;
    const active = await store.listByRealm(
      realmId,
      { purpose: key.purpose, scopeId: null, status: 'active' },
      tx
    );
    const partners =
      replaces.pairId === null
        ? []
        : active.filter(
            (row) =>
              row.pairId === replaces.pairId &&
              row.kid !== replaces.kid &&
              !replacedKids.has(row.kid)
          );
    const kids = [replaces.kid, ...partners.map((row) => row.kid)].filter(
      (kid) => !retired.has(kid)
    );
    const unpublishAt = KEY_PURPOSES[key.purpose].published ? at : null;
    for (const kid of kids) {
      const moved = await store.updateStatus(
        realmId,
        kid,
        { status: 'retired', retireAt: at, unpublishAt },
        tx
      );
      if (moved === undefined) {
        throw new KeyChangeRefusedError(
          'KEY_CHANGED',
          `A '${key.purpose}' key changed status during the key boot step; nothing was stored`
        );
      }
      retired.add(kid);
    }
    replacements.push(Object.freeze({ ...outcome(key, key.kid), retiredKids: kids }));
  }
  return replacements;
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
  // An ML-DSA-65 key to import comes with its Ed25519 key (`checkHybridPair`),
  // so the two are the realm's new pair.
  const pairId = keys.some((key) => key.algorithm === 'ML-DSA-65') ? randomUUID() : null;

  const imported: EnvironmentKeyOutcome[] = [];
  for (const key of keys) {
    if ((await store.findByKid(realmId, key.kid, tx)) !== undefined) {
      if (key.thumbprint !== null && key.kid !== key.thumbprint) {
        throw new InvalidConfigurationError(
          `${key.variables.join(' and ')} holds a new ${key.algorithm} key, but its configured kid is already another stored key's. A new key needs a new kid: change the kid variable, or remove it to use the key's thumbprint.`,
          { variables: key.variables, realmId, kid: key.kid }
        );
      }
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
      createdAt: at,
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
