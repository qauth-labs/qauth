import { createPrivateKey, createPublicKey, type KeyObject, randomUUID } from 'node:crypto';

import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import type { JWK } from 'jose';

import { usesDevelopmentKek } from './development-kek';
import { sealKeyMaterial } from './envelope';
import { MIN_RSA_MODULUS_BITS } from './environment-keys';
import type { KekProvider } from './kek-provider';
import {
  ActiveKeyConflictError,
  KeyChangeRefusedError,
  KeyCreationRefusedError,
  KeyIdConflictError,
  NextKeyConflictError,
} from './key-creation-errors';
import { assertAllowedBySigningMode, generateKeyMaterial } from './key-generation';
import {
  DEFAULT_KEY_PREPUBLISH_DAYS,
  DEFAULT_KEY_RETIRED_RETENTION_DAYS,
  isKeyPurpose,
  KEY_PURPOSES,
  type KeyAlgorithm,
  type KeyPurpose,
  type KeyPurposeDefinition,
  STANDARD_REALM_KEY_PURPOSES,
} from './key-purposes';
import type { NewKeyStatus, NewStoredKey, RealmKeyStore, StoredKeySummary } from './key-store';
import { isRealmId } from './realm-id';
import { isScopeId, MAX_SCOPE_ID_LENGTH } from './scope-id';
import { formatWebhookSecret } from './webhook-signature';

export { isScopeId, MAX_SCOPE_ID_LENGTH } from './scope-id';

/**
 * Creating a realm's keys (ADR-019 Decision 9, issue #463): generate, seal
 * under the KEK, and store, with the purpose rules of `KEY_PURPOSES` and the
 * deployment's algorithm switches applied first. The scoped keys of #547
 * (webhook secrets, upstream client-assertion keys) also rotate and are
 * deleted here.
 */

const DAY_MS = 86_400_000;

/** The deployment a {@link KeyFactory} creates keys for. */
export interface KeyFactoryOptions<Tx> {
  /** Where the keys are stored. See {@link RealmKeyStore}. */
  readonly store: RealmKeyStore<Tx>;
  /** Wraps each key's data key. */
  readonly kekProvider: KekProvider;
  /**
   * The signature algorithms `SIGNING_ALGORITHM_MODE` enables
   * (`cryptoEnv.enabledSignatureAlgorithms`). A key of an algorithm the mode
   * governs and does not enable is refused.
   */
  readonly enabledSignatureAlgorithms: readonly SignatureAlgorithm[];
  /**
   * `HYBRID_SIGNING_ENABLED`. When on, a new EdDSA `token_signing` key is
   * created together with an ML-DSA-65 key, and both share one `pair_id`
   * (ADR-005).
   */
  readonly hybridSigning: boolean;
  /**
   * Whether this is a federation-operator deployment, the only kind that may
   * create `trust_anchor` keys (ADR-019 Decision 9). Off by default. The
   * federation work names the switch that sets it; this is the seam only.
   */
  readonly federationOperator?: boolean;
  /**
   * How long a `next` scoped key waits before `activateNextKey` may make it
   * active, in ms: published for that long, or for a webhook secret, handed
   * out and signing beside the old one. Defaults to
   * {@link DEFAULT_KEY_PREPUBLISH_DAYS}. The rotation settings of #542 set it.
   */
  readonly prepublishMs?: number;
  /**
   * How long a retired published key stays in its JWKS, in ms. Defaults to
   * {@link DEFAULT_KEY_RETIRED_RETENTION_DAYS}.
   */
  readonly retiredRetentionMs?: number;
  /** The clock, in epoch ms. Defaults to `Date.now`. */
  readonly now?: () => number;
}

/** Input of {@link KeyFactory.createKey}. */
export interface CreateKeyInput<Tx> {
  /** A UUID. It is stored, and sealed into the key's associated data, in lowercase. */
  readonly realmId: string;
  readonly purpose: KeyPurpose;
  /** The owner inside the realm, for a scoped purpose only. */
  readonly scopeId?: string | null;
  /** One of the purpose's algorithms. Defaults to the purpose's default algorithm. */
  readonly algorithm?: KeyAlgorithm;
  /** Defaults to `active`. */
  readonly status?: NewKeyStatus;
  /** An outer transaction to create the key in, such as the one that creates the realm. */
  readonly tx?: Tx;
}

/** Input of {@link KeyFactory.importKey}. */
export interface ImportKeyInput<Tx> {
  /** A UUID. It is stored, and sealed into the key's associated data, in lowercase. */
  readonly realmId: string;
  /** A purpose that takes an imported key (`importable`): `upstream_client_assertion`. */
  readonly purpose: KeyPurpose;
  /** The owner inside the realm, for a scoped purpose: the provider the key signs for. */
  readonly scopeId?: string | null;
  /**
   * The algorithm the key must be for, one of the purpose's: the one the
   * party that will verify its signatures asks for, such as `ES256` for Sign
   * in with Apple. A key of another algorithm is refused.
   */
  readonly algorithm: KeyAlgorithm;
  /**
   * The key's id as its issuer named it, such as the key id a provider shows
   * beside the key it issued: printable ASCII but space, at most
   * {@link MAX_IMPORTED_KEY_ID_LENGTH} characters. Signatures name it in
   * their header.
   */
  readonly kid: string;
  /**
   * The private key in PEM, unencrypted: PKCS#8 (`BEGIN PRIVATE KEY`), as a
   * provider hands one out, or a traditional EC or RSA key. A JavaScript
   * string cannot be zeroed; the factory zeroes every buffer it makes of it.
   */
  readonly privateKeyPem: string;
  /** An outer transaction to import the key in. */
  readonly tx?: Tx;
}

/** The longest `kid` an imported key may have: `realm_keys.kid` holds 255. */
export const MAX_IMPORTED_KEY_ID_LENGTH = 255;

/** The longest PEM text an import reads: far more than an RSA-4096 key. */
export const MAX_IMPORTED_KEY_PEM_LENGTH = 16 * 1024;

/** Printable ASCII but space: a `kid` that reads the same in a header, a log line and a URL. */
const IMPORTED_KEY_ID_PATTERN = /^[\x21-\x7e]+$/;

/** Options of {@link KeyFactory.provisionRealmKeys}. */
export interface ProvisionRealmKeysOptions<Tx> {
  /** An outer transaction to create the keys in, such as the one that creates the realm. */
  readonly tx?: Tx;
}

/** A key the factory stored. It carries no private material. */
export interface CreatedKey {
  readonly realmId: string;
  readonly purpose: KeyPurpose;
  readonly scopeId: string | null;
  readonly algorithm: KeyAlgorithm;
  readonly kid: string;
  readonly status: NewKeyStatus;
  readonly pairId: string | null;
  readonly publishAt: number | null;
  readonly activateAt: number | null;
  readonly createdAt: number;
  /** The public JWK stored in `realm_public_keys`, for a published purpose. */
  readonly publicJwk?: JWK;
  /**
   * The new key's secret, for a purpose that shows it once
   * (`secretShownOnce`): a webhook secret in the Standard Webhooks form,
   * `whsec_` and base64. This result is the only place it ever appears;
   * nothing the factory or the signer returns later carries it.
   */
  readonly secret?: string;
}

/** Which scoped key {@link KeyFactory.activateNextKey} and {@link KeyFactory.deleteScopedKeys} act on. */
export interface ScopedKeyInput<Tx> {
  readonly realmId: string;
  /** A scoped purpose: `webhook_signing`, `upstream_client_assertion` or `agent_upstream_identity`. */
  readonly purpose: KeyPurpose;
  /** The subscription, provider or app identity the keys belong to. */
  readonly scopeId: string;
  /** An outer transaction to run in, such as the one that deletes the owner. */
  readonly tx?: Tx;
}

/** Input of {@link KeyFactory.activateNextKey}. */
export interface ActivateNextKeyInput<Tx> extends ScopedKeyInput<Tx> {
  /** The algorithm of the keys to rotate. Defaults to the purpose's default algorithm. */
  readonly algorithm?: KeyAlgorithm;
}

/** What {@link KeyFactory.activateNextKey} changed. */
export interface ActivatedKey {
  /** The key that signs from now on. */
  readonly activatedKid: string;
  /** The key that stopped signing, or `null` when the scope had no active key. */
  readonly retiredKid: string | null;
  /** Epoch ms. When the switch happened. */
  readonly activateAt: number;
  /** Epoch ms. When the retired key leaves its JWKS; `null` for an unpublished purpose. */
  readonly unpublishAt: number | null;
}

/** Creates realm keys. See {@link createKeyFactory}. */
export interface KeyFactory<Tx> {
  /**
   * Generate, seal and store one key, in one transaction. With hybrid signing
   * on, an EdDSA `token_signing` key comes with its ML-DSA-65 companion, and
   * both are stored together.
   *
   * @returns the stored keys: the requested key first, then its hybrid
   *   companion if there is one.
   * @throws KeyCreationRefusedError when the realm id, purpose, algorithm or
   *   scope is not one this deployment creates. Nothing is generated or stored.
   * @throws KeyIdConflictError when the realm already holds a key with the new
   *   `kid`. Nothing is stored.
   * @throws ActiveKeyConflictError when a new `active` key would be the second
   *   active key of its realm, purpose, scope and algorithm. Create it as
   *   `next` instead. Nothing is stored.
   *
   * A writer that commits between the checks and the insert can still make the
   * store raise its unique-constraint error; nothing is stored then either.
   */
  createKey(input: CreateKeyInput<Tx>): Promise<readonly CreatedKey[]>;
  /**
   * Seal and store a private key a party outside the deployment issued, in
   * one transaction: for an importable purpose only (`importable`), such as
   * the client-assertion key a provider issues for QAuth's client there
   * (#1073). The key keeps the `kid` its issuer gave it, and is published
   * like a generated key of its purpose.
   *
   * It becomes the scope's `active` key when the scope holds no active key of
   * its algorithm, and its `next` key otherwise: the active key keeps
   * signing until {@link activateNextKey} switches to it, so importing the
   * replacement of a key changes nothing yet.
   *
   * Nothing the factory returns, throws or logs carries the private key. Each
   * buffer made of it is zeroed before the call returns.
   *
   * @returns the stored key, with its public JWK; never material
   * @throws KeyCreationRefusedError as {@link createKey} does, and with
   *   `NOT_IMPORTABLE`, `INVALID_KEY_ID`, `INVALID_KEY` (no unencrypted
   *   private key in PEM), `KEY_ALGORITHM_MISMATCH` (a key of another
   *   algorithm, an EC key on another curve, an RSA key shorter than
   *   {@link MIN_RSA_MODULUS_BITS} bits) and `DEVELOPMENT_KEK`, before
   *   anything is stored
   * @throws KeyIdConflictError when the realm already holds a key with the `kid`
   * @throws NextKeyConflictError when the scope already holds a `next` key of
   *   the algorithm: switch to it first
   */
  importKey(input: ImportKeyInput<Tx>): Promise<CreatedKey>;
  /**
   * Create the standard keys of a realm in one transaction: `token_signing`
   * (with its ML-DSA-65 companion when hybrid signing is on),
   * `event_signing`, `cookie_hmac` and `data_at_rest`, each with its
   * purpose's default algorithm.
   *
   * A purpose that already holds an active unscoped key of its default
   * algorithm is left as it is (for `token_signing` with hybrid signing on:
   * both keys of the pair), so the call can be repeated: it fills the
   * standard keys a realm lacks, as the boot step for the default realm needs
   * (#485). If one key cannot be stored, none is.
   *
   * Two calls for one realm must not run at once. Both would see the same
   * missing keys, and the second would fail on the one-active-key index and
   * roll back. A caller that may run on several nodes, such as the boot step,
   * serializes them, for example with an advisory lock (#485).
   *
   * @returns the keys it created; empty when the realm lacked none.
   * @throws KeyCreationRefusedError (`INVALID_REALM_ID`) when the realm id is
   *   not a UUID, before the store is read.
   * @throws KeyCreationRefusedError (`HYBRID_PAIR_INCOMPLETE`) when hybrid
   *   signing is on and the realm holds only one active key of the
   *   `token_signing` pair. Creating the other half alone would leave two keys
   *   that do not rotate together; a rotation to a new pair fixes it (#542).
   */
  provisionRealmKeys(
    realmId: string,
    options?: ProvisionRealmKeysOptions<Tx>
  ): Promise<readonly CreatedKey[]>;
  /**
   * Finish the rotation of a scoped key, in one transaction: the scope's
   * `next` key becomes `active`, and its `active` key, if any, becomes
   * `retired`. A rotation starts with `createKey({ ..., status: 'next' })`,
   * which publishes the new key at once, or hands out the new webhook secret,
   * which then signs beside the old one.
   *
   * The overlap rules are those of the automatic rotation (ADR-019, #542):
   * the `next` key must have been published, or handed out, for
   * `prepublishMs` first, and a retired published key stays in its JWKS for
   * `retiredRetentionMs` after the switch. A retired webhook secret signs
   * nothing more.
   *
   * @throws KeyChangeRefusedError (`OVERLAP_NOT_ELAPSED`, with `notBefore`)
   *   before the window has run; (`NO_NEXT_KEY`) when there is nothing to
   *   activate; (`KEY_CHANGED`) when another writer moved a key meanwhile;
   *   (`UNSCOPED_PURPOSE`) for a purpose the rotation job of #542 rotates;
   *   and for a malformed realm id, scope id or algorithm. Nothing changes.
   */
  activateNextKey(input: ActivateNextKeyInput<Tx>): Promise<ActivatedKey>;
  /**
   * Delete every key of one scope, whatever its status, with its public rows:
   * the hook a subscription's or a provider's deletion calls, in the same
   * transaction (`tx`). Signers that hold one of the keys in memory drop it at
   * their next key-list read.
   *
   * @returns the `kid`s it deleted; empty when the scope held none.
   * @throws KeyChangeRefusedError for an unscoped purpose, or a malformed
   *   realm id or scope id, before the store is touched.
   */
  deleteScopedKeys(input: ScopedKeyInput<Tx>): Promise<readonly string[]>;
}

/**
 * The key factory, with the one call a manual rotation (#544) makes. Not
 * exported from the package: `createKeyFactory` returns the factory without
 * it, so no other caller can mark a `next` key as approved to switch early.
 */
export interface RotationKeyFactory<Tx> extends KeyFactory<Tx> {
  /**
   * Create a `next` key, or hybrid pair, as {@link KeyFactory.createKey} does,
   * that a manual rotation plans to switch to at `activatesAt` (epoch ms),
   * written as its `activateAt`. The scheduled rotation switches to such a
   * key once its pre-publication window has run, and to any other `next` key
   * once the active key's period has run as well.
   *
   * @throws TypeError when `activatesAt` is not a whole, non-negative number
   */
  createPlannedNextKey(
    input: Omit<CreateKeyInput<Tx>, 'status'>,
    activatesAt: number
  ): Promise<readonly CreatedKey[]>;
}

/** A validated request: what to generate for one `createKey`. */
interface KeyRequest {
  readonly realmId: string;
  readonly purpose: KeyPurpose;
  readonly definition: KeyPurposeDefinition;
  readonly scopeId: string | null;
  /** The requested algorithm first, then the hybrid companion. */
  readonly algorithms: readonly KeyAlgorithm[];
  readonly status: NewKeyStatus;
}

/** A generated and sealed key, ready to store. */
interface PreparedKey {
  readonly stored: NewStoredKey;
  readonly created: CreatedKey;
}

/**
 * Create the key factory of a deployment.
 *
 * @throws InvalidConfigurationError when hybrid signing is on and
 *   `SIGNING_ALGORITHM_MODE` does not enable ML-DSA-65. The config schema
 *   refuses that too; this keeps the factory closed on its own.
 */
export function createKeyFactory<Tx>(options: KeyFactoryOptions<Tx>): KeyFactory<Tx> {
  return keyFactoryParts(options).factory;
}

/**
 * The key factory of a deployment, with the call of a manual rotation (#544).
 * The rotation's own; see {@link RotationKeyFactory}.
 *
 * @throws InvalidConfigurationError as {@link createKeyFactory} does
 */
export function createRotationKeyFactory<Tx>(
  options: KeyFactoryOptions<Tx>
): RotationKeyFactory<Tx> {
  const { factory, createPlannedNextKey } = keyFactoryParts(options);
  return Object.freeze({ ...factory, createPlannedNextKey });
}

function keyFactoryParts<Tx>(options: KeyFactoryOptions<Tx>): {
  readonly factory: KeyFactory<Tx>;
  readonly createPlannedNextKey: RotationKeyFactory<Tx>['createPlannedNextKey'];
} {
  const { store, kekProvider, enabledSignatureAlgorithms } = options;
  // Strict comparisons, so a string from an untyped configuration path such
  // as 'false' leaves both switches off.
  const hybridSigning = options.hybridSigning === true;
  const federationOperator = options.federationOperator === true;
  const now = options.now ?? Date.now;
  const prepublishMs = options.prepublishMs ?? DEFAULT_KEY_PREPUBLISH_DAYS * DAY_MS;
  const retiredRetentionMs =
    options.retiredRetentionMs ?? DEFAULT_KEY_RETIRED_RETENTION_DAYS * DAY_MS;
  for (const [name, value] of [
    ['prepublish window', prepublishMs],
    ['retired-key retention', retiredRetentionMs],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new InvalidConfigurationError(`The key ${name} is a non-negative whole number of ms`);
    }
  }

  if (hybridSigning && !enabledSignatureAlgorithms.includes('ML-DSA-65')) {
    throw new InvalidConfigurationError(
      "HYBRID_SIGNING_ENABLED=true requires SIGNING_ALGORITHM_MODE='ed25519+ml-dsa-65'."
    );
  }

  function resolveRequest(input: Omit<CreateKeyInput<Tx>, 'tx'>): KeyRequest {
    const realmId = resolveRealmId(input.realmId);
    const { purpose } = input;
    if (typeof purpose !== 'string' || !isKeyPurpose(purpose)) {
      throw new KeyCreationRefusedError('UNKNOWN_PURPOSE', `Unknown key purpose '${purpose}'`);
    }
    const definition: KeyPurposeDefinition = KEY_PURPOSES[purpose];

    if (definition.federationOperatorOnly === true && !federationOperator) {
      throw new KeyCreationRefusedError(
        'FEDERATION_OPERATOR_ONLY',
        `Key purpose '${purpose}' is created only by a federation-operator deployment`
      );
    }

    const scopeId = resolveScopeId(purpose, definition, input.scopeId);

    const algorithm = input.algorithm ?? definition.defaultAlgorithm;
    if (!definition.algorithms.includes(algorithm)) {
      throw new KeyCreationRefusedError(
        'ALGORITHM_NOT_ALLOWED',
        `Key purpose '${purpose}' does not allow algorithm '${algorithm}' ` +
          `(allowed: ${definition.algorithms.join(', ')})`
      );
    }
    assertAllowedBySigningMode(algorithm, enabledSignatureAlgorithms);
    if (algorithm === definition.hybridCompanion) {
      throw new KeyCreationRefusedError(
        'HYBRID_COMPANION_ONLY',
        `A '${algorithm}' key of purpose '${purpose}' is created only with its ` +
          `'${definition.defaultAlgorithm}' key, as a hybrid pair`
      );
    }

    const algorithms: KeyAlgorithm[] = [algorithm];
    if (
      hybridSigning &&
      definition.hybridCompanion !== undefined &&
      algorithm === definition.defaultAlgorithm
    ) {
      assertAllowedBySigningMode(definition.hybridCompanion, enabledSignatureAlgorithms);
      algorithms.push(definition.hybridCompanion);
    }

    const status = input.status ?? 'active';
    if (status !== 'active' && status !== 'next') {
      throw new TypeError(`A new key is 'active' or 'next', not '${String(status)}'`);
    }

    return { realmId, purpose, definition, scopeId, algorithms, status };
  }

  /**
   * Generate and seal every key of a request. Plaintext material is zeroed
   * here. A `next` key carries `plannedActivateAt` as its `activateAt`: `null`
   * but for the key of a manual rotation.
   */
  async function prepareKeys(
    request: KeyRequest,
    plannedActivateAt: number | null = null
  ): Promise<PreparedKey[]> {
    const { realmId, purpose, definition, scopeId, status } = request;
    const pairId = request.algorithms.length > 1 ? randomUUID() : null;
    const at = now();
    const publishAt = definition.published ? at : null;
    const activateAt = status === 'active' ? at : plannedActivateAt;

    const prepared: PreparedKey[] = [];
    for (const algorithm of request.algorithms) {
      const generated = await generateKeyMaterial(algorithm, { enabledSignatureAlgorithms });
      try {
        const { kid } = generated;
        const sealed = await sealKeyMaterial(kekProvider, generated.material, {
          realmId,
          purpose,
          scopeId,
          kid,
          algorithm,
        });
        const row = {
          realmId,
          purpose,
          scopeId,
          algorithm,
          kid,
          status,
          pairId,
          ciphertext: sealed.ciphertext,
          iv: sealed.iv,
          wrappedDek: sealed.wrappedDek,
          kekRef: sealed.kekRef,
          aadVersion: sealed.aadVersion,
          activateAt,
          createdAt: at,
        };
        const base = {
          realmId,
          purpose,
          scopeId,
          algorithm,
          kid,
          status,
          pairId,
          activateAt,
          createdAt: at,
          // Formatted before the material is zeroed below. A string cannot be
          // zeroed; it lives as long as the caller keeps this result.
          ...(definition.secretShownOnce === true
            ? { secret: formatWebhookSecret(generated.material) }
            : {}),
        };

        if (definition.published) {
          if (generated.publicJwk === undefined || publishAt === null) {
            throw new Error(`Key purpose '${purpose}' is published but '${algorithm}' has no JWK`);
          }
          const publicJwk = generated.publicJwk;
          prepared.push({
            stored: { key: { ...row, publishAt }, publicJwk: { ...publicJwk } },
            created: Object.freeze({ ...base, publishAt, publicJwk }),
          });
        } else {
          prepared.push({
            stored: { key: { ...row, publishAt: null } },
            created: Object.freeze({ ...base, publishAt: null }),
          });
        }
      } finally {
        generated.material.fill(0);
      }
    }
    return prepared;
  }

  /**
   * Check every new key against the realm, then store the keys, inside `tx`:
   * its `kid` must be new, and an `active` key must be the only active key of
   * its realm, purpose, scope and algorithm.
   */
  async function writeKeys(prepared: readonly PreparedKey[], tx: Tx): Promise<CreatedKey[]> {
    const seen = new Set<string>();
    for (const { created } of prepared) {
      if (seen.has(created.kid)) throw new KeyIdConflictError(created.kid);
      seen.add(created.kid);
      if ((await store.findByKid(created.realmId, created.kid, tx)) !== undefined) {
        throw new KeyIdConflictError(created.kid);
      }
      // One key of each status signs or waits per realm, purpose, scope and
      // algorithm. The active rule has the one-active index behind it; the
      // next rule is this check alone.
      const sameStatus = await store.listByRealm(
        created.realmId,
        { purpose: created.purpose, scopeId: created.scopeId, status: created.status },
        tx
      );
      if (sameStatus.some((key) => key.algorithm === created.algorithm)) {
        throw created.status === 'active'
          ? new ActiveKeyConflictError(created.purpose, created.algorithm)
          : new NextKeyConflictError(created.purpose, created.algorithm);
      }
    }
    for (const { stored } of prepared) {
      await store.create(stored, tx);
    }
    return prepared.map(({ created }) => created);
  }

  async function createPlannedNextKey(
    input: Omit<CreateKeyInput<Tx>, 'status'>,
    activatesAt: number
  ): Promise<readonly CreatedKey[]> {
    if (!Number.isSafeInteger(activatesAt) || activatesAt < 0) {
      throw new TypeError('A planned activation is a whole, non-negative number of epoch ms');
    }
    const prepared = await prepareKeys(resolveRequest({ ...input, status: 'next' }), activatesAt);
    return store.transaction((tx) => writeKeys(prepared, tx), input.tx);
  }

  const factory: KeyFactory<Tx> = Object.freeze({
    async createKey(input: CreateKeyInput<Tx>): Promise<readonly CreatedKey[]> {
      // Generation and sealing (a KMS call for an adapter) happen before the
      // transaction opens, so it stays short.
      const prepared = await prepareKeys(resolveRequest(input));
      return store.transaction((tx) => writeKeys(prepared, tx), input.tx);
    },

    async importKey(input: ImportKeyInput<Tx>): Promise<CreatedKey> {
      const request = resolveRequest({
        realmId: input.realmId,
        purpose: input.purpose,
        scopeId: input.scopeId ?? null,
        algorithm: input.algorithm,
      });
      const { realmId, purpose, definition, scopeId } = request;
      if (definition.importable !== true || definition.kind !== 'signing') {
        throw new KeyCreationRefusedError(
          'NOT_IMPORTABLE',
          `Key purpose '${purpose}' takes no imported key`
        );
      }
      const algorithm = request.algorithms[0];
      const { kid } = input;
      if (
        typeof kid !== 'string' ||
        kid.length > MAX_IMPORTED_KEY_ID_LENGTH ||
        !IMPORTED_KEY_ID_PATTERN.test(kid)
      ) {
        throw new KeyCreationRefusedError(
          'INVALID_KEY_ID',
          `An imported key's kid is printable ASCII but space, at most ${MAX_IMPORTED_KEY_ID_LENGTH} characters`
        );
      }
      if (await usesDevelopmentKek(kekProvider)) {
        throw new KeyCreationRefusedError(
          'DEVELOPMENT_KEK',
          'A key from outside the deployment is never wrapped with the published development KEK: set KEK or KEK_PATH (KEK_PROVIDER=local), or another KEK provider, first'
        );
      }

      const { material, publicJwk } = importedKeyMaterial(algorithm, kid, input.privateKeyPem);
      try {
        const sealed = await sealKeyMaterial(kekProvider, material, {
          realmId,
          purpose,
          scopeId,
          kid,
          algorithm,
        });
        return await store.transaction(async (tx) => {
          // The scope's active key keeps signing: the import waits as `next`.
          const active = await store.listByRealm(
            realmId,
            { purpose, scopeId, status: 'active' },
            tx
          );
          const status: NewKeyStatus = active.some((key) => key.algorithm === algorithm)
            ? 'next'
            : 'active';
          const at = now();
          const activateAt = status === 'active' ? at : null;
          const base = {
            realmId,
            purpose,
            scopeId,
            algorithm,
            kid,
            status,
            pairId: null,
            activateAt,
            createdAt: at,
          };
          const row = {
            ...base,
            ciphertext: sealed.ciphertext,
            iv: sealed.iv,
            wrappedDek: sealed.wrappedDek,
            kekRef: sealed.kekRef,
            aadVersion: sealed.aadVersion,
          };
          const prepared: PreparedKey = definition.published
            ? {
                stored: { key: { ...row, publishAt: at }, publicJwk: { ...publicJwk } },
                created: Object.freeze({ ...base, publishAt: at, publicJwk }),
              }
            : {
                stored: { key: { ...row, publishAt: null } },
                created: Object.freeze({ ...base, publishAt: null }),
              };
          const [created] = await writeKeys([prepared], tx);
          return created;
        }, input.tx);
      } finally {
        material.fill(0);
      }
    },

    async provisionRealmKeys(
      requestedRealmId: string,
      provisionOptions: ProvisionRealmKeysOptions<Tx> = {}
    ): Promise<readonly CreatedKey[]> {
      // Checked before the store sees it, as createKey does.
      const realmId = resolveRealmId(requestedRealmId);
      return store.transaction(async (tx) => {
        const created: CreatedKey[] = [];
        for (const purpose of STANDARD_REALM_KEY_PURPOSES) {
          const definition: KeyPurposeDefinition = KEY_PURPOSES[purpose];
          const wanted =
            hybridSigning && definition.hybridCompanion !== undefined
              ? [definition.defaultAlgorithm, definition.hybridCompanion]
              : [definition.defaultAlgorithm];
          const active = await store.listByRealm(
            realmId,
            { purpose, scopeId: null, status: 'active' },
            tx
          );
          const present = wanted.filter((algorithm) =>
            active.some((key) => key.algorithm === algorithm)
          );
          if (present.length === wanted.length) continue;
          if (present.length > 0) {
            throw new KeyCreationRefusedError(
              'HYBRID_PAIR_INCOMPLETE',
              `The realm's active '${purpose}' keys are not a complete hybrid pair ` +
                `(active: ${present.join(', ')}; a pair is ${wanted.join(' and ')}). ` +
                'Rotate them to a new pair.'
            );
          }

          const prepared = await prepareKeys(resolveRequest({ realmId, purpose }));
          created.push(...(await writeKeys(prepared, tx)));
        }
        return created;
      }, provisionOptions.tx);
    },

    async activateNextKey(input: ActivateNextKeyInput<Tx>): Promise<ActivatedKey> {
      const { realmId, purpose, definition, scopeId } = resolveScopedKey(input);
      const algorithm = input.algorithm ?? definition.defaultAlgorithm;
      if (!definition.algorithms.includes(algorithm)) {
        throw new KeyChangeRefusedError(
          'ALGORITHM_NOT_ALLOWED',
          `Key purpose '${purpose}' does not allow algorithm '${String(algorithm)}'`
        );
      }

      return store.transaction(async (tx) => {
        const keys = (await store.listByRealm(realmId, { purpose, scopeId }, tx)).filter(
          (key) => key.algorithm === algorithm
        );
        const next = keys.filter((key) => key.status === 'next');
        const active = keys.filter((key) => key.status === 'active');
        if (next.length !== 1) {
          throw new KeyChangeRefusedError(
            'NO_NEXT_KEY',
            `The scope holds no next '${algorithm}' key for purpose '${purpose}'`
          );
        }
        const at = now();
        const notBefore = shownAt(next[0]) + prepublishMs;
        if (at < notBefore) {
          throw new KeyChangeRefusedError(
            'OVERLAP_NOT_ELAPSED',
            `The next '${algorithm}' key for purpose '${purpose}' may replace the active key ` +
              `from ${new Date(notBefore).toISOString()}`,
            notBefore
          );
        }

        const unpublishAt = definition.published ? at + retiredRetentionMs : null;
        // Retire first: the one-active index allows no moment with two.
        for (const old of active) {
          const retired = await store.updateStatus(
            realmId,
            old.kid,
            { status: 'retired', retireAt: at, unpublishAt },
            tx
          );
          if (retired === undefined) throw keyChanged(purpose);
        }
        const activated = await store.updateStatus(
          realmId,
          next[0].kid,
          { status: 'active', activateAt: at },
          tx
        );
        if (activated === undefined) throw keyChanged(purpose);

        return Object.freeze({
          activatedKid: next[0].kid,
          retiredKid: active[0]?.kid ?? null,
          activateAt: at,
          unpublishAt: active.length > 0 ? unpublishAt : null,
        });
      }, input.tx);
    },

    async deleteScopedKeys(input: ScopedKeyInput<Tx>): Promise<readonly string[]> {
      const { realmId, purpose, scopeId } = resolveScopedKey(input);
      return Object.freeze([
        ...(await store.transaction(
          (tx) => store.deleteByScope(realmId, purpose, scopeId, tx),
          input.tx
        )),
      ]);
    },
  });
  return { factory, createPlannedNextKey };
}

/** The key type each importable algorithm needs, as Node names it, with a label for refusals. */
const IMPORTED_KEY_TYPES: Readonly<
  Partial<
    Record<
      KeyAlgorithm,
      { readonly keyType: string; readonly curve?: string; readonly label: string }
    >
  >
> = Object.freeze({
  ES256: { keyType: 'ec', curve: 'prime256v1', label: 'an EC private key on P-256' },
  RS256: { keyType: 'rsa', label: `an RSA private key of at least ${MIN_RSA_MODULUS_BITS} bits` },
  EdDSA: { keyType: 'ed25519', label: 'an Ed25519 private key' },
});

/**
 * The PKCS#8 DER material and the public JWK of an imported private key,
 * checked against `algorithm`. The refusals never quote the text.
 */
function importedKeyMaterial(
  algorithm: KeyAlgorithm,
  kid: string,
  privateKeyPem: unknown
): { readonly material: Buffer; readonly publicJwk: JWK } {
  const wanted = IMPORTED_KEY_TYPES[algorithm];
  if (wanted === undefined) {
    throw new KeyCreationRefusedError('NOT_IMPORTABLE', `A '${algorithm}' key is never imported`);
  }
  if (
    typeof privateKeyPem !== 'string' ||
    privateKeyPem.length === 0 ||
    privateKeyPem.length > MAX_IMPORTED_KEY_PEM_LENGTH
  ) {
    throw invalidKey();
  }
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({ key: privateKeyPem, format: 'pem' });
  } catch {
    // An encrypted key (no passphrase is taken), a public key, a certificate
    // or text that is no PEM at all. The parser's message may quote the text.
    throw invalidKey();
  }
  const details = privateKey.asymmetricKeyDetails;
  if (
    privateKey.asymmetricKeyType !== wanted.keyType ||
    (wanted.curve !== undefined && details?.namedCurve !== wanted.curve) ||
    (wanted.keyType === 'rsa' && (details?.modulusLength ?? 0) < MIN_RSA_MODULUS_BITS)
  ) {
    throw new KeyCreationRefusedError(
      'KEY_ALGORITHM_MISMATCH',
      `The key is not ${wanted.label}, which ${algorithm} needs`
    );
  }
  const exported = createPublicKey(privateKey).export({ format: 'jwk' }) as JWK;
  const material = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' }));
  return {
    material,
    publicJwk: Object.freeze({ ...exported, kid, alg: algorithm, use: 'sig' }),
  };
}

function invalidKey(): KeyCreationRefusedError {
  return new KeyCreationRefusedError(
    'INVALID_KEY',
    'The key is no unencrypted private key in PEM, such as PKCS#8 (BEGIN PRIVATE KEY)'
  );
}

/** When a `next` key reached its outside party: its publication, or its creation when unpublished. */
function shownAt(key: StoredKeySummary): number {
  return key.publishAt ?? key.createdAt;
}

function keyChanged(purpose: KeyPurpose): KeyChangeRefusedError {
  return new KeyChangeRefusedError(
    'KEY_CHANGED',
    `A '${purpose}' key changed status during the rotation; nothing was changed`
  );
}

/**
 * The realm, scoped purpose and scope id that `activateNextKey` and
 * `deleteScopedKeys` act on, checked as `createKey` checks them.
 */
function resolveScopedKey(input: ScopedKeyInput<unknown>): {
  readonly realmId: string;
  readonly purpose: KeyPurpose;
  readonly definition: KeyPurposeDefinition;
  readonly scopeId: string;
} {
  if (!isRealmId(input.realmId)) {
    throw new KeyChangeRefusedError('INVALID_REALM_ID', 'A realm id is a UUID');
  }
  const { purpose } = input;
  if (typeof purpose !== 'string' || !isKeyPurpose(purpose)) {
    throw new KeyChangeRefusedError('UNKNOWN_PURPOSE', 'An unknown key purpose');
  }
  const definition: KeyPurposeDefinition = KEY_PURPOSES[purpose];
  if (!definition.scoped) {
    throw new KeyChangeRefusedError(
      'UNSCOPED_PURPOSE',
      `Key purpose '${purpose}' is not scoped; only scoped keys rotate and are deleted by scope here`
    );
  }
  if (!isScopeId(input.scopeId)) {
    throw new KeyChangeRefusedError(
      'INVALID_SCOPE_ID',
      `A scope id is a non-empty, well-formed string of at most ${MAX_SCOPE_ID_LENGTH} characters`
    );
  }
  return { realmId: input.realmId.toLowerCase(), purpose, definition, scopeId: input.scopeId };
}

/**
 * The stored realm id: a UUID in lowercase, the form Postgres returns for
 * `realm_keys.realm_id`. The realm id is part of the associated data that
 * seals a key, so a key sealed under another casing would not open from its
 * stored row.
 */
function resolveRealmId(realmId: unknown): string {
  if (!isRealmId(realmId)) {
    throw new KeyCreationRefusedError('INVALID_REALM_ID', 'A realm id is a UUID');
  }
  return realmId.toLowerCase();
}

/**
 * The stored scope id: a non-empty, well-formed string of at most
 * {@link MAX_SCOPE_ID_LENGTH} characters for a scoped purpose, `null` for an
 * unscoped one. A lone surrogate and a NUL are refused here, before a key is
 * generated: the associated-data encoder refuses the first, and Postgres text
 * the second.
 */
function resolveScopeId(
  purpose: KeyPurpose,
  definition: KeyPurposeDefinition,
  scopeId: string | null | undefined
): string | null {
  if (!definition.scoped) {
    if (scopeId !== undefined && scopeId !== null) {
      throw new KeyCreationRefusedError(
        'SCOPE_NOT_ALLOWED',
        `Key purpose '${purpose}' is not scoped and takes no scope id`
      );
    }
    return null;
  }
  if (scopeId === undefined || scopeId === null) {
    throw new KeyCreationRefusedError(
      'SCOPE_REQUIRED',
      `Key purpose '${purpose}' is scoped and needs a scope id`
    );
  }
  if (!isScopeId(scopeId)) {
    throw new KeyCreationRefusedError(
      'INVALID_SCOPE_ID',
      `A scope id is a non-empty, well-formed string of at most ${MAX_SCOPE_ID_LENGTH} characters`
    );
  }
  return scopeId;
}
