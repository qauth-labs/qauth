import { randomUUID } from 'node:crypto';

import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import type { JWK } from 'jose';

import { sealKeyMaterial } from './envelope';
import type { KekProvider } from './kek-provider';
import { KeyCreationRefusedError, KeyIdConflictError } from './key-creation-errors';
import { assertAllowedBySigningMode, generateKeyMaterial } from './key-generation';
import {
  isKeyPurpose,
  KEY_PURPOSES,
  type KeyAlgorithm,
  type KeyPurpose,
  type KeyPurposeDefinition,
  STANDARD_REALM_KEY_PURPOSES,
} from './key-purposes';
import type { NewKeyStatus, NewStoredKey, RealmKeyStore } from './key-store';

/**
 * Creating a realm's keys (ADR-019 Decision 9, issue #463): generate, seal
 * under the KEK, and store, with the purpose rules of `KEY_PURPOSES` and the
 * deployment's algorithm switches applied first.
 */

/** The longest `scope_id` that `realm_keys` holds. */
export const MAX_SCOPE_ID_LENGTH = 255;

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
  /** The clock, in epoch ms. Defaults to `Date.now`. */
  readonly now?: () => number;
}

/** Input of {@link KeyFactory.createKey}. */
export interface CreateKeyInput<Tx> {
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
  /** The public JWK stored in `realm_public_keys`, for a published purpose. */
  readonly publicJwk?: JWK;
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
   * @throws KeyCreationRefusedError when the purpose, algorithm or scope is
   *   not one this deployment creates. Nothing is generated or stored.
   * @throws KeyIdConflictError when the realm already holds a key with the new
   *   `kid`. Nothing is stored.
   */
  createKey(input: CreateKeyInput<Tx>): Promise<readonly CreatedKey[]>;
  /**
   * Create the standard keys of a realm in one transaction: `token_signing`
   * (with its ML-DSA-65 companion when hybrid signing is on),
   * `event_signing`, `cookie_hmac` and `data_at_rest`, each with its
   * purpose's default algorithm.
   *
   * A purpose that already holds an active unscoped key of its default
   * algorithm is left as it is, so the call is safe to repeat: it fills the
   * standard keys a realm lacks, as the boot step for the default realm needs
   * (#485). If one key cannot be stored, none is.
   *
   * @returns the keys it created; empty when the realm lacked none.
   */
  provisionRealmKeys(
    realmId: string,
    options?: ProvisionRealmKeysOptions<Tx>
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
  const { store, kekProvider, enabledSignatureAlgorithms, hybridSigning } = options;
  const federationOperator = options.federationOperator ?? false;
  const now = options.now ?? Date.now;

  if (hybridSigning && !enabledSignatureAlgorithms.includes('ML-DSA-65')) {
    throw new InvalidConfigurationError(
      "HYBRID_SIGNING_ENABLED=true requires SIGNING_ALGORITHM_MODE='ed25519+ml-dsa-65'."
    );
  }

  function resolveRequest(input: Omit<CreateKeyInput<Tx>, 'tx'>): KeyRequest {
    const { realmId, purpose } = input;
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

  /** Generate and seal every key of a request. Plaintext material is zeroed here. */
  async function prepareKeys(request: KeyRequest): Promise<PreparedKey[]> {
    const { realmId, purpose, definition, scopeId, status } = request;
    const pairId = request.algorithms.length > 1 ? randomUUID() : null;
    const at = now();
    const publishAt = definition.published ? at : null;
    const activateAt = status === 'active' ? at : null;

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
        };
        const base = { realmId, purpose, scopeId, algorithm, kid, status, pairId, activateAt };

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

  /** Check every new `kid` against the realm, then store the keys, inside `tx`. */
  async function writeKeys(prepared: readonly PreparedKey[], tx: Tx): Promise<CreatedKey[]> {
    const seen = new Set<string>();
    for (const { created } of prepared) {
      if (seen.has(created.kid)) throw new KeyIdConflictError(created.kid);
      seen.add(created.kid);
      if ((await store.findByKid(created.realmId, created.kid, tx)) !== undefined) {
        throw new KeyIdConflictError(created.kid);
      }
    }
    for (const { stored } of prepared) {
      await store.create(stored, tx);
    }
    return prepared.map(({ created }) => created);
  }

  return Object.freeze({
    async createKey(input: CreateKeyInput<Tx>): Promise<readonly CreatedKey[]> {
      // Generation and sealing (a KMS call for an adapter) happen before the
      // transaction opens, so it stays short.
      const prepared = await prepareKeys(resolveRequest(input));
      return store.transaction((tx) => writeKeys(prepared, tx), input.tx);
    },

    async provisionRealmKeys(
      realmId: string,
      provisionOptions: ProvisionRealmKeysOptions<Tx> = {}
    ): Promise<readonly CreatedKey[]> {
      return store.transaction(async (tx) => {
        const created: CreatedKey[] = [];
        for (const purpose of STANDARD_REALM_KEY_PURPOSES) {
          const { defaultAlgorithm } = KEY_PURPOSES[purpose];
          const active = await store.listByRealm(
            realmId,
            { purpose, scopeId: null, status: 'active' },
            tx
          );
          if (active.some((key) => key.algorithm === defaultAlgorithm)) continue;

          const prepared = await prepareKeys(resolveRequest({ realmId, purpose }));
          created.push(...(await writeKeys(prepared, tx)));
        }
        return created;
      }, provisionOptions.tx);
    },
  });
}

/**
 * The stored scope id: a non-empty, well-formed string of at most
 * {@link MAX_SCOPE_ID_LENGTH} characters for a scoped purpose, `null` for an
 * unscoped one. A lone surrogate is refused here, before a key is generated;
 * the associated-data encoder would refuse it later anyway.
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
  if (
    typeof scopeId !== 'string' ||
    scopeId.length === 0 ||
    scopeId.length > MAX_SCOPE_ID_LENGTH ||
    Buffer.from(scopeId, 'utf8').toString('utf8') !== scopeId
  ) {
    throw new KeyCreationRefusedError(
      'INVALID_SCOPE_ID',
      `A scope id is a non-empty, well-formed string of at most ${MAX_SCOPE_ID_LENGTH} characters`
    );
  }
  return scopeId;
}
