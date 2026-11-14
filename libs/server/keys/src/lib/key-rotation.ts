import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';

import type { KekProvider } from './kek-provider';
import { KeyChangeRefusedError } from './key-creation-errors';
import { createKeyFactory, type KeyFactory } from './key-factory';
import {
  KEY_PURPOSES,
  type KeyAlgorithm,
  type KeyPurpose,
  type KeyPurposeDefinition,
} from './key-purposes';
import {
  AUTOMATIC_ROTATION_PURPOSES,
  DEFAULT_KEY_ROTATION_SETTINGS,
  type KeyRotationSettings,
  type KeyRotationStep,
  planKeyRotation,
  type ResolvedKeyRotationSettings,
  resolveKeyRotationSettings,
  type RotatedKey,
} from './key-rotation-plan';
import type { RealmKeyStore, StoredKeySummary } from './key-store';
import { isRealmId } from './realm-id';

/**
 * The scheduled rotation job of #542: it runs the plan of
 * `key-rotation-plan.ts` for every rotating purpose of every realm, and writes
 * what it decides. Key custody: it creates keys, so only the signer's wiring
 * builds it.
 */

/** The store the rotation works through: the key factory's, plus a lock and the realms that hold keys. */
export interface KeyRotationStore<Tx> extends RealmKeyStore<Tx> {
  /**
   * Take the realm's key lock for the rest of `tx`: the transaction-level
   * advisory lock the key boot step takes too (`RealmKeyBootStore.lockRealm`).
   */
  lockRealm(realmId: string, tx: Tx): Promise<void>;
  /**
   * Up to `limit` ids of realms that hold at least one key, in ascending
   * order, after `afterRealmId` (from the first when `null`).
   */
  listRealmIds(afterRealmId: string | null, limit: number): Promise<readonly string[]>;
}

/** What a rotation is built from. */
export interface KeyRotationOptions<Tx> {
  readonly store: KeyRotationStore<Tx>;
  /** Wraps each new key's data key. */
  readonly kekProvider: KekProvider;
  /** `cryptoEnv.enabledSignatureAlgorithms`, as the key factory takes it. */
  readonly enabledSignatureAlgorithms: readonly SignatureAlgorithm[];
  /** `HYBRID_SIGNING_ENABLED`. */
  readonly hybridSigning: boolean;
  /** The windows. Defaults to {@link DEFAULT_KEY_ROTATION_SETTINGS}. */
  readonly settings?: KeyRotationSettings;
}

/** One run of the rotation. */
export interface KeyRotationRunOptions<Tx> {
  /** The clock, in epoch ms. Defaults to `Date.now`. */
  readonly now?: () => number;
  /** Stops the run between two purposes. */
  readonly signal?: AbortSignal;
  /**
   * The longest a token, cookie or ciphertext made with a key of `purpose` in
   * the realm may live, in ms: a retired key is kept at least that long after
   * the switch. `null` when one may live for ever; only an unpublished
   * purpose may answer `null`. Asked before the purpose's transaction opens.
   */
  readonly lifetimeOf: (realmId: string, purpose: KeyPurpose) => Promise<number | null>;
  /**
   * Called for each step inside its transaction, after the keys changed: the
   * place to write the audit row, in the same transaction. A throw rolls the
   * step back.
   */
  readonly onStep?: (step: KeyRotationStep, tx: Tx) => Promise<void>;
  /** How many realm ids {@link KeyRotation.rotateAll} reads at a time. Defaults to 100. */
  readonly pageSize?: number;
}

/** A purpose of a realm the run could not rotate. Its keys were left as they were. */
export interface KeyRotationFailure {
  readonly realmId: string;
  readonly purpose: KeyPurpose;
  readonly error: unknown;
}

/** What a run did. */
export interface KeyRotationReport {
  /** How many realms it looked at. */
  readonly realms: number;
  readonly steps: readonly KeyRotationStep[];
  readonly failures: readonly KeyRotationFailure[];
}

/** The scheduled rotation. See {@link createKeyRotation}. */
export interface KeyRotation<Tx> {
  /** The windows it runs with. */
  readonly settings: ResolvedKeyRotationSettings;
  /** Rotate every rotating purpose of one realm. */
  rotateRealm(realmId: string, run: KeyRotationRunOptions<Tx>): Promise<KeyRotationReport>;
  /** Rotate every rotating purpose of every realm that holds keys. */
  rotateAll(run: KeyRotationRunOptions<Tx>): Promise<KeyRotationReport>;
}

const DEFAULT_PAGE_SIZE = 100;

/**
 * Build the scheduled rotation of a deployment.
 *
 * Safe to run on many nodes at once and to repeat: each purpose of each realm
 * runs in its own transaction under the realm's key lock, and plans from the
 * keys it reads there. A purpose that fails (a refusal, a key another writer
 * moved, a failed audit write) is reported and rolled back; the run goes on
 * with the next.
 *
 * @throws InvalidConfigurationError for windows {@link resolveKeyRotationSettings} refuses
 */
export function createKeyRotation<Tx>(options: KeyRotationOptions<Tx>): KeyRotation<Tx> {
  const { store, kekProvider, enabledSignatureAlgorithms } = options;
  const hybridSigning = options.hybridSigning === true;
  const settings = resolveKeyRotationSettings(options.settings ?? DEFAULT_KEY_ROTATION_SETTINGS);

  async function rotatePurpose(
    realmId: string,
    purpose: KeyPurpose,
    run: KeyRotationRunOptions<Tx>,
    now: () => number,
    factory: KeyFactory<Tx>
  ): Promise<KeyRotationStep[]> {
    const definition: KeyPurposeDefinition = KEY_PURPOSES[purpose];
    const lifetimeMs = await run.lifetimeOf(realmId, purpose);
    if (lifetimeMs !== null && (!Number.isSafeInteger(lifetimeMs) || lifetimeMs < 0)) {
      throw new TypeError(
        `The lifetime of a '${purpose}' key is a non-negative whole number of ms`
      );
    }
    const leads = definition.algorithms.filter(
      (algorithm) => algorithm !== definition.hybridCompanion
    );

    return store.transaction(async (tx) => {
      await store.lockRealm(realmId, tx);
      const steps: KeyRotationStep[] = [];
      for (const algorithm of leads) {
        const keys = await store.listByRealm(realmId, { purpose, scopeId: null }, tx);
        const at = now();
        const plan = planKeyRotation({
          purpose,
          algorithm,
          keys,
          settings,
          hybridSigning,
          now: at,
        });
        if (plan.action === 'none') continue;
        if (plan.action === 'refuse') throw new KeyChangeRefusedError(plan.reason, plan.message);

        let step: KeyRotationStep;
        if (plan.action === 'create') {
          const created = await factory.createKey({
            realmId,
            purpose,
            algorithm,
            status: 'next',
            tx,
          });
          step = Object.freeze({
            kind: 'next_created',
            realmId,
            purpose,
            keys: Object.freeze(
              created.map((key) => Object.freeze({ kid: key.kid, algorithm: key.algorithm }))
            ),
            activatesAt: plan.activatesAt,
          });
        } else {
          if (lifetimeMs === null && definition.published) {
            throw new TypeError(
              `A retired '${purpose}' key is published, so its lifetime has an end`
            );
          }
          const switchAt = at + settings.activationDelayMs;
          const retainedUntil =
            lifetimeMs === null
              ? null
              : switchAt + Math.max(settings.retiredRetentionMs, lifetimeMs);
          // Retire first: the one-active index allows no moment with two.
          for (const key of plan.outgoing) {
            const moved = await store.updateStatus(
              realmId,
              key.kid,
              { status: 'retired', retireAt: switchAt, unpublishAt: retainedUntil },
              tx
            );
            if (moved === undefined) throw keyChanged(purpose);
          }
          for (const key of plan.incoming) {
            const moved = await store.updateStatus(
              realmId,
              key.kid,
              { status: 'active', activateAt: switchAt },
              tx
            );
            if (moved === undefined) throw keyChanged(purpose);
          }
          step = Object.freeze({
            kind: 'rotated',
            realmId,
            purpose,
            activated: Object.freeze(plan.incoming.map(rotatedKey)),
            retired: Object.freeze(plan.outgoing.map(rotatedKey)),
            switchAt,
            retainedUntil,
          });
        }
        if (run.onStep !== undefined) await run.onStep(step, tx);
        steps.push(step);
      }
      return steps;
    });
  }

  async function rotateRealmWith(
    realmId: string,
    run: KeyRotationRunOptions<Tx>,
    now: () => number,
    factory: KeyFactory<Tx>,
    steps: KeyRotationStep[],
    failures: KeyRotationFailure[]
  ): Promise<void> {
    for (const purpose of AUTOMATIC_ROTATION_PURPOSES) {
      run.signal?.throwIfAborted();
      try {
        steps.push(...(await rotatePurpose(realmId, purpose, run, now, factory)));
      } catch (error) {
        if (run.signal?.aborted === true) throw error;
        failures.push(Object.freeze({ realmId, purpose, error }));
      }
    }
  }

  function factoryFor(now: () => number): KeyFactory<Tx> {
    // Built per run so the new keys' times come from the run's clock.
    return createKeyFactory<Tx>({
      store,
      kekProvider,
      enabledSignatureAlgorithms,
      hybridSigning,
      prepublishMs: settings.prepublishMs,
      retiredRetentionMs: settings.retiredRetentionMs,
      now,
    });
  }

  function report(
    realms: number,
    steps: KeyRotationStep[],
    failures: KeyRotationFailure[]
  ): KeyRotationReport {
    return Object.freeze({
      realms,
      steps: Object.freeze(steps),
      failures: Object.freeze(failures),
    });
  }

  return Object.freeze({
    settings,

    async rotateRealm(realmId: string, run: KeyRotationRunOptions<Tx>): Promise<KeyRotationReport> {
      if (typeof realmId !== 'string' || !isRealmId(realmId)) {
        throw new KeyChangeRefusedError('INVALID_REALM_ID', 'A realm id is a UUID');
      }
      const now = run.now ?? Date.now;
      const steps: KeyRotationStep[] = [];
      const failures: KeyRotationFailure[] = [];
      await rotateRealmWith(realmId.toLowerCase(), run, now, factoryFor(now), steps, failures);
      return report(1, steps, failures);
    },

    async rotateAll(run: KeyRotationRunOptions<Tx>): Promise<KeyRotationReport> {
      const now = run.now ?? Date.now;
      const pageSize = run.pageSize ?? DEFAULT_PAGE_SIZE;
      if (!Number.isSafeInteger(pageSize) || pageSize < 1) {
        throw new TypeError('The realm page size is a positive whole number');
      }
      const factory = factoryFor(now);
      const steps: KeyRotationStep[] = [];
      const failures: KeyRotationFailure[] = [];
      let realms = 0;
      let after: string | null = null;
      for (;;) {
        run.signal?.throwIfAborted();
        const page = await store.listRealmIds(after, pageSize);
        for (const realmId of page) {
          await rotateRealmWith(realmId, run, now, factory, steps, failures);
          realms += 1;
        }
        if (page.length < pageSize) break;
        after = page[page.length - 1];
      }
      return report(realms, steps, failures);
    },
  });
}

function rotatedKey(key: StoredKeySummary): RotatedKey {
  return Object.freeze({ kid: key.kid, algorithm: key.algorithm as KeyAlgorithm });
}

function keyChanged(purpose: KeyPurpose): KeyChangeRefusedError {
  return new KeyChangeRefusedError(
    'KEY_CHANGED',
    `A '${purpose}' key changed status during the rotation; nothing was changed`
  );
}
