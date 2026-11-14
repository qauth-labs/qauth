import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';

import {
  type ApprovedOperation,
  isOperationNonce,
  isSecurityOperationActor,
  KEY_ROTATE_OPERATION,
  type KeyRotateOperation,
  keyRotationOperation,
  OperationApprovalError,
  operationDigest,
  type SecurityOperationActor,
} from './approved-operation';
import type { KekProvider } from './kek-provider';
import { KeyChangeRefusedError } from './key-creation-errors';
import { createKeyFactory, type KeyFactory } from './key-factory';
import {
  isKeyPurpose,
  KEY_PURPOSES,
  type KeyAlgorithm,
  type KeyPurpose,
  type KeyPurposeDefinition,
} from './key-purposes';
import {
  AUTOMATIC_ROTATION_PURPOSES,
  DEFAULT_KEY_ROTATION_SETTINGS,
  type KeyRotationNowPlan,
  type KeyRotationSettings,
  type KeyRotationStep,
  type NextKeyCreatedStep,
  planKeyRotation,
  planKeyRotationNow,
  type ResolvedKeyRotationSettings,
  resolveKeyRotationSettings,
  type RotatedKey,
} from './key-rotation-plan';
import type { RealmKeyStore, StoredKeySummary } from './key-store';
import { isRealmId } from './realm-id';

/**
 * The scheduled rotation job of #542: it runs the plan of
 * `key-rotation-plan.ts` for every rotating purpose of every realm, and writes
 * what it decides. Beside it, the manual rotation of #544
 * ({@link KeyRotation.rotateNow}) starts one purpose's rotation before it is
 * due, under an approval. Key custody: it creates keys, so only the signer's
 * wiring builds it.
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

/** A manual rotation: what to rotate, under which approval, and the hooks it calls. */
export interface RotateNowInput<Tx> {
  readonly realmId: string;
  /**
   * The purpose to rotate: one the scheduled rotation rotates
   * (`AUTOMATIC_ROTATION_PURPOSES`). Every active key of it rotates, each
   * algorithm and both keys of a hybrid pair.
   */
  readonly purpose: KeyPurpose;
  /**
   * The key's scope. Absent or `null`: every purpose a manual rotation takes
   * is realm-wide. The canonical record carries it all the same.
   */
  readonly scopeId?: string | null;
  /**
   * The approval of exactly this rotation (`keys.rotate`). It is consumed in
   * the transaction that creates the keys.
   */
  readonly approval: ApprovedOperation<KeyRotateOperation, Tx>;
  /** The clock, in epoch ms. Defaults to `Date.now`. */
  readonly now?: () => number;
  /**
   * The audit hook: called once per operation, inside its transaction, after
   * the keys changed and the approval was consumed, with the actor and the
   * approval id. A throw rolls the whole operation back.
   */
  readonly onAudit: (entry: KeyRotationNowRecord, tx: Tx) => Promise<void>;
  /**
   * The event hook: called inside the transaction for each `next` key (or
   * hybrid pair) the operation created, before the audit hook. A `next` key
   * that waited already is no new step. A throw rolls the operation back.
   */
  readonly onStep?: (step: NextKeyCreatedStep, tx: Tx) => Promise<void>;
}

/** The `next` keys of one algorithm after a manual rotation. */
export interface RotatedNowKeys {
  /** The algorithm rotated: the lead key's, never a hybrid companion's. */
  readonly algorithm: KeyAlgorithm;
  /** The `next` keys: the lead key, then its hybrid companion if it has one. */
  readonly keys: readonly RotatedKey[];
  /** `false` when the keys waited already, and none was created. */
  readonly created: boolean;
  /** Epoch ms. The earliest moment they may sign, once the scheduled rotation writes the switch. */
  readonly activatesAt: number;
}

/** What a manual rotation did, as the audit hook records it and `rotateNow` returns it. */
export interface KeyRotationNowRecord {
  readonly operation: KeyRotateOperation;
  /** The approval it ran under. */
  readonly approvalId: string;
  /** Who asked for it. */
  readonly actor: SecurityOperationActor;
  /** SHA-256 of the operation's canonical record: the digest the approval was consumed for. */
  readonly operationDigest: Buffer;
  readonly realmId: string;
  readonly purpose: KeyPurpose;
  readonly scopeId: string | null;
  /** One entry per algorithm of the purpose the realm holds an active key of. */
  readonly next: readonly RotatedNowKeys[];
}

/** The scheduled rotation. See {@link createKeyRotation}. */
export interface KeyRotation<Tx> {
  /** The windows it runs with. */
  readonly settings: ResolvedKeyRotationSettings;
  /** Rotate every rotating purpose of one realm. */
  rotateRealm(realmId: string, run: KeyRotationRunOptions<Tx>): Promise<KeyRotationReport>;
  /** Rotate every rotating purpose of every realm that holds keys. */
  rotateAll(run: KeyRotationRunOptions<Tx>): Promise<KeyRotationReport>;
  /**
   * Start a rotation of one purpose of a realm before it is due (ADR-019
   * Decision 9, #544), under an approval of exactly that rotation. It is a
   * security operation (ADR-019 Decision 7).
   *
   * In one transaction, under the realm's key lock: for each algorithm the
   * realm holds an active key of, it creates the `next` key at once (with its
   * hybrid companion when hybrid signing is on), which is published at once
   * and signs nothing yet. The windows of the scheduled rotation hold: the
   * scheduled rotation switches to the new key once it has been published for
   * the pre-publication window, and the old key stays published for the
   * retention after that. A key that must go at once is retired in an
   * emergency instead (#551).
   *
   * A `next` key that waits already is the rotation's key: it is returned and
   * no second one is created. The approval is consumed either way, and the
   * audit hook is called once.
   *
   * @throws OperationApprovalError before anything is read when the approval
   *   is missing, malformed or for another operation; and when
   *   {@link ApprovedOperation.consume} refuses it, with nothing changed
   * @throws KeyChangeRefusedError for a malformed realm id, an unknown purpose,
   *   one the scheduled rotation does not rotate (`NOT_A_ROTATING_PURPOSE`),
   *   a scope id (`SCOPE_NOT_ALLOWED`), a realm with no active key of it
   *   (`NO_ACTIVE_KEY`) and keys it cannot choose between (`AMBIGUOUS_KEYS`,
   *   `SPLIT_HYBRID_PAIR`), with nothing changed and the approval unused
   */
  rotateNow(input: RotateNowInput<Tx>): Promise<KeyRotationNowRecord>;
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

  async function rotateNow(input: RotateNowInput<Tx>): Promise<KeyRotationNowRecord> {
    const approval = checkedApproval(input?.approval);
    const { realmId, purpose } = rotateNowTarget(input);
    if (typeof input.onAudit !== 'function') {
      throw new TypeError('A manual rotation needs its audit hook');
    }
    const now = input.now ?? Date.now;
    // The record is built from what this call does, never handed in: the
    // approval approves it only if it was filed for exactly this digest.
    const operation = keyRotationOperation({
      realmId,
      purpose,
      scopeId: null,
      requester: approval.requester,
      nonce: approval.nonce,
    });
    const digest = operationDigest(operation);
    const definition: KeyPurposeDefinition = KEY_PURPOSES[purpose];
    const leads = definition.algorithms.filter(
      (algorithm) => algorithm !== definition.hybridCompanion
    );
    const factory = factoryFor(now);

    return store.transaction(async (tx) => {
      await store.lockRealm(realmId, tx);
      const keys = await store.listByRealm(realmId, { purpose, scopeId: null }, tx);
      const at = now();
      // Every algorithm is planned before anything is written or consumed, so
      // a refusal leaves the approval unused.
      const plans: { readonly algorithm: KeyAlgorithm; readonly plan: KeyRotationNowPlan }[] = [];
      for (const algorithm of leads) {
        const plan = planKeyRotationNow({
          purpose,
          algorithm,
          keys,
          settings,
          hybridSigning,
          now: at,
        });
        if (plan.action === 'refuse') throw new KeyChangeRefusedError(plan.reason, plan.message);
        if (plan.action !== 'none') plans.push({ algorithm, plan });
      }
      if (plans.length === 0) {
        throw new KeyChangeRefusedError(
          'NO_ACTIVE_KEY',
          `The realm holds no active '${purpose}' key to rotate`
        );
      }

      try {
        await approval.consume(Buffer.from(digest), tx);
      } catch (error) {
        throw new OperationApprovalError(
          'refused',
          `Approval ${approval.id} does not approve this rotation`,
          { cause: error }
        );
      }

      const next: RotatedNowKeys[] = [];
      for (const { algorithm, plan } of plans) {
        if (plan.action === 'keep') {
          next.push(
            Object.freeze({
              algorithm,
              keys: Object.freeze(plan.keys.map(rotatedKey)),
              created: false,
              activatesAt: plan.activatesAt,
            })
          );
          continue;
        }
        if (plan.action !== 'create') continue;
        const created = await factory.createKey({
          realmId,
          purpose,
          algorithm,
          status: 'next',
          tx,
        });
        const rotated = Object.freeze(
          created.map((key) => Object.freeze({ kid: key.kid, algorithm: key.algorithm }))
        );
        const step: NextKeyCreatedStep = Object.freeze({
          kind: 'next_created',
          realmId,
          purpose,
          keys: rotated,
          activatesAt: plan.activatesAt,
        });
        if (input.onStep !== undefined) await input.onStep(step, tx);
        next.push(
          Object.freeze({ algorithm, keys: rotated, created: true, activatesAt: plan.activatesAt })
        );
      }

      const record: KeyRotationNowRecord = Object.freeze({
        operation: KEY_ROTATE_OPERATION,
        approvalId: approval.id,
        actor: operation.requester,
        operationDigest: Buffer.from(digest),
        realmId,
        purpose,
        scopeId: null,
        next: Object.freeze(next),
      });
      await input.onAudit(record, tx);
      return record;
    });
  }

  return Object.freeze({
    settings,
    rotateNow,

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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The approval members a manual rotation reads, checked; a copy, so a getter cannot change them later. */
interface CheckedApproval<Tx> {
  readonly id: string;
  readonly requester: SecurityOperationActor;
  readonly nonce: string;
  consume(digest: Buffer, tx: Tx): Promise<void>;
}

/**
 * `approval`, when it is an approval of a manual rotation: an object with a
 * UUID id, the operation `keys.rotate`, an actor, a nonce and a `consume`
 * function. Its members are read once.
 *
 * @throws OperationApprovalError otherwise
 */
function checkedApproval<Tx>(approval: unknown): CheckedApproval<Tx> {
  if (approval === undefined || approval === null) {
    throw new OperationApprovalError('missing', 'A manual rotation needs an approval');
  }
  if (typeof approval !== 'object') {
    throw new OperationApprovalError('malformed', 'The approval is not an approval');
  }
  const given = approval as Partial<ApprovedOperation<string, Tx>>;
  const { id, operation, requester, nonce, consume } = given;
  if (operation !== KEY_ROTATE_OPERATION) {
    throw new OperationApprovalError(
      typeof operation === 'string' ? 'other_operation' : 'malformed',
      `The approval is not for '${KEY_ROTATE_OPERATION}'`
    );
  }
  if (typeof id !== 'string' || !UUID.test(id)) {
    throw new OperationApprovalError('malformed', 'An approval id is a UUID');
  }
  if (!isSecurityOperationActor(requester)) {
    throw new OperationApprovalError('malformed', "The approval's requester is not an actor");
  }
  if (!isOperationNonce(nonce)) {
    throw new OperationApprovalError('malformed', "The approval's nonce is not one");
  }
  if (typeof consume !== 'function') {
    throw new OperationApprovalError('malformed', 'The approval cannot be consumed');
  }
  return Object.freeze({
    id: id.toLowerCase(),
    requester: Object.freeze(
      requester.kind === 'break_glass'
        ? { kind: requester.kind, operatingSystemUser: requester.operatingSystemUser }
        : { kind: requester.kind, realmId: requester.realmId, accountId: requester.accountId }
    ),
    nonce,
    consume: (digest: Buffer, tx: Tx) => consume.call(approval, digest, tx),
  });
}

/**
 * The realm and purpose a manual rotation acts on: a UUID realm id in lower
 * case, and a purpose the scheduled rotation rotates, with no scope id.
 *
 * @throws KeyChangeRefusedError otherwise
 */
function rotateNowTarget(input: Pick<RotateNowInput<unknown>, 'realmId' | 'purpose' | 'scopeId'>): {
  readonly realmId: string;
  readonly purpose: KeyPurpose;
} {
  const { realmId, purpose, scopeId } = input;
  if (typeof realmId !== 'string' || !isRealmId(realmId)) {
    throw new KeyChangeRefusedError('INVALID_REALM_ID', 'A realm id is a UUID');
  }
  if (typeof purpose !== 'string' || !isKeyPurpose(purpose)) {
    throw new KeyChangeRefusedError('UNKNOWN_PURPOSE', 'An unknown key purpose');
  }
  if (!AUTOMATIC_ROTATION_PURPOSES.includes(purpose)) {
    throw new KeyChangeRefusedError(
      'NOT_A_ROTATING_PURPOSE',
      `Key purpose '${purpose}' does not rotate on a schedule, so it has no rotation to start ` +
        'early; its keys change through their own operations'
    );
  }
  if (scopeId !== undefined && scopeId !== null) {
    throw new KeyChangeRefusedError(
      'SCOPE_NOT_ALLOWED',
      `Key purpose '${purpose}' is not scoped and takes no scope id`
    );
  }
  return { realmId: realmId.toLowerCase(), purpose };
}
