import {
  type ApprovedOperation,
  checkedApproval,
  isKekRef,
  isOperationApprovalRefusal,
  KEK_ROTATE_OPERATION,
  type KekRotateOperation,
  kekRotationOperation,
  OperationApprovalError,
  operationDigest,
  type SecurityOperationActor,
} from './approved-operation';
import { rewrapDataKey, unwrapDataKey } from './envelope';
import { isKeyCustodyError, KekUnavailableError, type KeyCustodyErrorCode } from './errors';
import type { KekProvider } from './kek-provider';
import type { WrappedSignerKey } from './signer-key-store';

/**
 * THE KEK ROTATION (ADR-019 Decision 9, issue #545): move every stored key
 * from one key-encryption key to another without an outage.
 *
 * Each `realm_keys` row holds its material encrypted under its own data key,
 * and the data key wrapped by the KEK its `kek_ref` names. A KEK rotation
 * re-wraps the data keys only: {@link KekRewrap.rewrapAll} unwraps each data
 * key under the old KEK reference and wraps it under the new one, and the
 * encrypted material is not touched. Only data keys move, so a store of
 * hundreds of keys finishes in seconds.
 *
 * The node that runs it holds both KEKs: the new one as the KEK it wraps
 * under, the old one as one it still opens (for the default provider, `KEK`
 * and `KEK_PREVIOUS`). The signer nodes hold both while the job runs, so a
 * key opens whichever KEK wraps it at that moment, and signing goes on.
 *
 * One key moves per transaction, with a write that only a key still wrapped
 * under the old reference, as it was read, matches. A run that stops halfway
 * leaves every key wrapped under one KEK or the other, and running it again
 * moves the rest: it is resumable and safe to repeat, also on two hosts at
 * once.
 *
 * Rotating the KEK is a security operation (ADR-019 Decisions 7 and 9): it
 * runs under an approval of exactly this rotation (`kek.rotate`), bound to
 * the two references, the requester and a nonce. The admin API's approval
 * implements it; the operator command `auth-server:keys:rewrap`, on a host
 * that holds both KEKs, makes one of its own.
 *
 * Key custody: it unwraps data keys, so only the signer's wiring builds it.
 */

/** How many keys are wrapped under one KEK reference. */
export interface KekRefCount {
  readonly kekRef: string;
  readonly rows: number;
}

/** A key to re-wrap, as the store lists it. */
export interface KekRewrapCandidate {
  /** The row's id: the order the job pages through the keys in. */
  readonly id: string;
  readonly realmId: string;
  readonly kid: string;
}

/** One key's new wrap, and the wrap it must still hold for the write to happen. */
export interface WrappedDekChange {
  /** The `kek_ref` the row must still hold. */
  readonly fromKekRef: string;
  /** The `wrapped_dek` the row must still hold, byte for byte. */
  readonly fromWrappedDek: Buffer;
  /** The new `wrapped_dek`. */
  readonly wrappedDek: Buffer;
  /** The new `kek_ref`. */
  readonly kekRef: string;
}

/**
 * The storage the KEK rotation works through: the realm keys repository's
 * view of `realm_keys`. `Tx` is the store's transaction handle, as
 * {@link ApprovedOperation.consume} takes it.
 */
export interface KekRewrapStore<Tx> {
  /** Run `work` in one transaction: everything it writes is kept, or nothing is. */
  transaction<T>(work: (tx: Tx) => Promise<T>): Promise<T>;
  /** How many keys of any status, in every realm, each KEK reference wraps, by reference. */
  countByKekRef(): Promise<readonly KekRefCount[]>;
  /**
   * Up to `limit` keys of any status, in every realm, whose data key is
   * wrapped under `kekRef`, by row id in ascending order, after the row
   * `afterId` (from the first when `null`).
   */
  listByKekRef(
    kekRef: string,
    afterId: string | null,
    limit: number
  ): Promise<readonly KekRewrapCandidate[]>;
  /** A key's sealed row, as the signer reads it, or `undefined`. */
  getWrappedKey(realmId: string, kid: string): Promise<WrappedSignerKey | undefined>;
  /**
   * Write a key's new wrap in one statement, its own transaction: only when
   * the row still holds `change.fromKekRef` and `change.fromWrappedDek`. Only
   * `wrapped_dek` and `kek_ref` change.
   *
   * @returns whether the row changed: `false` when another writer moved or
   *   deleted it first
   */
  replaceWrappedDek(realmId: string, kid: string, change: WrappedDekChange): Promise<boolean>;
}

/** What a KEK rotation is built from. */
export interface KekRewrapOptions<Tx> {
  readonly store: KekRewrapStore<Tx>;
  /**
   * The node's KEK provider. It wraps under the new KEK and still unwraps
   * under the old one: for the default provider, `KEK` and `KEK_PREVIOUS`.
   */
  readonly kekProvider: KekProvider;
}

/** One KEK reference the stored keys name, after a run or when counted. */
export interface KekRefCensus {
  readonly kekRef: string;
  /** How many keys, of any status, in every realm, it wraps. */
  readonly rows: number;
  /** Whether it is the KEK this node wraps under. */
  readonly current: boolean;
  /**
   * Whether this node opens a key wrapped under it, tried on one of its keys.
   * `null` when none of its keys could be read to try (each was deleted in
   * the meantime), which counts as not opening.
   */
  readonly opens: boolean | null;
  /** Why not, when it does not open: the KEK provider's error code. */
  readonly reason?: KeyCustodyErrorCode;
}

/** A key the run could not re-wrap. It stays wrapped under the old reference. */
export interface KekRewrapFailure {
  readonly realmId: string;
  readonly kid: string;
  /** The KEK provider's error code, such as `KEY_DECRYPTION_FAILED`. */
  readonly code: KeyCustodyErrorCode;
}

/** What became of one key, as {@link RewrapAllInput.onKey} hears it. */
export interface KekRewrapProgress {
  readonly realmId: string;
  readonly kid: string;
  /**
   * `rewrapped`: this run moved it. `moved`: another writer re-wrapped or
   * deleted it first. `failed`: it does not open under the old reference.
   */
  readonly outcome: 'rewrapped' | 'moved' | 'failed';
}

/** What a KEK rotation records, as the audit hook receives it. */
export interface KekRotationRecord {
  readonly operation: KekRotateOperation;
  /** The approval it runs under. */
  readonly approvalId: string;
  /** Who asked for it. */
  readonly actor: SecurityOperationActor;
  /** SHA-256 of the operation's canonical record: the digest the approval was consumed for. */
  readonly operationDigest: Buffer;
  readonly from: string;
  readonly to: string;
  /** How many keys were wrapped under `from` when it started. */
  readonly rows: number;
}

/** What one run did, and where the stored keys stand after it. */
export interface KekRewrapReport extends KekRotationRecord {
  /** Keys this run re-wrapped from `from` to `to`. */
  readonly rewrapped: number;
  /** Keys another writer re-wrapped or deleted before this run could. */
  readonly moved: number;
  /** Keys that do not open under `from`; they stay wrapped under it. */
  readonly failures: readonly KekRewrapFailure[];
  /** Every KEK reference the stored keys name after the run, with its count. */
  readonly kekRefs: readonly KekRefCensus[];
  /**
   * Whether the rotation is done: no stored key is wrapped under `from`, no
   * key failed, and this node opens every KEK reference the store names.
   * Only then may `from`'s KEK be removed (`KEK_PREVIOUS`, for the default
   * provider), once no signer node wraps under it any more.
   */
  readonly complete: boolean;
}

/** A KEK rotation: what to move, under which approval, and the hooks it calls. */
export interface RewrapAllInput<Tx> {
  /** The KEK reference to re-wrap from: the old KEK, which this node still opens. */
  readonly from: string;
  /** The KEK reference to re-wrap to: the KEK this node's provider wraps under. */
  readonly to: string;
  /** The approval of exactly this rotation (`kek.rotate`). It is consumed before any key moves. */
  readonly approval: ApprovedOperation<KekRotateOperation, Tx>;
  /**
   * The audit hook: called once, inside the transaction that consumes the
   * approval, before any key moves. A throw stops the run with nothing moved.
   */
  readonly onAudit: (entry: KekRotationRecord, tx: Tx) => Promise<void>;
  /** Called after each key's write, with what became of it. A throw stops the run. */
  readonly onKey?: (progress: KekRewrapProgress) => Promise<void> | void;
  /** Stops the run between two keys. */
  readonly signal?: AbortSignal;
  /** How many keys are listed at a time. Defaults to 100. */
  readonly pageSize?: number;
}

/** The KEK rotation. See {@link createKekRewrap}. */
export interface KekRewrap<Tx> {
  /**
   * Re-wrap every stored key's data key from the KEK reference `from` to
   * `to`, under an approval of exactly that rotation, then count the keys
   * per KEK reference and try whether this node opens each one.
   *
   * Before anything is consumed or moved, it refuses a `to` that is not the
   * KEK this node's provider wraps under, and a `from` this node holds no KEK
   * for. A key that does not open under `from` is reported in `failures` and
   * left as it is; the run goes on with the next.
   *
   * @throws OperationApprovalError before anything is read when the approval
   *   is missing, malformed or for another operation; and when
   *   {@link ApprovedOperation.consume} refuses it, with nothing moved. Any
   *   other error of `consume` is passed on as it is, with nothing moved.
   * @throws KekRewrapRefusedError for a malformed or equal pair of references
   *   (`INVALID_KEK_REF`, `SAME_KEK_REF`), a `to` this node does not wrap
   *   under (`NOT_CURRENT_KEK`, `CURRENT_KEK_UNKNOWN`), a `from` it holds no
   *   KEK for (`FROM_KEK_NOT_HELD`), all before the approval is used; and
   *   when the provider starts to wrap under another reference during the
   *   run (`CURRENT_KEK_CHANGED`), with the keys moved so far kept
   * @throws KekUnavailableError when the provider reports itself unusable
   * @throws the provider's and the store's errors, other than a key that does
   *   not open, which stop the run with the keys moved so far kept; and the
   *   signal's reason when it is aborted
   */
  rewrapAll(input: RewrapAllInput<Tx>): Promise<KekRewrapReport>;
  /**
   * Count the stored keys per KEK reference, and try whether this node opens
   * each one, changing nothing. `current` marks the reference this node's
   * provider wraps under.
   *
   * @throws KekUnavailableError when the provider reports itself unusable
   */
  census(): Promise<readonly KekRefCensus[]>;
}

/** Why a KEK rotation was refused, as a stable value to branch on. */
export type KekRewrapRefusalReason =
  /** A KEK reference is empty, too long or not well-formed text (`isKekRef`). */
  | 'INVALID_KEK_REF'
  /** `from` and `to` are the same reference. */
  | 'SAME_KEK_REF'
  /** `to` is not the reference this node's provider wraps under. */
  | 'NOT_CURRENT_KEK'
  /** The provider does not say which reference it wraps under. */
  | 'CURRENT_KEK_UNKNOWN'
  /** This node's provider holds no KEK named `from`. */
  | 'FROM_KEK_NOT_HELD'
  /** During the run, the provider started to wrap under a reference other than `to`. */
  | 'CURRENT_KEK_CHANGED';

/**
 * A KEK rotation the node refused. Branch on {@link reason}. Messages name
 * KEK references, which are safe to log, and never a KEK.
 */
export class KekRewrapRefusedError extends Error {
  readonly statusCode: 400 | 409;
  readonly code = 'KEK_REWRAP_REFUSED';
  readonly reason: KekRewrapRefusalReason;

  constructor(reason: KekRewrapRefusalReason, message: string) {
    super(message);
    this.name = 'KekRewrapRefusedError';
    this.reason = reason;
    this.statusCode = reason === 'INVALID_KEK_REF' || reason === 'SAME_KEK_REF' ? 400 : 409;
    Object.setPrototypeOf(this, KekRewrapRefusedError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, KekRewrapRefusedError);
    }
  }
}

const DEFAULT_PAGE_SIZE = 100;

/** How many of a reference's keys the census reads before it gives up trying one. */
const PROBE_CANDIDATES = 4;

/** The identity a row's envelope is bound to, read from the row itself. */
function identityOf(row: WrappedSignerKey) {
  return {
    realmId: row.realmId,
    purpose: row.purpose,
    scopeId: row.scopeId,
    kid: row.kid,
    algorithm: row.algorithm,
  };
}

/**
 * Build the KEK rotation of a deployment. See the module comment.
 */
export function createKekRewrap<Tx>(options: KekRewrapOptions<Tx>): KekRewrap<Tx> {
  const { store, kekProvider } = options;

  /** The reference the provider wraps under. */
  async function currentKekRef(): Promise<string | undefined> {
    const health = await kekProvider.health();
    if (!health.ok) {
      throw new KekUnavailableError({
        cause: new Error(`${health.provider}: ${health.reason ?? 'no reason given'}`),
      });
    }
    return health.kekRef;
  }

  /**
   * Unwrap the data key of one key of `kekRef`, and zero it: `true` when it
   * opens, the provider's error when it does not, `null` when no listed key
   * could be read. Errors that are no key-custody error are thrown.
   */
  async function probe(kekRef: string): Promise<true | null | { code: KeyCustodyErrorCode }> {
    for (const candidate of await store.listByKekRef(kekRef, null, PROBE_CANDIDATES)) {
      const row = await store.getWrappedKey(candidate.realmId, candidate.kid);
      if (row === undefined || row.kekRef !== kekRef) continue;
      try {
        const dek = await unwrapDataKey(kekProvider, row, identityOf(row));
        dek.fill(0);
        return true;
      } catch (error) {
        if (isKeyCustodyError(error)) {
          return { code: (error as { code: KeyCustodyErrorCode }).code };
        }
        throw error;
      }
    }
    return null;
  }

  async function censusWith(current: string | undefined): Promise<readonly KekRefCensus[]> {
    const entries: KekRefCensus[] = [];
    for (const { kekRef, rows } of await store.countByKekRef()) {
      if (rows === 0) continue;
      const result = await probe(kekRef);
      entries.push(
        Object.freeze({
          kekRef,
          rows,
          current: kekRef === current,
          opens: result === null ? null : result === true,
          ...(result === null || result === true ? {} : { reason: result.code }),
        })
      );
    }
    return Object.freeze(entries);
  }

  async function rewrapAll(input: RewrapAllInput<Tx>): Promise<KekRewrapReport> {
    const approval = checkedApproval<Tx>(
      input?.approval,
      KEK_ROTATE_OPERATION,
      'A KEK rotation needs an approval'
    );
    const { from, to } = input;
    if (!isKekRef(from) || !isKekRef(to)) {
      throw new KekRewrapRefusedError(
        'INVALID_KEK_REF',
        'A KEK reference is 1 to 1024 characters of text without a control character'
      );
    }
    if (from === to) {
      throw new KekRewrapRefusedError(
        'SAME_KEK_REF',
        `The keys are wrapped under '${to}' already: a KEK rotation moves them to another KEK`
      );
    }
    if (typeof input.onAudit !== 'function') {
      throw new TypeError('A KEK rotation needs its audit hook');
    }
    const pageSize = input.pageSize ?? DEFAULT_PAGE_SIZE;
    if (!Number.isSafeInteger(pageSize) || pageSize < 1) {
      throw new TypeError('The page size is a positive whole number');
    }

    // Everything is checked before the approval is used, so a refusal leaves
    // it open for a run that can succeed.
    const current = await currentKekRef();
    if (current === undefined) {
      throw new KekRewrapRefusedError(
        'CURRENT_KEK_UNKNOWN',
        `The KEK provider '${kekProvider.name}' does not report the KEK it wraps under, so the rotation cannot check that it wraps under '${to}'`
      );
    }
    if (current !== to) {
      throw new KekRewrapRefusedError(
        'NOT_CURRENT_KEK',
        `This node wraps under '${current}', not '${to}': set the new KEK as the KEK this node wraps under (KEK, for the default provider), or re-wrap to '${current}'`
      );
    }
    const held = await probe(from);
    if (held !== true && held !== null && held.code === 'KEK_UNKNOWN_REF') {
      throw new KekRewrapRefusedError(
        'FROM_KEK_NOT_HELD',
        `This node holds no KEK named '${from}': set the old KEK as one it still opens (KEK_PREVIOUS, for the default provider)`
      );
    }
    if (held !== true && held !== null && held.code !== 'KEY_DECRYPTION_FAILED') {
      // The provider's backend refused or failed: no key would move.
      throw new KekUnavailableError({
        cause: new Error(`The KEK named '${from}' could not be used: ${held.code}`),
      });
    }

    const rows = (await store.countByKekRef()).find((entry) => entry.kekRef === from)?.rows ?? 0;
    // The record is built from what this call does, never handed in: the
    // approval approves it only if it was filed for exactly this digest.
    const operation = kekRotationOperation({
      from,
      to,
      requester: approval.requester,
      nonce: approval.nonce,
    });
    const digest = operationDigest(operation);
    const record: KekRotationRecord = Object.freeze({
      operation: KEK_ROTATE_OPERATION,
      approvalId: approval.id,
      actor: operation.requester,
      operationDigest: Buffer.from(digest),
      from,
      to,
      rows,
    });

    await store.transaction(async (tx) => {
      try {
        await approval.consume(Buffer.from(digest), tx);
      } catch (error) {
        // A refusal is the approval's answer. Any other error is a fault,
        // passed on as it is so that the caller may retry; the transaction
        // rolls back either way.
        if (!isOperationApprovalRefusal(error)) throw error;
        throw new OperationApprovalError(
          'refused',
          `Approval ${approval.id} does not approve this KEK rotation`,
          { cause: error }
        );
      }
      await input.onAudit(record, tx);
    });

    let rewrapped = 0;
    let moved = 0;
    const failures: KekRewrapFailure[] = [];
    let after: string | null = null;
    for (;;) {
      input.signal?.throwIfAborted();
      const page = await store.listByKekRef(from, after, pageSize);
      for (const candidate of page) {
        input.signal?.throwIfAborted();
        after = candidate.id;
        const outcome = await rewrapOne(candidate, from, to, failures);
        if (outcome === 'rewrapped') rewrapped += 1;
        else if (outcome === 'moved') moved += 1;
        if (input.onKey !== undefined) {
          await input.onKey(
            Object.freeze({ realmId: candidate.realmId, kid: candidate.kid, outcome })
          );
        }
      }
      if (page.length < pageSize) break;
    }

    const kekRefs = await censusWith(to);
    const complete =
      failures.length === 0 &&
      kekRefs.every((entry) => entry.kekRef !== from && entry.opens === true);
    return Object.freeze({
      ...record,
      rewrapped,
      moved,
      failures: Object.freeze(failures),
      kekRefs,
      complete,
    });
  }

  /**
   * Move one key from `from` to `to`. The crypto runs before the write, which
   * matches only the row as it was read, so nothing waits on the provider
   * inside a transaction.
   */
  async function rewrapOne(
    candidate: KekRewrapCandidate,
    from: string,
    to: string,
    failures: KekRewrapFailure[]
  ): Promise<KekRewrapProgress['outcome']> {
    const row = await store.getWrappedKey(candidate.realmId, candidate.kid);
    if (row === undefined || row.kekRef !== from) return 'moved';
    let next;
    try {
      next = await rewrapDataKey(kekProvider, row, identityOf(row));
    } catch (error) {
      if (!isKeyCustodyError(error, 'KEY_DECRYPTION_FAILED')) throw error;
      failures.push(
        Object.freeze({ realmId: row.realmId, kid: row.kid, code: 'KEY_DECRYPTION_FAILED' })
      );
      return 'failed';
    }
    if (next.kekRef !== to) {
      throw new KekRewrapRefusedError(
        'CURRENT_KEK_CHANGED',
        `The KEK provider wraps under '${next.kekRef}' now, not '${to}': run the rotation again to '${next.kekRef}'`
      );
    }
    const changed = await store.replaceWrappedDek(row.realmId, row.kid, {
      fromKekRef: from,
      fromWrappedDek: row.wrappedDek,
      wrappedDek: Buffer.from(next.wrapped),
      kekRef: next.kekRef,
    });
    return changed ? 'rewrapped' : 'moved';
  }

  return Object.freeze({
    rewrapAll,
    census: async () => censusWith(await currentKekRef()),
  });
}
