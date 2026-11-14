import { randomUUID } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import { KEK_A, KEK_B, localProvider, testKek } from '../testing/keks';
import {
  type ApprovedOperation,
  KEK_ROTATE_OPERATION,
  type KekRotateOperation,
  kekRotationOperation,
  newOperationNonce,
  OperationApprovalError,
  operationDigest,
} from './approved-operation';
import { openKeyMaterial, sealKeyMaterial } from './envelope';
import { KekUnavailableError } from './errors';
import type { KekProvider } from './kek-provider';
import {
  createKekRewrap,
  type KekRewrapProgress,
  KekRewrapRefusedError,
  type KekRewrapStore,
  type KekRotationRecord,
  type WrappedDekChange,
} from './kek-rewrap';
import { computeKekRef } from './kek-sources';
import type { WrappedSignerKey } from './signer-key-store';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const OPERATOR = { kind: 'break_glass', operatingSystemUser: 'qauth-ops' } as const;
const REF_A = computeKekRef(Buffer.from(KEK_A, 'base64'));
const REF_B = computeKekRef(Buffer.from(KEK_B, 'base64'));
const KEK_C = testKek(0xc3);
const REF_C = computeKekRef(Buffer.from(KEK_C, 'base64'));

/** The transaction handle of the memory store. */
interface Tx {
  readonly id: number;
}

interface Row extends WrappedSignerKey {
  readonly id: string;
}

/**
 * The store's rows and a {@link KekRewrapStore} over them. `replaceWrappedDek`
 * writes only a row that still holds the wrap it was read with, as the
 * repository's conditional update does.
 */
function memoryStore() {
  const rows: Row[] = [];
  const transactions: Tx[] = [];
  const writes: { readonly kid: string; readonly change: WrappedDekChange }[] = [];
  let next = 0;
  const store: KekRewrapStore<Tx> = {
    async transaction<T>(work: (tx: Tx) => Promise<T>): Promise<T> {
      const tx = { id: transactions.length + 1 };
      transactions.push(tx);
      return work(tx);
    },
    async countByKekRef() {
      const counts = new Map<string, number>();
      for (const row of rows) counts.set(row.kekRef, (counts.get(row.kekRef) ?? 0) + 1);
      return [...counts]
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([kekRef, count]) => ({ kekRef, rows: count }));
    },
    async listByKekRef(kekRef, afterId, limit) {
      return rows
        .filter((row) => row.kekRef === kekRef && (afterId === null || row.id > afterId))
        .sort((a, b) => (a.id < b.id ? -1 : 1))
        .slice(0, limit)
        .map(({ id, realmId, kid }) => ({ id, realmId, kid }));
    },
    async getWrappedKey(realmId, kid) {
      const row = rows.find((each) => each.realmId === realmId && each.kid === kid);
      return row === undefined ? undefined : { ...row };
    },
    async replaceWrappedDek(realmId, kid, change) {
      writes.push({ kid, change });
      const index = rows.findIndex(
        (row) =>
          row.realmId === realmId &&
          row.kid === kid &&
          row.kekRef === change.fromKekRef &&
          row.wrappedDek.equals(change.fromWrappedDek)
      );
      if (index === -1) return false;
      rows[index] = { ...rows[index], wrappedDek: change.wrappedDek, kekRef: change.kekRef };
      return true;
    },
  };

  /** Seal a fresh 32-byte "key" under `provider` and store it. */
  async function add(provider: KekProvider, kid = `kid-${next}`): Promise<Row> {
    next += 1;
    const identity = {
      realmId: REALM,
      purpose: 'data_at_rest',
      scopeId: null,
      kid,
      algorithm: 'A256GCM',
    };
    const material = Buffer.alloc(32, next);
    const sealed = await sealKeyMaterial(provider, material, identity);
    const row: Row = {
      id: String(next).padStart(6, '0'),
      ...identity,
      status: 'active',
      ...sealed,
    };
    rows.push(row);
    return row;
  }

  return { rows, transactions, writes, store, add };
}

/** An approval of `kek.rotate` that records each use, and resolves unless told to refuse. */
function approval(
  overrides: Partial<ApprovedOperation<KekRotateOperation, Tx>> = {}
): ApprovedOperation<KekRotateOperation, Tx> & { consume: ReturnType<typeof vi.fn> } {
  return {
    id: randomUUID(),
    operation: KEK_ROTATE_OPERATION,
    requester: OPERATOR,
    nonce: newOperationNonce(),
    consume: vi.fn(async () => undefined),
    ...overrides,
  } as ApprovedOperation<KekRotateOperation, Tx> & { consume: ReturnType<typeof vi.fn> };
}

const oldNode = () => localProvider({ KEK: KEK_A });
const rotatingNode = () => localProvider({ KEK: KEK_B, KEK_PREVIOUS: KEK_A });
const newNode = () => localProvider({ KEK: KEK_B });

async function world(keys = 5) {
  const memory = memoryStore();
  for (let index = 0; index < keys; index += 1) await memory.add(oldNode());
  const audits: { record: KekRotationRecord; tx: Tx }[] = [];
  const onAudit = vi.fn(async (record: KekRotationRecord, tx: Tx) => {
    audits.push({ record, tx });
  });
  return { ...memory, audits, onAudit };
}

async function opensWith(provider: KekProvider, row: Row): Promise<boolean> {
  try {
    (await openKeyMaterial(provider, row, row)).fill(0);
    return true;
  } catch {
    return false;
  }
}

describe('KEK rotation: re-wrapping every stored key', () => {
  it('moves every data key from the old KEK to the new one, and the material stays as it was', async () => {
    const w = await world(7);
    const before = w.rows.map((row) => ({ ...row }));
    const rewrap = createKekRewrap({ store: w.store, kekProvider: rotatingNode() });

    const report = await rewrap.rewrapAll({
      from: REF_A,
      to: REF_B,
      approval: approval(),
      onAudit: w.onAudit,
      pageSize: 3,
    });

    expect(report).toMatchObject({
      operation: 'kek.rotate',
      from: REF_A,
      to: REF_B,
      rows: 7,
      rewrapped: 7,
      moved: 0,
      failures: [],
      complete: true,
    });
    expect(report.kekRefs).toEqual([{ kekRef: REF_B, rows: 7, current: true, opens: true }]);
    for (const [index, row] of w.rows.entries()) {
      expect(row.kekRef).toBe(REF_B);
      // Only the wrapped data key changed.
      expect(row.ciphertext).toEqual(before[index].ciphertext);
      expect(row.iv).toEqual(before[index].iv);
      expect(row.aadVersion).toBe(before[index].aadVersion);
      expect(row.wrappedDek.equals(before[index].wrappedDek)).toBe(false);
      // The new KEK alone opens it, and the old one no longer does.
      expect(await opensWith(newNode(), row)).toBe(true);
      expect(await opensWith(oldNode(), row)).toBe(false);
      const material = await openKeyMaterial(newNode(), row, row);
      expect(material).toEqual(Buffer.alloc(32, index + 1));
    }
  });

  it('consumes the approval for the digest of exactly this rotation, with the audit row, before any key moves', async () => {
    const w = await world(2);
    const given = approval();
    const rewrap = createKekRewrap({ store: w.store, kekProvider: rotatingNode() });
    const kekRefsAtConsume: string[] = [];
    given.consume.mockImplementation(async () => {
      kekRefsAtConsume.push(...w.rows.map((row) => row.kekRef));
    });

    const report = await rewrap.rewrapAll({
      from: REF_A,
      to: REF_B,
      approval: given,
      onAudit: w.onAudit,
    });

    const expected = operationDigest(
      kekRotationOperation({ from: REF_A, to: REF_B, requester: OPERATOR, nonce: given.nonce })
    );
    expect(given.consume).toHaveBeenCalledTimes(1);
    const [digest, tx] = given.consume.mock.calls[0] as [Buffer, Tx];
    expect(digest.equals(expected)).toBe(true);
    expect(kekRefsAtConsume).toEqual([REF_A, REF_A]);
    // The audit row is written in the transaction that consumed the approval.
    expect(w.audits).toHaveLength(1);
    expect(w.audits[0].tx).toBe(tx);
    expect(w.audits[0].record).toEqual({
      operation: 'kek.rotate',
      approvalId: given.id,
      actor: OPERATOR,
      operationDigest: expected,
      from: REF_A,
      to: REF_B,
      rows: 2,
    });
    expect(report.approvalId).toBe(given.id);
  });

  it('moves nothing when the approval refuses, and passes a fault of consume on as it is', async () => {
    const w = await world(2);
    const rewrap = createKekRewrap({ store: w.store, kekProvider: rotatingNode() });
    const refusing = approval();
    refusing.consume.mockRejectedValue(
      new OperationApprovalError('refused', 'approved for another digest')
    );
    const refused = await rewrap
      .rewrapAll({ from: REF_A, to: REF_B, approval: refusing, onAudit: w.onAudit })
      .catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(OperationApprovalError);
    expect(refused).toMatchObject({ reason: 'refused' });

    const fault = new Error('connection reset');
    const failing = approval();
    failing.consume.mockRejectedValue(fault);
    await expect(
      rewrap.rewrapAll({ from: REF_A, to: REF_B, approval: failing, onAudit: w.onAudit })
    ).rejects.toBe(fault);

    expect(w.onAudit).not.toHaveBeenCalled();
    expect(w.writes).toEqual([]);
    expect(w.rows.every((row) => row.kekRef === REF_A)).toBe(true);
  });

  it.each([
    ['no approval', undefined, 'missing'],
    ['an approval of another operation', { operation: 'keys.rotate' }, 'other_operation'],
    ['an approval without a nonce', { nonce: 'short' }, 'malformed'],
  ])('refuses %s before anything is read', async (_name, overrides, reason) => {
    const w = await world(1);
    // The provider is frozen, so its health is watched through a delegate.
    const base = rotatingNode();
    const health = vi.fn(() => base.health());
    const kekProvider: KekProvider = { ...base, health };
    const rewrap = createKekRewrap({ store: w.store, kekProvider });
    const given = overrides === undefined ? undefined : approval(overrides as never);

    const error = await rewrap
      .rewrapAll({ from: REF_A, to: REF_B, approval: given as never, onAudit: w.onAudit })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(OperationApprovalError);
    expect(error).toMatchObject({ reason });
    expect(health).not.toHaveBeenCalled();
  });

  it.each([
    ['an empty reference', { from: '', to: REF_B }, 'INVALID_KEK_REF'],
    ['a reference with a control character', { from: `${REF_A}\n`, to: REF_B }, 'INVALID_KEK_REF'],
    ['the same reference twice', { from: REF_B, to: REF_B }, 'SAME_KEK_REF'],
    [
      'a target that is not the KEK the node wraps under',
      { from: REF_A, to: REF_C },
      'NOT_CURRENT_KEK',
    ],
  ])('refuses %s with the approval unused', async (_name, refs, reason) => {
    const w = await world(1);
    const given = approval();
    const rewrap = createKekRewrap({ store: w.store, kekProvider: rotatingNode() });

    const error = await rewrap
      .rewrapAll({ ...refs, approval: given, onAudit: w.onAudit })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(KekRewrapRefusedError);
    expect(error).toMatchObject({ reason, code: 'KEK_REWRAP_REFUSED' });
    expect(given.consume).not.toHaveBeenCalled();
    expect(w.writes).toEqual([]);
  });

  it('refuses a source KEK the node does not hold, with the approval unused', async () => {
    const w = await world(2);
    const given = approval();
    // KEK_PREVIOUS is not set: the node opens nothing wrapped under the old KEK.
    const rewrap = createKekRewrap({ store: w.store, kekProvider: newNode() });

    const error = await rewrap
      .rewrapAll({ from: REF_A, to: REF_B, approval: given, onAudit: w.onAudit })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(KekRewrapRefusedError);
    expect(error).toMatchObject({ reason: 'FROM_KEK_NOT_HELD', statusCode: 409 });
    expect((error as Error).message).toContain('KEK_PREVIOUS');
    expect(given.consume).not.toHaveBeenCalled();
  });

  it('refuses a provider that cannot be used, or that does not say what it wraps under', async () => {
    const w = await world(1);
    const down: KekProvider = {
      ...rotatingNode(),
      health: async () => ({ ok: false, provider: 'test', reason: 'backend down' }),
    };
    await expect(
      createKekRewrap({ store: w.store, kekProvider: down }).rewrapAll({
        from: REF_A,
        to: REF_B,
        approval: approval(),
        onAudit: w.onAudit,
      })
    ).rejects.toBeInstanceOf(KekUnavailableError);

    const silent: KekProvider = {
      ...rotatingNode(),
      health: async () => ({ ok: true, provider: 'test' }),
    };
    await expect(
      createKekRewrap({ store: w.store, kekProvider: silent }).rewrapAll({
        from: REF_A,
        to: REF_B,
        approval: approval(),
        onAudit: w.onAudit,
      })
    ).rejects.toMatchObject({ reason: 'CURRENT_KEK_UNKNOWN' });
    expect(w.writes).toEqual([]);
  });

  it('resumes where a stopped run left off, and a second run moves what is left', async () => {
    const w = await world(6);
    const rewrap = createKekRewrap({ store: w.store, kekProvider: rotatingNode() });
    const stop = new Error('killed');
    let seen = 0;

    await expect(
      rewrap.rewrapAll({
        from: REF_A,
        to: REF_B,
        approval: approval(),
        onAudit: w.onAudit,
        onKey: () => {
          seen += 1;
          if (seen === 2) throw stop;
        },
      })
    ).rejects.toBe(stop);
    expect(w.rows.map((row) => row.kekRef)).toEqual([REF_B, REF_B, REF_A, REF_A, REF_A, REF_A]);

    const again = await rewrap.rewrapAll({
      from: REF_A,
      to: REF_B,
      approval: approval(),
      onAudit: w.onAudit,
    });
    expect(again).toMatchObject({ rows: 4, rewrapped: 4, moved: 0, complete: true });
    expect(w.rows.every((row) => row.kekRef === REF_B)).toBe(true);

    // A third run finds nothing to move, and says the rotation is complete.
    const third = await rewrap.rewrapAll({
      from: REF_A,
      to: REF_B,
      approval: approval(),
      onAudit: w.onAudit,
    });
    expect(third).toMatchObject({ rows: 0, rewrapped: 0, complete: true });
  });

  it('stops between two keys when the signal is aborted', async () => {
    const w = await world(4);
    const controller = new AbortController();
    const rewrap = createKekRewrap({ store: w.store, kekProvider: rotatingNode() });

    await expect(
      rewrap.rewrapAll({
        from: REF_A,
        to: REF_B,
        approval: approval(),
        onAudit: w.onAudit,
        signal: controller.signal,
        onKey: () => controller.abort(new Error('stop')),
      })
    ).rejects.toThrow('stop');
    expect(w.rows.filter((row) => row.kekRef === REF_B)).toHaveLength(1);
  });

  it('counts a key another writer moved first, and writes over nothing', async () => {
    const w = await world(3);
    const rewrap = createKekRewrap({ store: w.store, kekProvider: rotatingNode() });
    const progress: KekRewrapProgress[] = [];
    const replace = w.store.replaceWrappedDek;
    // Another host moves the second key between this run's read and write.
    w.store.replaceWrappedDek = async (realmId, kid, change) => {
      if (kid === 'kid-1') {
        await replace(realmId, kid, { ...change });
        return replace(realmId, kid, change);
      }
      return replace(realmId, kid, change);
    };

    const report = await rewrap.rewrapAll({
      from: REF_A,
      to: REF_B,
      approval: approval(),
      onAudit: w.onAudit,
      onKey: (each) => {
        progress.push(each);
      },
    });

    expect(report).toMatchObject({ rewrapped: 2, moved: 1, complete: true });
    expect(progress.map((each) => [each.kid, each.outcome])).toEqual([
      ['kid-0', 'rewrapped'],
      ['kid-1', 'moved'],
      ['kid-2', 'rewrapped'],
    ]);
    expect(await opensWith(newNode(), w.rows[1])).toBe(true);
  });

  it('reports a key that does not open under the old KEK, moves the others, and is not complete', async () => {
    const w = await world(3);
    // The second row's wrapped data key is damaged.
    const damaged = Buffer.from(w.rows[1].wrappedDek);
    damaged[damaged.length - 1] ^= 0x01;
    w.rows[1] = { ...w.rows[1], wrappedDek: damaged };
    const rewrap = createKekRewrap({ store: w.store, kekProvider: rotatingNode() });

    const report = await rewrap.rewrapAll({
      from: REF_A,
      to: REF_B,
      approval: approval(),
      onAudit: w.onAudit,
    });

    expect(report).toMatchObject({ rewrapped: 2, moved: 0, complete: false });
    expect(report.failures).toEqual([
      { realmId: REALM, kid: 'kid-1', code: 'KEY_DECRYPTION_FAILED' },
    ]);
    expect(report.kekRefs.map(({ kekRef, rows }) => [kekRef, rows])).toEqual(
      [
        [REF_A, 1],
        [REF_B, 2],
      ].sort(([a], [b]) => ((a as string) < (b as string) ? -1 : 1))
    );
    expect(w.rows[1].kekRef).toBe(REF_A);
  });

  it('reports a key wrapped under a KEK this node cannot open, and is not complete', async () => {
    const w = await world(2);
    // A key wrapped under a third KEK, which this node holds neither as KEK nor as KEK_PREVIOUS.
    await w.add(localProvider({ KEK: KEK_C }), 'stranger');
    const rewrap = createKekRewrap({ store: w.store, kekProvider: rotatingNode() });

    const report = await rewrap.rewrapAll({
      from: REF_A,
      to: REF_B,
      approval: approval(),
      onAudit: w.onAudit,
    });

    expect(report.rewrapped).toBe(2);
    expect(report.complete).toBe(false);
    expect(report.kekRefs).toContainEqual({
      kekRef: REF_C,
      rows: 1,
      current: false,
      opens: false,
      reason: 'KEK_UNKNOWN_REF',
    });
    expect(report.kekRefs).toContainEqual({ kekRef: REF_B, rows: 2, current: true, opens: true });
  });

  it('is not complete when `from` names no stored key while keys remain under another KEK', async () => {
    // A mistyped `from`: the keys stay under REF_A, which this node still
    // opens as its previous KEK. The run moves nothing and must not say the
    // old KEK can go.
    const w = await world(2);
    const rewrap = createKekRewrap({ store: w.store, kekProvider: rotatingNode() });

    const report = await rewrap.rewrapAll({
      from: REF_C,
      to: REF_B,
      approval: approval(),
      onAudit: w.onAudit,
    });

    expect(report).toMatchObject({ rows: 0, rewrapped: 0, moved: 0, complete: false });
    expect(report.kekRefs).toEqual([{ kekRef: REF_A, rows: 2, current: false, opens: true }]);
  });

  it('stops when the provider starts to wrap under another KEK, keeping the keys moved so far', async () => {
    const w = await world(3);
    const base = rotatingNode();
    const other = localProvider({ KEK: KEK_C, KEK_PREVIOUS: KEK_A });
    let wraps = 0;
    const changing: KekProvider = {
      name: base.name,
      health: () => base.health(),
      unwrap: (wrapped, aad, kekRef) =>
        kekRef === REF_C ? other.unwrap(wrapped, aad, kekRef) : base.unwrap(wrapped, aad, kekRef),
      wrap: (dek, aad) => {
        wraps += 1;
        return wraps === 1 ? base.wrap(dek, aad) : other.wrap(dek, aad);
      },
    };
    const rewrap = createKekRewrap({ store: w.store, kekProvider: changing });

    await expect(
      rewrap.rewrapAll({ from: REF_A, to: REF_B, approval: approval(), onAudit: w.onAudit })
    ).rejects.toMatchObject({ reason: 'CURRENT_KEK_CHANGED' });
    expect(w.rows.map((row) => row.kekRef)).toEqual([REF_B, REF_A, REF_A]);
  });
});

describe('KEK rotation: counting the keys per KEK reference', () => {
  it('counts every reference, marks the current one and says which open, changing nothing', async () => {
    const w = await world(3);
    await w.add(newNode());
    await w.add(localProvider({ KEK: KEK_C }));
    const before = w.rows.map((row) => row.wrappedDek);

    const census = await createKekRewrap({
      store: w.store,
      kekProvider: rotatingNode(),
    }).census();

    expect([...census].sort((a, b) => (a.kekRef < b.kekRef ? -1 : 1))).toEqual(
      [
        { kekRef: REF_A, rows: 3, current: false, opens: true },
        { kekRef: REF_B, rows: 1, current: true, opens: true },
        { kekRef: REF_C, rows: 1, current: false, opens: false, reason: 'KEK_UNKNOWN_REF' },
      ].sort((a, b) => (a.kekRef < b.kekRef ? -1 : 1))
    );
    expect(w.writes).toEqual([]);
    expect(w.rows.map((row) => row.wrappedDek)).toEqual(before);
  });

  it('says nothing opens a reference none of whose keys can be read', async () => {
    const w = await world(1);
    const store: KekRewrapStore<Tx> = { ...w.store, getWrappedKey: async () => undefined };

    const census = await createKekRewrap({ store, kekProvider: rotatingNode() }).census();

    expect(census).toEqual([{ kekRef: REF_A, rows: 1, current: false, opens: null }]);
  });
});
