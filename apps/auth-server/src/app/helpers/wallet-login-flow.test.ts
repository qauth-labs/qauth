import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { WALLET_LOGIN_DONE_MARKER_TTL_MS } from '../constants';
import {
  createWalletLoginFlow,
  deleteWalletFlowDoneMarker,
  deleteWalletLoginFlow,
  deleteWalletPresentationSignal,
  discardWalletPresentation,
  generateWalletFlowSecret,
  isWalletLoginHandle,
  publishWalletPresentationSignal,
  readWalletFlowDoneMarker,
  readWalletLoginFlow,
  readWalletPresentationSignal,
  readWalletPresentationSignalRecord,
  readWalletPresentationStash,
  stashWalletPresentation,
  type WalletLoginFlow,
  writeWalletFlowDoneMarker,
} from './wallet-login-flow';

/**
 * Flow records and the wallet signal. The properties under test are the ones the
 * login screen's safety rests on: handles are unguessable and shape-checked, a
 * store failure degrades to "expired" rather than to a 500 mid-sign-in, and the
 * unauthenticated wallet side can never write anything but a fixed marker.
 */

function makeFastify() {
  const store = new Map<string, unknown>();
  const fastify = {
    sessionUtils: {
      setSession: vi.fn(async (key: string, value: unknown) => {
        store.set(key, value);
      }),
      getSession: vi.fn(async (key: string) => store.get(key) ?? null),
      deleteSession: vi.fn(async (key: string) => {
        store.delete(key);
      }),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as unknown as FastifyInstance, store, raw: fastify };
}

function flowFixture(overrides: Partial<WalletLoginFlow> = {}): WalletLoginFlow {
  return {
    stateHash: 'a'.repeat(64),
    assertedIdentifier: 'user@example.com',
    invocationUri: 'openid4vp://?state=abc',
    returnTo: '/',
    binder: generateWalletFlowSecret(),
    realmId: 'realm-1',
    verifierProfile: 'oid4vp-1.0-base',
    expiresAt: Date.now() + 60_000,
    createdAt: Date.now(),
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('wallet-login handles', () => {
  it('are 43 unguessable base64url characters', () => {
    const handle = generateWalletFlowSecret();
    expect(handle).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(isWalletLoginHandle(handle)).toBe(true);
  });

  it('never repeat', () => {
    const handles = new Set(Array.from({ length: 200 }, () => generateWalletFlowSecret()));
    expect(handles.size).toBe(200);
  });

  it.each([
    ['', 'empty'],
    ['../../etc/passwd', 'a path'],
    ['A'.repeat(42), 'too short'],
    ['A'.repeat(44), 'too long'],
    ['A'.repeat(42) + '/', 'an out-of-alphabet character'],
  ])('rejects %j (%s)', (candidate) => {
    expect(isWalletLoginHandle(candidate)).toBe(false);
  });

  it('rejects non-strings', () => {
    expect(isWalletLoginHandle(undefined)).toBe(false);
    expect(isWalletLoginHandle(42)).toBe(false);
    expect(isWalletLoginHandle({ toString: () => 'A'.repeat(43) })).toBe(false);
  });
});

describe('flow records', () => {
  it('round-trips under a namespaced key', async () => {
    const { fastify, store } = makeFastify();
    const flow = flowFixture();

    const handle = await createWalletLoginFlow(fastify, flow);
    expect([...store.keys()]).toEqual([`wallet-login:${handle}`]);
    expect(await readWalletLoginFlow(fastify, handle)).toEqual(flow);
  });

  it('reads nothing for a malformed handle, without touching the store', async () => {
    const { fastify, raw } = makeFastify();
    expect(await readWalletLoginFlow(fastify, '../admin')).toBeNull();
    expect(raw.sessionUtils.getSession).not.toHaveBeenCalled();
  });

  it('degrades to "expired" when the store is unavailable, rather than throwing', async () => {
    const { fastify, raw } = makeFastify();
    raw.sessionUtils.getSession.mockRejectedValueOnce(new Error('redis down'));

    await expect(readWalletLoginFlow(fastify, generateWalletFlowSecret())).resolves.toBeNull();
    expect(raw.log.warn).toHaveBeenCalled();
  });

  it('deletes without throwing when the store is unavailable', async () => {
    const { fastify, raw } = makeFastify();
    raw.sessionUtils.deleteSession.mockRejectedValueOnce(new Error('redis down'));
    await expect(
      deleteWalletLoginFlow(fastify, generateWalletFlowSecret())
    ).resolves.toBeUndefined();
  });

  it('is gone once deleted, so a terminal flow cannot be polled again', async () => {
    const { fastify } = makeFastify();
    const handle = await createWalletLoginFlow(fastify, flowFixture());

    await deleteWalletLoginFlow(fastify, handle);
    expect(await readWalletLoginFlow(fastify, handle)).toBeNull();
  });
});

describe('the wallet presentation signal', () => {
  const stateHash = 'b'.repeat(64);

  it('is written under its own namespace, keyed by the state digest', async () => {
    const { fastify, store } = makeFastify();
    await publishWalletPresentationSignal(fastify, stateHash, 'received');
    expect([...store.keys()]).toEqual([`wallet-login-signal:${stateHash}`]);
    expect(await readWalletPresentationSignal(fastify, stateHash)).toBe('received');
  });

  it('carries the wallet-error marker without any wallet-supplied text', async () => {
    const { fastify, store } = makeFastify();
    await publishWalletPresentationSignal(fastify, stateHash, 'wallet_error');
    expect(store.get(`wallet-login-signal:${stateHash}`)).toEqual({
      signal: 'wallet_error',
      at: expect.any(Number),
    });
  });

  it('reads as absent until a wallet has responded', async () => {
    const { fastify } = makeFastify();
    expect(await readWalletPresentationSignal(fastify, stateHash)).toBeNull();
  });

  it('ignores a stored value that is not one of the known markers', async () => {
    const { fastify, store } = makeFastify();
    store.set(`wallet-login-signal:${stateHash}`, { signal: 'authenticated' });
    expect(await readWalletPresentationSignal(fastify, stateHash)).toBeNull();
    expect(await readWalletPresentationSignalRecord(fastify, stateHash)).toBeNull();
  });

  it('reads the whole record — which signal, and when — for the same-device deadline (#405)', async () => {
    const { fastify } = makeFastify();
    const before = Date.now();
    await publishWalletPresentationSignal(fastify, stateHash, 'received');

    const record = await readWalletPresentationSignalRecord(fastify, stateHash);
    expect(record?.signal).toBe('received');
    expect(record?.at).toBeGreaterThanOrEqual(before);
    expect(record?.at).toBeLessThanOrEqual(Date.now());
    // The bare reader is a thin wrapper over the same read.
    expect(await readWalletPresentationSignal(fastify, stateHash)).toBe('received');
  });

  it('treats a record with no readable timestamp as arbitrarily old, never as now (#405)', async () => {
    // The only consumer of `at` is a rejection deadline; an unreadable value
    // must fail closed into that rejection rather than restart the clock.
    const { fastify, store } = makeFastify();
    store.set(`wallet-login-signal:${stateHash}`, { signal: 'received' });
    expect(await readWalletPresentationSignalRecord(fastify, stateHash)).toEqual({
      signal: 'received',
      at: 0,
    });
    store.set(`wallet-login-signal:${stateHash}`, { signal: 'received', at: 'soon' });
    expect(await readWalletPresentationSignalRecord(fastify, stateHash)).toEqual({
      signal: 'received',
      at: 0,
    });
  });

  it('carries the return_rejected marker the return route publishes (HAIP 1.0 §5.1) (#405)', async () => {
    const { fastify, store } = makeFastify();
    await publishWalletPresentationSignal(fastify, stateHash, 'return_rejected');
    expect(store.get(`wallet-login-signal:${stateHash}`)).toEqual({
      signal: 'return_rejected',
      at: expect.any(Number),
    });
    expect(await readWalletPresentationSignal(fastify, stateHash)).toBe('return_rejected');
  });

  it('never throws at the wallet: a failed publish only costs the browser a timeout', async () => {
    const { fastify, raw } = makeFastify();
    raw.sessionUtils.setSession.mockRejectedValueOnce(new Error('redis down'));

    await expect(
      publishWalletPresentationSignal(fastify, stateHash, 'received')
    ).resolves.toBeUndefined();
    expect(raw.log.warn).toHaveBeenCalled();
  });

  it('is deleted when its flow terminates', async () => {
    const { fastify } = makeFastify();
    await publishWalletPresentationSignal(fastify, stateHash, 'received');
    await deleteWalletPresentationSignal(fastify, stateHash);
    expect(await readWalletPresentationSignal(fastify, stateHash)).toBeNull();
  });
});

/**
 * The same-device return leg's records (#405, ADR-013). The flow record's
 * `sameDevice`, the discard that turns a foreign landing into a rejection, and
 * the done-marker the original tab consumes.
 */
describe('the same-device flag on the flow record (#405)', () => {
  it('round-trips when set, and reads as absent for a record written without it', async () => {
    const { fastify } = makeFastify();

    const same = await createWalletLoginFlow(fastify, flowFixture({ sameDevice: true }));
    expect((await readWalletLoginFlow(fastify, same))?.sameDevice).toBe(true);

    // A record from the previous binary — or a cross-device start, which
    // writes nothing — is cross-device by absence, never by a stored `false`
    // the old binary would not have written either.
    const cross = await createWalletLoginFlow(fastify, flowFixture());
    expect((await readWalletLoginFlow(fastify, cross))?.sameDevice).toBeUndefined();
  });
});

describe('discarding a presentation on a foreign landing (#405)', () => {
  const stateHash = 'c'.repeat(64);

  it('deletes the parked bytes and overwrites the signal with return_rejected', async () => {
    const { fastify, store } = makeFastify();
    await publishWalletPresentationSignal(fastify, stateHash, 'received');
    await stashWalletPresentation(fastify, stateHash, [
      { format: 'dc+sd-jwt', compact: 'a.b.c' } as never,
    ]);

    await discardWalletPresentation(fastify, stateHash);

    expect(await readWalletPresentationStash(fastify, stateHash)).toBeNull();
    expect(store.has(`wallet-presentation:${stateHash}`)).toBe(false);
    expect(await readWalletPresentationSignal(fastify, stateHash)).toBe('return_rejected');
  });

  it('never throws: a failed write costs only a slower refusal', async () => {
    const { fastify, raw } = makeFastify();
    raw.sessionUtils.deleteSession.mockRejectedValueOnce(new Error('redis down'));
    raw.sessionUtils.setSession.mockRejectedValueOnce(new Error('redis down'));

    await expect(discardWalletPresentation(fastify, stateHash)).resolves.toBeUndefined();
    expect(raw.log.warn).toHaveBeenCalledTimes(2);
  });
});

describe('the done-marker for the original tab (#405)', () => {
  const handle = generateWalletFlowSecret();
  const marker = { binder: generateWalletFlowSecret(), mode: 'login' as const, redirectTo: '/x' };

  it('is written under its own namespace, keyed by the flow handle, for the flow TTL', async () => {
    const { fastify, store, raw } = makeFastify();
    await writeWalletFlowDoneMarker(fastify, handle, marker);

    expect([...store.keys()]).toEqual([`wallet-login-done:${handle}`]);
    expect(raw.sessionUtils.setSession).toHaveBeenCalledWith(
      `wallet-login-done:${handle}`,
      marker,
      Math.floor(WALLET_LOGIN_DONE_MARKER_TTL_MS / 1000)
    );
    expect(await readWalletFlowDoneMarker(fastify, handle)).toEqual(marker);
  });

  it('reads nothing for a malformed handle, an unknown one, or a marker without a binder', async () => {
    const { fastify, store, raw } = makeFastify();
    expect(await readWalletFlowDoneMarker(fastify, '../admin')).toBeNull();
    expect(raw.sessionUtils.getSession).not.toHaveBeenCalled();

    expect(await readWalletFlowDoneMarker(fastify, handle)).toBeNull();

    store.set(`wallet-login-done:${handle}`, { mode: 'login', redirectTo: '/x' });
    expect(await readWalletFlowDoneMarker(fastify, handle)).toBeNull();
  });

  it('is gone once deleted, so the original tab can consume it exactly once', async () => {
    const { fastify } = makeFastify();
    await writeWalletFlowDoneMarker(fastify, handle, marker);
    await deleteWalletFlowDoneMarker(fastify, handle);
    expect(await readWalletFlowDoneMarker(fastify, handle)).toBeNull();
  });

  it('never throws on a store failure: the sign-in already happened', async () => {
    const { fastify, raw } = makeFastify();
    raw.sessionUtils.setSession.mockRejectedValueOnce(new Error('redis down'));
    await expect(writeWalletFlowDoneMarker(fastify, handle, marker)).resolves.toBeUndefined();

    raw.sessionUtils.getSession.mockRejectedValueOnce(new Error('redis down'));
    await expect(readWalletFlowDoneMarker(fastify, handle)).resolves.toBeNull();

    raw.sessionUtils.deleteSession.mockRejectedValueOnce(new Error('redis down'));
    await expect(deleteWalletFlowDoneMarker(fastify, handle)).resolves.toBeUndefined();
    expect(raw.log.warn).toHaveBeenCalledTimes(3);
  });
});
