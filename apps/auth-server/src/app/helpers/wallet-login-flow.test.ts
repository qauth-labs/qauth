import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  createWalletLoginFlow,
  deleteWalletLoginFlow,
  deleteWalletPresentationSignal,
  generateWalletFlowSecret,
  isWalletLoginHandle,
  publishWalletPresentationSignal,
  readWalletLoginFlow,
  readWalletPresentationSignal,
  type WalletLoginFlow,
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

  it('ignores a stored value that is not one of the two known markers', async () => {
    const { fastify, store } = makeFastify();
    store.set(`wallet-login-signal:${stateHash}`, { signal: 'authenticated' });
    expect(await readWalletPresentationSignal(fastify, stateHash)).toBeNull();
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
