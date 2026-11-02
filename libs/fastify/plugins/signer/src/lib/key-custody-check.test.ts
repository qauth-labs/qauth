import { randomBytes } from 'node:crypto';

import { KekUnavailableError, KeyCustodyError } from '@qauth-labs/server-keys';
import {
  createLocalKekProvider,
  type KekProvider,
  sealKeyMaterial,
  type WrappedSignerKey,
} from '@qauth-labs/server-keys/custody';
import { describe, expect, it, vi } from 'vitest';

import { checkKeyCustody, KEK_CANARY_LIMIT, type KekCanaryStore } from './key-custody-check';

/** The signer's readiness check (#500). */

const REALM_ID = '0190a5b2-7c3d-7e4f-8a9b-0c1d2e3f4a5b';
const KID = 'canary-kid';

function provider(byte: number): KekProvider {
  return createLocalKekProvider({
    env: { KEK: Buffer.alloc(32, byte).toString('base64'), NODE_ENV: 'test' },
    warn: () => undefined,
  });
}

/** A key sealed under `sealer`, as the store holds it. */
async function storedKey(sealer: KekProvider): Promise<WrappedSignerKey> {
  const identity = {
    realmId: REALM_ID,
    purpose: 'cookie_hmac',
    scopeId: null,
    kid: KID,
    algorithm: 'HS256',
  } as const;
  const sealed = await sealKeyMaterial(sealer, randomBytes(32), identity);
  return { ...identity, ...sealed, status: 'active' } as WrappedSignerKey;
}

function storeOf(keys: readonly WrappedSignerKey[]): KekCanaryStore & {
  listKekCanaries: ReturnType<typeof vi.fn>;
} {
  return {
    listKekCanaries: vi.fn(async () => keys.map(({ realmId, kid }) => ({ realmId, kid }))),
    getWrappedKey: async (realmId: string, kid: string) =>
      keys.find((key) => key.realmId === realmId && key.kid === kid),
  };
}

describe('checkKeyCustody', () => {
  it('resolves when the KEK opens each canary, and asks for at most the limit', async () => {
    const kek = provider(0x11);
    const store = storeOf([await storedKey(kek)]);

    await expect(checkKeyCustody(kek, store)).resolves.toBeUndefined();
    expect(store.listKekCanaries).toHaveBeenCalledWith(KEK_CANARY_LIMIT);
  });

  it('rejects when the configured KEK is not the one the canary is wrapped under', async () => {
    const store = storeOf([await storedKey(provider(0x11))]);

    const failure = checkKeyCustody(provider(0x22), store);
    await expect(failure).rejects.toBeInstanceOf(KeyCustodyError);
    await expect(failure).rejects.toMatchObject({ code: 'KEK_UNKNOWN_REF' });
  });

  it('rejects a canary whose wrapped key no longer authenticates', async () => {
    const kek = provider(0x11);
    const key = await storedKey(kek);
    const tampered = { ...key, wrappedDek: Buffer.from(key.wrappedDek).fill(0, 12, 20) };

    await expect(checkKeyCustody(kek, storeOf([tampered]))).rejects.toMatchObject({
      code: 'KEY_DECRYPTION_FAILED',
    });
  });

  it('rejects when the provider reports itself unusable, before reading the store', async () => {
    const kek = provider(0x11);
    const down: KekProvider = {
      ...kek,
      health: async () => ({ ok: false, provider: 'local', reason: 'backend down' }),
    };
    const store = storeOf([]);

    await expect(checkKeyCustody(down, store)).rejects.toBeInstanceOf(KekUnavailableError);
    expect(store.listKekCanaries).not.toHaveBeenCalled();
  });

  it('resolves on the provider report alone when no key is stored, and skips a canary deleted since', async () => {
    const kek = provider(0x11);
    await expect(checkKeyCustody(kek, storeOf([]))).resolves.toBeUndefined();

    const vanished: KekCanaryStore = {
      listKekCanaries: async () => [{ realmId: REALM_ID, kid: 'gone' }],
      getWrappedKey: async () => undefined,
    };
    await expect(checkKeyCustody(kek, vanished)).resolves.toBeUndefined();
  });
});
