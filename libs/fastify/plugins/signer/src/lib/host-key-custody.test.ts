import { randomBytes } from 'node:crypto';

import { KekUnavailableError, KeyCustodyError } from '@qauth-labs/server-keys';
import {
  createLocalKekProvider,
  type KekProvider,
  sealKeyMaterial,
  type WrappedSignerKey,
} from '@qauth-labs/server-keys/custody';
import { describe, expect, it, vi } from 'vitest';

import { proveHostKeyCustody, proveKeyCustody } from './host-key-custody';
import type { KekCanaryStore } from './key-custody-check';

/** The break-glass CLI's start check (#602): the host's KEK opens a stored key. */

const REALM_ID = '0190a5b2-7c3d-7e4f-8a9b-0c1d2e3f4a5b';

function provider(byte: number): KekProvider {
  return createLocalKekProvider({
    env: { KEK: Buffer.alloc(32, byte).toString('base64'), NODE_ENV: 'test' },
    warn: () => undefined,
  });
}

async function storedKey(sealer: KekProvider, kid = 'canary-kid'): Promise<WrappedSignerKey> {
  const identity = {
    realmId: REALM_ID,
    purpose: 'token_signing',
    scopeId: null,
    kid,
    algorithm: 'EdDSA',
  } as const;
  const sealed = await sealKeyMaterial(sealer, randomBytes(32), identity);
  return { ...identity, ...sealed, status: 'active' } as WrappedSignerKey;
}

function storeOf(keys: readonly WrappedSignerKey[]): KekCanaryStore {
  return {
    listKekCanaries: vi.fn(async () => keys.map(({ realmId, kid }) => ({ realmId, kid }))),
    getWrappedKey: async (realmId: string, kid: string) =>
      keys.find((key) => key.realmId === realmId && key.kid === kid),
  };
}

describe('proveKeyCustody', () => {
  it('resolves when the KEK opens the stored keys', async () => {
    const kek = provider(0x11);
    await expect(
      proveKeyCustody(kek, storeOf([await storedKey(kek), await storedKey(kek, 'second')]))
    ).resolves.toBeUndefined();
  });

  it('refuses a provider that reports itself unusable', async () => {
    const kek = provider(0x11);
    const down: KekProvider = {
      ...kek,
      health: async () => ({ ok: false, provider: 'local', reason: 'backend down' }),
    };
    await expect(proveKeyCustody(down, storeOf([await storedKey(kek)]))).rejects.toBeInstanceOf(
      KekUnavailableError
    );
  });

  it('refuses a provider whose unwrap fails', async () => {
    const kek = provider(0x11);
    const failing: KekProvider = {
      ...kek,
      unwrap: async () => {
        throw new KekUnavailableError({ cause: new Error('the KMS refused') });
      },
    };
    await expect(proveKeyCustody(failing, storeOf([await storedKey(kek)]))).rejects.toBeInstanceOf(
      KeyCustodyError
    );
  });

  it('refuses a KEK that is not the one the stored keys are wrapped under', async () => {
    const store = storeOf([await storedKey(provider(0x11))]);
    await expect(proveKeyCustody(provider(0x22), store)).rejects.toMatchObject({
      code: 'KEK_UNKNOWN_REF',
    });
  });

  it('refuses when there is no stored key to open: a usable provider alone proves nothing', async () => {
    const kek = provider(0x11);
    await expect(proveKeyCustody(kek, storeOf([]))).rejects.toBeInstanceOf(KekUnavailableError);
    const vanished: KekCanaryStore = {
      listKekCanaries: async () => [{ realmId: REALM_ID, kid: 'gone' }],
      getWrappedKey: async () => undefined,
    };
    await expect(proveKeyCustody(kek, vanished)).rejects.toBeInstanceOf(KekUnavailableError);
  });
});

describe('proveHostKeyCustody', () => {
  it('fails before it reads the database when the environment selects no usable provider', async () => {
    const db = new Proxy(
      {},
      {
        get: () => {
          throw new Error('the database was read');
        },
      }
    );
    await expect(
      proveHostKeyCustody({
        db: db as never,
        kekEnv: { KEK_PROVIDER: 'Not A Name', NODE_ENV: 'production' },
        warn: () => undefined,
      })
    ).rejects.toThrow(/KEK_PROVIDER/);
  });
});
