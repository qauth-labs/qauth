import { describe, expect, it, vi } from 'vitest';

import { PolicyValidationError } from './registry';
import {
  createRealmSecretStore,
  type EncryptedRealmSecret,
  REALM_SECRET_CONTEXT_PREFIX,
  type RealmSecretCipher,
  realmSecretContext,
  realmSecretPaths,
  type RealmSecretStorage,
} from './secret-store';

type Tx = { readonly id: string };

const REALM = '0190a6d4-5b8e-7c3a-9f12-3b4c5d6e7f80';
const OTHER_REALM = '0190a6d4-5b8e-7c3a-9f12-3b4c5d6e7f81';
const PASSWORD = 'smtp-password-that-must-never-be-stored';
const API_KEY = 're_api-key-that-must-never-be-stored';

/** `realm_secrets` in memory: ciphertext or `null` per realm and path. */
function memoryStorage() {
  const rows = new Map<string, EncryptedRealmSecret | null>();
  const keyOf = (realmId: string, path: string) => `${realmId} ${path}`;
  const storage: RealmSecretStorage<Tx> = {
    async read(realmId, path) {
      const key = keyOf(realmId, path);
      return rows.has(key) ? { ciphertext: rows.get(key)?.ciphertext ?? null } : undefined;
    },
    async write(realmId, path, value) {
      rows.set(keyOf(realmId, path), value);
    },
    async insertIfAbsent(realmId, path, value) {
      const key = keyOf(realmId, path);
      if (rows.has(key)) return false;
      rows.set(key, value);
      return true;
    },
  };
  return { storage, rows };
}

/**
 * A stand-in for the signer's `data_at_rest` operations, in its format: the
 * plaintext XORed with a key byte, bound to the realm and the context, so a
 * ciphertext copied to another field or realm does not decrypt.
 */
function fakeCipher(kid = 'kid-1') {
  let nonce = 0;
  const bind = (realmId: string, context: string) => `${realmId}|${context}|`;
  const cipher: RealmSecretCipher = {
    async encrypt({ realmId, plaintext, context }) {
      nonce += 1;
      const body = Buffer.from(bind(realmId, context) + plaintext, 'utf8').map(
        (byte) => byte ^ 0x5a
      );
      const iv = Buffer.alloc(12, nonce).toString('base64url');
      return `v1.${kid}.${iv}.${Buffer.from(body).toString('base64url')}`;
    },
    async decrypt({ realmId, ciphertext, context }) {
      const body = Buffer.from(ciphertext.split('.')[3] ?? '', 'base64url').map(
        (byte) => byte ^ 0x5a
      );
      const text = Buffer.from(body).toString('utf8');
      const prefix = bind(realmId, context);
      if (!text.startsWith(prefix)) throw new Error('ciphertext did not authenticate');
      return text.slice(prefix.length);
    },
  };
  return {
    cipher: { encrypt: vi.fn(cipher.encrypt), decrypt: vi.fn(cipher.decrypt) },
  };
}

function storeOver() {
  const memory = memoryStorage();
  const { cipher } = fakeCipher();
  const store = createRealmSecretStore<Tx>({ storage: memory.storage, cipher });
  return { ...memory, cipher, store };
}

/** Every value the storage holds, as one string. */
const dump = (rows: Map<string, EncryptedRealmSecret | null>) => JSON.stringify([...rows]);

describe('createRealmSecretStore (#529)', () => {
  it('keeps the mail secrets: the SMTP password and the Resend API key', () => {
    expect(realmSecretPaths()).toEqual(['mail.smtp.password', 'mail.resend.apiKey']);
  });

  it('stores only the ciphertext, with the kid it names, and decrypts it for use', async () => {
    const { store, rows, cipher } = storeOver();

    await store.put(REALM, 'mail.smtp.password', PASSWORD);

    const stored = rows.get(`${REALM} mail.smtp.password`);
    expect(stored?.ciphertext).toMatch(/^v1\.kid-1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(stored?.keyId).toBe('kid-1');
    expect(dump(rows)).not.toContain(PASSWORD);
    expect(cipher.encrypt).toHaveBeenCalledWith({
      realmId: REALM,
      plaintext: PASSWORD,
      context: 'realm_secrets:mail.smtp.password',
    });
    expect(await store.isSet(REALM, 'mail.smtp.password')).toBe(true);
    expect(await store.getForUse(REALM, 'mail.smtp.password')).toBe(PASSWORD);
    // Another realm, and the other secret, hold nothing.
    expect(await store.isSet(OTHER_REALM, 'mail.smtp.password')).toBe(false);
    expect(await store.getForUse(REALM, 'mail.resend.apiKey')).toBeUndefined();
  });

  it('binds a ciphertext to its field: one copied to another field does not decrypt', async () => {
    const { store, rows } = storeOver();
    await store.put(REALM, 'mail.smtp.password', PASSWORD);
    rows.set(`${REALM} mail.resend.apiKey`, rows.get(`${REALM} mail.smtp.password`) ?? null);

    await expect(store.getForUse(REALM, 'mail.resend.apiKey')).rejects.toThrow(
      'did not authenticate'
    );
  });

  it('uses a context outside the prefix the delivery role may decrypt', () => {
    expect(REALM_SECRET_CONTEXT_PREFIX.startsWith('delivery:')).toBe(false);
    for (const path of realmSecretPaths()) {
      expect(realmSecretContext(path)).toBe(`realm_secrets:${path}`);
    }
  });

  it('clears a secret to a row that holds none', async () => {
    const { store, rows } = storeOver();
    await store.put(REALM, 'mail.smtp.password', PASSWORD);

    await store.put(REALM, 'mail.smtp.password', null);

    expect(rows.get(`${REALM} mail.smtp.password`)).toBeNull();
    expect(await store.isSet(REALM, 'mail.smtp.password')).toBe(false);
    expect(await store.getForUse(REALM, 'mail.smtp.password')).toBeUndefined();
  });

  it('refuses a path that is not a secret field, naming neither the path nor a value', async () => {
    const { store, rows } = storeOver();
    for (const path of ['mail.smtp.host', 'mail.provider', PASSWORD, '']) {
      for (const call of [
        () => store.put(REALM, path, PASSWORD),
        () => store.isSet(REALM, path),
        () => store.getForUse(REALM, path),
      ]) {
        const refused = await call().catch((error: unknown) => error);
        expect(refused).toBeInstanceOf(TypeError);
        expect((refused as Error).message).not.toContain(PASSWORD);
      }
    }
    expect(rows.size).toBe(0);
  });

  it('refuses a value its field refuses, without repeating it, and stores nothing', async () => {
    const { store, rows, cipher } = storeOver();
    for (const value of ['', 'x'.repeat(1025), 42 as unknown as string]) {
      const refused = await store
        .put(REALM, 'mail.smtp.password', value)
        .catch((error: unknown) => error);
      expect(refused).toBeInstanceOf(PolicyValidationError);
      expect((refused as PolicyValidationError).issues).toEqual([
        { path: 'mail.smtp.password', message: expect.any(String) },
      ]);
      expect(JSON.stringify(refused)).not.toContain('x'.repeat(1025));
    }
    expect(cipher.encrypt).not.toHaveBeenCalled();
    expect(rows.size).toBe(0);
  });

  it('stores nothing when the cipher hands back something that is not a ciphertext', async () => {
    const memory = memoryStorage();
    const store = createRealmSecretStore<Tx>({
      storage: memory.storage,
      cipher: {
        encrypt: async ({ plaintext }) => plaintext,
        decrypt: async () => {
          throw new Error('unused');
        },
      },
    });

    const refused = await store
      .put(REALM, 'mail.smtp.password', PASSWORD)
      .catch((error: unknown) => error);

    expect(refused).toBeInstanceOf(Error);
    expect((refused as Error).message).not.toContain(PASSWORD);
    expect(memory.rows.size).toBe(0);
  });

  it('passes the transaction through to the storage', async () => {
    const memory = memoryStorage();
    const write = vi.spyOn(memory.storage, 'write');
    const read = vi.spyOn(memory.storage, 'read');
    const store = createRealmSecretStore<Tx>({
      storage: memory.storage,
      cipher: fakeCipher().cipher,
    });
    const tx = { id: 'tx-1' };

    await store.put(REALM, 'mail.smtp.password', PASSWORD, tx);
    await store.isSet(REALM, 'mail.smtp.password', tx);

    expect(write).toHaveBeenCalledWith(REALM, 'mail.smtp.password', expect.any(Object), tx);
    expect(read).toHaveBeenCalledWith(REALM, 'mail.smtp.password', tx);
  });

  describe('seed', () => {
    const seeds = new Map([['mail.smtp.password', PASSWORD]]);

    it('seeds a set secret and records an unset one, once', async () => {
      const { store, rows, cipher } = storeOver();

      expect(await store.seed(REALM, seeds)).toEqual({
        seeded: ['mail.smtp.password'],
        recordedUnset: ['mail.resend.apiKey'],
        present: [],
        leftWithoutRow: [],
      });
      expect(await store.getForUse(REALM, 'mail.smtp.password')).toBe(PASSWORD);
      expect(rows.get(`${REALM} mail.resend.apiKey`)).toBeNull();
      expect(dump(rows)).not.toContain(PASSWORD);

      // The next boot finds both rows, encrypts nothing and changes nothing,
      // even when the environment now sets the other key too.
      cipher.encrypt.mockClear();
      const again = await store.seed(
        REALM,
        new Map([
          ['mail.smtp.password', 'a-new-password-in-the-environment'],
          ['mail.resend.apiKey', API_KEY],
        ])
      );
      expect(again).toEqual({
        seeded: [],
        recordedUnset: [],
        present: ['mail.smtp.password', 'mail.resend.apiKey'],
        leftWithoutRow: [],
      });
      expect(cipher.encrypt).not.toHaveBeenCalled();
      expect(await store.getForUse(REALM, 'mail.smtp.password')).toBe(PASSWORD);
      expect(await store.isSet(REALM, 'mail.resend.apiKey')).toBe(false);
    });

    it('leaves a needed secret the environment lacks without a row, so a later boot still seeds it', async () => {
      const { store, rows } = storeOver();
      const needed = new Set(['mail.smtp.password']);

      expect(await store.seed(REALM, new Map(), { leaveWithoutRow: needed })).toEqual({
        seeded: [],
        recordedUnset: ['mail.resend.apiKey'],
        present: [],
        leftWithoutRow: ['mail.smtp.password'],
      });
      expect(rows.has(`${REALM} mail.smtp.password`)).toBe(false);

      // The next boot's environment sets it: it is stored then.
      expect(await store.seed(REALM, seeds, { leaveWithoutRow: needed })).toEqual({
        seeded: ['mail.smtp.password'],
        recordedUnset: [],
        present: ['mail.resend.apiKey'],
        leftWithoutRow: [],
      });
      expect(await store.getForUse(REALM, 'mail.smtp.password')).toBe(PASSWORD);
    });

    it('never seeds a secret an admin changed or cleared', async () => {
      const { store } = storeOver();
      await store.seed(REALM, seeds);
      await store.put(REALM, 'mail.smtp.password', 'changed-by-an-admin');
      await store.seed(REALM, seeds);
      expect(await store.getForUse(REALM, 'mail.smtp.password')).toBe('changed-by-an-admin');

      await store.put(REALM, 'mail.smtp.password', null);
      await store.seed(REALM, seeds);
      expect(await store.isSet(REALM, 'mail.smtp.password')).toBe(false);
    });

    it('leaves the row another node seeded first', async () => {
      const memory = memoryStorage();
      const store = createRealmSecretStore<Tx>({
        storage: {
          ...memory.storage,
          // The other node's insert lands between this node's read and its own.
          insertIfAbsent: async (realmId, path, value, tx) => {
            await memory.storage.insertIfAbsent(realmId, path, null, tx);
            return memory.storage.insertIfAbsent(realmId, path, value, tx);
          },
        },
        cipher: fakeCipher().cipher,
      });

      expect(await store.seed(REALM, seeds)).toEqual({
        seeded: [],
        recordedUnset: [],
        present: ['mail.smtp.password', 'mail.resend.apiKey'],
        leftWithoutRow: [],
      });
      expect(await store.isSet(REALM, 'mail.smtp.password')).toBe(false);
    });

    it('refuses a seed value its field refuses, naming the path only', async () => {
      const { store, rows } = storeOver();
      const refused = await store
        .seed(REALM, new Map([['mail.smtp.password', 'x'.repeat(2000)]]))
        .catch((error: unknown) => error);
      expect(refused).toBeInstanceOf(PolicyValidationError);
      expect(JSON.stringify(refused)).not.toContain('x'.repeat(2000));
      expect(rows.has(`${REALM} mail.smtp.password`)).toBe(false);
    });
  });
});
