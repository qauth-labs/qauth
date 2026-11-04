import { createPrivateKey } from 'node:crypto';

import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

import { KEK_A, localProvider } from '../testing/keks';
import { createMemoryKeyStore, type MemoryKeyStore } from '../testing/memory-key-store';
import { openKeyMaterial } from './envelope';
import type { KekProvider } from './kek-provider';
import {
  ActiveKeyConflictError,
  type KeyChangeRefusalReason,
  KeyChangeRefusedError,
  KeyCreationRefusedError,
  KeyIdConflictError,
  NextKeyConflictError,
} from './key-creation-errors';
import { createKeyFactory, type KeyFactoryOptions, MAX_SCOPE_ID_LENGTH } from './key-factory';
import { KEY_PURPOSES, type KeyPurpose } from './key-purposes';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const NOW = 1_800_000_000_000;
const ED25519_ONLY: readonly SignatureAlgorithm[] = ['EdDSA'];
const HYBRID_CAPABLE: readonly SignatureAlgorithm[] = ['EdDSA', 'ML-DSA-65'];
const DAY_MS = 86_400_000;

type FactoryOverrides = Partial<Omit<KeyFactoryOptions<unknown>, 'store' | 'kekProvider'>> & {
  store?: MemoryKeyStore;
};

function setup(overrides: FactoryOverrides = {}) {
  const store = overrides.store ?? createMemoryKeyStore();
  // The local provider is frozen, so the wrap count comes from a delegate.
  const inner = localProvider({ KEK: KEK_A });
  const wrap = vi.fn(inner.wrap);
  const kekProvider: KekProvider = { ...inner, wrap };
  const factory = createKeyFactory({
    enabledSignatureAlgorithms: ED25519_ONLY,
    hybridSigning: false,
    now: () => NOW,
    ...overrides,
    store,
    kekProvider,
  });
  return { factory, store, kekProvider, wrap };
}

/** A scope id for a scoped purpose, none for the others. */
function scopeFor(purpose: KeyPurpose): string | undefined {
  return KEY_PURPOSES[purpose].scoped ? 'subscription-1' : undefined;
}

describe('createKey', () => {
  it('stores one sealed active key, published with its public JWK', async () => {
    const { factory, store } = setup();

    const [key, ...rest] = await factory.createKey({ realmId: REALM, purpose: 'token_signing' });

    expect(rest).toEqual([]);
    expect(key).toMatchObject({
      realmId: REALM,
      purpose: 'token_signing',
      scopeId: null,
      algorithm: 'EdDSA',
      status: 'active',
      pairId: null,
      publishAt: NOW,
      activateAt: NOW,
    });
    expect(key.publicJwk).toMatchObject({ kty: 'OKP', alg: 'EdDSA', use: 'sig', kid: key.kid });

    expect(store.rows).toHaveLength(1);
    const [row] = store.rows;
    expect(row.key).toMatchObject({
      realmId: REALM,
      purpose: 'token_signing',
      scopeId: null,
      algorithm: 'EdDSA',
      kid: key.kid,
      status: 'active',
      pairId: null,
      publishAt: NOW,
      activateAt: NOW,
    });
    expect(row.publicJwk).toEqual(key.publicJwk);
  });

  it('seals the material so it opens only with the KEK and the row identity, as PKCS#8', async () => {
    const { factory, store, kekProvider } = setup();
    await factory.createKey({ realmId: REALM, purpose: 'event_signing' });
    const { key } = store.rows[0];

    const material = await openKeyMaterial(kekProvider, key, key);

    const privateKey = createPrivateKey({ key: material, format: 'der', type: 'pkcs8' });
    expect(privateKey.asymmetricKeyType).toBe('ed25519');
    expect(key.ciphertext.includes(material.subarray(0, 16))).toBe(false);
    await expect(
      openKeyMaterial(kekProvider, key, { ...key, purpose: 'token_signing' })
    ).rejects.toMatchObject({ code: 'KEY_DECRYPTION_FAILED' });
  });

  it('stores a symmetric key unpublished, with no public JWK', async () => {
    const { factory, store } = setup();

    const [key] = await factory.createKey({ realmId: REALM, purpose: 'cookie_hmac' });

    expect(key).toMatchObject({ algorithm: 'HS256', publishAt: null, activateAt: NOW });
    expect(key.publicJwk).toBeUndefined();
    expect(store.rows[0].publicJwk).toBeUndefined();
    expect(store.rows[0].key.publishAt).toBeNull();
  });

  it('creates a next key published ahead of activation', async () => {
    const { factory, store } = setup();

    const [key] = await factory.createKey({
      realmId: REALM,
      purpose: 'token_signing',
      status: 'next',
    });

    expect(key).toMatchObject({ status: 'next', publishAt: NOW, activateAt: null });
    expect(store.rows[0].key).toMatchObject({ status: 'next', activateAt: null });
  });

  it('takes the algorithm the caller names, within the purpose', async () => {
    const { factory } = setup();

    const [key] = await factory.createKey({
      realmId: REALM,
      purpose: 'token_signing',
      algorithm: 'RS256',
    });

    expect(key.algorithm).toBe('RS256');
    expect(key.publicJwk).toMatchObject({ kty: 'RSA', alg: 'RS256' });
  });

  it('stores a scoped key under its scope id', async () => {
    const { factory, store } = setup();

    const [key] = await factory.createKey({
      realmId: REALM,
      purpose: 'webhook_signing',
      scopeId: 'subscription-1',
    });

    expect(key).toMatchObject({ scopeId: 'subscription-1', algorithm: 'HS256' });
    expect(store.rows[0].key.scopeId).toBe('subscription-1');
  });

  it('runs in the caller’s transaction when given one', async () => {
    const { factory, store } = setup();
    const outer = { id: 99 };

    await factory.createKey({ realmId: REALM, purpose: 'cookie_hmac', tx: outer });

    expect(store.outerTransactions).toEqual([outer]);
  });

  it.each(
    (Object.keys(KEY_PURPOSES) as KeyPurpose[]).filter((purpose) => purpose !== 'trust_anchor')
  )('creates a %s key in a standard deployment', async (purpose) => {
    const { factory, store } = setup();

    const [key] = await factory.createKey({
      realmId: REALM,
      purpose,
      scopeId: scopeFor(purpose),
    });

    const definition = KEY_PURPOSES[purpose];
    expect(key.algorithm).toBe(definition.defaultAlgorithm);
    expect(store.rows).toHaveLength(1);
    expect(store.rows[0].publicJwk !== undefined).toBe(definition.published);
  });

  describe('with hybrid signing on', () => {
    const hybrid = { enabledSignatureAlgorithms: HYBRID_CAPABLE, hybridSigning: true };

    it('creates the Ed25519 and ML-DSA-65 token keys as a pair with one pair_id', async () => {
      const { factory, store } = setup(hybrid);

      const keys = await factory.createKey({ realmId: REALM, purpose: 'token_signing' });

      expect(keys.map((key) => key.algorithm)).toEqual(['EdDSA', 'ML-DSA-65']);
      const [ed25519, mlDsa] = keys;
      expect(ed25519.pairId).toMatch(/^[0-9a-f-]{36}$/);
      expect(mlDsa.pairId).toBe(ed25519.pairId);
      expect(ed25519.kid).not.toBe(mlDsa.kid);
      expect(mlDsa.publicJwk).toMatchObject({ kty: 'AKP', alg: 'ML-DSA-65', kid: mlDsa.kid });
      expect(store.rows.map((row) => row.key.pairId)).toEqual([ed25519.pairId, ed25519.pairId]);
      expect(store.rows.map((row) => row.key.status)).toEqual(['active', 'active']);
    });

    it('writes both keys of the pair in one transaction', async () => {
      const { factory, store } = setup({
        ...hybrid,
        store: createMemoryKeyStore({
          beforeCreate: (_input, index) => {
            if (index === 1) throw new Error('second insert fails');
          },
        }),
      });

      await expect(factory.createKey({ realmId: REALM, purpose: 'token_signing' })).rejects.toThrow(
        'second insert fails'
      );
      expect(store.rows).toEqual([]);
    });

    it('creates one key for a purpose with no hybrid companion', async () => {
      const { factory, store } = setup(hybrid);

      const keys = await factory.createKey({ realmId: REALM, purpose: 'event_signing' });

      expect(keys).toHaveLength(1);
      expect(keys[0].pairId).toBeNull();
      expect(store.rows).toHaveLength(1);
    });

    it('creates one key for an RS256 token key', async () => {
      const { factory } = setup(hybrid);

      const keys = await factory.createKey({
        realmId: REALM,
        purpose: 'token_signing',
        algorithm: 'RS256',
      });

      expect(keys.map((key) => [key.algorithm, key.pairId])).toEqual([['RS256', null]]);
    });

    it('refuses an ML-DSA-65 key on its own', async () => {
      const { factory, store } = setup(hybrid);

      await expect(
        factory.createKey({ realmId: REALM, purpose: 'token_signing', algorithm: 'ML-DSA-65' })
      ).rejects.toMatchObject({ reason: 'HYBRID_COMPANION_ONLY' });
      expect(store.rows).toEqual([]);
    });
  });

  it('leaves hybrid signing off unless the switch is the boolean true', async () => {
    const { factory } = setup({ hybridSigning: 'false' as unknown as boolean });

    const keys = await factory.createKey({ realmId: REALM, purpose: 'token_signing' });

    expect(keys.map((key) => key.algorithm)).toEqual(['EdDSA']);
  });

  it('creates one token key with hybrid signing off', async () => {
    const { factory, store } = setup({
      enabledSignatureAlgorithms: HYBRID_CAPABLE,
      hybridSigning: false,
    });

    const keys = await factory.createKey({ realmId: REALM, purpose: 'token_signing' });

    expect(keys.map((key) => [key.algorithm, key.pairId])).toEqual([['EdDSA', null]]);
    expect(store.rows).toHaveLength(1);
  });

  describe('trust_anchor', () => {
    it('is refused by default, before any key is generated or stored', async () => {
      const { factory, store, wrap } = setup();

      const attempt = factory.createKey({ realmId: REALM, purpose: 'trust_anchor' });

      await expect(attempt).rejects.toBeInstanceOf(KeyCreationRefusedError);
      await expect(attempt).rejects.toMatchObject({ reason: 'FEDERATION_OPERATOR_ONLY' });
      expect(wrap).not.toHaveBeenCalled();
      expect(store.calls).toEqual([]);
    });

    it('is refused when the federation-operator switch is off', async () => {
      const { factory } = setup({ federationOperator: false });

      await expect(
        factory.createKey({ realmId: REALM, purpose: 'trust_anchor' })
      ).rejects.toMatchObject({ reason: 'FEDERATION_OPERATOR_ONLY' });
    });

    it('is refused when the switch arrives as a string from an untyped path', async () => {
      const { factory } = setup({ federationOperator: 'true' as unknown as boolean });

      await expect(
        factory.createKey({ realmId: REALM, purpose: 'trust_anchor' })
      ).rejects.toMatchObject({ reason: 'FEDERATION_OPERATOR_ONLY' });
    });

    it('is created when the federation-operator switch is on', async () => {
      const { factory, store } = setup({ federationOperator: true });

      const [key] = await factory.createKey({ realmId: REALM, purpose: 'trust_anchor' });

      expect(key).toMatchObject({ purpose: 'trust_anchor', algorithm: 'RS256' });
      expect(store.rows).toHaveLength(1);
    });
  });

  describe('SIGNING_ALGORITHM_MODE', () => {
    it('refuses an algorithm the mode does not enable', async () => {
      const { factory, store, wrap } = setup({ enabledSignatureAlgorithms: [] });

      const attempt = factory.createKey({ realmId: REALM, purpose: 'token_signing' });

      await expect(attempt).rejects.toBeInstanceOf(KeyCreationRefusedError);
      await expect(attempt).rejects.toMatchObject({ reason: 'ALGORITHM_NOT_ENABLED' });
      expect(wrap).not.toHaveBeenCalled();
      expect(store.rows).toEqual([]);
    });

    it('refuses ML-DSA-65 under ed25519', async () => {
      const { factory } = setup();

      await expect(
        factory.createKey({ realmId: REALM, purpose: 'token_signing', algorithm: 'ML-DSA-65' })
      ).rejects.toMatchObject({ reason: 'ALGORITHM_NOT_ENABLED' });
    });

    it('refuses hybrid signing when the mode does not enable ML-DSA-65', () => {
      expect(() =>
        createKeyFactory({
          store: createMemoryKeyStore(),
          kekProvider: localProvider({ KEK: KEK_A }),
          enabledSignatureAlgorithms: ED25519_ONLY,
          hybridSigning: true,
        })
      ).toThrow(InvalidConfigurationError);
    });
  });

  it('refuses an algorithm the purpose does not allow', async () => {
    const { factory } = setup();

    await expect(
      factory.createKey({ realmId: REALM, purpose: 'token_signing', algorithm: 'ES256' })
    ).rejects.toMatchObject({ reason: 'ALGORITHM_NOT_ALLOWED' });
    await expect(
      factory.createKey({ realmId: REALM, purpose: 'oid4vp_request_signing', algorithm: 'EdDSA' })
    ).rejects.toMatchObject({ reason: 'ALGORITHM_NOT_ALLOWED' });
  });

  it.each(['', 'realm-1', '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e0'])(
    'refuses a realm id that is not a UUID (%j) before generating a key',
    async (realmId) => {
      const { factory, wrap } = setup();

      await expect(factory.createKey({ realmId, purpose: 'cookie_hmac' })).rejects.toMatchObject({
        reason: 'INVALID_REALM_ID',
      });
      expect(wrap).not.toHaveBeenCalled();
    }
  );

  it('stores an upper-case realm id in lowercase, so the key opens from its stored row', async () => {
    const { factory, store, kekProvider } = setup();

    const [created] = await factory.createKey({
      realmId: REALM.toUpperCase(),
      purpose: 'event_signing',
    });

    expect(created.realmId).toBe(REALM);
    const { key } = store.rows[0];
    expect(key.realmId).toBe(REALM);
    // Postgres returns the uuid column in lowercase.
    const material = await openKeyMaterial(kekProvider, key, { ...key, realmId: REALM });
    expect(material.length).toBeGreaterThan(0);
  });

  it('refuses an unknown purpose', async () => {
    const { factory } = setup();

    await expect(
      factory.createKey({ realmId: REALM, purpose: 'session_signing' as KeyPurpose })
    ).rejects.toMatchObject({ reason: 'UNKNOWN_PURPOSE' });
  });

  describe('scope ids', () => {
    it('are required by a scoped purpose', async () => {
      const { factory } = setup();

      await expect(
        factory.createKey({ realmId: REALM, purpose: 'webhook_signing' })
      ).rejects.toMatchObject({ reason: 'SCOPE_REQUIRED' });
    });

    it('are refused by an unscoped purpose', async () => {
      const { factory } = setup();

      await expect(
        factory.createKey({ realmId: REALM, purpose: 'token_signing', scopeId: 'x' })
      ).rejects.toMatchObject({ reason: 'SCOPE_NOT_ALLOWED' });
    });

    it.each([
      '',
      'x'.repeat(MAX_SCOPE_ID_LENGTH + 1),
      'provider-' + String.fromCharCode(0xd800),
      'provider\u0000',
    ])('are refused when empty, too long or not well-formed (%#)', async (scopeId) => {
      const { factory, wrap } = setup();

      await expect(
        factory.createKey({ realmId: REALM, purpose: 'upstream_client_assertion', scopeId })
      ).rejects.toMatchObject({ reason: 'INVALID_SCOPE_ID' });
      expect(wrap).not.toHaveBeenCalled();
    });
  });

  describe('the secret of a webhook subscription', () => {
    it('is returned once, in the Standard Webhooks form, and is the sealed material', async () => {
      const { factory, store, kekProvider } = setup();

      const [key] = await factory.createKey({
        realmId: REALM,
        purpose: 'webhook_signing',
        scopeId: 'subscription-1',
      });

      expect(key.secret).toMatch(/^whsec_[A-Za-z0-9+/]{43}=$/);
      const secret = Buffer.from((key.secret as string).slice('whsec_'.length), 'base64');
      expect(secret).toHaveLength(32);
      const { key: row } = store.rows[0];
      expect(await openKeyMaterial(kekProvider, row, row)).toEqual(secret);
      expect(row).not.toHaveProperty('secret');
      expect(JSON.stringify(row)).not.toContain(secret.toString('base64'));
    });

    it('is new for the next secret of a rotation', async () => {
      const { factory } = setup();
      const input = { realmId: REALM, purpose: 'webhook_signing', scopeId: 'sub-1' } as const;

      const [first] = await factory.createKey(input);
      const [next] = await factory.createKey({ ...input, status: 'next' });

      expect(next.secret).toMatch(/^whsec_/);
      expect(next.secret).not.toBe(first.secret);
    });

    it.each(
      (Object.keys(KEY_PURPOSES) as KeyPurpose[]).filter(
        (purpose) => purpose !== 'trust_anchor' && purpose !== 'webhook_signing'
      )
    )('is never returned for a %s key', async (purpose) => {
      const { factory } = setup();

      const [key] = await factory.createKey({
        realmId: REALM,
        purpose,
        scopeId: scopeFor(purpose),
      });

      expect(key).not.toHaveProperty('secret');
    });
  });

  describe('a second next key', () => {
    it('is refused before the insert, for the same realm, purpose, scope and algorithm', async () => {
      const { factory, store } = setup();
      const input = {
        realmId: REALM,
        purpose: 'upstream_client_assertion',
        scopeId: 'idp-1',
        status: 'next',
      } as const;
      await factory.createKey(input);

      const attempt = factory.createKey(input);

      await expect(attempt).rejects.toBeInstanceOf(NextKeyConflictError);
      await expect(attempt).rejects.toMatchObject({
        purpose: 'upstream_client_assertion',
        algorithm: 'RS256',
      });
      expect(store.rows).toHaveLength(1);
    });

    it('is allowed beside another scope or algorithm', async () => {
      const { factory, store } = setup();
      const input = {
        realmId: REALM,
        purpose: 'upstream_client_assertion',
        scopeId: 'idp-1',
        status: 'next',
      } as const;
      await factory.createKey(input);

      await factory.createKey({ ...input, scopeId: 'idp-2' });
      await factory.createKey({ ...input, algorithm: 'ES256' });

      expect(store.rows).toHaveLength(3);
    });
  });

  it('records when the key was created, by its own clock', async () => {
    const { factory, store } = setup();

    const [key] = await factory.createKey({ realmId: REALM, purpose: 'cookie_hmac' });

    expect(key.createdAt).toBe(NOW);
    expect(store.rows[0].key.createdAt).toBe(NOW);
  });

  describe('a second active key', () => {
    it('is refused before the insert, for the same realm, purpose, scope and algorithm', async () => {
      const { factory, store } = setup();
      const input = { realmId: REALM, purpose: 'webhook_signing', scopeId: 'sub-1' } as const;
      await factory.createKey(input);

      const attempt = factory.createKey(input);

      await expect(attempt).rejects.toBeInstanceOf(ActiveKeyConflictError);
      await expect(attempt).rejects.toMatchObject({
        purpose: 'webhook_signing',
        algorithm: 'HS256',
      });
      expect(store.rows).toHaveLength(1);
      expect(store.calls.filter((call) => call.method === 'create')).toHaveLength(1);
    });

    it('is allowed as next, and beside another scope or algorithm', async () => {
      const { factory, store } = setup();
      await factory.createKey({ realmId: REALM, purpose: 'webhook_signing', scopeId: 'sub-1' });

      await factory.createKey({
        realmId: REALM,
        purpose: 'webhook_signing',
        scopeId: 'sub-1',
        status: 'next',
      });
      await factory.createKey({ realmId: REALM, purpose: 'webhook_signing', scopeId: 'sub-2' });
      await factory.createKey({ realmId: REALM, purpose: 'token_signing' });
      await factory.createKey({ realmId: REALM, purpose: 'token_signing', algorithm: 'RS256' });

      expect(store.rows).toHaveLength(5);
    });
  });

  it('rejects a kid the realm already holds before the insert', async () => {
    const store = createMemoryKeyStore({ everyKidTaken: true });
    const { factory } = setup({ store });

    const attempt = factory.createKey({ realmId: REALM, purpose: 'token_signing' });

    await expect(attempt).rejects.toBeInstanceOf(KeyIdConflictError);
    expect(store.calls.map((call) => call.method)).toEqual(['transaction', 'findByKid']);
    expect(store.rows).toEqual([]);
  });

  it('checks every kid of a hybrid pair before inserting either key', async () => {
    const store = createMemoryKeyStore();
    const findByKid = store.findByKid.bind(store);
    let lookups = 0;
    store.findByKid = async (realmId, kid, tx) => {
      lookups += 1;
      return lookups === 2 ? { realmId, kid } : findByKid(realmId, kid, tx);
    };
    const { factory } = setup({
      store,
      enabledSignatureAlgorithms: HYBRID_CAPABLE,
      hybridSigning: true,
    });

    await expect(
      factory.createKey({ realmId: REALM, purpose: 'token_signing' })
    ).rejects.toBeInstanceOf(KeyIdConflictError);
    expect(store.calls.map((call) => call.method)).not.toContain('create');
  });
});

describe('provisionRealmKeys', () => {
  it('creates the four standard keys in one transaction', async () => {
    const { factory, store } = setup();

    const keys = await factory.provisionRealmKeys(REALM);

    expect(keys.map((key) => [key.purpose, key.algorithm, key.status])).toEqual([
      ['token_signing', 'EdDSA', 'active'],
      ['event_signing', 'EdDSA', 'active'],
      ['cookie_hmac', 'HS256', 'active'],
      ['data_at_rest', 'A256GCM', 'active'],
    ]);
    expect(store.rows).toHaveLength(4);
    expect(store.calls.filter((call) => call.method === 'transaction')).toHaveLength(1);
    const txIds = new Set(
      store.calls.filter((call) => call.method !== 'transaction').map((call) => call.tx?.id)
    );
    expect(txIds.size).toBe(1);
  });

  it('adds the ML-DSA-65 token key as a pair when hybrid signing is on', async () => {
    const { factory } = setup({ enabledSignatureAlgorithms: HYBRID_CAPABLE, hybridSigning: true });

    const keys = await factory.provisionRealmKeys(REALM);

    expect(keys.map((key) => [key.purpose, key.algorithm])).toEqual([
      ['token_signing', 'EdDSA'],
      ['token_signing', 'ML-DSA-65'],
      ['event_signing', 'EdDSA'],
      ['cookie_hmac', 'HS256'],
      ['data_at_rest', 'A256GCM'],
    ]);
    expect(keys[0].pairId).not.toBeNull();
    expect(keys[1].pairId).toBe(keys[0].pairId);
  });

  it('leaves a complete hybrid pair alone when called again', async () => {
    const { factory, store } = setup({
      enabledSignatureAlgorithms: HYBRID_CAPABLE,
      hybridSigning: true,
    });
    await factory.provisionRealmKeys(REALM);

    expect(await factory.provisionRealmKeys(REALM)).toEqual([]);
    expect(store.rows).toHaveLength(5);
  });

  it('refuses a realm whose token key has no ML-DSA-65 half once hybrid signing is on', async () => {
    const store = createMemoryKeyStore();
    await setup({ store }).factory.provisionRealmKeys(REALM);
    const { factory, wrap } = setup({
      store,
      enabledSignatureAlgorithms: HYBRID_CAPABLE,
      hybridSigning: true,
    });

    await expect(factory.provisionRealmKeys(REALM)).rejects.toMatchObject({
      reason: 'HYBRID_PAIR_INCOMPLETE',
    });
    expect(wrap).not.toHaveBeenCalled();
    expect(store.rows).toHaveLength(4);
  });

  it('refuses a realm whose token key has no Ed25519 half with hybrid signing on', async () => {
    const store = createMemoryKeyStore();
    const loneMlDsa = {
      realmId: REALM,
      purpose: 'token_signing',
      scopeId: null,
      algorithm: 'ML-DSA-65',
      kid: 'lone-ml-dsa',
      status: 'active',
      pairId: null,
      ciphertext: Buffer.alloc(48),
      iv: Buffer.alloc(12),
      wrappedDek: Buffer.alloc(61),
      kekRef: 'ref',
      aadVersion: 1,
      publishAt: null,
      activateAt: NOW,
      createdAt: NOW,
    } as const;
    await store.create({ key: loneMlDsa }, { id: 0 });
    const { factory } = setup({
      store,
      enabledSignatureAlgorithms: HYBRID_CAPABLE,
      hybridSigning: true,
    });

    await expect(factory.provisionRealmKeys(REALM)).rejects.toMatchObject({
      reason: 'HYBRID_PAIR_INCOMPLETE',
    });
    expect(store.rows).toHaveLength(1);
  });

  it('creates none of the keys when one cannot be stored', async () => {
    const store = createMemoryKeyStore({
      beforeCreate: (input) => {
        if (input.key.purpose === 'cookie_hmac') throw new Error('insert failed');
      },
    });
    const { factory } = setup({ store });

    await expect(factory.provisionRealmKeys(REALM)).rejects.toThrow('insert failed');
    expect(store.rows).toEqual([]);
  });

  it('creates only the standard keys a realm lacks, so it is safe to repeat', async () => {
    const { factory, store } = setup();
    await factory.createKey({ realmId: REALM, purpose: 'token_signing' });
    await factory.createKey({ realmId: REALM, purpose: 'cookie_hmac' });

    const keys = await factory.provisionRealmKeys(REALM);

    expect(keys.map((key) => key.purpose)).toEqual(['event_signing', 'data_at_rest']);
    expect(await factory.provisionRealmKeys(REALM)).toEqual([]);
    expect(store.rows).toHaveLength(4);
  });

  it('still creates the default token key beside an RS256 one', async () => {
    const { factory } = setup();
    await factory.createKey({ realmId: REALM, purpose: 'token_signing', algorithm: 'RS256' });

    const keys = await factory.provisionRealmKeys(REALM);

    expect(keys[0]).toMatchObject({ purpose: 'token_signing', algorithm: 'EdDSA' });
  });

  it.each(['', 'realm-1', '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e0'])(
    'refuses a realm id that is not a UUID (%j) before reading the store',
    async (realmId) => {
      const { factory, store } = setup();

      await expect(factory.provisionRealmKeys(realmId)).rejects.toMatchObject({
        reason: 'INVALID_REALM_ID',
      });
      expect(store.calls).toEqual([]);
    }
  );

  it('finds the keys of a realm named in upper case', async () => {
    const { factory, store } = setup();

    await factory.provisionRealmKeys(REALM.toUpperCase());

    expect(await factory.provisionRealmKeys(REALM)).toEqual([]);
    expect(store.rows.map((row) => row.key.realmId)).toEqual([REALM, REALM, REALM, REALM]);
  });

  it('runs in the caller’s transaction when given one', async () => {
    const { factory, store } = setup();
    const outer = { id: 42 };

    await factory.provisionRealmKeys(REALM, { tx: outer });

    expect(store.outerTransactions).toEqual([outer]);
  });
});

describe('activateNextKey', () => {
  /** A factory whose clock a test moves, with one active key and one next key in a scope. */
  async function rotating(
    purpose: 'webhook_signing' | 'upstream_client_assertion',
    overrides: FactoryOverrides = {}
  ) {
    let clock = NOW;
    const context = setup({ now: () => clock, ...overrides });
    const scope = { realmId: REALM, purpose, scopeId: 'scope-1' } as const;
    const [old] = await context.factory.createKey(scope);
    clock += DAY_MS;
    const [next] = await context.factory.createKey({ ...scope, status: 'next' });
    return {
      ...context,
      scope,
      old,
      next,
      advance: (ms: number) => {
        clock += ms;
      },
      statusOf: (kid: string) => context.store.rows.find((row) => row.key.kid === kid)?.key,
    };
  }

  async function refusalOf(promise: Promise<unknown>): Promise<KeyChangeRefusalReason> {
    const error = await promise.then(
      () => undefined,
      (caught: unknown) => caught
    );
    expect(error).toBeInstanceOf(KeyChangeRefusedError);
    return (error as KeyChangeRefusedError).reason;
  }

  it('refuses before the next key has been published for the prepublish window', async () => {
    const { factory, scope, next, old, advance, statusOf } = await rotating(
      'upstream_client_assertion'
    );
    advance(7 * DAY_MS - 1);

    const error = await factory.activateNextKey(scope).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(KeyChangeRefusedError);
    expect(error).toMatchObject({
      reason: 'OVERLAP_NOT_ELAPSED',
      statusCode: 409,
      notBefore: NOW + DAY_MS + 7 * DAY_MS,
    });
    expect(statusOf(next.kid)?.status).toBe('next');
    expect(statusOf(old.kid)?.status).toBe('active');
  });

  it('switches an upstream key after the window and keeps the old one published for the retention', async () => {
    const { factory, scope, next, old, advance, statusOf } = await rotating(
      'upstream_client_assertion'
    );
    advance(7 * DAY_MS);
    const switchAt = NOW + 8 * DAY_MS;

    const result = await factory.activateNextKey(scope);

    expect(result).toEqual({
      activatedKid: next.kid,
      retiredKid: old.kid,
      activateAt: switchAt,
      unpublishAt: switchAt + 14 * DAY_MS,
    });
    expect(statusOf(next.kid)).toMatchObject({ status: 'active', activateAt: switchAt });
    expect(statusOf(old.kid)).toMatchObject({
      status: 'retired',
      retireAt: switchAt,
      unpublishAt: switchAt + 14 * DAY_MS,
    });
  });

  it('switches a webhook secret after the window, with no JWKS window to keep', async () => {
    const { factory, scope, next, old, advance, statusOf } = await rotating('webhook_signing');
    await expect(refusalOf(factory.activateNextKey(scope))).resolves.toBe('OVERLAP_NOT_ELAPSED');
    advance(7 * DAY_MS);

    const result = await factory.activateNextKey(scope);

    expect(result).toMatchObject({
      activatedKid: next.kid,
      retiredKid: old.kid,
      unpublishAt: null,
    });
    expect(statusOf(old.kid)).toMatchObject({ status: 'retired', unpublishAt: null });
    expect(statusOf(next.kid)?.status).toBe('active');
  });

  it('takes its windows from the options', async () => {
    const { factory, scope, old, statusOf } = await rotating('upstream_client_assertion', {
      prepublishMs: 0,
      retiredRetentionMs: 1_000,
    });

    const result = await factory.activateNextKey(scope);

    expect(result.unpublishAt).toBe(NOW + DAY_MS + 1_000);
    expect(statusOf(old.kid)?.unpublishAt).toBe(NOW + DAY_MS + 1_000);
  });

  it.each([[{ prepublishMs: -1 }], [{ retiredRetentionMs: Number.NaN }], [{ prepublishMs: 1.5 }]])(
    'refuses the windows %o at creation',
    (windows) => {
      expect(() => setup(windows)).toThrow(InvalidConfigurationError);
    }
  );

  it('lets the next rotation start once the switch is done', async () => {
    const { factory, scope, advance } = await rotating('webhook_signing');
    advance(7 * DAY_MS);
    await factory.activateNextKey(scope);

    const [third] = await factory.createKey({ ...scope, status: 'next' });

    expect(third.secret).toMatch(/^whsec_/);
  });

  it('activates a next key in a scope with no active key', async () => {
    const { factory, store } = setup({ prepublishMs: 0 });
    const scope = { realmId: REALM, purpose: 'webhook_signing', scopeId: 'sub-1' } as const;
    const [next] = await factory.createKey({ ...scope, status: 'next' });

    await expect(factory.activateNextKey(scope)).resolves.toMatchObject({
      activatedKid: next.kid,
      retiredKid: null,
      unpublishAt: null,
    });
    expect(store.rows[0].key.status).toBe('active');
  });

  it('refuses a scope with no next key, and another scope or algorithm does not count', async () => {
    const { factory, scope } = await rotating('upstream_client_assertion', { prepublishMs: 0 });

    await expect(
      refusalOf(factory.activateNextKey({ ...scope, scopeId: 'scope-2' }))
    ).resolves.toBe('NO_NEXT_KEY');
    await expect(
      refusalOf(factory.activateNextKey({ ...scope, algorithm: 'ES256' }))
    ).resolves.toBe('NO_NEXT_KEY');
    await expect(
      refusalOf(
        factory.activateNextKey({ ...scope, realmId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02' })
      )
    ).resolves.toBe('NO_NEXT_KEY');
  });

  it('changes nothing when a key moved during the rotation', async () => {
    const { factory, scope, store, old, next, statusOf } = await rotating('webhook_signing', {
      prepublishMs: 0,
    });
    const updateStatus = store.updateStatus.bind(store);
    store.updateStatus = async (realmId, kid, change, tx) =>
      kid === next.kid ? undefined : updateStatus(realmId, kid, change, tx);

    await expect(refusalOf(factory.activateNextKey(scope))).resolves.toBe('KEY_CHANGED');
    expect(statusOf(old.kid)?.status).toBe('active');
    expect(statusOf(next.kid)?.status).toBe('next');
  });

  it('runs in the caller’s transaction when given one', async () => {
    const { factory, scope, store } = await rotating('webhook_signing', { prepublishMs: 0 });
    const outer = { id: 7 };

    await factory.activateNextKey({ ...scope, tx: outer });

    expect(store.outerTransactions.at(-1)).toBe(outer);
  });

  it.each([
    ['an unscoped purpose', { purpose: 'token_signing' }, 'UNSCOPED_PURPOSE'],
    ['an unknown purpose', { purpose: 'nope' }, 'UNKNOWN_PURPOSE'],
    ['a realm id that is not a UUID', { realmId: 'realm-1' }, 'INVALID_REALM_ID'],
    ['an empty scope id', { scopeId: '' }, 'INVALID_SCOPE_ID'],
    ['a scope id with a NUL', { scopeId: 'a\u0000b' }, 'INVALID_SCOPE_ID'],
    ['an algorithm the purpose does not allow', { algorithm: 'HS256' }, 'ALGORITHM_NOT_ALLOWED'],
  ] as const)('refuses %s before reading the store', async (_case, change, reason) => {
    const { factory, store } = setup();
    const input = {
      realmId: REALM,
      purpose: 'upstream_client_assertion',
      scopeId: 'idp-1',
      ...change,
    } as unknown as Parameters<typeof factory.activateNextKey>[0];

    await expect(refusalOf(factory.activateNextKey(input))).resolves.toBe(reason);
    expect(store.calls).toEqual([]);
  });
});

describe('deleteScopedKeys', () => {
  it('deletes every key of the scope, whatever its status, and nothing else', async () => {
    const { factory, store } = setup();
    const scope = { realmId: REALM, purpose: 'webhook_signing', scopeId: 'sub-1' } as const;
    const [active] = await factory.createKey(scope);
    const [next] = await factory.createKey({ ...scope, status: 'next' });
    await factory.createKey({ ...scope, scopeId: 'sub-2' });
    await factory.createKey({ ...scope, purpose: 'upstream_client_assertion' });
    await factory.provisionRealmKeys(REALM);

    const deleted = await factory.deleteScopedKeys(scope);

    expect(deleted).toEqual([active.kid, next.kid]);
    expect(Object.isFrozen(deleted)).toBe(true);
    expect(store.rows.map((row) => [row.key.purpose, row.key.scopeId])).toEqual([
      ['webhook_signing', 'sub-2'],
      ['upstream_client_assertion', 'sub-1'],
      ['token_signing', null],
      ['event_signing', null],
      ['cookie_hmac', null],
      ['data_at_rest', null],
    ]);
    await expect(factory.deleteScopedKeys(scope)).resolves.toEqual([]);
  });

  it('runs in the caller’s transaction, so the owner and its keys go together', async () => {
    const { factory, store } = setup();
    const outer = { id: 11 };

    await factory.deleteScopedKeys({
      realmId: REALM.toUpperCase(),
      purpose: 'upstream_client_assertion',
      scopeId: 'idp-1',
      tx: outer,
    });

    expect(store.outerTransactions).toEqual([outer]);
    expect(store.calls.map((call) => call.method)).toEqual(['transaction', 'deleteByScope']);
  });

  it.each([
    ['an unscoped purpose', { purpose: 'cookie_hmac' }, 'UNSCOPED_PURPOSE'],
    ['a realm id that is not a UUID', { realmId: '' }, 'INVALID_REALM_ID'],
    ['a missing scope id', { scopeId: undefined }, 'INVALID_SCOPE_ID'],
    [
      'a scope id too long for the column',
      { scopeId: 'x'.repeat(MAX_SCOPE_ID_LENGTH + 1) },
      'INVALID_SCOPE_ID',
    ],
  ] as const)('refuses %s before touching the store', async (_case, change, reason) => {
    const { factory, store } = setup();
    const input = {
      realmId: REALM,
      purpose: 'webhook_signing',
      scopeId: 'sub-1',
      ...change,
    } as unknown as Parameters<typeof factory.deleteScopedKeys>[0];

    await expect(factory.deleteScopedKeys(input)).rejects.toMatchObject({
      code: 'KEY_CHANGE_REFUSED',
      reason,
      statusCode: 400,
    });
    expect(store.calls).toEqual([]);
  });
});
