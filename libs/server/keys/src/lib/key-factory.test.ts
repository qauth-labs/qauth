import { createPrivateKey } from 'node:crypto';

import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

import { KEK_A, localProvider } from '../testing/keks';
import { createMemoryKeyStore, type MemoryKeyStore } from '../testing/memory-key-store';
import { openKeyMaterial } from './envelope';
import type { KekProvider } from './kek-provider';
import { KeyCreationRefusedError, KeyIdConflictError } from './key-creation-errors';
import { createKeyFactory, type KeyFactoryOptions, MAX_SCOPE_ID_LENGTH } from './key-factory';
import { KEY_PURPOSES, type KeyPurpose } from './key-purposes';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const NOW = 1_800_000_000_000;
const ED25519_ONLY: readonly SignatureAlgorithm[] = ['EdDSA'];
const HYBRID_CAPABLE: readonly SignatureAlgorithm[] = ['EdDSA', 'ML-DSA-65'];

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

    it.each(['', 'x'.repeat(MAX_SCOPE_ID_LENGTH + 1)])(
      'are refused when empty or too long (%#)',
      async (scopeId) => {
        const { factory } = setup();

        await expect(
          factory.createKey({ realmId: REALM, purpose: 'upstream_client_assertion', scopeId })
        ).rejects.toMatchObject({ reason: 'INVALID_SCOPE_ID' });
      }
    );
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

  it('runs in the caller’s transaction when given one', async () => {
    const { factory, store } = setup();
    const outer = { id: 42 };

    await factory.provisionRealmKeys(REALM, { tx: outer });

    expect(store.outerTransactions).toEqual([outer]);
  });
});
