import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import { describe, expect, it, vi } from 'vitest';

import { KEK_A, localProvider } from '../testing/keks';
import { createMemoryKeyStore } from '../testing/memory-key-store';
import { createMemorySignerStore } from '../testing/memory-signer-store';
import { createInProcessSigner } from './in-process-signer';
import { createKeyFactory } from './key-factory';
import {
  createPublishedKeyReader,
  isPublishedAt,
  publicKeyIdentity,
  realmJwksOf,
  verificationKeysOf,
} from './published-keys';
import { isSignerError } from './signer-errors';
import type { PublicKeyRecord } from './signer-key-store';

const REALM_A = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const REALM_B = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02';
const NOW = 1_800_000_000_000;
const HYBRID: readonly SignatureAlgorithm[] = ['EdDSA', 'ML-DSA-65'];

async function setup() {
  const keys = createMemoryKeyStore();
  const kekProvider = localProvider({ KEK: KEK_A });
  const factory = createKeyFactory({
    store: keys,
    kekProvider,
    enabledSignatureAlgorithms: HYBRID,
    hybridSigning: true,
    now: () => NOW,
  });
  for (const realmId of [REALM_A, REALM_B]) await factory.provisionRealmKeys(realmId);
  const store = createMemorySignerStore(keys, {
    [REALM_A]: 'https://a.example.test',
    [REALM_B]: 'https://b.example.test',
  });
  const signer = createInProcessSigner({
    store,
    kekProvider,
    enabledSignatureAlgorithms: HYBRID,
    hybridSigning: true,
    now: () => NOW,
  });
  return { store, signer };
}

describe('createPublishedKeyReader (#491, #495)', () => {
  it('answers as the in-process signer does, from the published keys alone', async () => {
    const { store, signer } = await setup();
    const listPublicKeys = vi.fn(store.listPublicKeys);
    const reader = createPublishedKeyReader({ listPublicKeys }, { now: () => NOW });

    for (const realmId of [REALM_A, REALM_B]) {
      expect(await reader.getVerificationKeys('local', realmId, 'token_signing')).toEqual(
        await signer.getVerificationKeys('local', realmId, 'token_signing')
      );
      expect(await reader.getJwks('local', realmId)).toEqual(
        await signer.getJwks('local', realmId)
      );
    }
    // Public material only: no JWK carries a private member.
    const jwks = await reader.getJwks('local', REALM_A);
    expect(jwks.keys.length).toBeGreaterThan(0);
    for (const jwk of jwks.keys) {
      for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'priv']) {
        expect(jwk).not.toHaveProperty(member);
      }
    }
  });

  it('keeps one realm apart from another', async () => {
    const { store } = await setup();
    const reader = createPublishedKeyReader(store, { now: () => NOW });
    const a = await reader.getVerificationKeys('local', REALM_A, 'token_signing');
    const b = await reader.getVerificationKeys('local', REALM_B, 'token_signing');
    const kidsOfB = new Set(b.map((key) => key.kid));
    expect(a.some((key) => kidsOfB.has(key.kid))).toBe(false);
  });

  it('reads the store at most once per refresh interval', async () => {
    const { store } = await setup();
    let clock = NOW;
    const listPublicKeys = vi.fn(store.listPublicKeys);
    const reader = createPublishedKeyReader(
      { listPublicKeys },
      { now: () => clock, refreshIntervalMs: 1000 }
    );
    await Promise.all([1, 2, 3].map(() => reader.getJwks('local', REALM_A)));
    await reader.getVerificationKeys('local', REALM_A, 'token_signing');
    expect(listPublicKeys).toHaveBeenCalledTimes(1);
    clock += 1000;
    await reader.getJwks('local', REALM_A);
    expect(listPublicKeys).toHaveBeenCalledTimes(2);
  });

  it('refuses a purpose with no verification keys, a bad realm id and an unknown caller', async () => {
    const { store } = await setup();
    const reader = createPublishedKeyReader(store, { now: () => NOW });
    for (const attempt of [
      reader.getVerificationKeys('local', REALM_A, 'data_at_rest' as 'token_signing'),
      reader.getVerificationKeys('local', 'not-a-realm', 'token_signing'),
      reader.getJwks('nobody' as 'local', REALM_A),
    ]) {
      await expect(attempt).rejects.toSatisfy((error: unknown) => isSignerError(error));
    }
  });
});

describe('a retired key with no set end to its publication (#492)', () => {
  const published = (
    kid: string,
    status: PublicKeyRecord['status'],
    unpublishAt: number | null
  ): PublicKeyRecord => ({
    kid,
    purpose: 'token_signing',
    algorithm: 'EdDSA',
    status,
    publicJwk: { kty: 'OKP', crv: 'Ed25519', x: kid, alg: 'EdDSA' },
    publishAt: NOW - 1000,
    unpublishAt,
  });
  const records = [
    published('active', 'active', null),
    published('next', 'next', null),
    published('retired-open', 'retired', null),
    published('retired-kept', 'retired', NOW + 1),
    published('retired-ended', 'retired', NOW),
  ];

  it('is out of its window at once, while an active or next key stays open-ended', () => {
    const inWindow = (kid: string) =>
      isPublishedAt(records.find((record) => record.kid === kid) as PublicKeyRecord, NOW);
    expect(inWindow('active')).toBe(true);
    expect(inWindow('next')).toBe(true);
    expect(inWindow('retired-kept')).toBe(true);
    expect(inWindow('retired-open')).toBe(false);
    expect(inWindow('retired-ended')).toBe(false);
  });

  it('neither verifies nor is served, so the verification set and the JWKS agree', async () => {
    expect(verificationKeysOf(records, 'token_signing', NOW).map((key) => key.kid)).toEqual([
      'active',
      'retired-kept',
    ]);
    expect(realmJwksOf(records, NOW).keys.map((jwk) => jwk.kid)).toEqual([
      'active',
      'next',
      'retired-kept',
    ]);

    const reader = createPublishedKeyReader(
      { listPublicKeys: async () => records },
      { now: () => NOW }
    );
    const verifying = await reader.getVerificationKeys('local', REALM_A, 'token_signing');
    const served = await reader.getJwks('local', REALM_A);
    expect(verifying.map((key) => key.kid)).not.toContain('retired-open');
    expect(served.keys.map((jwk) => jwk.kid)).not.toContain('retired-open');
  });
});

describe('publicKeyIdentity', () => {
  it('keeps the key type and public value only, for each key type', () => {
    expect(
      publicKeyIdentity({
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'abc',
        kid: 'k',
        use: 'sig',
        alg: 'EdDSA',
      })
    ).toEqual({ kty: 'OKP', crv: 'Ed25519', x: 'abc' });
    expect(publicKeyIdentity({ kty: 'RSA', n: 'nn', e: 'AQAB', kid: 'r' })).toEqual({
      kty: 'RSA',
      n: 'nn',
      e: 'AQAB',
    });
    expect(publicKeyIdentity({ kty: 'AKP', alg: 'ML-DSA-65', pub: 'pp' })).toEqual({
      kty: 'AKP',
      alg: 'ML-DSA-65',
      pub: 'pp',
    });
  });

  it('names nothing for a key type it does not know or a missing public value', () => {
    expect(publicKeyIdentity({ kty: 'oct', k: 'secret' })).toBeUndefined();
    expect(publicKeyIdentity({ kty: 'OKP', crv: 'Ed25519' })).toBeUndefined();
  });
});
