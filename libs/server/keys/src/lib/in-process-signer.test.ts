import { KeyObject } from 'node:crypto';

import {
  getSignatureBackend,
  importPublicSigningJwk,
  type JwsAlgorithm,
  MlDsaKey,
  type SignatureAlgorithm,
  verifyHybrid,
  verifyWithHeader,
} from '@qauth-labs/core-crypto';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { decodeProtectedHeader, type JWK } from 'jose';
import { describe, expect, it, type Mock, vi } from 'vitest';

import { KEK_A, KEK_B, localProvider } from '../testing/keks';
import { createMemoryKeyStore, type MemoryKeyStore } from '../testing/memory-key-store';
import { createMemorySignerStore, type MemorySignerStore } from '../testing/memory-signer-store';
import { openKeyMaterial } from './envelope';
import { isKeyCustodyError } from './errors';
import { createInProcessSigner, type InProcessSignerOptions } from './in-process-signer';
import type { KekProvider } from './kek-provider';
import { createKeyFactory, type KeyFactory } from './key-factory';
import {
  type RealmJwks,
  type Signer,
  SIGNER_OPERATIONS,
  type SignerOperation,
  type SignJwsRequest,
} from './signer';
import {
  DataDecryptionError,
  isSignerError,
  RealmIssuerNotFoundError,
  SignerAccessDeniedError,
  SignerKeyNotFoundError,
  type SignerRefusalReason,
  SignerRequestRefusedError,
} from './signer-errors';
import { SIGNER_CALLERS, SIGNER_POLICY, type SignerCaller } from './signer-policy';
import { JWS_TYP_BY_PURPOSE } from './signer-typ';

const REALM_A = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const REALM_B = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02';
const REALM_WITHOUT_KEYS = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e03';
const REALM_WITHOUT_ISSUER = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e04';
const ISSUER_A = 'https://a.example.test';
const ISSUER_B = 'https://b.example.test';
const NOW = 1_800_000_000_000;
const REFRESH_MS = 60_000;
const ED25519_ONLY: readonly SignatureAlgorithm[] = ['EdDSA'];
const HYBRID: readonly SignatureAlgorithm[] = ['EdDSA', 'ML-DSA-65'];

const CLAIMS = Object.freeze({
  sub: 'user-1',
  aud: 'client-1',
  iat: NOW / 1000,
  exp: NOW / 1000 + 300,
});

interface Setup {
  readonly signer: Signer;
  readonly store: MemorySignerStore;
  readonly keys: MemoryKeyStore;
  readonly factory: KeyFactory<unknown>;
  readonly kekProvider: KekProvider;
  readonly unwrap: Mock<KekProvider['unwrap']>;
  readonly enabled: readonly SignatureAlgorithm[];
  advance(ms: number): void;
}

interface SetupOptions {
  /** Hybrid signing for both the factory and the signer. */
  readonly hybrid?: boolean;
  /** Realms whose standard keys are provisioned. Defaults to A and B. */
  readonly realms?: readonly string[];
  /** The KEK provider the signer unwraps with. Defaults to one holding the factory's KEK. */
  readonly signerKek?: KekProvider;
  readonly signer?: Partial<InProcessSignerOptions>;
}

async function setup(options: SetupOptions = {}): Promise<Setup> {
  const hybrid = options.hybrid === true;
  const enabled = hybrid ? HYBRID : ED25519_ONLY;
  const keys = createMemoryKeyStore();
  const sealing = localProvider({ KEK: KEK_A });
  const factory = createKeyFactory({
    store: keys,
    kekProvider: sealing,
    enabledSignatureAlgorithms: enabled,
    hybridSigning: hybrid,
    now: () => NOW,
  });
  for (const realmId of options.realms ?? [REALM_A, REALM_B]) {
    await factory.provisionRealmKeys(realmId);
  }

  const store = createMemorySignerStore(keys, {
    [REALM_A]: ISSUER_A,
    [REALM_B]: ISSUER_B,
    [REALM_WITHOUT_KEYS]: 'https://empty.example.test',
    [REALM_WITHOUT_ISSUER]: null,
  });
  // The local provider is frozen, so the unwrap count comes from a delegate.
  const inner = options.signerKek ?? sealing;
  const unwrap = vi.fn(inner.unwrap);
  const kekProvider: KekProvider = { ...inner, unwrap };
  let clock = NOW;
  const signer = createInProcessSigner({
    store,
    kekProvider,
    enabledSignatureAlgorithms: enabled,
    hybridSigning: hybrid,
    refreshIntervalMs: REFRESH_MS,
    now: () => clock,
    ...options.signer,
  });
  return {
    signer,
    store,
    keys,
    factory: factory as KeyFactory<unknown>,
    kekProvider,
    unwrap,
    enabled,
    advance: (ms) => {
      clock += ms;
    },
  };
}

function accessToken(realmId = REALM_A, overrides: Partial<SignJwsRequest> = {}): SignJwsRequest {
  return { realmId, purpose: 'token_signing', typ: 'at+jwt', claims: CLAIMS, ...overrides };
}

/** Verify `token` with the key its `kid` names in `jwks`, as a relying party would. */
async function verifyWithJwks(token: string, jwks: RealmJwks, issuer: string) {
  const { kid, alg } = decodeProtectedHeader(token);
  const jwk = jwks.keys.find((key) => key.kid === kid);
  if (jwk === undefined) throw new Error(`no published key for kid ${String(kid)}`);
  const key = await importPublicSigningJwk(jwk, alg as JwsAlgorithm);
  return verifyWithHeader(token, key, {
    algorithms: [alg as JwsAlgorithm],
    issuer,
    currentDate: new Date(NOW),
  });
}

function activeKid(keys: MemoryKeyStore, realmId: string, purpose: string, algorithm = 'EdDSA') {
  const row = keys.rows.find(
    ({ key }) =>
      key.realmId === realmId &&
      key.purpose === purpose &&
      key.algorithm === algorithm &&
      key.status === 'active'
  );
  if (row === undefined) throw new Error(`no ${purpose} ${algorithm} key`);
  return row.key.kid;
}

async function refusal(promise: Promise<unknown>): Promise<SignerRefusalReason> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught
  );
  expect(error).toBeInstanceOf(SignerRequestRefusedError);
  return (error as SignerRequestRefusedError).reason;
}

describe('createInProcessSigner', () => {
  it('refuses hybrid signing when SIGNING_ALGORITHM_MODE does not enable ML-DSA-65', () => {
    const store = createMemorySignerStore(createMemoryKeyStore());
    expect(() =>
      createInProcessSigner({
        store,
        kekProvider: localProvider({ KEK: KEK_A }),
        enabledSignatureAlgorithms: ED25519_ONLY,
        hybridSigning: true,
      })
    ).toThrow(InvalidConfigurationError);
  });

  it.each([
    { keyCacheSize: 0 },
    { keyCacheSize: 1.5 },
    { refreshIntervalMs: -1 },
    { refreshIntervalMs: Number.NaN },
  ])('refuses the cache option %o', (option) => {
    const store = createMemorySignerStore(createMemoryKeyStore());
    expect(() =>
      createInProcessSigner({
        store,
        kekProvider: localProvider({ KEK: KEK_A }),
        enabledSignatureAlgorithms: ED25519_ONLY,
        hybridSigning: false,
        ...option,
      })
    ).toThrow(InvalidConfigurationError);
  });
});

describe('signJws', () => {
  it('signs a token that verifies against the key published for its kid', async () => {
    const { signer, keys } = await setup();

    const token = await signer.signJws('local', accessToken());
    const jwks = await signer.getJwks('local', REALM_A);
    const { claims, protectedHeader } = await verifyWithJwks(token, jwks, ISSUER_A);

    expect(protectedHeader).toEqual({
      alg: 'EdDSA',
      kid: activeKid(keys, REALM_A, 'token_signing'),
      typ: 'at+jwt',
    });
    expect(claims).toEqual({ iss: ISSUER_A, ...CLAIMS });
  });

  it('verifies against the verification keys of its purpose too', async () => {
    const { signer } = await setup();

    const token = await signer.signJws('local', accessToken());
    const verificationKeys = await signer.getVerificationKeys('local', REALM_A, 'token_signing');

    await expect(
      verifyWithJwks(token, { keys: verificationKeys.map((key) => key.publicJwk) }, ISSUER_A)
    ).resolves.toBeDefined();
  });

  it('takes iss from the realm row and kid from its active key', async () => {
    const { signer, keys } = await setup();

    const token = await signer.signJws('local', accessToken(REALM_B));
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));

    expect(payload.iss).toBe(ISSUER_B);
    expect(decodeProtectedHeader(token).kid).toBe(activeKid(keys, REALM_B, 'token_signing'));
  });

  it('accepts the realm id in any case', async () => {
    const { signer } = await setup();

    await expect(signer.signJws('local', accessToken(REALM_A.toUpperCase()))).resolves.toEqual(
      expect.any(String)
    );
  });

  describe('refuses a caller-supplied iss or kid', () => {
    it('refuses iss among the claims', async () => {
      const { signer } = await setup();
      const claims = { ...CLAIMS, iss: 'https://evil.example.test' };

      expect(await refusal(signer.signJws('local', accessToken(REALM_A, { claims })))).toBe(
        'RESERVED_CLAIM'
      );
    });

    it('refuses an iss that a toJSON method would add at signing time', async () => {
      const { signer } = await setup();
      const claims = { toJSON: () => ({ ...CLAIMS, iss: 'https://evil.example.test' }) };

      expect(await refusal(signer.signJws('local', accessToken(REALM_A, { claims })))).toBe(
        'RESERVED_CLAIM'
      );
    });

    it.each(['kid', 'iss', 'alg', 'header', 'issuer'])(
      'refuses a %s field on the request',
      async (field) => {
        const { signer } = await setup();
        const request = { ...accessToken(), [field]: 'chosen-by-caller' } as SignJwsRequest;

        expect(await refusal(signer.signJws('local', request))).toBe('UNEXPECTED_FIELD');
      }
    );
  });

  describe('binds each purpose to its typ values', () => {
    it.each([
      ['token_signing', 'at+jwt'],
      ['token_signing', 'JWT'],
      ['event_signing', 'secevent+jwt'],
      ['event_signing', 'logout+jwt'],
    ] as const)('%s signs %s', async (purpose, typ) => {
      const { signer } = await setup();

      const token = await signer.signJws('local', accessToken(REALM_A, { purpose, typ }));

      expect(decodeProtectedHeader(token).typ).toBe(typ);
    });

    it.each([
      ['token_signing', 'logout+jwt'],
      ['token_signing', 'secevent+jwt'],
      ['event_signing', 'at+jwt'],
      ['event_signing', 'JWT'],
      ['token_signing', 'AT+JWT'],
      ['token_signing', 'jwt'],
      ['token_signing', ''],
    ] as const)('%s refuses %s', async (purpose, typ) => {
      const { signer, unwrap } = await setup();

      expect(await refusal(signer.signJws('local', accessToken(REALM_A, { purpose, typ })))).toBe(
        'TYP_NOT_ALLOWED'
      );
      expect(unwrap).not.toHaveBeenCalled();
    });

    it.each(['cookie_hmac', 'data_at_rest', 'federation_entity', 'oid4vp_request_signing', 'nope'])(
      'does not sign with %s',
      async (purpose) => {
        const { signer } = await setup();
        const request = accessToken(REALM_A, { purpose } as unknown as Partial<SignJwsRequest>);

        expect(await refusal(signer.signJws('local', request))).toBe('PURPOSE_NOT_ALLOWED');
      }
    );
  });

  it('signs with the RS256 key when asked for RS256', async () => {
    const { signer, factory } = await setup();
    const [rsa] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'token_signing',
      algorithm: 'RS256',
    });

    const token = await signer.signJws(
      'local',
      accessToken(REALM_A, { typ: 'JWT', algorithm: 'RS256' })
    );

    expect(decodeProtectedHeader(token)).toMatchObject({ alg: 'RS256', kid: rsa.kid });
    await expect(
      verifyWithJwks(token, await signer.getJwks('local', REALM_A), ISSUER_A)
    ).resolves.toBeDefined();
  });

  it.each([
    ['token_signing', 'ML-DSA-65'],
    ['token_signing', 'ES256'],
    ['event_signing', 'ES256'],
    ['token_signing', 'HS256'],
  ] as const)('refuses %s with %s', async (purpose, algorithm) => {
    const { signer } = await setup();
    const request = accessToken(REALM_A, {
      purpose,
      typ: JWS_TYP_BY_PURPOSE[purpose][0],
      algorithm,
    } as unknown as Partial<SignJwsRequest>);

    expect(await refusal(signer.signJws('local', request))).toBe('ALGORITHM_NOT_ALLOWED');
  });

  it('refuses a scope id for an unscoped purpose', async () => {
    const { signer } = await setup();

    expect(await refusal(signer.signJws('local', accessToken(REALM_A, { scopeId: 's' })))).toBe(
      'SCOPE_NOT_ALLOWED'
    );
  });

  it.each([
    ['an array', []],
    ['a string', 'claims'],
    ['null', null],
    ['a BigInt claim', { exp: BigInt(1) }],
  ])('refuses claims that are %s', async (_, claims) => {
    const { signer } = await setup();
    const request = accessToken(REALM_A, { claims } as unknown as Partial<SignJwsRequest>);

    expect(await refusal(signer.signJws('local', request))).toBe('INVALID_CLAIMS');
  });

  it('refuses a realm id that is not a UUID', async () => {
    const { signer } = await setup();

    expect(await refusal(signer.signJws('local', accessToken('realm-a')))).toBe('INVALID_REALM_ID');
  });

  it.each([REALM_WITHOUT_ISSUER, '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6eff'])(
    'refuses a realm without an issuer (%s)',
    async (realmId) => {
      const { signer } = await setup();

      await expect(signer.signJws('local', accessToken(realmId))).rejects.toBeInstanceOf(
        RealmIssuerNotFoundError
      );
    }
  );

  it('gives a typed error for a realm with no key and creates none', async () => {
    const { signer, keys, store } = await setup();
    const rowsBefore = keys.rows.length;
    const createsBefore = keys.calls.filter((call) => call.method === 'create').length;

    const error = await signer.signJws('local', accessToken(REALM_WITHOUT_KEYS)).catch((e) => e);

    expect(error).toBeInstanceOf(SignerKeyNotFoundError);
    expect(error).toMatchObject({
      code: 'SIGNER_KEY_NOT_FOUND',
      realmId: REALM_WITHOUT_KEYS,
      purpose: 'token_signing',
      algorithm: 'EdDSA',
    });
    expect(keys.rows).toHaveLength(rowsBefore);
    expect(keys.calls.filter((call) => call.method === 'create')).toHaveLength(createsBefore);
    expect(store.calls).not.toContain('getWrappedKey');
  });

  it('signs for two realms with their own keys', async () => {
    const { signer, keys } = await setup();

    const tokenA = await signer.signJws('local', accessToken(REALM_A));
    const tokenB = await signer.signJws('local', accessToken(REALM_B));
    const jwksA = await signer.getJwks('local', REALM_A);
    const jwksB = await signer.getJwks('local', REALM_B);

    expect(decodeProtectedHeader(tokenA).kid).toBe(activeKid(keys, REALM_A, 'token_signing'));
    expect(decodeProtectedHeader(tokenB).kid).toBe(activeKid(keys, REALM_B, 'token_signing'));
    expect(decodeProtectedHeader(tokenA).kid).not.toBe(decodeProtectedHeader(tokenB).kid);
    await expect(verifyWithJwks(tokenA, jwksA, ISSUER_A)).resolves.toBeDefined();
    await expect(verifyWithJwks(tokenB, jwksB, ISSUER_B)).resolves.toBeDefined();
    await expect(verifyWithJwks(tokenA, jwksB, ISSUER_A)).rejects.toThrow(/no published key/);
  });
});

describe('a key that does not unwrap', () => {
  it('gives the KEK provider typed error, and never signs with another key', async () => {
    const { signer, unwrap, store } = await setup({
      signerKek: localProvider({ KEK: KEK_B }),
    });

    const error = await signer.signJws('local', accessToken()).catch((e) => e);

    expect(isKeyCustodyError(error, 'KEK_UNKNOWN_REF')).toBe(true);
    expect(unwrap).toHaveBeenCalledTimes(1);
    expect(store.calls.filter((call) => call === 'getWrappedKey')).toHaveLength(1);
  });

  it('refuses a key whose sealed bytes were changed, with no fallback to another algorithm', async () => {
    const { signer, keys, store, factory, unwrap } = await setup();
    await factory.createKey({ realmId: REALM_A, purpose: 'token_signing', algorithm: 'RS256' });
    const kid = activeKid(keys, REALM_A, 'token_signing');
    const row = keys.rows.find(({ key }) => key.kid === kid);
    const ciphertext = Buffer.from(row?.key.ciphertext ?? []);
    ciphertext[0] ^= 0xff;
    store.replaceSealed(REALM_A, kid, { ciphertext });

    const error = await signer.signJws('local', accessToken()).catch((e) => e);

    expect(isKeyCustodyError(error, 'KEY_DECRYPTION_FAILED')).toBe(true);
    expect(unwrap).toHaveBeenCalledTimes(1);
    // The next call tries the same key again: a failure is not cached, and
    // nothing switches to the RS256 key.
    await expect(signer.signJws('local', accessToken())).rejects.toSatisfy((e: unknown) =>
      isKeyCustodyError(e, 'KEY_DECRYPTION_FAILED')
    );
    expect(unwrap).toHaveBeenCalledTimes(2);
  });

  it('refuses a key row moved to another purpose', async () => {
    const { signer, keys, store } = await setup();
    // The event signing key's sealed bytes under the token signing key's kid:
    // the associated data names the other purpose and kid, so it cannot open.
    const event = keys.rows.find(
      ({ key }) => key.realmId === REALM_A && key.purpose === 'event_signing'
    );
    store.replaceSealed(REALM_A, activeKid(keys, REALM_A, 'token_signing'), {
      ciphertext: event?.key.ciphertext,
      iv: event?.key.iv,
      wrappedDek: event?.key.wrappedDek,
    });

    await expect(signer.signJws('local', accessToken())).rejects.toSatisfy((e: unknown) =>
      isKeyCustodyError(e, 'KEY_DECRYPTION_FAILED')
    );
  });
});

describe('the key cache', () => {
  it('signs with a warm cache without reading the store', async () => {
    const { signer, store } = await setup();
    await signer.signJws('local', accessToken());
    store.calls.length = 0;

    await signer.signJws('local', accessToken());
    await signer.signJws('local', accessToken(REALM_A, { typ: 'JWT' }));

    expect(store.calls).toEqual([]);
  });

  it('reads only the key list again after the refresh interval, and keeps the unwrapped key', async () => {
    const { signer, store, unwrap, advance } = await setup();
    await signer.signJws('local', accessToken());
    store.calls.length = 0;

    advance(REFRESH_MS);
    await signer.signJws('local', accessToken());

    expect(store.calls).toEqual(['listKeys']);
    expect(unwrap).toHaveBeenCalledTimes(1);
  });

  it('follows a rotation within one refresh interval', async () => {
    const { signer, store, factory, keys, advance } = await setup();
    const oldKid = activeKid(keys, REALM_A, 'token_signing');
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'token_signing',
      status: 'next',
    });
    await signer.signJws('local', accessToken());

    store.update(REALM_A, oldKid, { status: 'retired', retireAt: NOW });
    store.update(REALM_A, next.kid, { status: 'active' });

    expect(decodeProtectedHeader(await signer.signJws('local', accessToken())).kid).toBe(oldKid);
    advance(REFRESH_MS);
    expect(decodeProtectedHeader(await signer.signJws('local', accessToken())).kid).toBe(next.kid);
  });

  it('unwraps a key once for concurrent first calls', async () => {
    const { signer, unwrap } = await setup();

    await Promise.all([1, 2, 3].map(() => signer.signJws('local', accessToken())));

    expect(unwrap).toHaveBeenCalledTimes(1);
  });

  it('holds no more keys than its size limit', async () => {
    const { signer, unwrap } = await setup({ signer: { keyCacheSize: 1 } });

    await signer.signJws('local', accessToken());
    await signer.signJws(
      'local',
      accessToken(REALM_A, { purpose: 'event_signing', typ: 'logout+jwt' })
    );
    await signer.signJws('local', accessToken());

    expect(unwrap).toHaveBeenCalledTimes(3);
  });
});

describe('signHybrid', () => {
  it('returns the detached-parallel carrier, which verifyHybrid accepts', async () => {
    const { signer, keys, enabled } = await setup({ hybrid: true });

    const hybrid = await signer.signHybrid('local', {
      realmId: REALM_A,
      typ: 'at+jwt',
      claims: CLAIMS,
    });
    const verification = await signer.getVerificationKeys('local', REALM_A, 'token_signing');
    const edJwk = verification.find((key) => key.algorithm === 'EdDSA')?.publicJwk as JWK;
    const mlDsaJwk = verification.find((key) => key.algorithm === 'ML-DSA-65')?.publicJwk as JWK;
    const backend = getSignatureBackend('ML-DSA-65', enabled);

    const claims = await verifyHybrid(
      hybrid,
      {
        ed: await importPublicSigningJwk(edJwk, 'EdDSA'),
        mlDsa: (pqcKid) =>
          pqcKid === mlDsaJwk.kid
            ? backend.importKey((mlDsaJwk as Record<string, unknown>)['pub'] as string, 'public')
            : undefined,
      },
      {
        algorithms: ['EdDSA'],
        issuer: ISSUER_A,
        currentDate: new Date(NOW),
        enabledSignatureAlgorithms: enabled,
        requirePqc: true,
      }
    );

    expect(claims).toEqual({ iss: ISSUER_A, ...CLAIMS });
    expect(hybrid.pqcAlg).toBe('ML-DSA-65');
    expect(decodeProtectedHeader(hybrid.token)).toEqual({
      alg: 'EdDSA',
      kid: activeKid(keys, REALM_A, 'token_signing'),
      typ: 'at+jwt',
      pqc_alg: 'ML-DSA-65',
      pqc_kid: activeKid(keys, REALM_A, 'token_signing', 'ML-DSA-65'),
    });
  });

  it('is refused while hybrid signing is off, and unwraps nothing', async () => {
    const { signer, unwrap } = await setup();

    expect(
      await refusal(signer.signHybrid('local', { realmId: REALM_A, typ: 'at+jwt', claims: CLAIMS }))
    ).toBe('HYBRID_SIGNING_DISABLED');
    expect(unwrap).not.toHaveBeenCalled();
  });

  it('gives a typed error for a realm without a complete pair', async () => {
    const { signer, keys, store } = await setup({ hybrid: true });
    store.update(REALM_A, activeKid(keys, REALM_A, 'token_signing', 'ML-DSA-65'), {
      status: 'retired',
    });

    await expect(
      signer.signHybrid('local', { realmId: REALM_A, typ: 'at+jwt', claims: CLAIMS })
    ).rejects.toBeInstanceOf(SignerKeyNotFoundError);
  });

  it('binds typ and refuses iss as signJws does', async () => {
    const { signer } = await setup({ hybrid: true });

    expect(
      await refusal(
        signer.signHybrid('local', { realmId: REALM_A, typ: 'logout+jwt', claims: CLAIMS })
      )
    ).toBe('TYP_NOT_ALLOWED');
    expect(
      await refusal(
        signer.signHybrid('local', {
          realmId: REALM_A,
          typ: 'at+jwt',
          claims: { ...CLAIMS, iss: ISSUER_B },
        })
      )
    ).toBe('RESERVED_CLAIM');
  });
});

describe('getCookieSecrets', () => {
  it('returns the active secret and no previous one before a rotation', async () => {
    const { signer, keys } = await setup();

    const secrets = await signer.getCookieSecrets('local', REALM_A);

    expect(secrets.current.kid).toBe(activeKid(keys, REALM_A, 'cookie_hmac', 'HS256'));
    expect(secrets.current.secret).toHaveLength(32);
    expect(secrets.previous).toBeNull();
  });

  it('returns the most recently retired secret as the previous one', async () => {
    const { signer, keys, factory, store, advance } = await setup();
    const first = activeKid(keys, REALM_A, 'cookie_hmac', 'HS256');
    const before = await signer.getCookieSecrets('local', REALM_A);
    const [second] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'cookie_hmac',
      status: 'next',
    });
    store.update(REALM_A, first, { status: 'retired', retireAt: NOW + 1 });
    store.update(REALM_A, second.kid, { status: 'active' });
    advance(REFRESH_MS);

    const after = await signer.getCookieSecrets('local', REALM_A);

    expect(after.current.kid).toBe(second.kid);
    expect(after.previous?.kid).toBe(first);
    expect(after.previous?.secret.equals(before.current.secret)).toBe(true);
    expect(after.current.secret.equals(before.current.secret)).toBe(false);
  });

  it('hands out copies: changing one does not change the next', async () => {
    const { signer } = await setup();
    const first = await signer.getCookieSecrets('local', REALM_A);
    const original = Buffer.from(first.current.secret);

    first.current.secret.fill(0);

    expect((await signer.getCookieSecrets('local', REALM_A)).current.secret.equals(original)).toBe(
      true
    );
  });

  it('gives a typed error for a realm with no cookie key', async () => {
    const { signer } = await setup();

    await expect(signer.getCookieSecrets('local', REALM_WITHOUT_KEYS)).rejects.toBeInstanceOf(
      SignerKeyNotFoundError
    );
  });
});

describe('encrypt and decrypt', () => {
  const plaintext = Buffer.from('an upstream refresh token');

  it('round-trips, and the ciphertext names the key kid', async () => {
    const { signer, keys } = await setup();

    const ciphertext = await signer.encrypt('local', {
      realmId: REALM_A,
      plaintext,
      context: 'row-1',
    });

    expect(ciphertext.split('.').slice(0, 2)).toEqual([
      'v1',
      activeKid(keys, REALM_A, 'data_at_rest', 'A256GCM'),
    ]);
    expect(ciphertext).not.toContain(plaintext.toString('base64url'));
    expect(
      await signer.decrypt('local', { realmId: REALM_A, ciphertext, context: 'row-1' })
    ).toEqual(plaintext);
  });

  it('never repeats a ciphertext', async () => {
    const { signer } = await setup();
    const request = { realmId: REALM_A, plaintext };

    expect(await signer.encrypt('local', request)).not.toBe(await signer.encrypt('local', request));
  });

  it('refuses another context', async () => {
    const { signer } = await setup();
    const ciphertext = await signer.encrypt('local', {
      realmId: REALM_A,
      plaintext,
      context: 'row-1',
    });

    await expect(
      signer.decrypt('local', { realmId: REALM_A, ciphertext, context: 'row-2' })
    ).rejects.toBeInstanceOf(DataDecryptionError);
    await expect(signer.decrypt('local', { realmId: REALM_A, ciphertext })).rejects.toBeInstanceOf(
      DataDecryptionError
    );
  });

  it("refuses another realm's ciphertext", async () => {
    const { signer } = await setup();
    const ciphertext = await signer.encrypt('local', { realmId: REALM_A, plaintext });

    await expect(signer.decrypt('local', { realmId: REALM_B, ciphertext })).rejects.toBeInstanceOf(
      SignerKeyNotFoundError
    );
  });

  /** `ciphertext` with one bit of part `index` flipped. */
  function flipBit(ciphertext: string, index: number): string {
    const parts = ciphertext.split('.');
    const bytes = Buffer.from(parts[index], 'base64url');
    bytes[0] ^= 0x01;
    parts[index] = bytes.toString('base64url');
    return parts.join('.');
  }

  it.each([
    ['a changed body', (c: string) => flipBit(c, 3)],
    ['a changed nonce', (c: string) => flipBit(c, 2)],
    ['another version', (c: string) => c.replace(/^v1/, 'v2')],
    ['a missing part', (c: string) => c.split('.').slice(0, 3).join('.')],
    [
      'a short nonce',
      (c: string) =>
        c
          .split('.')
          .map((p, i) => (i === 2 ? 'AAAA' : p))
          .join('.'),
    ],
    ['an empty string', () => ''],
  ])('refuses %s', async (_, change) => {
    const { signer } = await setup();
    const ciphertext = await signer.encrypt('local', { realmId: REALM_A, plaintext });

    const error = await signer
      .decrypt('local', { realmId: REALM_A, ciphertext: change(ciphertext) })
      .catch((e) => e);

    expect(error).toBeInstanceOf(DataDecryptionError);
    expect(isSignerError(error, 'DATA_DECRYPTION_FAILED')).toBe(true);
    expect(error.message).not.toContain(plaintext.toString());
  });

  it('decrypts with a retired key after a rotation, and refuses a compromised one', async () => {
    const { signer, keys, factory, store, advance } = await setup();
    const oldKid = activeKid(keys, REALM_A, 'data_at_rest', 'A256GCM');
    const old = await signer.encrypt('local', { realmId: REALM_A, plaintext });
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'data_at_rest',
      status: 'next',
    });
    store.update(REALM_A, oldKid, { status: 'retired', retireAt: NOW });
    store.update(REALM_A, next.kid, { status: 'active' });
    advance(REFRESH_MS);

    const fresh = await signer.encrypt('local', { realmId: REALM_A, plaintext });

    expect(fresh.split('.')[1]).toBe(next.kid);
    expect(await signer.decrypt('local', { realmId: REALM_A, ciphertext: old })).toEqual(plaintext);

    store.update(REALM_A, oldKid, { status: 'compromised' });
    advance(REFRESH_MS);
    await expect(
      signer.decrypt('local', { realmId: REALM_A, ciphertext: old })
    ).rejects.toBeInstanceOf(SignerKeyNotFoundError);
  });

  it('finds a key created after the key list was read', async () => {
    const { signer, keys, factory, store } = await setup();
    const oldKid = activeKid(keys, REALM_A, 'data_at_rest', 'A256GCM');
    await signer.encrypt('local', { realmId: REALM_A, plaintext });
    // Another node rotated: this signer's list is still fresh and lacks the key.
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'data_at_rest',
      status: 'next',
    });
    store.update(REALM_A, oldKid, { status: 'retired', retireAt: NOW });
    store.update(REALM_A, next.kid, { status: 'active' });
    const other = createInProcessSigner({
      store,
      kekProvider: localProvider({ KEK: KEK_A }),
      enabledSignatureAlgorithms: ED25519_ONLY,
      hybridSigning: false,
      now: () => NOW,
    });
    const ciphertext = await other.encrypt('local', { realmId: REALM_A, plaintext });

    expect(await signer.decrypt('local', { realmId: REALM_A, ciphertext })).toEqual(plaintext);
  });

  it.each([
    ['a string plaintext', { plaintext: 'text' }, 'INVALID_PLAINTEXT'],
    ['a context that is not a string', { plaintext, context: 1 }, 'INVALID_CONTEXT'],
    ['a context that is too long', { plaintext, context: 'x'.repeat(1025) }, 'INVALID_CONTEXT'],
    ['a lone surrogate in the context', { plaintext, context: '\uD800' }, 'INVALID_CONTEXT'],
    ['a kid field', { plaintext, kid: 'k' }, 'UNEXPECTED_FIELD'],
  ])('refuses %s', async (_, fields, reason) => {
    const { signer } = await setup();
    const request = { realmId: REALM_A, ...fields } as unknown as Parameters<Signer['encrypt']>[1];

    expect(await refusal(signer.encrypt('local', request))).toBe(reason);
  });
});

describe('getVerificationKeys and getJwks', () => {
  it('publish the token and event signing keys, never a symmetric key', async () => {
    const { signer, keys } = await setup();

    const jwks = await signer.getJwks('local', REALM_A);

    expect(jwks.keys.map((key) => key.kid)).toEqual([
      activeKid(keys, REALM_A, 'token_signing'),
      activeKid(keys, REALM_A, 'event_signing'),
    ]);
    for (const key of jwks.keys) {
      expect(key).toMatchObject({ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', use: 'sig' });
      expect(key).not.toHaveProperty('d');
    }
  });

  it('list a next key in the JWKS but not among the verification keys', async () => {
    const { signer, factory } = await setup();
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'token_signing',
      status: 'next',
    });

    const jwks = await signer.getJwks('local', REALM_A);
    const verification = await signer.getVerificationKeys('local', REALM_A, 'token_signing');

    expect(jwks.keys.map((key) => key.kid)).toContain(next.kid);
    expect(verification.map((key) => key.kid)).not.toContain(next.kid);
  });

  it('keep a retired key until its window closes, and drop a compromised one at once', async () => {
    const { signer, keys, store, advance } = await setup();
    const kid = activeKid(keys, REALM_A, 'token_signing');
    store.update(REALM_A, kid, { status: 'retired', unpublishAt: NOW + 2 * REFRESH_MS });

    expect((await signer.getVerificationKeys('local', REALM_A, 'token_signing'))[0]).toMatchObject({
      kid,
      status: 'retired',
    });

    advance(2 * REFRESH_MS);
    expect(await signer.getVerificationKeys('local', REALM_A, 'token_signing')).toEqual([]);
    expect((await signer.getJwks('local', REALM_A)).keys.map((key) => key.kid)).not.toContain(kid);

    const event = activeKid(keys, REALM_A, 'event_signing');
    store.update(REALM_A, event, { status: 'compromised' });
    advance(REFRESH_MS);
    expect((await signer.getJwks('local', REALM_A)).keys).toEqual([]);
  });

  it('return frozen copies', async () => {
    const { signer } = await setup();

    const jwks = await signer.getJwks('local', REALM_A);

    expect(Object.isFrozen(jwks.keys)).toBe(true);
    expect(Object.isFrozen(jwks.keys[0])).toBe(true);
  });

  it('refuse a published key that carries a private member', async () => {
    const { signer, keys } = await setup();
    const row = keys.rows.find(({ publicJwk }) => publicJwk !== undefined);
    if (row?.publicJwk === undefined) throw new Error('no published key');
    (row.publicJwk as Record<string, unknown>)['d'] = 'private';

    await expect(signer.getJwks('local', REALM_A)).rejects.toThrow(/private member/);
  });

  it.each(['cookie_hmac', 'data_at_rest', 'oid4vp_response_encryption'])(
    'have no verification keys for %s',
    async (purpose) => {
      const { signer } = await setup();

      expect(
        await refusal(signer.getVerificationKeys('local', REALM_A, purpose as 'token_signing'))
      ).toBe('PURPOSE_NOT_ALLOWED');
    }
  );
});

/** One call per operation, with a valid request. Typed so a new operation must be added. */
const CALLS: Record<SignerOperation, (signer: Signer, caller: SignerCaller) => Promise<unknown>> = {
  signJws: (signer, caller) => signer.signJws(caller, accessToken()),
  signHybrid: (signer, caller) =>
    signer.signHybrid(caller, { realmId: REALM_A, typ: 'at+jwt', claims: CLAIMS }),
  getCookieSecrets: (signer, caller) => signer.getCookieSecrets(caller, REALM_A),
  encrypt: (signer, caller) =>
    signer.encrypt(caller, { realmId: REALM_A, plaintext: Buffer.from('data') }),
  decrypt: async (signer, caller) =>
    signer.decrypt(caller, {
      realmId: REALM_A,
      ciphertext: await signer.encrypt('local', {
        realmId: REALM_A,
        plaintext: Buffer.from('data'),
      }),
    }),
  getVerificationKeys: (signer, caller) =>
    signer.getVerificationKeys(caller, REALM_A, 'token_signing'),
  getJwks: (signer, caller) => signer.getJwks(caller, REALM_A),
};

describe('caller policy', () => {
  const cases = SIGNER_CALLERS.flatMap((caller) =>
    SIGNER_OPERATIONS.map((operation) => [caller, operation] as const)
  );

  it.each(cases)('%s calling %s follows SIGNER_POLICY', async (caller, operation) => {
    const { signer } = await setup({ hybrid: true });
    const grant = SIGNER_POLICY[caller];
    const allowed =
      operation === 'signJws' ? grant.signJws.includes('token_signing') : grant[operation];

    const result = CALLS[operation](signer, caller);

    if (allowed) {
      await expect(result).resolves.toBeDefined();
    } else {
      await expect(result).rejects.toBeInstanceOf(SignerAccessDeniedError);
    }
  });

  it('refuses getCookieSecrets to delivery', async () => {
    const { signer, unwrap } = await setup();

    await expect(signer.getCookieSecrets('delivery', REALM_A)).rejects.toMatchObject({
      code: 'SIGNER_ACCESS_DENIED',
      caller: 'delivery',
      operation: 'getCookieSecrets',
    });
    expect(unwrap).not.toHaveBeenCalled();
  });

  it.each(['token_signing', 'event_signing'] as const)(
    'refuses signJws for %s to web',
    async (purpose) => {
      const { signer } = await setup();
      const typ = JWS_TYP_BY_PURPOSE[purpose][0];

      await expect(
        signer.signJws('web', accessToken(REALM_A, { purpose, typ }))
      ).rejects.toMatchObject({ code: 'SIGNER_ACCESS_DENIED', caller: 'web', purpose });
    }
  );

  it('lets delivery sign event tokens and not access tokens; api the other way round', async () => {
    const { signer } = await setup();
    const logout = accessToken(REALM_A, { purpose: 'event_signing', typ: 'logout+jwt' });

    await expect(signer.signJws('delivery', logout)).resolves.toEqual(expect.any(String));
    await expect(signer.signJws('delivery', accessToken())).rejects.toBeInstanceOf(
      SignerAccessDeniedError
    );
    await expect(signer.signJws('api', accessToken())).resolves.toEqual(expect.any(String));
    await expect(signer.signJws('api', logout)).rejects.toBeInstanceOf(SignerAccessDeniedError);
  });

  it.each(['signer', 'LOCAL', '', undefined, 'web; local'])(
    'refuses the unknown caller %s without echoing it',
    async (caller) => {
      const { signer } = await setup();

      const error = await signer
        .getJwks(caller as unknown as SignerCaller, REALM_A)
        .catch((e) => e);

      expect(error).toBeInstanceOf(SignerAccessDeniedError);
      expect(error.caller).toBeUndefined();
      if (caller) expect(error.message).not.toContain(`'${caller}'`);
    }
  );
});

describe('key material', () => {
  /** Every private material the realm stores, opened with the KEK, in the forms it could leak in. */
  async function storedMaterials(setup: Setup) {
    const materials: { purpose: string; bytes: Buffer }[] = [];
    for (const { key } of setup.keys.rows) {
      const bytes = await openKeyMaterial(setup.kekProvider, key, key);
      materials.push({ purpose: key.purpose, bytes });
      // The raw Ed25519 private key is the last 32 bytes of its PKCS#8 form.
      if (key.algorithm === 'EdDSA') {
        materials.push({ purpose: key.purpose, bytes: bytes.subarray(bytes.length - 32) });
      }
    }
    return materials;
  }

  function encodings(bytes: Buffer): string[] {
    return [bytes.toString('base64url'), bytes.toString('base64'), bytes.toString('hex')];
  }

  /** The purposes whose material appears anywhere in `value`, and any key object found. */
  function leaks(value: unknown, materials: { purpose: string; bytes: Buffer }[]) {
    const found = new Set<string>();
    const visit = (node: unknown): void => {
      if (node instanceof KeyObject || node instanceof MlDsaKey) found.add('key object');
      else if (typeof CryptoKey !== 'undefined' && node instanceof CryptoKey)
        found.add('key object');
      else if (node instanceof Uint8Array) {
        for (const { purpose, bytes } of materials) {
          if (Buffer.from(node).includes(bytes)) found.add(purpose);
        }
      } else if (typeof node === 'string') {
        for (const { purpose, bytes } of materials) {
          if (encodings(bytes).some((encoded) => node.includes(encoded))) found.add(purpose);
        }
      } else if (typeof node === 'object' && node !== null) {
        for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv']) {
          if (Object.hasOwn(node, member) && 'kty' in node) found.add('private JWK member');
        }
        for (const child of Object.values(node)) visit(child);
        if (node instanceof Error) visit(node.message);
      }
    };
    visit(value);
    return [...found].sort();
  }

  it('offers exactly the operations of the interface', async () => {
    const { signer } = await setup({ hybrid: true });

    expect(Reflect.ownKeys(signer).sort()).toEqual([...SIGNER_OPERATIONS].sort());
    expect(Object.keys(CALLS).sort()).toEqual([...SIGNER_OPERATIONS].sort());
    expect(Object.isFrozen(signer)).toBe(true);
  });

  it('returns no key material from any operation but the cookie secrets', async () => {
    const context = await setup({ hybrid: true });
    const materials = await storedMaterials(context);
    expect(materials.map(({ purpose }) => purpose)).toEqual(
      expect.arrayContaining(['token_signing', 'event_signing', 'cookie_hmac', 'data_at_rest'])
    );

    for (const operation of Object.keys(context.signer) as SignerOperation[]) {
      const result = await CALLS[operation](context.signer, 'local');
      const expected = operation === 'getCookieSecrets' ? ['cookie_hmac'] : [];

      expect({ operation, leaks: leaks(result, materials) }).toEqual({
        operation,
        leaks: expected,
      });
    }
  });

  it('puts no key material in an error', async () => {
    const context = await setup({ hybrid: true });
    const materials = await storedMaterials(context);
    const errors = await Promise.all([
      context.signer.signJws('local', accessToken(REALM_A, { typ: 'logout+jwt' })).catch((e) => e),
      context.signer.signJws('web', accessToken()).catch((e) => e),
      context.signer.signJws('local', accessToken(REALM_WITHOUT_KEYS)).catch((e) => e),
      context.signer.decrypt('local', { realmId: REALM_A, ciphertext: 'v1.x.y.z' }).catch((e) => e),
    ]);
    const kekFailure = await (
      await setup({ hybrid: true, signerKek: localProvider({ KEK: KEK_B }) })
    ).signer
      .signHybrid('local', { realmId: REALM_A, typ: 'at+jwt', claims: CLAIMS })
      .catch((e) => e);

    for (const error of [...errors, kekFailure]) {
      expect(error).toBeInstanceOf(Error);
      expect(leaks(error, materials)).toEqual([]);
      expect(leaks(JSON.stringify(error), materials)).toEqual([]);
    }
  });
});
