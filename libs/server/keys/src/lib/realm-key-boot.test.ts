import { createPrivateKey, generateKeyPairSync, randomBytes } from 'node:crypto';

import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { KEK_A, localProvider } from '../testing/keks';
import {
  createMemoryKeyStore,
  type MemoryKeyStore,
  type MemoryStoredKey,
} from '../testing/memory-key-store';
import { openKeyMaterial } from './envelope';
import type { EnvironmentKeySettings, EnvironmentKeySource } from './environment-keys';
import type { KekProvider } from './kek-provider';
import { KeyCreationRefusedError } from './key-creation-errors';
import { bootRealmKeys, type BootRealmKeysOptions } from './realm-key-boot';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const NOW = 1_800_000_000_000;
const LATER = NOW + 60_000;
const ED25519_ONLY: readonly SignatureAlgorithm[] = ['EdDSA'];
const HYBRID_CAPABLE: readonly SignatureAlgorithm[] = ['EdDSA', 'ML-DSA-65'];
const COOKIE_SECRET = 'an-operator-session-cookie-secret-0123456789';

function pem(type: 'ed25519' | 'rsa'): string {
  const { privateKey } =
    type === 'ed25519'
      ? generateKeyPairSync('ed25519')
      : generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
}

function source(value: string, ...variables: string[]): EnvironmentKeySource {
  return { value, variables };
}

const ED25519_PEM = pem('ed25519');
const RSA_PEM = pem('rsa');
const SEED = randomBytes(32).toString('base64url');

/** The variables of a deployment from before the key store. */
const UPGRADE: EnvironmentKeySettings = {
  ed25519: { privateKey: source(ED25519_PEM, 'JWT_PRIVATE_KEY') },
  rs256: {
    privateKey: source(RSA_PEM, 'JWT_RS256_PRIVATE_KEY'),
    kid: source('rsa-1', 'JWT_RS256_KID'),
  },
  cookieSecret: source(COOKIE_SECRET, 'SESSION_COOKIE_SECRET'),
};

type BootOverrides = Partial<Omit<BootRealmKeysOptions<unknown>, 'store'>>;

function boot(store: MemoryKeyStore, overrides: BootOverrides = {}) {
  return bootRealmKeys({
    store,
    kekProvider: localProvider({ KEK: KEK_A }),
    enabledSignatureAlgorithms: ED25519_ONLY,
    hybridSigning: false,
    realmId: REALM,
    now: () => NOW,
    ...overrides,
  });
}

/** The realm's keys as `purpose/algorithm`, in a stable order. */
function inventory(store: MemoryKeyStore): string[] {
  return store.rows.map(({ key }) => `${key.purpose}/${key.algorithm}`).sort();
}

function storedKey(store: MemoryKeyStore, kid: string): MemoryStoredKey {
  const row = store.rows.find(({ key }) => key.kid === kid);
  if (row === undefined) throw new Error(`no stored key ${kid}`);
  return row.key;
}

async function open(store: MemoryKeyStore, kid: string, provider: KekProvider): Promise<Buffer> {
  const key = storedKey(store, kid);
  return openKeyMaterial(provider, key, {
    realmId: key.realmId,
    purpose: key.purpose,
    scopeId: key.scopeId,
    kid: key.kid,
    algorithm: key.algorithm,
  });
}

async function refusal(promise: Promise<unknown>): Promise<InvalidConfigurationError> {
  const error = await promise.then(
    () => undefined,
    (reason: unknown) => reason
  );
  expect(error).toBeInstanceOf(InvalidConfigurationError);
  return error as InvalidConfigurationError;
}

describe('bootRealmKeys — first boot after the upgrade', () => {
  it('imports each configured key and creates only the standard keys still missing', async () => {
    const store = createMemoryKeyStore();

    const result = await boot(store, { environmentKeys: UPGRADE });

    expect(result.imported.map((key) => [key.purpose, key.algorithm, key.variables])).toEqual([
      ['token_signing', 'EdDSA', ['JWT_PRIVATE_KEY']],
      ['token_signing', 'RS256', ['JWT_RS256_PRIVATE_KEY', 'JWT_RS256_KID']],
      ['cookie_hmac', 'HS256', ['SESSION_COOKIE_SECRET']],
    ]);
    expect(result.alreadyStored).toEqual([]);
    expect(result.generated.map((key) => `${key.purpose}/${key.algorithm}`).sort()).toEqual([
      'data_at_rest/A256GCM',
      'event_signing/EdDSA',
    ]);
    expect(inventory(store)).toEqual([
      'cookie_hmac/HS256',
      'data_at_rest/A256GCM',
      'event_signing/EdDSA',
      'token_signing/EdDSA',
      'token_signing/RS256',
    ]);
  });

  it('stores the imported keys active and published, under the configured or thumbprint kid', async () => {
    const store = createMemoryKeyStore();

    const { imported } = await boot(store, { environmentKeys: UPGRADE });

    const [ed25519, rs256, cookie] = imported;
    expect(rs256.kid).toBe('rsa-1');
    expect(ed25519.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(storedKey(store, ed25519.kid)).toMatchObject({
      status: 'active',
      pairId: null,
      activateAt: NOW,
      publishAt: NOW,
    });
    const published = store.rows.find(({ key }) => key.kid === ed25519.kid)?.publicJwk;
    expect(published).toMatchObject({ kty: 'OKP', crv: 'Ed25519', kid: ed25519.kid });
    expect(storedKey(store, cookie.kid)).toMatchObject({ status: 'active', publishAt: null });
  });

  it('seals what the variables hold, so the stored keys open to the same keys', async () => {
    const store = createMemoryKeyStore();
    const provider = localProvider({ KEK: KEK_A });

    const { imported } = await bootRealmKeys({
      store,
      kekProvider: provider,
      enabledSignatureAlgorithms: ED25519_ONLY,
      hybridSigning: false,
      realmId: REALM,
      environmentKeys: UPGRADE,
    });

    const [ed25519, rs256, cookie] = imported;
    const edMaterial = await open(store, ed25519.kid, provider);
    expect(
      createPrivateKey({ key: edMaterial, format: 'der', type: 'pkcs8' }).equals(
        createPrivateKey(ED25519_PEM)
      )
    ).toBe(true);
    const rsaMaterial = await open(store, rs256.kid, provider);
    expect(
      createPrivateKey({ key: rsaMaterial, format: 'der', type: 'pkcs8' }).equals(
        createPrivateKey(RSA_PEM)
      )
    ).toBe(true);
    expect((await open(store, cookie.kid, provider)).toString('utf8')).toBe(COOKIE_SECRET);
  });

  it('takes the realm lock inside the transaction before it reads anything', async () => {
    const store = createMemoryKeyStore();

    await boot(store, { environmentKeys: UPGRADE });

    expect(store.calls[0]).toMatchObject({ method: 'transaction' });
    expect(store.calls[1]).toMatchObject({ method: 'lockRealm' });
  });

  it('imports the Ed25519 and ML-DSA-65 keys as one hybrid pair', async () => {
    const store = createMemoryKeyStore();

    const { imported, generated } = await boot(store, {
      enabledSignatureAlgorithms: HYBRID_CAPABLE,
      hybridSigning: true,
      environmentKeys: {
        ed25519: UPGRADE.ed25519,
        mlDsa: { seed: source(SEED, 'JWT_MLDSA_PRIVATE_KEY') },
      },
    });

    const [ed25519, mlDsa] = imported;
    const pairId = storedKey(store, ed25519.kid).pairId;
    expect(pairId).toEqual(expect.any(String));
    expect(storedKey(store, mlDsa.kid)).toMatchObject({ algorithm: 'ML-DSA-65', pairId });
    expect(generated.some((key) => key.purpose === 'token_signing')).toBe(false);
  });
});

describe('bootRealmKeys — later boots', () => {
  it('imports nothing when the variables are still set, and reports them as stored', async () => {
    const store = createMemoryKeyStore();
    const first = await boot(store, { environmentKeys: UPGRADE });
    const rowsAfterFirst = store.rows.length;

    const second = await boot(store, { environmentKeys: UPGRADE });

    expect(second.imported).toEqual([]);
    expect(second.generated).toEqual([]);
    expect(second.alreadyStored).toEqual(first.imported);
    expect(store.rows).toHaveLength(rowsAfterFirst);
  });

  it('recognises a stored key by its public key, after its kid variable is removed', async () => {
    const store = createMemoryKeyStore();
    await boot(store, { environmentKeys: UPGRADE });

    const second = await boot(store, {
      environmentKeys: { rs256: { privateKey: source(RSA_PEM, 'JWT_RS256_PRIVATE_KEY') } },
    });

    expect(second.imported).toEqual([]);
    expect(second.alreadyStored).toEqual([
      expect.objectContaining({ algorithm: 'RS256', kid: 'rsa-1' }),
    ]);
  });

  it('replaces the active key when a variable holds a new one, retiring and unpublishing it at once', async () => {
    const store = createMemoryKeyStore();
    const { imported } = await boot(store, { environmentKeys: UPGRADE });
    const oldKid = imported[0].kid;

    const result = await boot(store, {
      now: () => LATER,
      environmentKeys: { ed25519: { privateKey: source(pem('ed25519'), 'JWT_PRIVATE_KEY') } },
    });

    const [replacement] = result.imported;
    expect(replacement).toMatchObject({ purpose: 'token_signing', algorithm: 'EdDSA' });
    expect(replacement.kid).not.toBe(oldKid);
    expect(result.replaced).toEqual([{ ...replacement, retiredKids: [oldKid] }]);
    expect(result.alreadyStored).toEqual([]);
    expect(result.generated).toEqual([]);
    expect(storedKey(store, oldKid)).toMatchObject({
      status: 'retired',
      retireAt: LATER,
      unpublishAt: LATER,
    });
    expect(storedKey(store, replacement.kid)).toMatchObject({
      status: 'active',
      activateAt: LATER,
      publishAt: LATER,
    });
  });

  it('replaces the RS256 key under a new configured kid', async () => {
    const store = createMemoryKeyStore();
    await boot(store, { environmentKeys: UPGRADE });

    const result = await boot(store, {
      environmentKeys: {
        rs256: {
          privateKey: source(pem('rsa'), 'JWT_RS256_PRIVATE_KEY'),
          kid: source('rsa-2', 'JWT_RS256_KID'),
        },
      },
    });

    expect(result.replaced).toEqual([
      expect.objectContaining({ algorithm: 'RS256', kid: 'rsa-2', retiredKids: ['rsa-1'] }),
    ]);
    expect(storedKey(store, 'rsa-1').status).toBe('retired');
  });

  it('refuses a new key under the configured kid of the key it would replace, and stores nothing', async () => {
    const store = createMemoryKeyStore();
    await boot(store, { environmentKeys: UPGRADE });
    const before = store.rows.map(({ key }) => `${key.kid}:${key.status}`);

    const error = await refusal(
      boot(store, {
        environmentKeys: {
          rs256: {
            privateKey: source(pem('rsa'), 'JWT_RS256_PRIVATE_KEY'),
            kid: source('rsa-1', 'JWT_RS256_KID'),
          },
        },
      })
    );

    expect(error.message).toContain('A new key needs a new kid');
    expect(error.details).toMatchObject({
      variables: ['JWT_RS256_PRIVATE_KEY', 'JWT_RS256_KID'],
      kid: 'rsa-1',
    });
    expect(store.rows.map(({ key }) => `${key.kid}:${key.status}`)).toEqual(before);
  });

  it('changes nothing for a variable that holds a key the store retired, and reports it', async () => {
    const store = createMemoryKeyStore();
    const { imported } = await boot(store, { environmentKeys: UPGRADE });
    const { imported: replacements } = await boot(store, {
      environmentKeys: { ed25519: { privateKey: source(pem('ed25519'), 'JWT_PRIVATE_KEY') } },
    });
    const rows = store.rows.length;

    const result = await boot(store, { environmentKeys: { ed25519: UPGRADE.ed25519 } });

    expect(result.imported).toEqual([]);
    expect(result.replaced).toEqual([]);
    expect(result.alreadyStored).toEqual([]);
    expect(result.inactive).toEqual([
      { ...imported[0], status: 'retired', activeKid: replacements[0].kid },
    ]);
    expect(store.rows).toHaveLength(rows);
    expect(storedKey(store, replacements[0].kid).status).toBe('active');
  });

  it('refuses a variable that holds a key the realm marked compromised', async () => {
    const store = createMemoryKeyStore();
    const { imported } = await boot(store, { environmentKeys: UPGRADE });
    const stored = store.rows.find(({ key }) => key.kid === imported[0].kid);
    if (stored === undefined) throw new Error('not stored');
    (stored.key as { status: string }).status = 'compromised';

    const error = await refusal(boot(store, { environmentKeys: { ed25519: UPGRADE.ed25519 } }));

    expect(error.message).toContain('marked compromised');
  });

  it('does not import a cookie secret into a realm that has a cookie key', async () => {
    const store = createMemoryKeyStore();
    const fresh = await boot(store);
    const cookieKey = fresh.generated.find((key) => key.purpose === 'cookie_hmac');

    const result = await boot(store, {
      environmentKeys: { cookieSecret: source(COOKIE_SECRET, 'SESSION_COOKIE_SECRET') },
    });

    expect(result.imported).toEqual([]);
    expect(result.alreadyStored).toEqual([
      {
        purpose: 'cookie_hmac',
        algorithm: 'HS256',
        kid: cookieKey?.kid,
        variables: ['SESSION_COOKIE_SECRET'],
      },
    ]);
  });

  it('refuses an ML-DSA-65 key that would join an Ed25519 key stored without one', async () => {
    const store = createMemoryKeyStore();
    await boot(store, {
      enabledSignatureAlgorithms: HYBRID_CAPABLE,
      environmentKeys: { ed25519: UPGRADE.ed25519 },
    });

    const error = await refusal(
      boot(store, {
        enabledSignatureAlgorithms: HYBRID_CAPABLE,
        hybridSigning: true,
        environmentKeys: {
          ed25519: UPGRADE.ed25519,
          mlDsa: { seed: source(SEED, 'JWT_MLDSA_PRIVATE_KEY') },
        },
      })
    );

    expect(error.message).toContain('set JWT_PRIVATE_KEY to a new key as well');
    expect(error.details).toMatchObject({ variables: ['JWT_MLDSA_PRIVATE_KEY'] });
  });

  it('turns hybrid signing on when both keys of the pair are new: the Ed25519 key is replaced', async () => {
    const store = createMemoryKeyStore();
    const { imported } = await boot(store, {
      enabledSignatureAlgorithms: HYBRID_CAPABLE,
      environmentKeys: { ed25519: UPGRADE.ed25519 },
    });

    const result = await boot(store, {
      enabledSignatureAlgorithms: HYBRID_CAPABLE,
      hybridSigning: true,
      environmentKeys: {
        ed25519: { privateKey: source(pem('ed25519'), 'JWT_PRIVATE_KEY') },
        mlDsa: { seed: source(SEED, 'JWT_MLDSA_PRIVATE_KEY') },
      },
    });

    const [ed25519, mlDsa] = result.imported;
    expect(result.replaced).toEqual([{ ...ed25519, retiredKids: [imported[0].kid] }]);
    const pairId = storedKey(store, ed25519.kid).pairId;
    expect(pairId).toEqual(expect.any(String));
    expect(storedKey(store, mlDsa.kid)).toMatchObject({ status: 'active', pairId });
  });

  it('replaces both keys of a hybrid pair as a new pair', async () => {
    const store = createMemoryKeyStore();
    const hybrid = { enabledSignatureAlgorithms: HYBRID_CAPABLE, hybridSigning: true };
    const first = await boot(store, {
      ...hybrid,
      environmentKeys: {
        ed25519: UPGRADE.ed25519,
        mlDsa: { seed: source(SEED, 'JWT_MLDSA_PRIVATE_KEY') },
      },
    });
    const oldPair = storedKey(store, first.imported[0].kid).pairId;

    const result = await boot(store, {
      ...hybrid,
      environmentKeys: {
        ed25519: { privateKey: source(pem('ed25519'), 'JWT_PRIVATE_KEY') },
        mlDsa: { seed: source(randomBytes(32).toString('base64url'), 'JWT_MLDSA_PRIVATE_KEY') },
      },
    });

    expect(result.replaced.map((key) => [key.algorithm, key.retiredKids])).toEqual([
      ['EdDSA', [first.imported[0].kid]],
      ['ML-DSA-65', [first.imported[1].kid]],
    ]);
    const [ed25519, mlDsa] = result.imported;
    const newPair = storedKey(store, ed25519.kid).pairId;
    expect(newPair).not.toBe(oldPair);
    expect(storedKey(store, mlDsa.kid).pairId).toBe(newPair);
    for (const { kid } of first.imported) expect(storedKey(store, kid).status).toBe('retired');
  });

  it('refuses a new Ed25519 key while the ML-DSA-65 variable still holds the stored half', async () => {
    const store = createMemoryKeyStore();
    const hybrid = { enabledSignatureAlgorithms: HYBRID_CAPABLE, hybridSigning: true };
    const mlDsa = { seed: source(SEED, 'JWT_MLDSA_PRIVATE_KEY') };
    await boot(store, { ...hybrid, environmentKeys: { ed25519: UPGRADE.ed25519, mlDsa } });
    const before = store.rows.map(({ key }) => `${key.kid}:${key.status}`);

    const error = await refusal(
      boot(store, {
        ...hybrid,
        environmentKeys: {
          ed25519: { privateKey: source(pem('ed25519'), 'JWT_PRIVATE_KEY') },
          mlDsa,
        },
      })
    );

    expect(error.message).toContain('set JWT_MLDSA_PRIVATE_KEY to a new key as well');
    expect(error.details).toMatchObject({ variables: ['JWT_PRIVATE_KEY'] });
    expect(store.rows.map(({ key }) => `${key.kid}:${key.status}`)).toEqual(before);
  });

  it('retires the hybrid partner of a replaced key when hybrid signing is off', async () => {
    const store = createMemoryKeyStore();
    const first = await boot(store, {
      enabledSignatureAlgorithms: HYBRID_CAPABLE,
      hybridSigning: true,
      environmentKeys: {
        ed25519: UPGRADE.ed25519,
        mlDsa: { seed: source(SEED, 'JWT_MLDSA_PRIVATE_KEY') },
      },
    });
    const [oldEd25519, oldMlDsa] = first.imported.map((key) => key.kid);

    const result = await boot(store, {
      enabledSignatureAlgorithms: HYBRID_CAPABLE,
      environmentKeys: { ed25519: { privateKey: source(pem('ed25519'), 'JWT_PRIVATE_KEY') } },
    });

    expect(result.replaced).toEqual([
      expect.objectContaining({ algorithm: 'EdDSA', retiredKids: [oldEd25519, oldMlDsa] }),
    ]);
    expect(storedKey(store, oldMlDsa)).toMatchObject({ status: 'retired', unpublishAt: NOW });
    expect(storedKey(store, result.imported[0].kid).pairId).toBeNull();
  });
});

describe('bootRealmKeys — a fresh deployment', () => {
  it('generates the standard keys and an RS256 signing key', async () => {
    const store = createMemoryKeyStore();

    const result = await boot(store);

    expect(result.imported).toEqual([]);
    expect(inventory(store)).toEqual([
      'cookie_hmac/HS256',
      'data_at_rest/A256GCM',
      'event_signing/EdDSA',
      'token_signing/EdDSA',
      'token_signing/RS256',
    ]);
    expect(store.rows.every(({ key }) => key.status === 'active')).toBe(true);
  });

  it('generates no RS256 key on a realm that imported its signing key', async () => {
    const store = createMemoryKeyStore();

    await boot(store, { environmentKeys: { ed25519: UPGRADE.ed25519 } });

    expect(inventory(store)).not.toContain('token_signing/RS256');
  });

  it('generates no RS256 key on a realm that already had signing keys', async () => {
    const store = createMemoryKeyStore();
    await boot(store, { environmentKeys: { ed25519: UPGRADE.ed25519 } });

    const second = await boot(store);

    expect(second.generated).toEqual([]);
  });

  it('generates the hybrid pair with hybrid signing on', async () => {
    const store = createMemoryKeyStore();

    await boot(store, { enabledSignatureAlgorithms: HYBRID_CAPABLE, hybridSigning: true });

    expect(inventory(store)).toContain('token_signing/ML-DSA-65');
    expect(inventory(store)).toContain('token_signing/RS256');
  });
});

describe('bootRealmKeys — the KEK', () => {
  it('refuses to import a key another realm already stores, naming the variable, and stores nothing (#491)', async () => {
    const store = createMemoryKeyStore();
    const otherRealm = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02';
    await boot(store, {
      realmId: otherRealm,
      environmentKeys: { ed25519: { privateKey: source(ED25519_PEM, 'JWT_PRIVATE_KEY') } },
    });
    const before = store.rows.length;

    const error = await refusal(
      boot(store, {
        environmentKeys: { ed25519: { privateKey: source(ED25519_PEM, 'JWT_PRIVATE_KEY') } },
      })
    );
    expect(error.message).toContain('another realm of this deployment already stores');
    expect(error.details).toEqual({ variables: ['JWT_PRIVATE_KEY'] });
    expect(store.rows.length).toBe(before);

    // A key of its own imports as before.
    await expect(
      boot(store, {
        environmentKeys: { ed25519: { privateKey: source(pem('ed25519'), 'JWT_PRIVATE_KEY') } },
      })
    ).resolves.toMatchObject({ imported: [expect.objectContaining({ algorithm: 'EdDSA' })] });
  });

  it('refuses to import under the development KEK, naming the variables', async () => {
    const store = createMemoryKeyStore();
    const warnings: unknown[] = [];

    const error = await refusal(
      bootRealmKeys({
        store,
        // No KEK and no KEK_PATH: outside production the provider falls back
        // to the published development KEK.
        kekProvider: localProvider({}, warnings as never[]),
        enabledSignatureAlgorithms: ED25519_ONLY,
        hybridSigning: false,
        realmId: REALM,
        environmentKeys: UPGRADE,
      })
    );

    expect(error.message).toContain('no KEK is set');
    expect(error.details).toEqual({
      variables: [
        'JWT_PRIVATE_KEY',
        'JWT_RS256_PRIVATE_KEY',
        'JWT_RS256_KID',
        'SESSION_COOKIE_SECRET',
      ],
    });
    expect(store.rows).toEqual([]);
  });

  it('refuses the development KEK when it is set explicitly', async () => {
    const { DEV_KEK_DEFAULT } = await import('./kek-sources');

    await refusal(
      bootRealmKeys({
        store: createMemoryKeyStore(),
        kekProvider: localProvider({ KEK: DEV_KEK_DEFAULT }),
        enabledSignatureAlgorithms: ED25519_ONLY,
        hybridSigning: false,
        realmId: REALM,
        environmentKeys: { ed25519: UPGRADE.ed25519 },
      })
    );
  });

  it('lets a fresh deployment generate its keys under the development KEK', async () => {
    const store = createMemoryKeyStore();

    await bootRealmKeys({
      store,
      kekProvider: localProvider({}),
      enabledSignatureAlgorithms: ED25519_ONLY,
      hybridSigning: false,
      realmId: REALM,
    });

    expect(store.rows).toHaveLength(5);
  });
});

describe('bootRealmKeys — what is stored', () => {
  it('stores no imported private key, PEM or secret in plaintext in any column', async () => {
    const store = createMemoryKeyStore();
    await boot(store, {
      enabledSignatureAlgorithms: HYBRID_CAPABLE,
      hybridSigning: true,
      environmentKeys: { ...UPGRADE, mlDsa: { seed: source(SEED, 'JWT_MLDSA_PRIVATE_KEY') } },
    });

    const secrets: Buffer[] = [
      createPrivateKey(ED25519_PEM).export({ type: 'pkcs8', format: 'der' }),
      createPrivateKey(RSA_PEM).export({ type: 'pkcs8', format: 'der' }),
      Buffer.from(SEED, 'base64url'),
      Buffer.from(COOKIE_SECRET, 'utf8'),
    ];
    // The raw scalar of the Ed25519 key: the last 32 bytes of its PKCS#8 form.
    secrets.push(secrets[0].subarray(secrets[0].length - 32));
    const texts = [ED25519_PEM, RSA_PEM, SEED, COOKIE_SECRET];
    // The private JWK members of both PEM keys, as a JWK would carry them.
    const privateJwks = [ED25519_PEM, RSA_PEM].map(
      (value) => createPrivateKey(value).export({ format: 'jwk' }) as Record<string, string>
    );
    texts.push(privateJwks[0]['d'], privateJwks[1]['d'], privateJwks[1]['p']);

    for (const { key, publicJwk } of store.rows) {
      for (const value of Object.values(key)) {
        if (Buffer.isBuffer(value)) {
          for (const secret of secrets) expect(value.includes(secret)).toBe(false);
        }
        if (typeof value === 'string') {
          for (const text of texts) expect(value.includes(text)).toBe(false);
        }
      }
      const serialised = JSON.stringify(publicJwk ?? {});
      for (const text of texts) expect(serialised.includes(text)).toBe(false);
      expect(publicJwk ?? {}).not.toHaveProperty('d');
    }
  });
});

describe('bootRealmKeys — refusals before anything is read', () => {
  it('refuses a realm id that is not a UUID', async () => {
    await expect(boot(createMemoryKeyStore(), { realmId: 'master' })).rejects.toBeInstanceOf(
      KeyCreationRefusedError
    );
  });

  it('refuses an ML-DSA-65 key with hybrid signing off', async () => {
    const store = createMemoryKeyStore();

    await refusal(
      boot(store, {
        enabledSignatureAlgorithms: HYBRID_CAPABLE,
        environmentKeys: { mlDsa: { seed: source(SEED, 'JWT_MLDSA_PRIVATE_KEY') } },
      })
    );
    expect(store.calls).toEqual([]);
  });
});
