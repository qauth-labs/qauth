import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';

import {
  deriveMlDsaPublicKey,
  getSignatureBackend,
  type SignatureAlgorithm,
} from '@qauth-labs/core-crypto';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { calculateJwkThumbprint } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  type EnvironmentKeySource,
  MIN_RSA_MODULUS_BITS,
  prepareEnvironmentKeys,
} from './environment-keys';

const ED25519_ONLY: readonly SignatureAlgorithm[] = ['EdDSA'];
const HYBRID_CAPABLE: readonly SignatureAlgorithm[] = ['EdDSA', 'ML-DSA-65'];

function pemPair(type: 'ed25519' | 'rsa', modulusLength = 2048) {
  const { privateKey, publicKey } =
    type === 'ed25519'
      ? generateKeyPairSync('ed25519')
      : generateKeyPairSync('rsa', { modulusLength });
  return {
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

function source(value: string, ...variables: string[]): EnvironmentKeySource {
  return { value, variables };
}

/** The refusal of `promise`, which must be an `InvalidConfigurationError`. */
async function refusal(promise: Promise<unknown>): Promise<InvalidConfigurationError> {
  const error = await promise.then(
    () => undefined,
    (reason: unknown) => reason
  );
  expect(error).toBeInstanceOf(InvalidConfigurationError);
  return error as InvalidConfigurationError;
}

const ED25519 = pemPair('ed25519');
const RSA = pemPair('rsa');
const SEED = randomBytes(32).toString('base64url');

describe('prepareEnvironmentKeys — Ed25519', () => {
  it('derives the public key with node:crypto and names the key by its thumbprint', async () => {
    const [key] = await prepareEnvironmentKeys(
      { ed25519: { privateKey: source(ED25519.privateKey, 'JWT_PRIVATE_KEY') } },
      { enabledSignatureAlgorithms: ED25519_ONLY }
    );

    const expectedJwk = createPublicKey(ED25519.publicKey).export({ format: 'jwk' });
    const thumbprint = await calculateJwkThumbprint(expectedJwk, 'sha256');
    expect(key).toMatchObject({
      purpose: 'token_signing',
      algorithm: 'EdDSA',
      kid: thumbprint,
      thumbprint,
      variables: ['JWT_PRIVATE_KEY'],
    });
    expect(key.publicJwk).toEqual({
      ...expectedJwk,
      alg: 'EdDSA',
      use: 'sig',
      kid: thumbprint,
    });
    expect(key.publicJwk).not.toHaveProperty('d');
  });

  it('keeps the private key as PKCS#8 DER, the form a generated key is sealed in', async () => {
    const [key] = await prepareEnvironmentKeys(
      { ed25519: { privateKey: source(ED25519.privateKey, 'JWT_PRIVATE_KEY') } },
      { enabledSignatureAlgorithms: ED25519_ONLY }
    );

    const reimported = createPrivateKey({ key: key.material, format: 'der', type: 'pkcs8' });
    expect(reimported.equals(createPrivateKey(ED25519.privateKey))).toBe(true);
  });

  it('accepts JWT_PUBLIC_KEY when it is the public half, and lists its variable', async () => {
    const [key] = await prepareEnvironmentKeys(
      {
        ed25519: {
          privateKey: source(ED25519.privateKey, 'JWT_PRIVATE_KEY_PATH'),
          publicKey: source(ED25519.publicKey, 'JWT_PUBLIC_KEY'),
        },
      },
      { enabledSignatureAlgorithms: ED25519_ONLY }
    );

    expect(key.variables).toEqual(['JWT_PRIVATE_KEY_PATH', 'JWT_PUBLIC_KEY']);
  });

  it('refuses a JWT_PUBLIC_KEY that is not the public half, naming both variables', async () => {
    const other = pemPair('ed25519');

    const error = await refusal(
      prepareEnvironmentKeys(
        {
          ed25519: {
            privateKey: source(ED25519.privateKey, 'JWT_PRIVATE_KEY'),
            publicKey: source(other.publicKey, 'JWT_PUBLIC_KEY'),
          },
        },
        { enabledSignatureAlgorithms: ED25519_ONLY }
      )
    );

    expect(error.message).toContain('JWT_PUBLIC_KEY does not match JWT_PRIVATE_KEY');
    expect(error.message).not.toContain('BEGIN');
    expect(error.details).toEqual({ variables: ['JWT_PUBLIC_KEY'] });
  });

  it('refuses a value that is not a PEM key without quoting it', async () => {
    const error = await refusal(
      prepareEnvironmentKeys(
        { ed25519: { privateKey: source('not-a-key-but-a-secret-value', 'JWT_PRIVATE_KEY') } },
        { enabledSignatureAlgorithms: ED25519_ONLY }
      )
    );

    expect(error.message).toContain('JWT_PRIVATE_KEY does not hold a private key');
    expect(error.message).not.toContain('not-a-key-but-a-secret-value');
  });

  it('refuses an RSA key where an Ed25519 key belongs', async () => {
    const error = await refusal(
      prepareEnvironmentKeys(
        { ed25519: { privateKey: source(RSA.privateKey, 'JWT_PRIVATE_KEY') } },
        { enabledSignatureAlgorithms: ED25519_ONLY }
      )
    );

    expect(error.message).toBe('JWT_PRIVATE_KEY must hold an Ed25519 private key.');
  });
});

describe('prepareEnvironmentKeys — RS256', () => {
  it('keeps a configured kid', async () => {
    const [key] = await prepareEnvironmentKeys(
      {
        rs256: {
          privateKey: source(RSA.privateKey, 'JWT_RS256_PRIVATE_KEY'),
          kid: source('rsa-2026', 'JWT_RS256_KID'),
        },
      },
      { enabledSignatureAlgorithms: ED25519_ONLY }
    );

    const expectedJwk = createPublicKey(RSA.publicKey).export({ format: 'jwk' });
    expect(key).toMatchObject({
      algorithm: 'RS256',
      kid: 'rsa-2026',
      thumbprint: await calculateJwkThumbprint(expectedJwk, 'sha256'),
      variables: ['JWT_RS256_PRIVATE_KEY', 'JWT_RS256_KID'],
    });
    expect(key.publicJwk).toEqual({ ...expectedJwk, alg: 'RS256', use: 'sig', kid: 'rsa-2026' });
  });

  it('names the key by its thumbprint when no kid is configured', async () => {
    const [key] = await prepareEnvironmentKeys(
      { rs256: { privateKey: source(RSA.privateKey, 'JWT_RS256_PRIVATE_KEY') } },
      { enabledSignatureAlgorithms: ED25519_ONLY }
    );

    expect(key.kid).toBe(key.thumbprint);
  });

  it(`refuses an RSA key shorter than ${MIN_RSA_MODULUS_BITS} bits`, async () => {
    const short = pemPair('rsa', 1024);

    const error = await refusal(
      prepareEnvironmentKeys(
        { rs256: { privateKey: source(short.privateKey, 'JWT_RS256_PRIVATE_KEY') } },
        { enabledSignatureAlgorithms: ED25519_ONLY }
      )
    );

    expect(error.details).toEqual({ variables: ['JWT_RS256_PRIVATE_KEY'], bits: 1024 });
  });

  it('refuses a JWT_RS256_PUBLIC_KEY that is not the public half', async () => {
    const error = await refusal(
      prepareEnvironmentKeys(
        {
          rs256: {
            privateKey: source(RSA.privateKey, 'JWT_RS256_PRIVATE_KEY'),
            publicKey: source(pemPair('rsa').publicKey, 'JWT_RS256_PUBLIC_KEY'),
          },
        },
        { enabledSignatureAlgorithms: ED25519_ONLY }
      )
    );

    expect(error.message).toContain('JWT_RS256_PUBLIC_KEY does not match JWT_RS256_PRIVATE_KEY');
  });

  it('refuses an empty configured kid', async () => {
    const error = await refusal(
      prepareEnvironmentKeys(
        {
          rs256: {
            privateKey: source(RSA.privateKey, 'JWT_RS256_PRIVATE_KEY'),
            kid: source('  ', 'JWT_RS256_KID'),
          },
        },
        { enabledSignatureAlgorithms: ED25519_ONLY }
      )
    );

    expect(error.details).toEqual({ variables: ['JWT_RS256_KID'] });
  });
});

describe('prepareEnvironmentKeys — ML-DSA-65', () => {
  it('derives the AKP public key from the seed and keeps a configured kid', async () => {
    const [key] = await prepareEnvironmentKeys(
      {
        mlDsa: {
          seed: source(SEED, 'JWT_MLDSA_PRIVATE_KEY'),
          kid: source('pq-1', 'JWT_MLDSA_KID'),
        },
      },
      { enabledSignatureAlgorithms: HYBRID_CAPABLE }
    );

    const backend = getSignatureBackend('ML-DSA-65', HYBRID_CAPABLE);
    const pub = backend.exportKey(deriveMlDsaPublicKey(backend.importKey(SEED, 'private')));
    expect(key).toMatchObject({ algorithm: 'ML-DSA-65', kid: 'pq-1' });
    expect(key.publicJwk).toEqual({
      kty: 'AKP',
      pub,
      use: 'sig',
      alg: 'ML-DSA-65',
      kid: 'pq-1',
    });
    expect(key.thumbprint).toBe(
      await calculateJwkThumbprint({ kty: 'AKP', alg: 'ML-DSA-65', pub }, 'sha256')
    );
    expect(key.material).toEqual(Buffer.from(SEED, 'base64url'));
  });

  it('refuses a seed that is not 32 bytes of base64url', async () => {
    const error = await refusal(
      prepareEnvironmentKeys(
        { mlDsa: { seed: source('c2hvcnQ', 'JWT_MLDSA_PRIVATE_KEY') } },
        { enabledSignatureAlgorithms: HYBRID_CAPABLE }
      )
    );

    expect(error.details).toEqual({ variables: ['JWT_MLDSA_PRIVATE_KEY'] });
  });

  it('needs SIGNING_ALGORITHM_MODE to enable ML-DSA-65', async () => {
    await expect(
      prepareEnvironmentKeys(
        { mlDsa: { seed: source(SEED, 'JWT_MLDSA_PRIVATE_KEY') } },
        { enabledSignatureAlgorithms: ED25519_ONLY }
      )
    ).rejects.toThrow();
  });
});

describe('prepareEnvironmentKeys — cookie secret', () => {
  it('keeps the UTF-8 bytes of the secret under a random kid', async () => {
    const secret = 'a-session-cookie-secret-of-at-least-32-characters';
    const [first] = await prepareEnvironmentKeys(
      { cookieSecret: source(secret, 'SESSION_COOKIE_SECRET') },
      { enabledSignatureAlgorithms: ED25519_ONLY }
    );
    const [second] = await prepareEnvironmentKeys(
      { cookieSecret: source(secret, 'SESSION_COOKIE_SECRET') },
      { enabledSignatureAlgorithms: ED25519_ONLY }
    );

    expect(first).toMatchObject({
      purpose: 'cookie_hmac',
      algorithm: 'HS256',
      thumbprint: null,
      variables: ['SESSION_COOKIE_SECRET'],
    });
    expect(first.publicJwk).toBeUndefined();
    expect(first.material.toString('utf8')).toBe(secret);
    expect(first.kid).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(second.kid).not.toBe(first.kid);
  });
});

describe('prepareEnvironmentKeys — every key', () => {
  it('returns the keys in a fixed order', async () => {
    const keys = await prepareEnvironmentKeys(
      {
        cookieSecret: source('x'.repeat(40), 'SESSION_COOKIE_SECRET'),
        mlDsa: { seed: source(SEED, 'JWT_MLDSA_PRIVATE_KEY') },
        rs256: { privateKey: source(RSA.privateKey, 'JWT_RS256_PRIVATE_KEY') },
        ed25519: { privateKey: source(ED25519.privateKey, 'JWT_PRIVATE_KEY') },
      },
      { enabledSignatureAlgorithms: HYBRID_CAPABLE }
    );

    expect(keys.map((key) => key.algorithm)).toEqual(['EdDSA', 'RS256', 'ML-DSA-65', 'HS256']);
  });
});
