import { createPublicKey, generateKeyPairSync } from 'node:crypto';

import { DEV_SESSION_COOKIE_SECRET_DEFAULT } from '@qauth-labs/server-config';
import { calculateJwkThumbprint } from 'jose';
import { describe, expect, it } from 'vitest';

import { type KeyVariableConfig, keyVariableSettings, thumbprintKid } from './key-variables';

const ED25519 = generateKeyPairSync('ed25519');
const ED25519_PEM = ED25519.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const ED25519_PUBLIC_PEM = ED25519.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const SECRET = 'an-operator-session-cookie-secret-0123456789';

const BASE: KeyVariableConfig = {
  JWT_PRIVATE_KEY: ED25519_PEM,
  HYBRID_SIGNING_ENABLED: false,
  SESSION_COOKIE_SECRET: DEV_SESSION_COOKIE_SECRET_DEFAULT,
};

describe('keyVariableSettings', () => {
  it('names the variables the operator set, value or file', () => {
    const settings = keyVariableSettings(
      { ...BASE, JWT_PUBLIC_KEY: ED25519_PUBLIC_PEM },
      { JWT_PRIVATE_KEY_PATH: '/run/secrets/jwt', JWT_PUBLIC_KEY: ED25519_PUBLIC_PEM }
    );

    expect(settings.ed25519).toEqual({
      privateKey: { value: ED25519_PEM, variables: ['JWT_PRIVATE_KEY_PATH'] },
      publicKey: { value: ED25519_PUBLIC_PEM, variables: ['JWT_PUBLIC_KEY'] },
    });
  });

  it('names both variables when both are set', () => {
    const settings = keyVariableSettings(BASE, {
      JWT_PRIVATE_KEY: ED25519_PEM,
      JWT_PRIVATE_KEY_PATH: '/run/secrets/jwt',
    });

    expect(settings.ed25519?.privateKey.variables).toEqual([
      'JWT_PRIVATE_KEY',
      'JWT_PRIVATE_KEY_PATH',
    ]);
  });

  it('passes the RS256 key with its public key and kid', () => {
    const settings = keyVariableSettings(
      { ...BASE, JWT_RS256_PRIVATE_KEY: 'rsa-pem', JWT_RS256_KID: 'rsa-1' },
      { JWT_RS256_PRIVATE_KEY: 'rsa-pem', JWT_RS256_KID: 'rsa-1' }
    );

    expect(settings.rs256).toEqual({
      privateKey: { value: 'rsa-pem', variables: ['JWT_RS256_PRIVATE_KEY'] },
      kid: { value: 'rsa-1', variables: ['JWT_RS256_KID'] },
    });
  });

  it('passes the ML-DSA-65 seed only with hybrid signing on', () => {
    const config = { ...BASE, JWT_MLDSA_PRIVATE_KEY: 'seed', JWT_MLDSA_KID: 'pq-1' };
    const raw = { JWT_MLDSA_PRIVATE_KEY: 'seed', JWT_MLDSA_KID: 'pq-1' };

    expect(keyVariableSettings(config, raw).mlDsa).toBeUndefined();
    expect(keyVariableSettings({ ...config, HYBRID_SIGNING_ENABLED: true }, raw).mlDsa).toEqual({
      seed: { value: 'seed', variables: ['JWT_MLDSA_PRIVATE_KEY'] },
      kid: { value: 'pq-1', variables: ['JWT_MLDSA_KID'] },
    });
  });

  it('passes SESSION_COOKIE_SECRET only when the operator set it', () => {
    expect(keyVariableSettings(BASE, {}).cookieSecret).toBeUndefined();
    expect(
      keyVariableSettings(BASE, { SESSION_COOKIE_SECRET: DEV_SESSION_COOKIE_SECRET_DEFAULT })
        .cookieSecret
    ).toBeUndefined();
    expect(
      keyVariableSettings(
        { ...BASE, SESSION_COOKIE_SECRET: SECRET },
        { SESSION_COOKIE_SECRET: SECRET }
      ).cookieSecret
    ).toEqual({ value: SECRET, variables: ['SESSION_COOKIE_SECRET'] });
  });

  it('passes nothing for a key whose variable is unset', () => {
    expect(
      keyVariableSettings(
        { HYBRID_SIGNING_ENABLED: false, SESSION_COOKIE_SECRET: DEV_SESSION_COOKIE_SECRET_DEFAULT },
        {}
      )
    ).toEqual({});
  });
});

describe('thumbprintKid', () => {
  it('is the RFC 7638 thumbprint of the public key', async () => {
    const expected = await calculateJwkThumbprint(
      createPublicKey(ED25519_PUBLIC_PEM).export({ format: 'jwk' }),
      'sha256'
    );

    await expect(thumbprintKid(ED25519_PEM)).resolves.toBe(expected);
  });

  it('is undefined for a value that is not a PEM key', async () => {
    await expect(thumbprintKid('not a key')).resolves.toBeUndefined();
  });
});
