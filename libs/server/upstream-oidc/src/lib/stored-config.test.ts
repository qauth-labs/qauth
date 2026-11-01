import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import {
  describeUpstreamOidcConfig,
  openUpstreamOidcConfig,
  sealUpstreamOidcConfig,
  storedUpstreamOidcConfigSchema,
  UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX,
  upstreamClientSecretContext,
  UpstreamOidcConfigError,
  type UpstreamSecretCipher,
} from './stored-config';

/**
 * The stored form of a provider's config (#601): the client secret sealed
 * with the data-at-rest key, through the signer role, and never in a view.
 * The flow tests in fastify-plugin-federation run the same codec over the
 * real in-process signer.
 */

const SECRET = 'a-client-secret-of-some-length';
const OWNER = { realmId: 'realm-1', providerId: 'oidc_corp', caller: 'api' } as const;
const CONFIG = {
  issuer: 'https://idp.example.com',
  clientId: 'qauth-client',
  clientAuthentication: { method: 'client_secret_post', clientSecret: SECRET },
};

/** AES-GCM bound to realm and context, shaped like `Signer.encrypt`/`decrypt`. */
function testCipher() {
  const key = randomBytes(32);
  const cipher: UpstreamSecretCipher = {
    encrypt: vi.fn(async (_caller: string, { realmId, plaintext, context }) => {
      const iv = randomBytes(12);
      const gcm = createCipheriv('aes-256-gcm', key, iv).setAAD(
        Buffer.from(`${realmId}|${context}`)
      );
      const sealed = Buffer.concat([gcm.update(plaintext), gcm.final(), gcm.getAuthTag()]);
      return `v1.kid1.${iv.toString('base64url')}.${sealed.toString('base64url')}`;
    }),
    decrypt: vi.fn(async (_caller: string, { realmId, ciphertext, context }) => {
      const [, , iv, sealed] = ciphertext.split('.');
      const bytes = Buffer.from(sealed, 'base64url');
      const gcm = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'))
        .setAAD(Buffer.from(`${realmId}|${context}`))
        .setAuthTag(bytes.subarray(-16));
      return Buffer.concat([gcm.update(bytes.subarray(0, -16)), gcm.final()]);
    }),
  };
  return cipher;
}

describe('the stored config', () => {
  it('seals the client secret, so the stored form holds it in no encoding', async () => {
    const cipher = testCipher();
    const stored = await sealUpstreamOidcConfig(cipher, OWNER, CONFIG);
    expect(stored.clientAuthentication).toEqual({
      method: 'client_secret_post',
      clientSecretSealed: expect.stringMatching(/^v1\./),
    });
    const text = JSON.stringify(stored);
    for (const form of [
      SECRET,
      Buffer.from(SECRET).toString('base64'),
      Buffer.from(SECRET).toString('base64url'),
      Buffer.from(SECRET).toString('hex'),
    ]) {
      expect(text).not.toContain(form);
    }
    expect(cipher.encrypt).toHaveBeenCalledWith('api', {
      realmId: 'realm-1',
      plaintext: Buffer.from(SECRET),
      context: `${UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX}realm-1:oidc_corp`,
    });
  });

  it('opens to the config the method parses, the secret decrypted', async () => {
    const cipher = testCipher();
    const stored = await sealUpstreamOidcConfig(cipher, OWNER, CONFIG);
    const opened = await openUpstreamOidcConfig(cipher, OWNER, stored);
    expect(opened.clientAuthentication).toEqual(CONFIG.clientAuthentication);
    expect(opened.issuer).toBe(CONFIG.issuer);
  });

  it('does not open for another provider or another realm', async () => {
    const cipher = testCipher();
    const stored = await sealUpstreamOidcConfig(cipher, OWNER, CONFIG);
    await expect(
      openUpstreamOidcConfig(cipher, { ...OWNER, providerId: 'oidc_other' }, stored)
    ).rejects.toThrow();
    await expect(
      openUpstreamOidcConfig(cipher, { ...OWNER, realmId: 'realm-2' }, stored)
    ).rejects.toThrow();
  });

  it('never shows the secret or its ciphertext in the view', async () => {
    const stored = await sealUpstreamOidcConfig(testCipher(), OWNER, CONFIG);
    const view = describeUpstreamOidcConfig(stored);
    expect(view.clientAuthentication).toEqual({
      method: 'client_secret_post',
      clientSecretSet: true,
    });
    const text = JSON.stringify(view);
    expect(text).not.toContain(SECRET);
    expect(text).not.toContain(
      (stored.clientAuthentication as { clientSecretSealed: string }).clientSecretSealed
    );
  });

  it('stores a private_key_jwt config without a secret, and calls no cipher', async () => {
    const cipher = testCipher();
    const stored = await sealUpstreamOidcConfig(cipher, OWNER, {
      ...CONFIG,
      clientAuthentication: { method: 'private_key_jwt', signingAlgorithm: 'ES256' },
    });
    expect(stored.clientAuthentication).toEqual({
      method: 'private_key_jwt',
      signingAlgorithm: 'ES256',
    });
    expect(cipher.encrypt).not.toHaveBeenCalled();
    await openUpstreamOidcConfig(cipher, OWNER, stored);
    expect(cipher.decrypt).not.toHaveBeenCalled();
  });

  it('refuses a stored form with the plaintext secret in it', () => {
    expect(
      storedUpstreamOidcConfigSchema.safeParse({
        ...CONFIG,
        scopes: ['openid'],
        responseMode: 'query',
        idTokenSigningAlgorithms: ['RS256'],
        fetchUserinfo: false,
      }).success
    ).toBe(false);
  });

  it('names failing members, never their values', async () => {
    const error = await sealUpstreamOidcConfig(testCipher(), OWNER, {
      ...CONFIG,
      issuer: `http://${SECRET}.example.com`,
    }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(UpstreamOidcConfigError);
    expect(JSON.stringify((error as UpstreamOidcConfigError).issues)).not.toContain(SECRET);
    expect((error as UpstreamOidcConfigError).issues).toEqual(['issuer: custom']);
  });

  it('builds a context only from ids without a colon', () => {
    expect(() => upstreamClientSecretContext('realm:1', 'oidc_corp')).toThrow(TypeError);
    expect(() => upstreamClientSecretContext('realm-1', 'oidc:corp')).toThrow(TypeError);
    expect(upstreamClientSecretContext('realm-1', 'oidc_corp')).not.toMatch(/^delivery:/);
  });
});
