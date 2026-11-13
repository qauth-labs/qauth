import { createPublicKey, verify } from 'node:crypto';

import type { DbClient } from '@qauth-labs/infra-db';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { createTestSigner } from '../testing/memory-signer';
import { createRepositorySignerKeyStore } from './repository-key-stores';

/**
 * The client record the signer reads for an upstream provider (#1073):
 * `findUpstreamClient` over the realm's plugin state, or a generic provider's
 * row. The repositories stand in for the database: they answer what the
 * stored columns hold, as `listAssertionClients` and `findAssertionClient`
 * select them (their own integration tests cover the SQL).
 */

const plugins = vi.hoisted(() => ({ listAssertionClients: vi.fn() }));
const providers = vi.hoisted(() => ({ findAssertionClient: vi.fn() }));
vi.mock('@qauth-labs/infra-db', () => ({
  createRealmsRepository: () => ({}),
  createRealmKeysRepository: () => ({}),
  createRealmAuthMethodPluginsRepository: () => plugins,
  createRealmUpstreamProvidersRepository: () => providers,
}));

const REALM = '0190a3c2-6c1a-7b51-9a4e-0c8f2d6b1e01';
const OTHER_REALM = '0190a3c2-6c1a-7b51-9a4e-0c8f2d6b1e02';
const DB = {} as DbClient;

/** An Apple-like preset's client: a Services ID, and a Team ID as its assertion issuer. */
const APPLE_CLIENT = {
  clientId: 'com.example.signin',
  assertionIssuer: 'TEAM123456',
  algorithm: 'ES256',
};

beforeEach(() => {
  plugins.listAssertionClients.mockReset();
  providers.findAssertionClient.mockReset();
});

describe('findUpstreamClient', () => {
  it("answers the realm's configured client of a plugin, with its assertion issuer", async () => {
    plugins.listAssertionClients.mockImplementation(async (realmId: string, type: string) =>
      realmId === REALM && type === 'apple' ? [APPLE_CLIENT] : []
    );
    const store = createRepositorySignerKeyStore(DB);

    await expect(store.findUpstreamClient(REALM, 'apple')).resolves.toEqual({
      clientId: 'com.example.signin',
      assertionIssuer: 'TEAM123456',
    });
    expect(plugins.listAssertionClients).toHaveBeenCalledWith(REALM, 'apple');
    expect(providers.findAssertionClient).not.toHaveBeenCalled();
  });

  it('answers the client id alone for a preset that names no assertion issuer', async () => {
    plugins.listAssertionClients.mockResolvedValue([{ clientId: 'qauth', algorithm: 'RS256' }]);
    const store = createRepositorySignerKeyStore(DB);

    await expect(store.findUpstreamClient(REALM, 'corp_sso')).resolves.toEqual({
      clientId: 'qauth',
    });
  });

  it('answers none for a realm without the provider', async () => {
    plugins.listAssertionClients.mockImplementation(async (realmId: string, type: string) =>
      realmId === REALM && type === 'apple' ? [APPLE_CLIENT] : []
    );
    const store = createRepositorySignerKeyStore(DB);

    await expect(store.findUpstreamClient(OTHER_REALM, 'apple')).resolves.toBeUndefined();
    await expect(store.findUpstreamClient(REALM, 'other_provider')).resolves.toBeUndefined();
  });

  it('answers none when two enabled plugin states share the type, rather than pick one', async () => {
    plugins.listAssertionClients.mockResolvedValue([
      APPLE_CLIENT,
      { clientId: 'com.example.other', algorithm: 'ES256' },
    ]);
    const store = createRepositorySignerKeyStore(DB);

    await expect(store.findUpstreamClient(REALM, 'apple')).resolves.toBeUndefined();
  });

  it("reads a generic provider's own row, and never the plugin states, for an oidc_ type", async () => {
    providers.findAssertionClient.mockResolvedValue({ clientId: 'qauth-rp', algorithm: 'RS256' });
    const store = createRepositorySignerKeyStore(DB);

    await expect(store.findUpstreamClient(REALM, 'oidc_corp')).resolves.toEqual({
      clientId: 'qauth-rp',
    });
    expect(providers.findAssertionClient).toHaveBeenCalledWith(REALM, 'oidc_corp');
    expect(plugins.listAssertionClients).not.toHaveBeenCalled();

    providers.findAssertionClient.mockResolvedValue(undefined);
    await expect(store.findUpstreamClient(REALM, 'oidc_other')).resolves.toBeUndefined();
  });
});

/** The header and payload of a compact JWS, and whether `jwk` verifies it. */
function readAssertion(jws: string, jwk: Record<string, unknown>) {
  const [header, payload, signature] = jws.split('.');
  const verified = verify(
    'sha256',
    Buffer.from(`${header}.${payload}`),
    { key: createPublicKey({ key: jwk as never, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
    Buffer.from(signature, 'base64url')
  );
  return {
    header: JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >,
    payload: JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >,
    verified,
  };
}

describe('the signer, reading the client record through findUpstreamClient', () => {
  async function signFor(stored: Record<string, unknown>[]) {
    plugins.listAssertionClients.mockResolvedValue(stored);
    const test = createTestSigner({
      refreshIntervalMs: 0,
      upstreamClients: createRepositorySignerKeyStore(DB),
    });
    const realmId = await test.addRealm({ issuer: 'https://login.example.com' });
    // Only the provider's ES256 key: its client record is the stored one above.
    await test.addUpstreamClient(realmId, 'apple', { clientId: 'unread', algorithm: 'ES256' });
    const assertion = await test.signer.signClientAssertion('api', {
      realmId,
      providerId: 'apple',
      audience: 'https://appleid.apple.com',
      algorithm: 'ES256',
      claims: { exp: Math.floor(Date.now() / 1000) + 300, jti: 'assertion-1' },
    });
    const jwks = await test.signer.getUpstreamJwks('api', realmId, 'apple');
    const [jwk] = jwks.keys as Record<string, unknown>[];
    return { ...readAssertion(assertion, jwk), kid: jwk['kid'] };
  }

  it("signs with a preset's assertion issuer as iss and its client id as sub", async () => {
    const { header, payload, verified, kid } = await signFor([APPLE_CLIENT]);

    expect(verified).toBe(true);
    expect(header).toMatchObject({ alg: 'ES256', kid });
    expect(payload).toMatchObject({
      iss: 'TEAM123456',
      sub: 'com.example.signin',
      aud: 'https://appleid.apple.com',
    });
  });

  it('signs with the client id as iss when the preset names no assertion issuer', async () => {
    const { payload, verified } = await signFor([
      { clientId: 'com.example.signin', algorithm: 'ES256' },
    ]);

    expect(verified).toBe(true);
    expect(payload).toMatchObject({ iss: 'com.example.signin', sub: 'com.example.signin' });
  });

  it('signs nothing for a realm whose provider holds no client record', async () => {
    await expect(signFor([])).rejects.toMatchObject({ code: 'SIGNER_UPSTREAM_CLIENT_NOT_FOUND' });
  });
});
