import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import {
  API_KEY_SCHEME,
  assertStaticApiKeysAllowed,
  authenticateApiKey,
  generateApiKey,
  parseApiKeyPrefix,
} from './api-key';

/**
 * A fake argon2id hasher: the "hash" is a reversible marker so tests can assert
 * which plaintext was hashed and emulate constant-time verification without the
 * real (slow) argon2 cost. verifyPassword fails safe on a malformed hash, like
 * the real one.
 */
function fakeHasher() {
  return {
    hashPassword: vi.fn(async (plain: string) => `argon2id$${plain}`),
    verifyPassword: vi.fn(async (hash: string, plain: string) => hash === `argon2id$${plain}`),
  };
}

function makeFastify(overrides: Record<string, unknown> = {}) {
  const hasher = fakeHasher();
  const fastify = {
    passwordHasher: hasher,
    log: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
    repositories: {
      apiKeys: {
        findByPrefix: vi.fn(),
        touchLastUsed: vi.fn(async () => undefined),
      },
      oauthClients: {
        findById: vi.fn(),
      },
      realms: {
        findById: vi.fn(),
      },
    },
    ...overrides,
  };
  return { fastify: fastify as unknown as FastifyInstance, hasher };
}

describe('generateApiKey', () => {
  it('produces a qauth_<id>_<secret> key, hashes the full plaintext, never returns the plaintext in storable fields', async () => {
    const { fastify, hasher } = makeFastify();
    const generated = await generateApiKey(fastify);

    expect(generated.key).toMatch(/^qauth_[0-9a-f]{16}_[0-9a-f]{64}$/);
    expect(generated.prefix).toMatch(/^qauth_[0-9a-f]{16}$/);
    expect(generated.key.startsWith(`${generated.prefix}_`)).toBe(true);
    expect(generated.last4).toHaveLength(4);
    expect(generated.key.endsWith(generated.last4)).toBe(true);

    // The hash covers the FULL key (the real hasher is argon2id; here the fake
    // marks the input so we can assert WHICH plaintext was hashed).
    expect(hasher.hashPassword).toHaveBeenCalledWith(generated.key);
    expect(generated.keyHash).toBe(`argon2id$${generated.key}`);
  });

  it('generates unique keys across calls', async () => {
    const { fastify } = makeFastify();
    const a = await generateApiKey(fastify);
    const b = await generateApiKey(fastify);
    expect(a.key).not.toBe(b.key);
    expect(a.prefix).not.toBe(b.prefix);
  });
});

describe('assertStaticApiKeysAllowed (the environment gate)', () => {
  it('allows a development client whose realm ceiling permits development', () => {
    expect(() =>
      assertStaticApiKeysAllowed(
        { environment: 'development' },
        { maxEnvironmentLaxity: 'development' }
      )
    ).not.toThrow();
  });

  it('refuses a production client with 403', () => {
    expect.assertions(2);
    try {
      assertStaticApiKeysAllowed(
        { environment: 'production' },
        { maxEnvironmentLaxity: 'development' }
      );
    } catch (err) {
      expect((err as { statusCode: number }).statusCode).toBe(403);
      expect((err as Error).message).toMatch(/client_credentials/);
    }
  });

  it('refuses a client with an UNSET environment with 403 (fail-safe to production)', () => {
    expect.assertions(1);
    try {
      assertStaticApiKeysAllowed({}, { maxEnvironmentLaxity: 'development' });
    } catch (err) {
      expect((err as { statusCode: number }).statusCode).toBe(403);
    }
  });

  it('refuses a staging client with 403 (staging keeps production-grade security)', () => {
    expect(() =>
      assertStaticApiKeysAllowed({ environment: 'staging' }, { maxEnvironmentLaxity: 'staging' })
    ).toThrow();
  });

  it('refuses a development client when the REALM ceiling forces production', () => {
    // The gate is the STRICTER of client vs realm — a realm pinned to production
    // overrides a development client.
    expect(() =>
      assertStaticApiKeysAllowed(
        { environment: 'development' },
        { maxEnvironmentLaxity: 'production' }
      )
    ).toThrow();
  });
});

describe('parseApiKeyPrefix', () => {
  it('extracts the prefix from a raw key', () => {
    expect(parseApiKeyPrefix('qauth_0123456789abcdef_deadbeef')).toBe('qauth_0123456789abcdef');
  });

  it('extracts the prefix from a Bearer header value', () => {
    expect(parseApiKeyPrefix('Bearer qauth_0123456789abcdef_deadbeef')).toBe(
      'qauth_0123456789abcdef'
    );
  });

  it('returns null for non-qauth tokens (e.g. a JWT)', () => {
    expect(parseApiKeyPrefix('Bearer eyJhbGciOi.something.else')).toBeNull();
    expect(parseApiKeyPrefix('qauth_short')).toBeNull();
    expect(parseApiKeyPrefix(undefined)).toBeNull();
  });
});

describe('authenticateApiKey', () => {
  const liveKeyRow = (prefix: string, key: string, over: Record<string, unknown> = {}) => ({
    id: 'key-1',
    realmId: 'realm-1',
    clientId: 'client-uuid-1',
    developerId: 'dev-1',
    name: 'laptop',
    keyHash: `argon2id$${key}`,
    prefix,
    last4: key.slice(-4),
    createdAt: 1700,
    lastUsedAt: null,
    revokedAt: null,
    ...over,
  });

  const devClient = {
    id: 'client-uuid-1',
    clientId: 'app-123',
    realmId: 'realm-1',
    enabled: true,
    environment: 'development',
  };
  const devRealm = { id: 'realm-1', maxEnvironmentLaxity: 'development' };

  it('authenticates a valid, live key for a development client and touches lastUsedAt', async () => {
    const { fastify } = makeFastify();
    const generated = await generateApiKey(fastify);
    const row = liveKeyRow(generated.prefix, generated.key);

    (fastify.repositories.apiKeys.findByPrefix as ReturnType<typeof vi.fn>).mockResolvedValue(row);
    (fastify.repositories.oauthClients.findById as ReturnType<typeof vi.fn>).mockResolvedValue(
      devClient
    );
    (fastify.repositories.realms.findById as ReturnType<typeof vi.fn>).mockResolvedValue(devRealm);

    const result = await authenticateApiKey(fastify, `Bearer ${generated.key}`);

    expect(result).toEqual({
      clientId: 'client-uuid-1',
      clientClientId: 'app-123',
      apiKeyId: 'key-1',
      developerId: 'dev-1',
    });
    expect(fastify.repositories.apiKeys.touchLastUsed).toHaveBeenCalledWith('key-1');
  });

  it('rejects a REVOKED key (returns null, no client lookup)', async () => {
    const { fastify } = makeFastify();
    const generated = await generateApiKey(fastify);
    const row = liveKeyRow(generated.prefix, generated.key, { revokedAt: 1800 });

    (fastify.repositories.apiKeys.findByPrefix as ReturnType<typeof vi.fn>).mockResolvedValue(row);

    const result = await authenticateApiKey(fastify, generated.key);

    expect(result).toBeNull();
    expect(fastify.repositories.oauthClients.findById).not.toHaveBeenCalled();
    expect(fastify.repositories.apiKeys.touchLastUsed).not.toHaveBeenCalled();
  });

  it('rejects when the secret does not match the stored hash', async () => {
    const { fastify } = makeFastify();
    const generated = await generateApiKey(fastify);
    // Store a hash of a DIFFERENT key under the same prefix.
    const row = liveKeyRow(generated.prefix, `${generated.prefix}_wrongsecret`);
    row.keyHash = `argon2id$${generated.prefix}_wrongsecret`;

    (fastify.repositories.apiKeys.findByPrefix as ReturnType<typeof vi.fn>).mockResolvedValue(row);

    const result = await authenticateApiKey(fastify, generated.key);
    expect(result).toBeNull();
  });

  it('rejects an unknown prefix (no row)', async () => {
    const { fastify } = makeFastify();
    (fastify.repositories.apiKeys.findByPrefix as ReturnType<typeof vi.fn>).mockResolvedValue(
      undefined
    );
    const result = await authenticateApiKey(fastify, 'qauth_0123456789abcdef_deadbeefcafe');
    expect(result).toBeNull();
  });

  it('rejects a valid key whose client has since moved to PRODUCTION (gate re-applied on use)', async () => {
    const { fastify } = makeFastify();
    const generated = await generateApiKey(fastify);
    const row = liveKeyRow(generated.prefix, generated.key);

    (fastify.repositories.apiKeys.findByPrefix as ReturnType<typeof vi.fn>).mockResolvedValue(row);
    (fastify.repositories.oauthClients.findById as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...devClient,
      environment: 'production',
    });
    (fastify.repositories.realms.findById as ReturnType<typeof vi.fn>).mockResolvedValue(devRealm);

    const result = await authenticateApiKey(fastify, generated.key);
    expect(result).toBeNull();
    expect(fastify.repositories.apiKeys.touchLastUsed).not.toHaveBeenCalled();
  });

  it('rejects a valid key whose REALM ceiling has since forced production', async () => {
    const { fastify } = makeFastify();
    const generated = await generateApiKey(fastify);
    const row = liveKeyRow(generated.prefix, generated.key);

    (fastify.repositories.apiKeys.findByPrefix as ReturnType<typeof vi.fn>).mockResolvedValue(row);
    (fastify.repositories.oauthClients.findById as ReturnType<typeof vi.fn>).mockResolvedValue(
      devClient
    );
    (fastify.repositories.realms.findById as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 'realm-1',
      maxEnvironmentLaxity: 'production',
    });

    const result = await authenticateApiKey(fastify, generated.key);
    expect(result).toBeNull();
  });

  it('rejects when the owning client is disabled', async () => {
    const { fastify } = makeFastify();
    const generated = await generateApiKey(fastify);
    const row = liveKeyRow(generated.prefix, generated.key);

    (fastify.repositories.apiKeys.findByPrefix as ReturnType<typeof vi.fn>).mockResolvedValue(row);
    (fastify.repositories.oauthClients.findById as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...devClient,
      enabled: false,
    });

    const result = await authenticateApiKey(fastify, generated.key);
    expect(result).toBeNull();
  });

  it('returns null for a non-qauth credential without any DB hit', async () => {
    const { fastify } = makeFastify();
    const result = await authenticateApiKey(fastify, 'Bearer not-an-api-key');
    expect(result).toBeNull();
    expect(fastify.repositories.apiKeys.findByPrefix).not.toHaveBeenCalled();
  });

  it('exposes the scheme constant', () => {
    expect(API_KEY_SCHEME).toBe('qauth');
  });
});
