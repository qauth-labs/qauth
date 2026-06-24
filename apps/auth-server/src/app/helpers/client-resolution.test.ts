import { beforeEach, describe, expect, it, vi } from 'vitest';

const { ENV, ssrfSafeGet } = vi.hoisted(() => ({
  ENV: {
    CIMD_ENABLED: true,
    CIMD_TRUST_POLICY: 'accept-any-https' as const,
    CIMD_TRUSTED_DOMAINS: [] as string[],
    CIMD_CACHE_DEFAULT_TTL: 300,
    CIMD_CACHE_MAX_TTL: 3600,
    CIMD_MAX_DOCUMENT_BYTES: 65536,
    CIMD_FETCH_TIMEOUT_MS: 5000,
    CIMD_ALLOW_PRIVATE_ADDRESSES: false,
  },
  ssrfSafeGet: vi.fn(),
}));
vi.mock('../../config/env', () => ({ env: ENV }));

// Mock only the network layer; exercise the REAL CIMD resolver + the REAL
// pre-registered → CIMD priority logic. Errors thus originate inside cimd.ts,
// not the test file.
vi.mock('./ssrf-safe-fetch', async () => {
  const actual = await vi.importActual<typeof import('./ssrf-safe-fetch')>('./ssrf-safe-fetch');
  return { ...actual, ssrfSafeGet };
});

import { cimdSentinelSecretHash, isCimdClient, resolveClient } from './client-resolution';

const CIMD_ID = 'https://app.example.com/client.json';

function ok(body: unknown, headers: Record<string, string> = {}) {
  return { status: 200, body: JSON.stringify(body), headers };
}

function fastifyStub() {
  const upserted: any[] = [];
  const store = new Map<string, string>();
  return {
    fastify: {
      redis: {
        get: vi.fn(async (k: string) => store.get(k) ?? null),
        set: vi.fn(async (k: string, v: string) => {
          store.set(k, v);
          return 'OK';
        }),
      },
      repositories: {
        oauthClients: {
          findByClientId: vi.fn(),
          upsertCimdClient: vi.fn(async (row: any) => {
            const persisted = {
              ...row,
              id: '11111111-1111-1111-1111-111111111111',
              audience: null,
              dynamicRegisteredAt: null,
              createdAt: 1,
              updatedAt: 1,
            };
            upserted.push(persisted);
            return persisted;
          }),
        },
      },
      passwordHasher: { hashPassword: vi.fn(async () => 'argon2id$sentinel') },
    } as any,
    upserted,
  };
}

beforeEach(() => {
  ssrfSafeGet.mockReset();
  ENV.CIMD_ENABLED = true;
});

describe('resolveClient — pre-registered → CIMD priority (MCP 2025-11-25)', () => {
  it('returns a pre-registered client without consulting CIMD (priority 1)', async () => {
    const { fastify } = fastifyStub();
    const preReg = { id: 'db-uuid', clientId: 'app-123', redirectUris: [], metadata: null };
    fastify.repositories.oauthClients.findByClientId.mockResolvedValue(preReg);

    const { client } = await resolveClient(fastify, 'realm-1', 'app-123');

    expect(client).toBe(preReg);
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });

  it('a pre-registered URL client_id still wins over a re-fetch (priority 1)', async () => {
    const { fastify } = fastifyStub();
    const preReg = { id: 'db-uuid', clientId: CIMD_ID, redirectUris: [], metadata: null };
    fastify.repositories.oauthClients.findByClientId.mockResolvedValue(preReg);

    const { client } = await resolveClient(fastify, 'realm-1', CIMD_ID);

    expect(client).toBe(preReg);
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });

  it('materialises a CIMD client when not pre-registered (priority 2)', async () => {
    const { fastify, upserted } = fastifyStub();
    fastify.repositories.oauthClients.findByClientId.mockResolvedValue(undefined);
    ssrfSafeGet.mockResolvedValue(
      ok({
        client_id: CIMD_ID,
        client_name: 'Example',
        redirect_uris: ['https://app.example.com/cb'],
      })
    );

    const { client } = await resolveClient(fastify, 'realm-1', CIMD_ID);

    expect(client).not.toBeNull();
    expect(client!.clientId).toBe(CIMD_ID);
    expect(client!.redirectUris).toEqual(['https://app.example.com/cb']);
    // Persisted as a public client so auth-code / refresh / audit FKs hold.
    expect(upserted[0].tokenEndpointAuthMethod).toBe('none');
    expect(upserted[0].requirePkce).toBe(true);
    expect(isCimdClient(client!)).toBe(true);
  });

  // Regression (DoS / OWASP API4): the unauthenticated CIMD resolution path
  // must NOT invoke the CPU/memory-intensive Argon2id KDF. It stores a
  // synchronously-built, well-formed argon2id sentinel instead.
  it('does NOT run Argon2id on the unauthenticated CIMD path (DoS guard)', async () => {
    const { fastify, upserted } = fastifyStub();
    fastify.repositories.oauthClients.findByClientId.mockResolvedValue(undefined);
    ssrfSafeGet.mockResolvedValue(
      ok({
        client_id: CIMD_ID,
        client_name: 'Example',
        redirect_uris: ['https://app.example.com/cb'],
      })
    );

    await resolveClient(fastify, 'realm-1', CIMD_ID);

    expect(fastify.passwordHasher.hashPassword).not.toHaveBeenCalled();
    // Sentinel is shaped like a genuine argon2id PHC string.
    expect(upserted[0].clientSecretHash).toMatch(/^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$/);
  });

  it('returns null + reason when CIMD resolution fails (client_id ≠ URL)', async () => {
    const { fastify } = fastifyStub();
    fastify.repositories.oauthClients.findByClientId.mockResolvedValue(undefined);
    // Document claims a different client_id than the URL it was fetched from.
    ssrfSafeGet.mockResolvedValue(
      ok({
        client_id: 'https://evil.example/other.json',
        client_name: 'Impostor',
        redirect_uris: ['https://evil.example/cb'],
      })
    );

    const { client, reason } = await resolveClient(fastify, 'realm-1', CIMD_ID);

    expect(client).toBeNull();
    expect(reason).toMatch(/does not match/);
    // Never materialised a row for the rejected document.
    expect(fastify.repositories.oauthClients.upsertCimdClient).not.toHaveBeenCalled();
  });

  it('cimdSentinelSecretHash returns a unique, well-formed, unverifiable argon2id string', () => {
    const a = cimdSentinelSecretHash();
    const b = cimdSentinelSecretHash();
    expect(a).toMatch(/^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[^$]+\$[^$]+$/);
    expect(a).not.toBe(b); // random salt + digest each call
  });

  it('returns null for an unknown opaque client_id (priority 3, no CIMD attempt)', async () => {
    const { fastify } = fastifyStub();
    fastify.repositories.oauthClients.findByClientId.mockResolvedValue(undefined);

    const { client, reason } = await resolveClient(fastify, 'realm-1', 'totally-unknown');

    expect(client).toBeNull();
    expect(reason).toBe('invalid_client');
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });
});
