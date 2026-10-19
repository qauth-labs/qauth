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

import {
  cimdSentinelSecretHash,
  isAgentClient,
  isCimdClient,
  resolveClient,
} from './client-resolution';

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

  // ADR-012 §3: the metadata document is the management surface. A
  // materialised row is a cache of it, so every resolution re-applies the
  // document, CIMD_ENABLED and the trust policy.
  describe('re-resolves a materialised CIMD client on every use', () => {
    const DOC = {
      client_id: CIMD_ID,
      client_name: 'Example',
      redirect_uris: ['https://app.example.com/cb'],
    };

    async function materialise() {
      const stub = fastifyStub();
      stub.fastify.repositories.oauthClients.findByClientId.mockResolvedValue(undefined);
      ssrfSafeGet.mockResolvedValue(ok(DOC));
      const { client } = await resolveClient(stub.fastify, 'realm-1', CIMD_ID);
      expect(client).not.toBeNull();
      // From here on the row exists, exactly as after a first authorize.
      stub.fastify.repositories.oauthClients.findByClientId.mockResolvedValue(stub.upserted[0]);
      stub.fastify.repositories.oauthClients.upsertCimdClient.mockClear();
      stub.fastify.redis.get.mockResolvedValue(null); // expire the document cache
      return stub;
    }

    it('applies an edited document (new redirect_uris) to the stored client', async () => {
      const { fastify } = await materialise();
      ssrfSafeGet.mockResolvedValue(
        ok({ ...DOC, redirect_uris: ['https://app.example.com/new-cb'] })
      );

      const { client } = await resolveClient(fastify, 'realm-1', CIMD_ID);

      expect(fastify.repositories.oauthClients.upsertCimdClient).toHaveBeenCalledOnce();
      expect(client!.redirectUris).toEqual(['https://app.example.com/new-cb']);
    });

    it('writes nothing when the document is unchanged', async () => {
      const { fastify, upserted } = await materialise();
      ssrfSafeGet.mockResolvedValue(ok(DOC));

      const { client } = await resolveClient(fastify, 'realm-1', CIMD_ID);

      expect(client).toBe(upserted[0]);
      expect(fastify.repositories.oauthClients.upsertCimdClient).not.toHaveBeenCalled();
    });

    // Regression (ANT-2026-AF8IKIPI): `canonicalJson` sorted object keys with
    // `localeCompare`. ICU collation is quadratic in a run of combining marks
    // that are out of canonical order, once per comparison, and JWK member
    // names are the document author's — a stored row keeps whatever an earlier
    // document carried.
    it('compares the stored key set with the document without collating member names', async () => {
      const marks = [0x345, 0x35d, 0x35c, 0x315, 0x301, 0x316, 0x31b, 0x321, 0x711, 0x670, 0x334];
      const storedJwk: Record<string, unknown> = {
        kty: 'EC',
        ['й' + marks.map((mark) => String.fromCharCode(mark).repeat(800)).join('')]: 0,
      };
      // Names before and after 'й' in turns keep the long name where the sort
      // compares it again and again.
      for (let n = 0; n < 30; n++) {
        storedJwk['а' + String.fromCharCode(0x430 + n)] = 0;
        storedJwk['я' + String.fromCharCode(0x430 + n)] = 0;
      }
      const { fastify, upserted } = await materialise();
      fastify.repositories.oauthClients.findByClientId.mockResolvedValue({
        ...upserted[0],
        tokenEndpointAuthMethod: 'private_key_jwt',
        jwks: { keys: [storedJwk] },
      });
      ssrfSafeGet.mockResolvedValue(
        ok({
          ...DOC,
          token_endpoint_auth_method: 'private_key_jwt',
          jwks: { keys: [{ kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' }] },
        })
      );

      const startedAt = performance.now();
      const { client } = await resolveClient(fastify, 'realm-1', CIMD_ID);

      expect(performance.now() - startedAt).toBeLessThan(1000);
      expect(client).not.toBeNull();
      expect(fastify.repositories.oauthClients.upsertCimdClient).toHaveBeenCalledOnce();
    }, 60_000);

    it('fails closed once CIMD is switched off, even for a stored client', async () => {
      const { fastify } = await materialise();
      ENV.CIMD_ENABLED = false;

      const { client, reason } = await resolveClient(fastify, 'realm-1', CIMD_ID);

      expect(client).toBeNull();
      expect(reason).toBeDefined();
    });

    it('fails closed once the host leaves the trust allowlist', async () => {
      const { fastify } = await materialise();
      (ENV as { CIMD_TRUST_POLICY: string }).CIMD_TRUST_POLICY = 'allowlist';
      ENV.CIMD_TRUSTED_DOMAINS = ['other.example.com'];
      try {
        const { client } = await resolveClient(fastify, 'realm-1', CIMD_ID);
        expect(client).toBeNull();
      } finally {
        (ENV as { CIMD_TRUST_POLICY: string }).CIMD_TRUST_POLICY = 'accept-any-https';
        ENV.CIMD_TRUSTED_DOMAINS = [];
      }
    });

    // ANT-2026-D0XJAT8S follow-up: a document that adds a redirect URI
    // registration would refuse is refused whole, and the client already
    // materialised from its earlier version stops resolving (fail closed).
    it('fails closed once the document lists a redirect_uri registration would refuse', async () => {
      const { fastify } = await materialise();
      ssrfSafeGet.mockResolvedValue(
        ok(
          { ...DOC, redirect_uris: [...DOC.redirect_uris, 'http://app.example.com/plain'] },
          { 'cache-control': 'no-store' }
        )
      );
      // The earlier document is still cached; drop it as its TTL would.
      fastify.redis.get.mockResolvedValue(null);

      const { client, reason } = await resolveClient(fastify, 'realm-1', CIMD_ID);

      expect(client).toBeNull();
      expect(reason).toMatch(/^CIMD document refused: invalid_redirect_uri: /);
      expect(fastify.repositories.oauthClients.upsertCimdClient).not.toHaveBeenCalled();
    });

    it('fails closed when the document can no longer be fetched', async () => {
      const { fastify } = await materialise();
      ssrfSafeGet.mockResolvedValue({ status: 404, body: '', headers: {} });

      const { client } = await resolveClient(fastify, 'realm-1', CIMD_ID);

      expect(client).toBeNull();
    });

    it('never lets the document re-enable a client the server disabled', async () => {
      const { fastify, upserted } = await materialise();
      fastify.repositories.oauthClients.findByClientId.mockResolvedValue({
        ...upserted[0],
        enabled: false,
      });
      ssrfSafeGet.mockResolvedValue(
        ok({ ...DOC, redirect_uris: ['https://app.example.com/new-cb'] })
      );

      await resolveClient(fastify, 'realm-1', CIMD_ID);

      expect(fastify.repositories.oauthClients.upsertCimdClient).toHaveBeenCalledWith(
        expect.objectContaining({ enabled: false })
      );
    });

    // ANT-2026-DR5XI3LV: `suspended` is operator state. A re-resolution never
    // writes it, so the document can neither clear a suspension nor race one.
    it('never writes `suspended`, so the document cannot lift an operator suspension', async () => {
      const { fastify, upserted } = await materialise();
      const suspendedRow = { ...upserted[0], suspended: true, suspendedAt: 1_700 };
      fastify.repositories.oauthClients.findByClientId.mockResolvedValue(suspendedRow);
      ssrfSafeGet.mockResolvedValue(
        ok({
          ...DOC,
          client_name: 'Renamed by its host',
          redirect_uris: ['https://app.example.com/cb'],
        })
      );

      await resolveClient(fastify, 'realm-1', CIMD_ID);

      const write = fastify.repositories.oauthClients.upsertCimdClient.mock.calls[0][0];
      expect(write).not.toHaveProperty('suspended');
      expect(write).not.toHaveProperty('suspendedAt');
    });

    it('hands back the suspended row when the document is unchanged', async () => {
      const { fastify, upserted } = await materialise();
      const suspendedRow = { ...upserted[0], suspended: true, suspendedAt: 1_700 };
      fastify.repositories.oauthClients.findByClientId.mockResolvedValue(suspendedRow);
      ssrfSafeGet.mockResolvedValue(ok(DOC));

      const { client } = await resolveClient(fastify, 'realm-1', CIMD_ID);

      expect(client?.suspended).toBe(true);
      expect(fastify.repositories.oauthClients.upsertCimdClient).not.toHaveBeenCalled();
    });
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

describe('isAgentClient — fail-closed agent classification (ADR-007 §2)', () => {
  it('is true only for a strict isAgent === true', () => {
    expect(isAgentClient({ isAgent: true })).toBe(true);
  });

  it('is false for a standard client', () => {
    expect(isAgentClient({ isAgent: false })).toBe(false);
  });

  it('fails closed for missing / null / undefined (treats as non-agent, never throws)', () => {
    // A client omitting the flag is the real escalation direction — it must
    // read as NOT an agent, not as truthy and not as an error.
    expect(isAgentClient({})).toBe(false);
    expect(isAgentClient(null)).toBe(false);
    expect(isAgentClient(undefined)).toBe(false);
  });
});
