/**
 * Operator grants for CIMD clients against real Postgres (#770).
 *
 * These cases pin what an entry of the seed manifest's `cimd_clients` writes,
 * what it leaves alone, and that the grant outlives a CIMD re-resolution,
 * which rewrites the row from the client's metadata document.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createOAuthClientsRepository, createRealmsRepository } from '../lib/repositories';
import { type IntegrationDb, setupIntegrationDb } from '../lib/repositories/integration-setup';
import { oauthClients } from '../lib/schema/core';
import { applyCimdClientGrant } from './cimd-client-grants';

const CLIENT_ID = 'https://client.example.com/oauth/metadata.json';

describe('applyCimdClientGrant (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
  }, 180_000);

  afterAll(async () => {
    await ctx?.teardown();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !ctx) {
      testCtx.skip();
      return;
    }
    await ctx.reset();
  });

  function db() {
    if (!ctx) throw new Error('integration db not initialised');
    return ctx.database.db;
  }

  async function realm(name: string) {
    return createRealmsRepository(db()).create({ name });
  }

  async function row(realmId: string) {
    const [r] = await db()
      .select()
      .from(oauthClients)
      .where(and(eq(oauthClients.realmId, realmId), eq(oauthClients.clientId, CLIENT_ID)));
    return r;
  }

  /** Every column but the ones a grant writes. */
  function withoutGrant(r: object) {
    const rest: Record<string, unknown> = { ...r };
    delete rest['scopes'];
    delete rest['audience'];
    delete rest['updatedAt'];
    return rest;
  }

  /** What `resolveClient` hands `upsertCimdClient` once it has read the document. */
  function resolvedFromDocument(realmId: string) {
    return {
      realmId,
      clientId: CLIENT_ID,
      clientSecretHash: 'sentinel-from-resolution',
      name: 'Example Client',
      description: 'CIMD client (client_id metadata document)',
      redirectUris: ['http://127.0.0.1/callback'],
      grantTypes: ['authorization_code' as const, 'refresh_token' as const],
      responseTypes: ['code' as const],
      tokenEndpointAuthMethod: 'none' as const,
      requirePkce: true,
      enabled: true,
      developerId: null,
      provisionedByOperator: false,
      scopes: [],
      isAgent: false,
      metadata: {
        registrationType: 'cimd',
        client_id_metadata_url: CLIENT_ID,
        client_uri: 'https://client.example.com',
      },
    };
  }

  it('creates a CIMD row whose grant outlives the first resolution', async () => {
    const r = await realm('cimd-grant-1');

    const result = await applyCimdClientGrant(db(), r.id, {
      client_id: CLIENT_ID,
      scopes: ['mcp:read', 'offline_access'],
      audience: ['https://mcp.example.com/mcp'],
    });
    expect(result).toEqual({ clientId: CLIENT_ID, status: 'created' });

    const pending = await row(r.id);
    expect(pending.metadata).toEqual({
      registrationType: 'cimd',
      client_id_metadata_url: CLIENT_ID,
    });
    expect(pending.redirectUris).toEqual([]);
    expect(pending.tokenEndpointAuthMethod).toBe('none');
    expect(pending.provisionedByOperator).toBe(false);
    expect(pending.clientSecretHash).toMatch(/^\$argon2id\$/);

    const resolved = await createOAuthClientsRepository(db()).upsertCimdClient(
      resolvedFromDocument(r.id)
    );

    expect(resolved.id).toBe(pending.id);
    expect(resolved.name).toBe('Example Client');
    expect(resolved.redirectUris).toEqual(['http://127.0.0.1/callback']);
    expect(resolved.scopes).toEqual(['mcp:read', 'offline_access']);
    expect(resolved.audience).toEqual(['https://mcp.example.com/mcp']);
    // The upsert never rewrites the secret column.
    expect(resolved.clientSecretHash).toBe(pending.clientSecretHash);
  });

  it('updates only scopes and audience of a resolved CIMD row', async () => {
    const r = await realm('cimd-grant-2');
    const clients = createOAuthClientsRepository(db());
    const resolved = await clients.upsertCimdClient(resolvedFromDocument(r.id));
    await clients.update(r.id, resolved.id, { enabled: false });
    const before = await row(r.id);

    const result = await applyCimdClientGrant(db(), r.id, {
      client_id: CLIENT_ID,
      scopes: ['mcp:read'],
    });

    expect(result.status).toBe('updated');
    const after = await row(r.id);
    expect(after.scopes).toEqual(['mcp:read']);
    expect(after.audience).toBeNull();
    expect(withoutGrant(after)).toEqual(withoutGrant(before));
    expect(after.enabled).toBe(false);
  });

  it('reports unchanged and writes nothing when the grant already holds', async () => {
    const r = await realm('cimd-grant-3');
    const spec = { client_id: CLIENT_ID, scopes: ['mcp:read'], audience: null };
    await applyCimdClientGrant(db(), r.id, spec);
    const before = await row(r.id);

    const again = await applyCimdClientGrant(db(), r.id, spec);

    expect(again.status).toBe('unchanged');
    expect((await row(r.id)).updatedAt).toBe(before.updatedAt);
  });

  it('refuses a pre-registered client with the same client_id and leaves it alone', async () => {
    const r = await realm('cimd-grant-4');
    await createOAuthClientsRepository(db()).create({
      realmId: r.id,
      clientId: CLIENT_ID,
      clientSecretHash: 'h',
      name: 'Operator client',
      redirectUris: ['https://client.example.com/cb'],
      scopes: ['mcp:read'],
      provisionedByOperator: true,
    });
    const before = await row(r.id);

    const result = await applyCimdClientGrant(db(), r.id, {
      client_id: CLIENT_ID,
      scopes: ['mcp:read', 'mcp:write'],
    });

    expect(result).toEqual({ clientId: CLIENT_ID, status: 'not_cimd' });
    expect(await row(r.id)).toEqual(before);
  });

  it('grants per realm', async () => {
    const a = await realm('cimd-grant-5a');
    const b = await realm('cimd-grant-5b');

    await applyCimdClientGrant(db(), a.id, { client_id: CLIENT_ID, scopes: ['mcp:read'] });

    expect((await row(a.id)).scopes).toEqual(['mcp:read']);
    expect(await row(b.id)).toBeUndefined();
  });
});
