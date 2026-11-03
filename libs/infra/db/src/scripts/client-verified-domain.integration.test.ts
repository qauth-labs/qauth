/**
 * The verified-domain tool against real Postgres (#914): it writes
 * `verified_domain` and `updated_at` and nothing else (the secret stays), the
 * stored form passes the database's CHECK, and it refuses a client whose
 * screens would not show the domain.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createOAuthClientsRepository, createRealmsRepository } from '../lib/repositories';
import { type IntegrationDb, setupIntegrationDb } from '../lib/repositories/integration-setup';
import { oauthClients } from '../lib/schema/core';
import type { NewOAuthClient } from '../types';
import { setClientVerifiedDomain } from './client-verified-domain';

describe('setClientVerifiedDomain (real Postgres)', () => {
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

  async function seed(realmName: string, clientId: string, extra: Partial<NewOAuthClient> = {}) {
    const realm = await createRealmsRepository(db()).create({ name: realmName });
    const client = await createOAuthClientsRepository(db()).create({
      realmId: realm.id,
      clientId,
      clientSecretHash: 'argon2-hash-of-the-secret',
      name: clientId,
      redirectUris: ['https://notes.example.com/cb'],
      provisionedByOperator: true,
      updatedAt: 1,
      ...extra,
    });
    return { realm, client };
  }

  async function row(id: string) {
    const [r] = await db().select().from(oauthClients).where(eq(oauthClients.id, id));
    return r;
  }

  it('sets the stored form on an operator-provisioned client and changes nothing else', async () => {
    const { client } = await seed('vd-1', 'notes');
    const before = await row(client.id);

    const result = await setClientVerifiedDomain(db(), {
      realm: 'vd-1',
      clientId: 'notes',
      domain: 'Bücher.Example.',
    });

    expect(result).toEqual({
      status: 'set',
      id: client.id,
      clientId: 'notes',
      previous: null,
      verifiedDomain: 'xn--bcher-kva.example',
    });
    const after = await row(client.id);
    expect(after.verifiedDomain).toBe('xn--bcher-kva.example');
    expect(after.updatedAt).toBeGreaterThan(1);
    // The secret, the redirect URIs and the marker stay as they were.
    expect({ ...after, verifiedDomain: null, updatedAt: before.updatedAt }).toEqual(before);
  });

  it('replaces, keeps and clears the domain, writing only when it changes', async () => {
    const { client } = await seed('vd-2', 'notes', { verifiedDomain: 'old.example.com' });

    await expect(
      setClientVerifiedDomain(db(), {
        realm: 'vd-2',
        clientId: 'notes',
        domain: 'notes.example.com',
      })
    ).resolves.toMatchObject({
      status: 'set',
      previous: 'old.example.com',
      verifiedDomain: 'notes.example.com',
    });
    const set = await row(client.id);

    await expect(
      setClientVerifiedDomain(db(), {
        realm: 'vd-2',
        clientId: 'notes',
        domain: 'NOTES.example.com',
      })
    ).resolves.toMatchObject({ status: 'unchanged', verifiedDomain: 'notes.example.com' });
    expect((await row(client.id)).updatedAt).toBe(set.updatedAt);

    await expect(
      setClientVerifiedDomain(db(), { realm: 'vd-2', clientId: 'notes', domain: null })
    ).resolves.toMatchObject({
      status: 'cleared',
      previous: 'notes.example.com',
      verifiedDomain: null,
    });
    expect((await row(client.id)).verifiedDomain).toBeNull();

    await expect(
      setClientVerifiedDomain(db(), { realm: 'vd-2', clientId: 'notes', domain: null })
    ).resolves.toMatchObject({ status: 'unchanged', verifiedDomain: null });
  });

  it('refuses a client whose screens would not show the domain, and writes nothing', async () => {
    const { realm } = await seed('vd-3', 'portal-app', {
      provisionedByOperator: false,
      metadata: { registrationType: 'dynamic' },
    });
    const clients = createOAuthClientsRepository(db());
    const cimd = await clients.upsertCimdClient({
      realmId: realm.id,
      clientId: 'https://agent.example.com/client.json',
      clientSecretHash: 'sentinel',
      name: 'Agent',
      redirectUris: ['https://agent.example.com/cb'],
      tokenEndpointAuthMethod: 'none',
      enabled: true,
      metadata: { registrationType: 'cimd' },
    });

    await expect(
      setClientVerifiedDomain(db(), {
        realm: 'vd-3',
        clientId: 'portal-app',
        domain: 'portal.example.com',
      })
    ).resolves.toEqual({ status: 'not_operator_provisioned', clientId: 'portal-app' });
    await expect(
      setClientVerifiedDomain(db(), {
        realm: 'vd-3',
        clientId: cimd.clientId,
        domain: 'agent.example.com',
      })
    ).resolves.toEqual({ status: 'cimd_client', clientId: cimd.clientId });

    const stored = await db()
      .select({ verifiedDomain: oauthClients.verifiedDomain })
      .from(oauthClients)
      .where(eq(oauthClients.realmId, realm.id));
    expect(stored).toEqual([{ verifiedDomain: null }, { verifiedDomain: null }]);
  });

  it('reports an unknown realm or client, and touches no other realm’s client of that id', async () => {
    const { client: other } = await seed('vd-4', 'notes');
    await createRealmsRepository(db()).create({ name: 'vd-5' });

    await expect(
      setClientVerifiedDomain(db(), {
        realm: 'nope',
        clientId: 'notes',
        domain: 'notes.example.com',
      })
    ).resolves.toEqual({ status: 'realm_not_found' });
    await expect(
      setClientVerifiedDomain(db(), {
        realm: 'vd-5',
        clientId: 'notes',
        domain: 'notes.example.com',
      })
    ).resolves.toEqual({ status: 'client_not_found' });
    expect((await row(other.id)).verifiedDomain).toBeNull();
  });
});
