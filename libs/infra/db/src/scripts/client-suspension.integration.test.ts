/**
 * The operator suspension tool against real Postgres (ANT-2026-DR5XI3LV).
 *
 * `suspended` is the operator's cut-off, separate from the owner's `enabled`.
 * These cases pin what the tool writes (and what it leaves alone) on the real
 * migrated schema, and that a CIMD re-resolution can never clear it.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createOAuthClientsRepository, createRealmsRepository } from '../lib/repositories';
import { type IntegrationDb, setupIntegrationDb } from '../lib/repositories/integration-setup';
import { auditLogs } from '../lib/schema/audit';
import { oauthClients } from '../lib/schema/core';
import { events } from '../lib/schema/events';
import { setClientSuspension } from './client-suspension';

describe('setClientSuspension (real Postgres)', () => {
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

  async function seed(realmName: string, clientId: string, enabled = true) {
    const realm = await createRealmsRepository(db()).create({ name: realmName });
    const client = await createOAuthClientsRepository(db()).create({
      realmId: realm.id,
      clientId,
      clientSecretHash: 'h',
      name: clientId,
      redirectUris: ['https://app.example.com/cb'],
      enabled,
    });
    return { realm, client };
  }

  async function row(id: string) {
    const [r] = await db().select().from(oauthClients).where(eq(oauthClients.id, id));
    return r;
  }

  it('suspends, records it, and leaves the owner switch alone', async () => {
    const { realm, client } = await seed('susp-1', 'app-1');

    const result = await setClientSuspension(db(), {
      realm: 'susp-1',
      clientId: 'app-1',
      suspend: true,
    });

    expect(result).toMatchObject({ status: 'suspended', suspended: true, enabled: true });
    const stored = await row(client.id);
    expect(stored.suspended).toBe(true);
    expect(stored.suspendedAt).toEqual(expect.any(Number));
    expect(stored.enabled).toBe(true);
    // The record is an event in the realm, committed with the change; no
    // audit row is written any more (#458).
    const recorded = await db().select().from(events).where(eq(events.realmId, realm.id));
    expect(recorded).toHaveLength(1);
    expect(recorded[0]).toMatchObject({
      type: 'urn:qauth:event:client.suspended:v1-rc.0',
      category: 'admin',
      actorType: 'operator_cli',
      subjectType: 'client',
      subjectId: 'app-1',
      clientId: 'app-1',
      data: {},
    });
    expect(await db().select().from(auditLogs)).toHaveLength(0);
  });

  it('is idempotent and lifts only the suspension', async () => {
    const { realm, client } = await seed('susp-2', 'app-2', false);
    await setClientSuspension(db(), { realm: 'susp-2', clientId: 'app-2', suspend: true });

    const again = await setClientSuspension(db(), {
      realm: 'susp-2',
      clientId: 'app-2',
      suspend: true,
    });
    expect(again.status).toBe('unchanged');

    const lifted = await setClientSuspension(db(), {
      realm: 'susp-2',
      clientId: 'app-2',
      suspend: false,
    });
    expect(lifted).toMatchObject({ status: 'lifted', suspended: false, enabled: false });
    // One event per change, none for the run that changed nothing.
    const recorded = await db()
      .select({ type: events.type })
      .from(events)
      .where(eq(events.realmId, realm.id))
      .orderBy(events.seq);
    expect(recorded.map((event) => event.type)).toEqual([
      'urn:qauth:event:client.suspended:v1-rc.0',
      'urn:qauth:event:client.suspension_lifted:v1-rc.0',
    ]);
    const stored = await row(client.id);
    expect(stored.suspended).toBe(false);
    expect(stored.suspendedAt).toBeNull();
    // The owner's disable is still the owner's to undo.
    expect(stored.enabled).toBe(false);
  });

  it('reports an unknown realm or client without writing', async () => {
    await seed('susp-3', 'app-3');
    await expect(
      setClientSuspension(db(), { realm: 'nope', clientId: 'app-3', suspend: true })
    ).resolves.toEqual({ status: 'realm_not_found' });
    await expect(
      setClientSuspension(db(), { realm: 'susp-3', clientId: 'nope', suspend: true })
    ).resolves.toEqual({ status: 'client_not_found' });
  });

  it('survives a CIMD re-resolution that refreshes the row', async () => {
    const realm = await createRealmsRepository(db()).create({ name: 'susp-cimd' });
    const clients = createOAuthClientsRepository(db());
    const cimd = {
      realmId: realm.id,
      clientId: 'https://app.example.com/client.json',
      clientSecretHash: 'sentinel',
      name: 'Before',
      redirectUris: ['https://app.example.com/cb'],
      tokenEndpointAuthMethod: 'none' as const,
      enabled: true,
    };
    const created = await clients.upsertCimdClient(cimd);
    await setClientSuspension(db(), {
      realm: 'susp-cimd',
      clientId: cimd.clientId,
      suspend: true,
    });

    const refreshed = await clients.upsertCimdClient({ ...cimd, name: 'After' });

    expect(refreshed.name).toBe('After');
    expect(refreshed.suspended).toBe(true);
    expect((await row(created.id)).suspended).toBe(true);
  });

  it('cannot be undone through the repository update an owner route uses', async () => {
    const { client } = await seed('susp-4', 'app-4');
    await setClientSuspension(db(), { realm: 'susp-4', clientId: 'app-4', suspend: true });

    // PATCH /api/clients/:id writes `enabled` through `update`; whatever an
    // owner sends, the suspension stands.
    await createOAuthClientsRepository(db()).update(client.realmId, client.id, {
      enabled: true,
    });

    const stored = await row(client.id);
    expect(stored.enabled).toBe(true);
    expect(stored.suspended).toBe(true);
  });
});
