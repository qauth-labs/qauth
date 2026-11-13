/**
 * The operator suspension tool against real Postgres (ANT-2026-DR5XI3LV).
 *
 * `suspended` is the operator's cut-off, separate from the owner's `enabled`.
 * These cases pin what the tool writes (and what it leaves alone) on the real
 * migrated schema, that a CIMD re-resolution can never clear it, and that a
 * suspension ends the client's refresh tokens and codes for good (#893).
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  createOAuthClientsRepository,
  createRealmsRepository,
  createRefreshTokensRepository,
  createUsersRepository,
} from '../lib/repositories';
import { type IntegrationDb, setupIntegrationDb } from '../lib/repositories/integration-setup';
import { auditLogs } from '../lib/schema/audit';
import { oauthClients } from '../lib/schema/core';
import { events } from '../lib/schema/events';
import { setClientSuspension, SUSPENDED_CLIENT_REVOKE_REASON } from './client-suspension';

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
  describe('what a suspension ends with it (#893)', () => {
    const HOUR = 3_600_000;

    async function seedClient(realmId: string, clientId: string): Promise<string> {
      const client = await createOAuthClientsRepository(db()).create({
        realmId,
        clientId,
        clientSecretHash: 'h',
        name: clientId,
        redirectUris: ['https://app.example.com/cb'],
        enabled: true,
      });
      return client.id;
    }

    async function seedUser(realmId: string): Promise<string> {
      const user = await createUsersRepository(db()).create({ realmId }, testPrimaryCredential());
      return user.id;
    }

    async function seedToken(userId: string, oauthClientId: string): Promise<string> {
      const created = await createRefreshTokensRepository(db()).create({
        tokenHash: `hash-${Math.random().toString(36).slice(2)}`,
        userId,
        oauthClientId,
        familyId: crypto.randomUUID(),
        familyCreatedAt: Date.now(),
        familySessionExpiresAt: null,
        authTime: null,
        amr: null,
        scopes: ['openid'],
        expiresAt: Date.now() + HOUR,
      });
      return created.id;
    }

    async function seedCode(oauthClientId: string, userId: string): Promise<string> {
      const { rows } = await db().execute<{ id: string }>(sql`
        INSERT INTO authorization_codes
          (code, oauth_client_id, user_id, redirect_uri, code_challenge, expires_at)
        VALUES (${`code-${Math.random().toString(36).slice(2)}`}, ${oauthClientId}, ${userId},
                'https://app.example.com/cb', 'c', ${Date.now() + 60_000})
        RETURNING id::text AS id`);
      return rows[0].id;
    }

    async function tokenState(id: string) {
      const { rows } = await db().execute<{ revoked: boolean; revoked_reason: string | null }>(
        sql`SELECT revoked, revoked_reason FROM refresh_tokens WHERE id = ${id}`
      );
      return rows[0];
    }

    async function codeUsed(id: string): Promise<boolean> {
      const { rows } = await db().execute<{ used: boolean }>(
        sql`SELECT used FROM authorization_codes WHERE id = ${id}`
      );
      return rows[0].used;
    }

    it("revokes every user's refresh tokens of the client and spends its codes, and lifting brings none back", async () => {
      const realm = await createRealmsRepository(db()).create({ name: 'susp-end-1' });
      const suspended = await seedClient(realm.id, 'app-end-1');
      const other = await seedClient(realm.id, 'app-end-2');
      const alice = await seedUser(realm.id);
      const bob = await seedUser(realm.id);
      const tokens = [await seedToken(alice, suspended), await seedToken(bob, suspended)];
      const codes = [await seedCode(suspended, alice), await seedCode(suspended, bob)];
      const othersToken = await seedToken(alice, other);
      const othersCode = await seedCode(other, alice);

      const result = await setClientSuspension(db(), {
        realm: 'susp-end-1',
        clientId: 'app-end-1',
        suspend: true,
      });
      expect(result).toMatchObject({ status: 'suspended', revokedTokens: 2 });
      const lifted = await setClientSuspension(db(), {
        realm: 'susp-end-1',
        clientId: 'app-end-1',
        suspend: false,
      });
      // The suspension left nothing for the lift to revoke.
      expect(lifted).toMatchObject({ status: 'lifted', revokedTokens: 0 });

      for (const id of tokens) {
        expect(await tokenState(id)).toEqual({
          revoked: true,
          revoked_reason: SUSPENDED_CLIENT_REVOKE_REASON,
        });
      }
      for (const id of codes) expect(await codeUsed(id)).toBe(true);
      // Another client of the realm keeps what it holds.
      expect(await tokenState(othersToken)).toEqual({ revoked: false, revoked_reason: null });
      expect(await codeUsed(othersCode)).toBe(false);
    });

    it('revokes nothing on a run that changes nothing, and lifting revokes what a suspension left', async () => {
      const realm = await createRealmsRepository(db()).create({ name: 'susp-end-2' });
      const client = await seedClient(realm.id, 'app-end-3');
      const user = await seedUser(realm.id);
      // Suspended by hand, as a suspension made before #893 also was: no
      // tool run revoked what it holds.
      await db().update(oauthClients).set({ suspended: true }).where(eq(oauthClients.id, client));
      const token = await seedToken(user, client);
      const code = await seedCode(client, user);

      const again = await setClientSuspension(db(), {
        realm: 'susp-end-2',
        clientId: 'app-end-3',
        suspend: true,
      });
      expect(again.status).toBe('unchanged');
      expect(await tokenState(token)).toEqual({ revoked: false, revoked_reason: null });
      expect(await codeUsed(code)).toBe(false);

      const lifted = await setClientSuspension(db(), {
        realm: 'susp-end-2',
        clientId: 'app-end-3',
        suspend: false,
      });
      expect(lifted).toMatchObject({ status: 'lifted', revokedTokens: 1 });
      expect(await tokenState(token)).toEqual({
        revoked: true,
        revoked_reason: SUSPENDED_CLIENT_REVOKE_REASON,
      });
      expect(await codeUsed(code)).toBe(true);
    });
  });
});
