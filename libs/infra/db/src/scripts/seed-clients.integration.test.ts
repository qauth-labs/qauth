/**
 * The seed manifest's first-party profile against real Postgres (#631,
 * ADR-017 Decision 2).
 *
 * Setting, changing and removing a profile through `db:seed-oauth-clients`
 * writes the three columns and a `client.first_party_changed` event in one
 * transaction, and removing it revokes every refresh token of the client,
 * in every family and for every user, and no other client's.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { FIRST_PARTY_REMOVED_REVOKE_REASON } from '../lib/first-party/first-party-change';
import { createRealmsRepository, createRefreshTokensRepository } from '../lib/repositories';
import { type IntegrationDb, setupIntegrationDb } from '../lib/repositories/integration-setup';
import { oauthClients } from '../lib/schema/core';
import { events } from '../lib/schema/events';
import { refreshTokens } from '../lib/schema/tokens';
import { provisionClient } from './seed-clients';
import { type ClientSpec, manifestSchema } from './seed-manifest';

const FIRST_PARTY_CHANGED = 'urn:qauth:event:client.first_party_changed:v1-rc.0';

const KEYS = {
  keys: [{ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }],
};

const NATIVE = {
  client_id: 'notes-backend',
  name: 'Notes',
  grant_types: ['authorization_code', 'refresh_token'],
  redirect_uris: ['com.example.notes:/callback'],
  token_endpoint_auth_method: 'private_key_jwt',
  jwks: KEYS,
  first_party_profile: 'native_backend',
  first_party_reason: 'Notes is our own app, published under our brand.',
};

/** An entry as the seed reads it, after the manifest schema. */
function spec(entry: Record<string, unknown>): ClientSpec {
  const client = manifestSchema.parse({ realm: 'r', clients: [entry] }).clients?.[0];
  if (!client) throw new Error('no client');
  return client;
}

/** The same entry with some members left out. */
function without(entry: Record<string, unknown>, ...keys: string[]): Record<string, unknown> {
  return Object.fromEntries(Object.entries(entry).filter(([key]) => !keys.includes(key)));
}

describe('seed-oauth-clients first-party profile (real Postgres)', () => {
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

  function integration(): IntegrationDb {
    if (!ctx) throw new Error('integration db not initialised');
    return ctx;
  }

  function db() {
    return integration().database.db;
  }

  async function realm(name: string): Promise<string> {
    return (await createRealmsRepository(db()).create({ name })).id;
  }

  async function user(realmId: string): Promise<string> {
    const {
      rows: [row],
    } = await integration().database.pool.query<{ id: string }>(
      `INSERT INTO users (realm_id) VALUES ($1) RETURNING id`,
      [realmId]
    );
    return row.id;
  }

  async function client(realmId: string, clientId: string) {
    const [row] = await db()
      .select()
      .from(oauthClients)
      .where(and(eq(oauthClients.realmId, realmId), eq(oauthClients.clientId, clientId)));
    return row;
  }

  /** A live refresh token of a new family. */
  async function token(userId: string, oauthClientId: string, revoked = false): Promise<string> {
    const now = Date.now();
    const created = await createRefreshTokensRepository(db()).create({
      userId,
      oauthClientId,
      tokenHash: randomUUID().replace(/-/g, '').padEnd(64, '0'),
      familyId: randomUUID(),
      familyCreatedAt: now,
      familySessionExpiresAt: null,
      expiresAt: now + 3_600_000,
      scopes: [],
    });
    if (revoked) {
      await createRefreshTokensRepository(db()).revoke(created.id, 'logout');
    }
    return created.id;
  }

  async function tokenState(id: string) {
    const [row] = await db()
      .select({ revoked: refreshTokens.revoked, revokedReason: refreshTokens.revokedReason })
      .from(refreshTokens)
      .where(eq(refreshTokens.id, id));
    return row;
  }

  async function firstPartyEvents(realmId: string) {
    return db()
      .select({
        type: events.type,
        category: events.category,
        actorType: events.actorType,
        subjectType: events.subjectType,
        subjectId: events.subjectId,
        clientId: events.clientId,
        data: events.data,
      })
      .from(events)
      .where(and(eq(events.realmId, realmId), eq(events.type, FIRST_PARTY_CHANGED)))
      .orderBy(events.seq);
  }

  it('sets a native profile with its policy defaults and reason, and records it', async () => {
    const realmId = await realm('fp-1');

    const issued = await provisionClient(db(), realmId, spec(NATIVE), false);

    expect(issued).toMatchObject({ action: 'created', firstPartyChanged: true });
    const row = await client(realmId, 'notes-backend');
    expect(row).toMatchObject({
      firstPartyProfile: 'native_backend',
      firstPartyPolicy: { flows: ['login'], email_code_after_password: false, pkce_required: true },
      firstPartyReason: 'Notes is our own app, published under our brand.',
      tokenEndpointAuthMethod: 'private_key_jwt',
      provisionedByOperator: true,
      developerId: null,
    });
    expect(await firstPartyEvents(realmId)).toEqual([
      {
        type: FIRST_PARTY_CHANGED,
        category: 'admin',
        actorType: 'operator_cli',
        subjectType: 'client',
        subjectId: 'notes-backend',
        clientId: 'notes-backend',
        data: {
          from: null,
          to: 'native_backend',
          flows: ['login'],
          pkceRequired: true,
          writtenReason: 'Notes is our own app, published under our brand.',
          revokedTokenCount: 0,
        },
      },
    ]);
  });

  it('records nothing for a rotation that leaves the profile as it was', async () => {
    const realmId = await realm('fp-2');
    await provisionClient(db(), realmId, spec(NATIVE), false);

    const rotated = await provisionClient(db(), realmId, spec(NATIVE), true);

    expect(rotated).toMatchObject({ action: 'rotated', firstPartyChanged: false });
    expect(await firstPartyEvents(realmId)).toHaveLength(1);
  });

  it('records a change of the policy or the reason', async () => {
    const realmId = await realm('fp-3');
    await provisionClient(db(), realmId, spec(NATIVE), false);

    await provisionClient(
      db(),
      realmId,
      spec({
        ...NATIVE,
        first_party_policy: { flows: ['login', 'register'], pkce_required: false },
      }),
      true
    );
    await provisionClient(
      db(),
      realmId,
      spec({
        ...NATIVE,
        first_party_policy: { flows: ['login', 'register'], pkce_required: false },
        first_party_reason: 'Reworded.',
      }),
      true
    );

    const recorded = await firstPartyEvents(realmId);
    expect(recorded.map((event) => event.data)).toEqual([
      expect.objectContaining({ from: null, to: 'native_backend' }),
      {
        from: 'native_backend',
        to: 'native_backend',
        flows: ['login', 'register'],
        pkceRequired: false,
        writtenReason: 'Notes is our own app, published under our brand.',
        revokedTokenCount: 0,
      },
      expect.objectContaining({ writtenReason: 'Reworded.', revokedTokenCount: 0 }),
    ]);
  });

  it("removing the profile revokes every refresh token of the client, and no other client's", async () => {
    const realmId = await realm('fp-4');
    await provisionClient(db(), realmId, spec(NATIVE), false);
    await provisionClient(
      db(),
      realmId,
      spec({ client_id: 'other', name: 'Other', grant_types: ['authorization_code'] }),
      false
    );
    const flagged = await client(realmId, 'notes-backend');
    const other = await client(realmId, 'other');
    const alice = await user(realmId);
    const bob = await user(realmId);
    const aliceFamily1 = await token(alice, flagged.id);
    const aliceFamily2 = await token(alice, flagged.id);
    const bobFamily = await token(bob, flagged.id);
    const loggedOut = await token(bob, flagged.id, true);
    const otherClients = await token(alice, other.id);

    const removed = await provisionClient(
      db(),
      realmId,
      spec(without(NATIVE, 'first_party_profile', 'first_party_reason')),
      true
    );

    expect(removed).toMatchObject({
      action: 'rotated',
      firstPartyChanged: true,
      revokedTokenCount: 3,
    });
    expect(await client(realmId, 'notes-backend')).toMatchObject({
      firstPartyProfile: null,
      firstPartyPolicy: null,
      firstPartyReason: null,
    });
    for (const id of [aliceFamily1, aliceFamily2, bobFamily]) {
      expect(await tokenState(id)).toEqual({
        revoked: true,
        revokedReason: FIRST_PARTY_REMOVED_REVOKE_REASON,
      });
    }
    // An already-revoked token keeps its reason; another client's stays live.
    expect(await tokenState(loggedOut)).toEqual({ revoked: true, revokedReason: 'logout' });
    expect(await tokenState(otherClients)).toEqual({ revoked: false, revokedReason: null });

    const recorded = await firstPartyEvents(realmId);
    expect(recorded.at(-1)?.data).toEqual({
      from: 'native_backend',
      to: null,
      revokedTokenCount: 3,
    });
  });

  it('changes nothing without --rotate, whatever the manifest says', async () => {
    const realmId = await realm('fp-5');
    await provisionClient(db(), realmId, spec(NATIVE), false);
    const alice = await user(realmId);
    const flagged = await client(realmId, 'notes-backend');
    const live = await token(alice, flagged.id);

    const skipped = await provisionClient(
      db(),
      realmId,
      spec(without(NATIVE, 'first_party_profile', 'first_party_reason')),
      false
    );

    expect(skipped.action).toBe('skipped');
    expect((await client(realmId, 'notes-backend')).firstPartyProfile).toBe('native_backend');
    expect(await tokenState(live)).toEqual({ revoked: false, revokedReason: null });
    expect(await firstPartyEvents(realmId)).toHaveLength(1);
  });

  it('refuses, before issuing a secret, a --rotate entry flagging a client that can never be first party', async () => {
    const realmId = await realm('fp-6');
    const developerId = await user(realmId);
    const kinds = [
      ['developer_owned', { developerId }],
      ['dynamic', { dynamicRegisteredAt: 1, metadata: { registrationType: 'dynamic' } }],
      ['cimd', { metadata: { registrationType: 'cimd' } }],
    ] as const;
    for (const [refusal, columns] of kinds) {
      const clientId = `taken-${refusal}`;
      await db()
        .insert(oauthClients)
        .values({
          realmId,
          clientId,
          clientSecretHash: 'unchanged-hash',
          name: clientId,
          redirectUris: ['https://app.example.com/cb'],
          ...columns,
        });
      const before = await client(realmId, clientId);

      const issued = await provisionClient(
        db(),
        realmId,
        spec({ ...NATIVE, client_id: clientId }),
        true
      );

      expect(issued, refusal).toEqual({ clientId, secret: '', action: 'refused', refusal });
      expect(await client(realmId, clientId), refusal).toEqual(before);
    }
    expect(await firstPartyEvents(realmId)).toEqual([]);
  });
});
