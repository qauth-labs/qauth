/**
 * The system client's provisioner against real Postgres (ADR-017 phase F0,
 * #631).
 *
 * A new deployment gets a `private_key_jwt` `web_redirect` client with the
 * portal's callback; an existing secret-based row, as an earlier auth server
 * created it, is re-provisioned in place, keeping its id, audience, scopes and
 * the operator's suspension; a second run changes nothing; and a row the
 * profile's CHECKs would refuse is refused by name and left alone.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { resolveFirstPartyProfile } from '@qauth-labs/shared-validation';
import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createOAuthClientsRepository, createRealmsRepository } from '../repositories';
import { type IntegrationDb, setupIntegrationDb } from '../repositories/integration-setup';
import { oauthClients } from '../schema/core';
import { events } from '../schema/events';
import {
  DEFAULT_SYSTEM_CLIENT_REASON,
  provisionSystemClient,
  systemClientSpecSchema,
} from './provision';

const FIRST_PARTY_CHANGED = 'urn:qauth:event:client.first_party_changed:v1-rc.0';
const JWKS = {
  keys: [{ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }],
};
const CALLBACK = 'https://portal.example.com/auth/callback';
const SPEC = systemClientSpecSchema.parse({ redirect_uris: [CALLBACK], jwks: JWKS });

describe('provisionSystemClient (real Postgres)', () => {
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

  async function realm(name: string): Promise<string> {
    return (await createRealmsRepository(db()).create({ name })).id;
  }

  async function systemRow(realmId: string, clientId = 'system') {
    const [row] = await db()
      .select()
      .from(oauthClients)
      .where(and(eq(oauthClients.realmId, realmId), eq(oauthClients.clientId, clientId)));
    return row;
  }

  async function recorded(realmId: string) {
    return db()
      .select({ type: events.type, actorType: events.actorType, data: events.data })
      .from(events)
      .where(and(eq(events.realmId, realmId), eq(events.type, FIRST_PARTY_CHANGED)))
      .orderBy(events.seq);
  }

  it('creates the system client as a private_key_jwt web_redirect client with the callback', async () => {
    const realmId = await realm('master');

    const result = await provisionSystemClient(db(), 'master', SPEC);

    expect(result).toMatchObject({
      status: 'created',
      clientId: 'system',
      firstPartyChanged: true,
    });
    const row = await systemRow(realmId);
    expect(row).toMatchObject({
      clientId: 'system',
      // The developer API's audience from the start (#524), as the auth
      // server's getOrCreateSystemClient creates the row.
      audience: ['urn:qauth:aud:developer:v1-rc.0'],
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwks: JWKS,
      jwksUri: null,
      redirectUris: [CALLBACK],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      requirePkce: true,
      firstPartyProfile: 'web_redirect',
      firstPartyPolicy: null,
      firstPartyReason: DEFAULT_SYSTEM_CLIENT_REASON,
      provisionedByOperator: true,
      developerId: null,
      isAgent: false,
      enabled: true,
      suspended: false,
    });
    expect(row.clientSecretHash).toMatch(/^\$argon2id\$/);
    expect(resolveFirstPartyProfile(row)).toEqual({ profile: 'web_redirect' });
    expect(await recorded(realmId)).toEqual([
      {
        type: FIRST_PARTY_CHANGED,
        actorType: 'operator_cli',
        data: {
          from: null,
          to: 'web_redirect',
          writtenReason: DEFAULT_SYSTEM_CLIENT_REASON,
          revokedTokenCount: 0,
        },
      },
    ]);
  });

  it('re-provisions the secret-based row an earlier auth server created, in place', async () => {
    const realmId = await realm('master');
    // As getOrCreateSystemClient wrote it before #631, plus what an operator
    // or a later release may have set on it since.
    const earlier = await createOAuthClientsRepository(db()).create({
      realmId,
      clientId: 'system',
      clientSecretHash: '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA',
      name: 'System Client',
      redirectUris: [],
      grantTypes: ['refresh_token'],
      requirePkce: false,
      developerId: null,
      provisionedByOperator: true,
      audience: ['urn:qauth:aud:developer:v1-rc.0'],
      scopes: ['openid'],
    });
    await db()
      .update(oauthClients)
      .set({ suspended: true, suspendedAt: 1 })
      .where(eq(oauthClients.id, earlier.id));

    const result = await provisionSystemClient(db(), 'master', SPEC);

    expect(result).toMatchObject({ status: 'updated', id: earlier.id, firstPartyChanged: true });
    expect(await systemRow(realmId)).toMatchObject({
      id: earlier.id,
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwks: JWKS,
      redirectUris: [CALLBACK],
      grantTypes: ['authorization_code', 'refresh_token'],
      requirePkce: true,
      firstPartyProfile: 'web_redirect',
      // Left as they were.
      name: 'System Client',
      audience: ['urn:qauth:aud:developer:v1-rc.0'],
      scopes: ['openid'],
      suspended: true,
      enabled: true,
      clientSecretHash: '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA',
    });
    expect(await recorded(realmId)).toHaveLength(1);
  });

  it('changes nothing, and records nothing, on a second run with the same configuration', async () => {
    const realmId = await realm('master');
    await provisionSystemClient(db(), 'master', SPEC);
    const first = await systemRow(realmId);

    const again = await provisionSystemClient(db(), 'master', SPEC);

    expect(again).toMatchObject({ status: 'unchanged', firstPartyChanged: false });
    expect(await systemRow(realmId)).toEqual(first);
    expect(await recorded(realmId)).toHaveLength(1);
  });

  it('follows a new callback or new keys without a profile event, and records a new reason', async () => {
    const realmId = await realm('master');
    await provisionSystemClient(db(), 'master', SPEC);

    const moved = await provisionSystemClient(
      db(),
      'master',
      systemClientSpecSchema.parse({
        redirect_uris: ['https://developers.example.com/auth/callback'],
        jwks_uri: 'https://developers.example.com/jwks.json',
      })
    );
    expect(moved).toMatchObject({ status: 'updated', firstPartyChanged: false });
    expect(await systemRow(realmId)).toMatchObject({
      redirectUris: ['https://developers.example.com/auth/callback'],
      jwks: null,
      jwksUri: 'https://developers.example.com/jwks.json',
    });

    const reworded = await provisionSystemClient(
      db(),
      'master',
      systemClientSpecSchema.parse({
        redirect_uris: ['https://developers.example.com/auth/callback'],
        jwks_uri: 'https://developers.example.com/jwks.json',
        first_party_reason: 'Our developer portal.',
      })
    );
    expect(reworded).toMatchObject({ status: 'updated', firstPartyChanged: true });
    expect((await recorded(realmId)).map((event) => event.data)).toEqual([
      expect.objectContaining({ from: null, to: 'web_redirect' }),
      {
        from: 'web_redirect',
        to: 'web_redirect',
        writtenReason: 'Our developer portal.',
        revokedTokenCount: 0,
      },
    ]);
  });

  it('uses the configured client id, in the configured realm only', async () => {
    const acme = await realm('acme');
    const other = await realm('other');

    await provisionSystemClient(
      db(),
      'acme',
      systemClientSpecSchema.parse({ client_id: 'portal', redirect_uris: [CALLBACK], jwks: JWKS })
    );

    expect((await systemRow(acme, 'portal')).firstPartyProfile).toBe('web_redirect');
    expect(await systemRow(other, 'portal')).toBeUndefined();
    expect(await systemRow(acme, 'system')).toBeUndefined();
  });

  it('reports a realm that does not exist yet, and writes nothing', async () => {
    expect(await provisionSystemClient(db(), 'master', SPEC)).toEqual({
      status: 'realm_not_found',
      realm: 'master',
    });
    expect(await db().select().from(oauthClients)).toEqual([]);
  });

  it("refuses a developer's client, an agent, a dynamic or a CIMD registration by name, and leaves it", async () => {
    const realmId = await realm('master');
    const {
      rows: [developer],
    } = await (ctx as IntegrationDb).database.pool.query<{ id: string }>(
      `INSERT INTO users (realm_id) VALUES ($1) RETURNING id`,
      [realmId]
    );
    const cases = [
      ['developer_owned', { developerId: developer.id }],
      ['agent', { isAgent: true }],
      ['dynamic', { dynamicRegisteredAt: 1, metadata: { registrationType: 'dynamic' } }],
      ['cimd', { metadata: { registrationType: 'cimd' } }],
    ] as const;
    for (const [reason, columns] of cases) {
      const clientId = `taken-${reason}`;
      await db()
        .insert(oauthClients)
        .values({
          realmId,
          clientId,
          clientSecretHash: 'h',
          name: clientId,
          redirectUris: ['https://app.example.com/cb'],
          ...columns,
        });
      const before = await systemRow(realmId, clientId);

      const result = await provisionSystemClient(
        db(),
        'master',
        systemClientSpecSchema.parse({ client_id: clientId, redirect_uris: [CALLBACK], jwks: JWKS })
      );

      expect(result, reason).toEqual({ status: 'refused', realm: 'master', clientId, reason });
      expect(await systemRow(realmId, clientId), reason).toEqual(before);
    }
    expect(await recorded(realmId)).toEqual([]);
  });
});
