/**
 * The operator's listing of redirect URIs the consent screen cannot show
 * (#914), against real Postgres: the repository's keyset scan over the
 * migrated schema, the realm join, the realm filter, and that it writes
 * nothing.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createOAuthClientsRepository, createRealmsRepository } from '../lib/repositories';
import { type IntegrationDb, setupIntegrationDb } from '../lib/repositories/integration-setup';
import { oauthClients } from '../lib/schema/core';
import type { NewOAuthClient } from '../types';
import { listUnshowableRedirectUris } from './unshowable-redirect-uris';

describe('listUnshowableRedirectUris (real Postgres)', () => {
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

  function client(realmId: string, clientId: string, redirectUris: string[]): NewOAuthClient {
    return { realmId, clientId, clientSecretHash: 'h', name: clientId, redirectUris };
  }

  it('lists every realm’s clients with such a URI, by realm and client id, with who can fix it', async () => {
    const realms = createRealmsRepository(db());
    const master = await realms.create({ name: 'master' });
    const acme = await realms.create({ name: 'acme' });
    const clients = createOAuthClientsRepository(db());
    await clients.create(client(master.id, 'fine', ['https://app.example.com/cb']));
    await clients.create({
      ...client(master.id, 'dyn', ['https://app.example.com/cb', 'https://my_app.example.com/cb']),
      metadata: { registrationType: 'dynamic' },
    });
    await clients.create({
      ...client(acme.id, 'seeded', ['http://[2001:db8::1]:8080/cb']),
      provisionedByOperator: true,
    });
    await clients.create({
      ...client(acme.id, 'https://agent.example.com/client.json', [
        `com.example.${'a'.repeat(53)}:/cb`,
      ]),
      metadata: { registrationType: 'cimd' },
    });
    const before = await db().select().from(oauthClients);

    const result = await listUnshowableRedirectUris(db(), {});

    expect(result).toEqual({
      status: 'listed',
      scan: {
        clients: [
          expect.objectContaining({
            realmId: acme.id,
            realmName: 'acme',
            clientId: 'https://agent.example.com/client.json',
            source: 'cimd',
            redirectUris: [{ uri: `com.example.${'a'.repeat(53)}:/cb`, reason: 'scheme' }],
          }),
          expect.objectContaining({
            realmName: 'acme',
            clientId: 'seeded',
            source: 'operator',
            redirectUris: [{ uri: 'http://[2001:db8::1]:8080/cb', reason: 'ip_literal' }],
          }),
          expect.objectContaining({
            realmId: master.id,
            realmName: 'master',
            clientId: 'dyn',
            source: 'dynamic',
            redirectUris: [{ uri: 'https://my_app.example.com/cb', reason: 'host' }],
          }),
        ],
        scanned: 4,
        complete: true,
      },
    });
    // It only reads.
    expect(await db().select().from(oauthClients)).toEqual(before);
  });

  it('lists only the named realm, and reports an unknown one', async () => {
    const realms = createRealmsRepository(db());
    const master = await realms.create({ name: 'master' });
    const acme = await realms.create({ name: 'acme' });
    const clients = createOAuthClientsRepository(db());
    await clients.create(client(master.id, 'a', ['https://a_b.example.com/cb']));
    await clients.create(client(acme.id, 'b', ['https://c_d.example.com/cb']));

    const result = await listUnshowableRedirectUris(db(), { realm: 'acme' });
    expect(result.status).toBe('listed');
    if (result.status !== 'listed') return;
    expect(result.scan.clients.map((entry) => [entry.realmName, entry.clientId])).toEqual([
      ['acme', 'b'],
    ]);
    expect(result.scan.scanned).toBe(1);

    await expect(listUnshowableRedirectUris(db(), { realm: 'nope' })).resolves.toEqual({
      status: 'realm_not_found',
    });
  });

  it('reads past the first page of clients', async () => {
    const realm = await createRealmsRepository(db()).create({ name: 'big' });
    // More than one page of the scan (500 rows), with the one to find last
    // inserted, so it sits on whichever page its random id puts it.
    await db()
      .insert(oauthClients)
      .values(
        Array.from({ length: 520 }, (_, i) =>
          client(realm.id, `c-${i}`, [
            i === 519 ? 'https://last_one.example.com/cb' : 'https://ok.example.com/cb',
          ])
        )
      );

    const result = await listUnshowableRedirectUris(db(), {});

    expect(result.status).toBe('listed');
    if (result.status !== 'listed') return;
    expect(result.scan.scanned).toBe(520);
    expect(result.scan.complete).toBe(true);
    expect(result.scan.clients.map((entry) => entry.clientId)).toEqual(['c-519']);
  });
});
