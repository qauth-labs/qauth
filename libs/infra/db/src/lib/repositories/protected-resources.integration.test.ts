/**
 * Real-Postgres integration tests for the protected resources of each realm
 * (`protected_resources`, migration 0081, issue #1087).
 *
 * The rules under test live in the DDL and the repository: one row per realm
 * and resource indicator, a client list only when the resource is not open
 * to every client, writes guarded by the row's version, every read scoped to
 * its realm, and the cascade with the realm.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { realms } from '../schema';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import {
  createProtectedResourcesRepository,
  type ProtectedResourceSettings,
  type ProtectedResourcesRepository,
} from './protected-resources.repository';

const RESOURCE = 'https://mcp.example.com/mcp';

const SETTINGS: ProtectedResourceSettings = {
  scopes: [
    {
      scope: 'files:read',
      text: { en: 'Read your files', tr: 'Dosyalarınızı okuma' },
      sensitive: false,
    },
    { scope: 'files:write', text: { en: 'Change your files' }, sensitive: true },
  ],
  anyClient: true,
  clientIds: [],
};

describe('protected resources (real Postgres, #1087)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let repo: ProtectedResourcesRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    repo = createProtectedResourcesRepository(ctx.database.db);
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

  function database(): IntegrationDb['database'] {
    if (!ctx) throw new Error('no ctx');
    return ctx.database;
  }

  async function realm(name: string): Promise<string> {
    const [row] = await database()
      .db.insert(realms)
      .values({ name: `${name}-${Math.random().toString(36).slice(2)}` })
      .returning({ id: realms.id });
    return row.id;
  }

  it('registers a resource once per realm, and keeps it apart per realm', async () => {
    const alpha = await realm('alpha');
    const beta = await realm('beta');
    const created = await repo.create(alpha, RESOURCE, SETTINGS);
    expect(created).toMatchObject({
      realmId: alpha,
      resource: RESOURCE,
      anyClient: true,
      clientIds: [],
      version: 1,
      scopes: SETTINGS.scopes,
    });
    if (created === undefined) throw new Error('not created');

    // The same indicator again in the realm: nothing written.
    expect(await repo.create(alpha, RESOURCE, SETTINGS)).toBeUndefined();
    // Another realm registers its own.
    expect(await repo.create(beta, RESOURCE, SETTINGS)).toMatchObject({ realmId: beta });

    expect(await repo.findById(alpha, created.id)).toMatchObject({ id: created.id });
    expect(await repo.findById(beta, created.id)).toBeUndefined();
    expect(await repo.findByResource(alpha, RESOURCE)).toMatchObject({ id: created.id });
    expect((await repo.listByRealm(alpha)).map((row) => row.id)).toEqual([created.id]);
    expect(await repo.listByRealm('not-a-uuid')).toEqual([]);
  });

  it('updates and deletes only at the version the caller read', async () => {
    const alpha = await realm('alpha');
    const created = await repo.create(alpha, RESOURCE, SETTINGS);
    if (created === undefined) throw new Error('not created');

    const listed = {
      ...SETTINGS,
      anyClient: false,
      clientIds: ['app', 'https://agent.example/client.json'],
    };
    expect(await repo.update(alpha, created.id, listed, 2)).toBeUndefined();
    const updated = await repo.update(alpha, created.id, listed, 1);
    expect(updated).toMatchObject({
      version: 2,
      anyClient: false,
      clientIds: ['app', 'https://agent.example/client.json'],
    });

    expect(await repo.delete(alpha, created.id, 1)).toBe(false);
    expect(await repo.delete(alpha, created.id, 2)).toBe(true);
    expect(await repo.findById(alpha, created.id)).toBeUndefined();
  });

  it('stores no client list beside any_client, and refuses one written by hand', async () => {
    const alpha = await realm('alpha');
    const created = await repo.create(alpha, RESOURCE, { ...SETTINGS, clientIds: ['app'] });
    expect(created?.clientIds).toEqual([]);

    await expect(
      database().pool.query(
        `INSERT INTO protected_resources (realm_id, resource, any_client, client_ids)
         VALUES ($1, 'https://other.example', true, '["app"]'::jsonb)`,
        [alpha]
      )
    ).rejects.toMatchObject({ constraint: 'protected_resources_any_client_lists_none' });
    await expect(
      database().pool.query(
        `INSERT INTO protected_resources (realm_id, resource) VALUES ($1, 'https://other.example#x')`,
        [alpha]
      )
    ).rejects.toMatchObject({ constraint: 'protected_resources_resource_form' });
  });

  it('goes with its realm', async () => {
    const alpha = await realm('alpha');
    await repo.create(alpha, RESOURCE, SETTINGS);
    await database().pool.query('DELETE FROM realms WHERE id = $1', [alpha]);
    expect(await repo.listByRealm(alpha)).toEqual([]);
  });
});
