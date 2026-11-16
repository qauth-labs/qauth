/**
 * The seed manifest's `resources` section against real Postgres (#1087):
 * an entry registers its resource, converges a registration that differs,
 * leaves one that holds it alone, and never touches a resource it does not
 * list or another realm's.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createProtectedResourcesRepository, createRealmsRepository } from '../lib/repositories';
import { type IntegrationDb, setupIntegrationDb } from '../lib/repositories/integration-setup';
import { applyResourceEntry } from './protected-resource-seed';
import type { ResourceSpec } from './seed-manifest';

const RESOURCE = 'https://mcp.example.com/mcp';

const ENTRY: ResourceSpec = {
  resource: RESOURCE,
  scopes: [{ scope: 'files:read', text: { en: 'Read your files' } }],
  clients: 'any_client',
};

describe('applyResourceEntry (real Postgres)', () => {
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

  it('registers the resource, then leaves it alone while the entry is the same', async () => {
    const alpha = await realm('alpha');
    expect(await applyResourceEntry(db(), alpha.id, ENTRY)).toMatchObject({ status: 'created' });
    const repo = createProtectedResourcesRepository(db());
    expect(await repo.findByResource(alpha.id, RESOURCE)).toMatchObject({
      anyClient: true,
      clientIds: [],
      version: 1,
      scopes: [{ scope: 'files:read', text: { en: 'Read your files' }, sensitive: false }],
    });

    expect(await applyResourceEntry(db(), alpha.id, ENTRY)).toEqual({
      resource: RESOURCE,
      status: 'unchanged',
      changes: [],
    });
    expect((await repo.findByResource(alpha.id, RESOURCE))?.version).toBe(1);
  });

  it('converges a registration that differs, and names what changed', async () => {
    const alpha = await realm('alpha');
    await applyResourceEntry(db(), alpha.id, ENTRY);
    const narrowed: ResourceSpec = {
      ...ENTRY,
      scopes: [
        ...ENTRY.scopes,
        { scope: 'files:write', text: { en: 'Change your files' }, sensitive: true },
      ],
      clients: ['app'],
    };
    expect(await applyResourceEntry(db(), alpha.id, narrowed)).toEqual({
      resource: RESOURCE,
      status: 'updated',
      changes: ['scope added: files:write', 'open to: any client -> app'],
    });
    expect(
      await createProtectedResourcesRepository(db()).findByResource(alpha.id, RESOURCE)
    ).toMatchObject({ anyClient: false, clientIds: ['app'], version: 2 });
  });

  it('touches no resource it does not list, nor another realm', async () => {
    const alpha = await realm('alpha');
    const beta = await realm('beta');
    const repo = createProtectedResourcesRepository(db());
    const other = await repo.create(alpha.id, 'https://other.example/mcp', {
      scopes: [{ scope: 'x', text: { en: 'X' }, sensitive: false }],
      anyClient: true,
      clientIds: [],
    });
    await applyResourceEntry(db(), alpha.id, ENTRY);
    expect(await repo.findById(alpha.id, other?.id ?? '')).toMatchObject({ version: 1 });
    expect(await repo.listByRealm(beta.id)).toEqual([]);
  });
});
