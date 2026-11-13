/**
 * Real-Postgres integration tests for the generic upstream OpenID Connect
 * providers of each realm (`realm_upstream_providers`, migration 0060, issue
 * #639).
 *
 * The rules under test live in the DDL: one provider per type in a realm, the
 * defaults of the listing and verification switches, the CHECKs on the type,
 * the display name and the config, and the cascade with the realm. The
 * repository's ordering and its writes ride on them.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { realms } from '../schema';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import {
  createRealmUpstreamProvidersRepository,
  type RealmUpstreamProvidersRepository,
} from './realm-upstream-providers.repository';

/** A stored config; its client secret is a sealed value, never plaintext. */
const CONFIG = { issuer: 'https://idp.example.com', clientId: 'qauth', clientSecret: 'v1.k.iv.ct' };

describe('realm upstream providers (real Postgres, #639)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let repo: RealmUpstreamProvidersRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    repo = createRealmUpstreamProvidersRepository(ctx.database.db);
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

  it('creates a provider with the defaults, finds it, and keeps it apart per realm', async () => {
    const alpha = await realm('alpha');
    const beta = await realm('beta');
    expect(await repo.find(alpha, 'oidc_corp')).toBeUndefined();

    const created = await repo.create({
      realmId: alpha,
      type: 'oidc_corp',
      displayName: 'Example Corp',
      config: CONFIG,
    });
    expect(created).toMatchObject({
      realmId: alpha,
      type: 'oidc_corp',
      displayName: 'Example Corp',
      displayOrder: 0,
      hidden: false,
      enabled: true,
      marksVerified: true,
      config: CONFIG,
    });
    expect(created.id).toMatch(/^[0-9a-f-]{36}$/);

    expect(await repo.find(alpha, 'oidc_corp')).toEqual(created);
    expect(await repo.find(beta, 'oidc_corp')).toBeUndefined();
    expect(await repo.listByRealm(beta)).toEqual([]);
    // The same type is free in another realm.
    await expect(
      repo.create({ realmId: beta, type: 'oidc_corp', displayName: 'Example Corp', config: CONFIG })
    ).resolves.toMatchObject({ realmId: beta });
  });

  it('lists a realm by display order, then type', async () => {
    const realmId = await realm('alpha');
    const base = { realmId, config: CONFIG };
    await repo.create({ ...base, type: 'oidc_zeta', displayName: 'Zeta', displayOrder: 1 });
    await repo.create({ ...base, type: 'oidc_beta', displayName: 'Beta', displayOrder: 1 });
    await repo.create({ ...base, type: 'oidc_alpha', displayName: 'Alpha', displayOrder: 2 });
    await repo.create({ ...base, type: 'oidc_gamma', displayName: 'Gamma', displayOrder: -1 });

    const rows = await repo.listByRealm(realmId);
    expect(rows.map((row) => row.type)).toEqual([
      'oidc_gamma',
      'oidc_beta',
      'oidc_zeta',
      'oidc_alpha',
    ]);
  });

  it('refuses a second provider of a type in a realm with a UniqueConstraintError', async () => {
    const realmId = await realm('alpha');
    const data = { realmId, type: 'oidc_corp', displayName: 'Example Corp', config: CONFIG };
    await repo.create(data);

    await expect(repo.create(data)).rejects.toBeInstanceOf(UniqueConstraintError);
  });

  it('changes the named fields, stamps updated_at and leaves the rest', async () => {
    const realmId = await realm('alpha');
    const created = await repo.create({
      realmId,
      type: 'oidc_corp',
      displayName: 'Example Corp',
      config: CONFIG,
    });
    // Make the stamp distinguishable from the creation time.
    await database().pool.query(
      'UPDATE realm_upstream_providers SET updated_at = 1, created_at = 1 WHERE id = $1',
      [created.id]
    );

    const updated = await repo.update(realmId, 'oidc_corp', {
      enabled: false,
      hidden: true,
      marksVerified: false,
      displayName: 'Example Corp Staff',
    });
    expect(updated).toMatchObject({
      id: created.id,
      enabled: false,
      hidden: true,
      marksVerified: false,
      displayName: 'Example Corp Staff',
      displayOrder: 0,
      config: CONFIG,
      createdAt: 1,
    });
    expect(updated?.updatedAt).toBeGreaterThan(1);

    expect(await repo.update(realmId, 'oidc_other', { enabled: false })).toBeUndefined();
    expect(await repo.update(await realm('beta'), 'oidc_corp', { enabled: false })).toBe(undefined);
    expect((await repo.find(realmId, 'oidc_corp'))?.enabled).toBe(false);
  });

  it("deletes one realm's provider and no other", async () => {
    const alpha = await realm('alpha');
    const beta = await realm('beta');
    for (const realmId of [alpha, beta]) {
      await repo.create({
        realmId,
        type: 'oidc_corp',
        displayName: 'Example Corp',
        config: CONFIG,
      });
    }

    expect(await repo.delete(alpha, 'oidc_corp')).toBe(true);
    expect(await repo.delete(alpha, 'oidc_corp')).toBe(false);
    expect(await repo.find(alpha, 'oidc_corp')).toBeUndefined();
    expect(await repo.find(beta, 'oidc_corp')).toBeDefined();
  });

  it.each([
    ['no oidc_ prefix', 'corp'],
    ['an upper-case alias', 'oidc_Corp'],
    ['an alias that starts with an underscore', 'oidc__corp'],
    ['an ID-JAG type, an issuer URL', 'oidc_https://idp.example.com'],
    ['an empty alias', 'oidc_'],
    ['an alias of 59 characters', `oidc_${'a'.repeat(59)}`],
  ])('refuses %s as a type', async (_case, type) => {
    const realmId = await realm('alpha');
    await expect(
      repo.create({ realmId, type, displayName: 'Provider', config: CONFIG })
    ).rejects.toMatchObject({
      cause: { code: '23514', constraint: 'realm_upstream_providers_type_form' },
    });
  });

  it('accepts an alias of the longest length, 58 characters', async () => {
    const realmId = await realm('alpha');
    await expect(
      repo.create({
        realmId,
        type: `oidc_${'a'.repeat(58)}`,
        displayName: 'Provider',
        config: CONFIG,
      })
    ).resolves.toBeDefined();
  });

  it.each([
    ['an empty display name', ''],
    ['a display name of 65 characters', 'x'.repeat(65)],
  ])('refuses %s', async (_case, displayName) => {
    const realmId = await realm('alpha');
    await expect(
      repo.create({ realmId, type: 'oidc_corp', displayName, config: CONFIG })
    ).rejects.toMatchObject({
      cause: { code: '23514', constraint: 'realm_upstream_providers_display_name_length' },
    });
  });

  it.each([
    ['an array', `'[]'`],
    ['a string', `'"config"'`],
    ['a number', `'42'`],
    ['null', `'null'`],
  ])('refuses a config that is %s', async (_case, config) => {
    const realmId = await realm('alpha');
    await expect(
      database().pool.query(
        `INSERT INTO realm_upstream_providers (realm_id, type, display_name, config) VALUES ($1, 'oidc_corp', 'Example Corp', ${config}::jsonb)`,
        [realmId]
      )
    ).rejects.toMatchObject({
      code: '23514',
      constraint: 'realm_upstream_providers_config_object',
    });
  });

  it("finds the client a private_key_jwt provider's assertions are signed for, and none otherwise (#1073)", async () => {
    const realmId = await realm('alpha');
    const other = await realm('beta');
    await repo.create({
      realmId,
      type: 'oidc_signed',
      displayName: 'Signed',
      config: {
        ...CONFIG,
        clientId: 'signed-client',
        clientAuthentication: { method: 'private_key_jwt', signingAlgorithm: 'ES256' },
      },
    });
    await repo.create({ realmId, type: 'oidc_secret', displayName: 'Secret', config: CONFIG });

    expect(await repo.findAssertionClient(realmId, 'oidc_signed')).toEqual({
      clientId: 'signed-client',
      algorithm: 'ES256',
    });
    expect(await repo.findAssertionClient(realmId, 'oidc_secret')).toBeUndefined();
    expect(await repo.findAssertionClient(realmId, 'oidc_missing')).toBeUndefined();
    expect(await repo.findAssertionClient(other, 'oidc_signed')).toBeUndefined();

    await repo.update(realmId, 'oidc_signed', { enabled: false });
    expect(await repo.findAssertionClient(realmId, 'oidc_signed')).toBeUndefined();
  });

  it('deletes the rows of a deleted realm', async () => {
    const realmId = await realm('alpha');
    await repo.create({ realmId, type: 'oidc_corp', displayName: 'Example Corp', config: CONFIG });
    await database().pool.query('DELETE FROM realms WHERE id = $1', [realmId]);
    const { rows } = await database().pool.query(
      'SELECT count(*)::int AS count FROM realm_upstream_providers WHERE realm_id = $1',
      [realmId]
    );
    expect(rows[0]).toEqual({ count: 0 });
  });
});
