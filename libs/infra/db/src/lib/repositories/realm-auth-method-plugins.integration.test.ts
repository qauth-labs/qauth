/**
 * Real-Postgres integration tests for each realm's AuthMethod plugin state
 * (`realm_auth_method_plugins`, migration 0050, issue #600).
 *
 * The rules under test live in the DDL and in the conditional writes: one row
 * per realm and plugin, the CHECKs on the stored forms (a secret that is not
 * a data-at-rest ciphertext is refused, so none is stored in the clear), the
 * cascade with the realm, and a write that names a version the row is not at
 * writing nothing.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { realms } from '../schema';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import {
  createRealmAuthMethodPluginsRepository,
  type RealmAuthMethodPluginsRepository,
} from './realm-auth-method-plugins.repository';

/** A ciphertext in the signer's form, `v1.<kid>.<iv>.<ciphertext>`. */
const CIPHERTEXT = 'v1.kid-1.aXY.Y2lwaGVydGV4dA';

describe('realm AuthMethod plugin state (real Postgres, #600)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let repo: RealmAuthMethodPluginsRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    repo = createRealmAuthMethodPluginsRepository(ctx.database.db);
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

  it('creates a row at version 1, then writes only over the version it names', async () => {
    const realmId = await realm('alpha');
    expect(await repo.find(realmId, 'corp')).toBeUndefined();

    const created = await repo.save(
      realmId,
      'corp',
      { enabled: false, config: { clientId: 'qauth' }, secrets: { clientSecret: CIPHERTEXT } },
      null
    );
    expect(created).toMatchObject({
      realmId,
      pluginId: 'corp',
      enabled: false,
      config: { clientId: 'qauth' },
      secrets: { clientSecret: CIPHERTEXT },
      version: 1,
    });

    // A second create finds the row and writes nothing.
    expect(
      await repo.save(realmId, 'corp', { enabled: true, config: {}, secrets: {} }, null)
    ).toBeUndefined();
    // A write over another version writes nothing either.
    expect(
      await repo.save(realmId, 'corp', { enabled: true, config: {}, secrets: {} }, 2)
    ).toBeUndefined();
    expect((await repo.find(realmId, 'corp'))?.enabled).toBe(false);

    const enabled = await repo.save(
      realmId,
      'corp',
      { enabled: true, config: { clientId: 'qauth' }, secrets: { clientSecret: CIPHERTEXT } },
      1
    );
    expect(enabled).toMatchObject({ enabled: true, version: 2 });
    expect(await repo.listByRealm(realmId)).toEqual([enabled]);
  });

  it("keeps each realm's state apart", async () => {
    const alpha = await realm('alpha');
    const beta = await realm('beta');
    await repo.save(alpha, 'corp', { enabled: true, config: {}, secrets: {} }, null);

    expect(await repo.find(beta, 'corp')).toBeUndefined();
    expect(await repo.listByRealm(beta)).toEqual([]);
    expect(
      await repo.save(beta, 'corp', { enabled: true, config: {}, secrets: {} }, 1)
    ).toBeUndefined();
  });

  it.each([
    ['a plaintext secret', { clientSecret: 'hunter2' }],
    ['a secret that is not a string', { clientSecret: 42 }],
    ['a ciphertext with a part missing', { clientSecret: 'v1.kid.iv' }],
    ['a ciphertext of another format', { clientSecret: 'v2.kid.iv.ct' }],
  ])('refuses %s, so no secret is stored in the clear', async (_case, secrets) => {
    const realmId = await realm('alpha');
    await expect(
      database().pool.query(
        `INSERT INTO realm_auth_method_plugins (realm_id, plugin_id, secrets) VALUES ($1, 'corp', $2)`,
        [realmId, JSON.stringify(secrets)]
      )
    ).rejects.toMatchObject({
      code: '23514',
      constraint: 'realm_auth_method_plugins_secrets_ciphertext',
    });
  });

  it.each([
    ['an array', `'["v1.kid-1.aXY.Y2lwaGVydGV4dA"]'`],
    ['a string', `'"v1.kid-1.aXY.Y2lwaGVydGV4dA"'`],
    ['a number', `'42'`],
    ['null', `'null'`],
  ])(
    'refuses secrets that are %s by the object CHECK, never with a jsonpath error',
    async (_case, secrets) => {
      const realmId = await realm('alpha');
      await expect(
        database().pool.query(
          `INSERT INTO realm_auth_method_plugins (realm_id, plugin_id, secrets) VALUES ($1, 'corp', ${secrets}::jsonb)`,
          [realmId]
        )
      ).rejects.toMatchObject({
        code: '23514',
        constraint: 'realm_auth_method_plugins_secrets_object',
      });
    }
  );

  it.each([
    [
      'a plugin id outside the contract rule',
      `'Corp SSO'`,
      `'{}'`,
      'realm_auth_method_plugins_plugin_id_form',
    ],
    ['a config that is not an object', `'corp'`, `'[]'`, 'realm_auth_method_plugins_config_object'],
  ])('refuses %s', async (_case, pluginId, config, constraint) => {
    const realmId = await realm('alpha');
    await expect(
      database().pool.query(
        `INSERT INTO realm_auth_method_plugins (realm_id, plugin_id, config) VALUES ($1, ${pluginId}, ${config}::jsonb)`,
        [realmId]
      )
    ).rejects.toMatchObject({ code: '23514', constraint });
  });

  it('deletes the rows of a deleted realm', async () => {
    const realmId = await realm('alpha');
    await repo.save(realmId, 'corp', { enabled: true, config: {}, secrets: {} }, null);
    await database().pool.query('DELETE FROM realms WHERE id = $1', [realmId]);
    const { rows } = await database().pool.query(
      'SELECT count(*)::int AS count FROM realm_auth_method_plugins WHERE realm_id = $1',
      [realmId]
    );
    expect(rows[0]).toEqual({ count: 0 });
  });
});
