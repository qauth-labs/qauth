/**
 * Real-Postgres integration tests for the passkey relying-party columns
 * (migration 0028, issue #467).
 *
 * What only a database can show: the RP ID lock written once and never
 * changed (`realms_webauthn_rp_id_permanent`), its stored form (CHECK
 * `realms_webauthn_rp_id_normalised`), two first enrolments racing under
 * different RP IDs, the operator-set client origins column, and a credential
 * id that exists once per realm (`idx_user_credentials_realm_provider_sub_unique`).
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { BadRequestError, UniqueConstraintError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { InvalidRealmHostError } from '@qauth-labs/shared-validation';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { UserCredentialsRepository } from '../../types';
import { users } from '../schema';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createRealmsRepository, type RealmsRepository } from './realms.repository';
import { createUserCredentialsRepository } from './user-credentials.repository';

describe('passkey relying-party columns (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let realmsRepo: RealmsRepository;
  let credentials: UserCredentialsRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    realmsRepo = createRealmsRepository(ctx.database.db);
    credentials = createUserCredentialsRepository(ctx.database.db);
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

  async function seedRealm(name = 'master', host = 'auth.example.com') {
    return (await realmsRepo.createWithPrimaryHost({ name, issuer: `https://${host}` }, host))
      .realm;
  }

  async function seedUser(realmId: string) {
    const [user] = await database().db.insert(users).values({ realmId }).returning();
    return user;
  }

  describe('realms.webauthn_rp_id, the RP ID lock', () => {
    it('is NULL on a realm with no passkey', async () => {
      expect((await seedRealm()).webauthnRpId).toBeNull();
    });

    it('is written by the first lock and accepted again by the same RP ID', async () => {
      const realm = await seedRealm();

      const locked = await realmsRepo.lockWebAuthnRpId(realm.id, 'auth.example.com');
      expect(locked.webauthnRpId).toBe('auth.example.com');
      await expect(
        realmsRepo.lockWebAuthnRpId(realm.id, 'AUTH.example.com.')
      ).resolves.toMatchObject({ webauthnRpId: 'auth.example.com' });
    });

    it('refuses another RP ID once locked, through the repository and by hand', async () => {
      const realm = await seedRealm();
      await realmsRepo.lockWebAuthnRpId(realm.id, 'auth.example.com');

      await expect(realmsRepo.lockWebAuthnRpId(realm.id, 'example.com')).rejects.toBeInstanceOf(
        BadRequestError
      );
      await expect(
        database().pool.query(`UPDATE realms SET webauthn_rp_id = 'example.com' WHERE id = $1`, [
          realm.id,
        ])
      ).rejects.toMatchObject({ code: '23514', constraint: 'realms_webauthn_rp_id_permanent' });
      await expect(
        database().pool.query(`UPDATE realms SET webauthn_rp_id = NULL WHERE id = $1`, [realm.id])
      ).rejects.toMatchObject({ constraint: 'realms_webauthn_rp_id_permanent' });
      expect((await realmsRepo.findById(realm.id))?.webauthnRpId).toBe('auth.example.com');
    });

    it('leaves other columns of a locked realm writable', async () => {
      const realm = await seedRealm();
      await realmsRepo.lockWebAuthnRpId(realm.id, 'auth.example.com');

      await expect(realmsRepo.update(realm.id, { enabled: false })).resolves.toMatchObject({
        enabled: false,
        webauthnRpId: 'auth.example.com',
      });
    });

    it('lets one of two racing first enrolments win, under the realm row lock', async () => {
      const realm = await seedRealm();

      const results = await Promise.allSettled([
        realmsRepo.lockWebAuthnRpId(realm.id, 'auth.example.com'),
        realmsRepo.lockWebAuthnRpId(realm.id, 'example.com'),
      ]);

      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      const stored = (await realmsRepo.findById(realm.id))?.webauthnRpId;
      expect(['auth.example.com', 'example.com']).toContain(stored);
    });

    it('refuses what cannot be an RP ID, in the repository and in the CHECK', async () => {
      const realm = await seedRealm();

      await expect(realmsRepo.lockWebAuthnRpId(realm.id, '192.0.2.1')).rejects.toBeInstanceOf(
        InvalidRealmHostError
      );
      for (const value of ['Auth.Example.com', '192.0.2.1', '[::1]', 'auth.example.com:443']) {
        await expect(
          database().pool.query(`UPDATE realms SET webauthn_rp_id = $2 WHERE id = $1`, [
            realm.id,
            value,
          ])
        ).rejects.toMatchObject({ constraint: 'realms_webauthn_rp_id_normalised' });
      }
    });
  });

  describe('oauth_clients.webauthn_allowed_origins', () => {
    it('defaults to an empty array and refuses anything but an array', async () => {
      const realm = await seedRealm();
      const { rows } = await database().pool.query<{ webauthn_allowed_origins: unknown }>(
        `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris)
         VALUES ($1, 'app', 'hash', 'App', '[]') RETURNING webauthn_allowed_origins`,
        [realm.id]
      );
      expect(rows[0].webauthn_allowed_origins).toEqual([]);

      await expect(
        database().pool.query(
          `UPDATE oauth_clients SET webauthn_allowed_origins = '"https://app.example.com"' WHERE realm_id = $1`,
          [realm.id]
        )
      ).rejects.toMatchObject({ constraint: 'oauth_clients_webauthn_allowed_origins_is_array' });
    });
  });

  describe('a credential id exists once per realm', () => {
    const CREDENTIAL_ID = 'sYUC8p5I9SxqFernBPHmDxz_YVZXmVJdW8s-m3RTTqE';

    it('refuses a second webauthn credential with the same id in the realm, for any user', async () => {
      const realm = await seedRealm();
      const ada = await seedUser(realm.id);
      const grace = await seedUser(realm.id);
      const row = (userId: string) => ({
        userId,
        realmId: realm.id,
        providerType: 'webauthn',
        externalSub: CREDENTIAL_ID,
        credentialData: { rp_id: 'auth.example.com' },
      });

      await credentials.create(row(ada.id));
      await expect(credentials.create(row(grace.id))).rejects.toBeInstanceOf(UniqueConstraintError);
      await expect(credentials.create(row(ada.id))).rejects.toMatchObject({
        constraint: 'idx_user_credentials_realm_provider_sub_unique',
      });
    });

    it('accepts the same id in another realm, which has its own RP ID', async () => {
      const master = await seedRealm();
      const tenant = await seedRealm('tenant', 'tenant.example.com');
      for (const realm of [master, tenant]) {
        await credentials.create({
          userId: (await seedUser(realm.id)).id,
          realmId: realm.id,
          providerType: 'webauthn',
          externalSub: CREDENTIAL_ID,
          credentialData: {},
        });
      }
      expect(
        await credentials.findByRealmProviderSub(tenant.id, 'webauthn', CREDENTIAL_ID)
      ).toMatchObject({ realmId: tenant.id });
    });
  });
});
