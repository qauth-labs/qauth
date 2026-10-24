/**
 * Real-Postgres integration tests for the passkey relying-party columns
 * (migrations 0028 and 0034, issues #467 and #553).
 *
 * What only a database can show: the RP ID setting and its lock
 * (`realms.webauthn_rp_id`, `realms.webauthn_rp_id_locked_at`), the lock taken
 * once by the first enrolment and then refused to every writer
 * (`realms_webauthn_rp_id_locked`), two first enrolments racing on one realm,
 * the stored form of an RP ID (CHECK `realms_webauthn_rp_id_normalised`), the
 * operator-set client origins column, and a credential id that exists once
 * per realm (`idx_user_credentials_realm_provider_sub_unique`).
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { BadRequestError, UniqueConstraintError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { InvalidRealmHostError, resolveRpId } from '@qauth-labs/shared-validation';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { DbTransaction, UserCredentialsRepository } from '../../types';
import { users } from '../schema';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import {
  createRealmsRepository,
  type RealmsRepository,
  type RpIdEnrolmentLock,
} from './realms.repository';
import { createUserCredentialsRepository } from './user-credentials.repository';

/** A promise and the function that settles it. */
function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

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

  async function seedRealm(name = 'master', host = 'auth.example.com', port = '') {
    return (
      await realmsRepo.createWithPrimaryHost({ name, issuer: `https://${host}${port}` }, host)
    ).realm;
  }

  async function seedUser(realmId: string) {
    const [user] = await database().db.insert(users).values({ realmId }).returning();
    return user;
  }

  /** Store a passkey as the enrolment does: the lock, then the credential, in one transaction. */
  async function enrol(
    realmId: string,
    externalSub: string,
    tx: DbTransaction
  ): Promise<RpIdEnrolmentLock> {
    const lock = await realmsRepo.lockRpIdForEnrolment(tx, realmId);
    const [user] = await tx.insert(users).values({ realmId }).returning();
    await credentials.create(
      {
        userId: user.id,
        realmId,
        providerType: 'webauthn',
        externalSub,
        credentialData: { rp_id: lock.rpId },
      },
      tx
    );
    return lock;
  }

  async function storedLock(realmId: string) {
    const { rows } = await database().pool.query<{
      webauthn_rp_id: string | null;
      webauthn_rp_id_locked_at: string | null;
    }>(`SELECT webauthn_rp_id, webauthn_rp_id_locked_at FROM realms WHERE id = $1`, [realmId]);
    return rows[0];
  }

  describe('realms.webauthn_rp_id, the RP ID setting', () => {
    it('is NULL, the realm host, and unlocked on a new realm', async () => {
      const realm = await seedRealm();
      expect(realm).toMatchObject({ webauthnRpId: null, webauthnRpIdLockedAt: null });
      expect(resolveRpId(realm)).toBe('auth.example.com');
    });

    it('takes a parent domain, normalised, and goes back to the realm host while unlocked', async () => {
      const realm = await seedRealm();

      await expect(realmsRepo.setWebAuthnRpId(realm.id, 'Example.COM.')).resolves.toMatchObject({
        webauthnRpId: 'example.com',
      });
      await expect(realmsRepo.setWebAuthnRpId(realm.id, null)).resolves.toMatchObject({
        webauthnRpId: null,
      });
      expect(await storedLock(realm.id)).toEqual({
        webauthn_rp_id: null,
        webauthn_rp_id_locked_at: null,
      });
    });

    it('refuses a name that is neither the primary host nor a parent of it, and an IP', async () => {
      const realm = await seedRealm();

      for (const rpId of ['evil.com', 'notexample.com', 'login.example.com']) {
        await expect(realmsRepo.setWebAuthnRpId(realm.id, rpId)).rejects.toBeInstanceOf(
          BadRequestError
        );
      }
      await expect(realmsRepo.setWebAuthnRpId(realm.id, '192.0.2.1')).rejects.toBeInstanceOf(
        InvalidRealmHostError
      );
      expect((await storedLock(realm.id)).webauthn_rp_id).toBeNull();
    });

    it('refuses what cannot be an RP ID in the CHECK, for a writer that skips the repository', async () => {
      const realm = await seedRealm();
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

  describe('lockRpIdForEnrolment, the RP ID lock', () => {
    it('locks on the first enrolment, returns the realm host without the issuer port, and keeps the first lock time', async () => {
      const realm = await seedRealm('master', 'auth.example.com', ':8443');

      const first = await database().db.transaction((tx) => enrol(realm.id, 'Zmlyc3Q', tx));
      expect(first).toMatchObject({ rpId: 'auth.example.com', lockedNow: true });
      expect(await storedLock(realm.id)).toEqual({
        webauthn_rp_id: null,
        webauthn_rp_id_locked_at: String(first.lockedAt),
      });

      const second = await database().db.transaction((tx) => enrol(realm.id, 'c2Vjb25k', tx));
      expect(second).toEqual({
        rpId: 'auth.example.com',
        lockedAt: first.lockedAt,
        lockedNow: false,
      });
    });

    it('rolls back with the enrolment that took it, leaving the realm unlocked', async () => {
      const realm = await seedRealm();

      await expect(
        database().db.transaction(async (tx) => {
          await realmsRepo.lockRpIdForEnrolment(tx, realm.id);
          throw new Error('the passkey could not be stored');
        })
      ).rejects.toThrow('the passkey could not be stored');
      expect((await storedLock(realm.id)).webauthn_rp_id_locked_at).toBeNull();
    });

    it('makes a later change of the RP ID fail at the database, whoever writes it', async () => {
      const realm = await seedRealm();
      await database().db.transaction((tx) => enrol(realm.id, 'bG9ja2Vk', tx));

      await expect(realmsRepo.setWebAuthnRpId(realm.id, 'example.com')).rejects.toBeInstanceOf(
        BadRequestError
      );
      for (const statement of [
        `UPDATE realms SET webauthn_rp_id = 'example.com' WHERE id = $1`,
        // NULL and the host spelled out are one RP ID, but the stored value is locked as is.
        `UPDATE realms SET webauthn_rp_id = 'auth.example.com' WHERE id = $1`,
        `UPDATE realms SET webauthn_rp_id_locked_at = NULL WHERE id = $1`,
        `UPDATE realms SET webauthn_rp_id_locked_at = webauthn_rp_id_locked_at + 1 WHERE id = $1`,
        `UPDATE realms SET webauthn_rp_id_locked_at = NULL, webauthn_rp_id = 'example.com' WHERE id = $1`,
      ]) {
        await expect(database().pool.query(statement, [realm.id])).rejects.toMatchObject({
          code: '23514',
          constraint: 'realms_webauthn_rp_id_locked',
        });
      }
      expect(await realmsRepo.findById(realm.id)).toMatchObject({ webauthnRpId: null });
    });

    it('accepts a setting that names the locked RP ID again, and changes nothing', async () => {
      const realm = await seedRealm();
      await database().db.transaction((tx) => enrol(realm.id, 'c2FtZQ', tx));
      const before = await storedLock(realm.id);

      await expect(realmsRepo.setWebAuthnRpId(realm.id, null)).resolves.toMatchObject({
        webauthnRpId: null,
      });
      await expect(realmsRepo.setWebAuthnRpId(realm.id, 'AUTH.example.com')).resolves.toMatchObject(
        { webauthnRpId: null }
      );
      expect(await storedLock(realm.id)).toEqual(before);
    });

    it('leaves the other columns of a locked realm writable', async () => {
      const realm = await seedRealm();
      await database().db.transaction((tx) => enrol(realm.id, 'b3RoZXI', tx));

      await expect(realmsRepo.update(realm.id, { enabled: false })).resolves.toMatchObject({
        enabled: false,
        webauthnRpId: null,
      });
    });

    it('reports a parent-domain RP ID in resolveRpId after the lock', async () => {
      const realm = await seedRealm();
      await realmsRepo.setWebAuthnRpId(realm.id, 'example.com');

      const lock = await database().db.transaction((tx) => enrol(realm.id, 'cGFyZW50', tx));
      expect(lock).toMatchObject({ rpId: 'example.com', lockedNow: true });

      const locked = await realmsRepo.findById(realm.id);
      if (!locked) throw new Error('realm gone');
      expect(locked.webauthnRpIdLockedAt).toBe(lock.lockedAt);
      expect(resolveRpId(locked)).toBe('example.com');
      await expect(realmsRepo.setWebAuthnRpId(realm.id, null)).rejects.toBeInstanceOf(
        BadRequestError
      );
    });

    it('locks once when two first enrolments race, and both get the same RP ID', async () => {
      const realm = await seedRealm();
      await realmsRepo.setWebAuthnRpId(realm.id, 'example.com');
      const firstLocked = deferred();
      const releaseFirst = deferred();

      const first = database().db.transaction(async (tx) => {
        const lock = await enrol(realm.id, 'cmFjZS1h', tx);
        firstLocked.resolve();
        await releaseFirst.promise;
        return lock;
      });
      await firstLocked.promise;
      const second = database().db.transaction((tx) => enrol(realm.id, 'cmFjZS1i', tx));

      // The second enrolment is queued on the realm row the first one holds.
      const deadline = Date.now() + 10_000;
      for (;;) {
        const { rows } = await database().pool.query<{ waiting: string }>(
          `SELECT count(*) AS waiting FROM pg_stat_activity
           WHERE datname = current_database() AND wait_event_type = 'Lock'`
        );
        if (Number(rows[0].waiting) > 0) break;
        if (Date.now() > deadline) throw new Error('the second enrolment never waited');
        await new Promise((settle) => setTimeout(settle, 20));
      }
      releaseFirst.resolve();

      const [a, b] = await Promise.all([first, second]);
      expect(a).toMatchObject({ rpId: 'example.com', lockedNow: true });
      expect(b).toEqual({ rpId: 'example.com', lockedAt: a.lockedAt, lockedNow: false });
      expect(await storedLock(realm.id)).toEqual({
        webauthn_rp_id: 'example.com',
        webauthn_rp_id_locked_at: String(a.lockedAt),
      });
      const { rows } = await database().pool.query<{ count: string }>(
        `SELECT count(*) FROM user_credentials WHERE realm_id = $1 AND provider_type = 'webauthn'`,
        [realm.id]
      );
      expect(Number(rows[0].count)).toBe(2);
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
