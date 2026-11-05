/**
 * Real-DB integration tests for the session-epoch repository and the password
 * update of a credential (#642).
 *
 * Exercises what a recording client cannot: the upsert that advances the
 * counter, the guard that keeps a later time, the foreign key that holds a
 * user to its realm, the cascade from the user and the realm, and the one
 * statement that replaces a password's keys of `credential_data` and clears
 * the disabled mark while keeping every other key and every other row.
 *
 * Requires Docker; self-skips without it and fails on CI
 * (`requireDockerOrSkip`).
 */
import { NotFoundError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { UserCredentialsRepository } from '../../types';
import { realms, users,userSessionEpochs } from '../schema';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createUserCredentialsRepository } from './user-credentials.repository';
import {
  createUserSessionEpochsRepository,
  type UserSessionEpochsRepository,
} from './user-session-epochs.repository';

describe('session epochs and the password update (real Postgres, #642)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let epochs: UserSessionEpochsRepository;
  let credentials: UserCredentialsRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    epochs = createUserSessionEpochsRepository(ctx.database.db);
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

  function db() {
    if (!ctx) throw new Error('integration db not initialised');
    return ctx.database.db;
  }

  async function seedUser(name: string) {
    const [realm] = await db().insert(realms).values({ name }).returning({ id: realms.id });
    const [user] = await db().insert(users).values({ realmId: realm.id }).returning();
    return { realmId: realm.id, userId: user.id };
  }

  describe('the session epoch', () => {
    it('has none for a user never reset, then 1 at the first advance', async () => {
      const { realmId, userId } = await seedUser('realm-first');
      await expect(epochs.find(realmId, userId)).resolves.toBeUndefined();

      await expect(epochs.advance({ realmId, userId, at: 1_000 })).resolves.toEqual({
        epoch: 1,
        advancedAt: 1_000,
      });
      await expect(epochs.find(realmId, userId)).resolves.toEqual({ epoch: 1, advancedAt: 1_000 });
    });

    it('counts every advance, and never moves the time back', async () => {
      const { realmId, userId } = await seedUser('realm-count');
      await epochs.advance({ realmId, userId, at: 5_000 });
      await expect(epochs.advance({ realmId, userId, at: 9_000 })).resolves.toEqual({
        epoch: 2,
        advancedAt: 9_000,
      });
      // A node whose clock is behind keeps the later time.
      await expect(epochs.advance({ realmId, userId, at: 7_000 })).resolves.toEqual({
        epoch: 3,
        advancedAt: 9_000,
      });
    });

    it("refuses a user of another realm, and answers another realm's read as none", async () => {
      const { realmId, userId } = await seedUser('realm-own');
      const other = await seedUser('realm-other');
      await epochs.advance({ realmId, userId, at: 1_000 });

      await expect(
        epochs.advance({ realmId: other.realmId, userId, at: 2_000 })
      ).rejects.toBeInstanceOf(NotFoundError);
      await expect(epochs.find(other.realmId, userId)).resolves.toBeUndefined();
      await expect(epochs.find(realmId, userId)).resolves.toEqual({ epoch: 1, advancedAt: 1_000 });
    });

    it('works inside a transaction, and a rollback takes the advance with it', async () => {
      const { realmId, userId } = await seedUser('realm-tx');
      await expect(
        db().transaction(async (tx) => {
          await epochs.advance({ realmId, userId, at: 1_000 }, tx);
          throw new Error('rolled back');
        })
      ).rejects.toThrow('rolled back');
      await expect(epochs.find(realmId, userId)).resolves.toBeUndefined();
    });

    it('refuses a row whose user is of another realm, even written past the repository', async () => {
      const { userId } = await seedUser('realm-fk');
      const other = await seedUser('realm-fk-other');
      await expect(
        db().insert(userSessionEpochs).values({
          userId,
          realmId: other.realmId,
          epoch: 1,
          advancedAt: 1,
        })
      ).rejects.toThrow();
    });

    it('deletes the row with the user and with the realm', async () => {
      const first = await seedUser('realm-cascade-user');
      const second = await seedUser('realm-cascade-realm');
      await epochs.advance({ ...first, at: 1_000 });
      await epochs.advance({ ...second, at: 1_000 });

      await db().delete(users).where(eq(users.id, first.userId));
      await db().delete(realms).where(eq(realms.id, second.realmId));

      expect(await db().select().from(userSessionEpochs)).toEqual([]);
    });
  });

  describe('the password update of a credential', () => {
    const SEEDED_AT = 1_600_000_000_000;

    async function seedCredentials() {
      const { realmId, userId } = await seedUser('realm-password');
      const password = await credentials.create({
        userId,
        realmId,
        providerType: 'password',
        externalSub: 'user@example.com',
        credentialData: {
          password_hash: '$argon2id$old',
          email_verified: false,
          password_normalization: 'nfc',
          future_sibling: 'must-survive',
        },
        disabledAt: SEEDED_AT,
        createdAt: SEEDED_AT,
        updatedAt: SEEDED_AT,
      });
      const passkey = await credentials.create({
        userId,
        realmId,
        providerType: 'webauthn',
        externalSub: 'credential-id',
        credentialData: { public_key: 'key' },
        disabledAt: SEEDED_AT,
        createdAt: SEEDED_AT,
        updatedAt: SEEDED_AT,
      });
      return { realmId, userId, password, passkey };
    }

    it("replaces the password's keys, keeps the others and clears the disabled mark", async () => {
      const { realmId, password } = await seedCredentials();

      const updated = await credentials.updatePassword(realmId, password.id, {
        password_hash: '$argon2id$new',
        email_verified: true,
      });

      // A marker the new data does not carry is dropped: the new hash is of
      // the password as typed.
      expect(updated?.credentialData).toEqual({
        password_hash: '$argon2id$new',
        email_verified: true,
        future_sibling: 'must-survive',
      });
      expect(updated?.disabledAt).toBeNull();
      expect(updated?.updatedAt).toBeGreaterThan(SEEDED_AT);
    });

    it("never touches a second factor's row", async () => {
      const { realmId, password, passkey } = await seedCredentials();

      await expect(
        credentials.updatePassword(realmId, passkey.id, {
          password_hash: '$argon2id$new',
          email_verified: true,
        })
      ).resolves.toBeUndefined();
      await credentials.updatePassword(realmId, password.id, {
        password_hash: '$argon2id$new',
        email_verified: true,
        password_normalization: 'nfc',
      });

      const after = await credentials.findById(realmId, passkey.id);
      expect(after?.credentialData).toEqual({ public_key: 'key' });
      expect(after?.disabledAt).toBe(SEEDED_AT);
    });

    it("answers another realm's credential as none, and writes nothing", async () => {
      const { password } = await seedCredentials();
      const other = await seedUser('realm-password-other');

      await expect(
        credentials.updatePassword(other.realmId, password.id, {
          password_hash: '$argon2id$new',
          email_verified: true,
        })
      ).resolves.toBeUndefined();
      const after = await credentials.findById(password.realmId, password.id);
      expect(after?.credentialData).toMatchObject({ password_hash: '$argon2id$old' });
    });
  });
});
