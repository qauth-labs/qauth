/**
 * Real-DB integration tests for the admin enrolments repository (#602,
 * migration 0079; the read and the redemption by id of the enrolment step,
 * #621).
 *
 * Exercises what a unit test cannot: a token that works once against the
 * conditional update, the refusal of a used, an expired and another realm's
 * token, the row that holds only the token's hash, the trigger that refuses
 * every change but one redemption, the composite foreign key and the
 * cascades.
 *
 * Requires Docker; self-skips without it and fails on CI
 * (`requireDockerOrSkip`).
 */
import { createHash, randomBytes } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { adminEnrolments, realms, userCredentials, users } from '../schema';
import {
  ADMIN_ENROLMENT_DEFAULT_TTL_MS,
  type AdminEnrolmentsRepository,
  adminEnrolmentTokenHash,
  createAdminEnrolmentsRepository,
} from './admin-enrolments.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';

/**
 * Each test's moment of enrolment: the clock when it starts, as the trigger
 * reads the database's own clock to refuse an expired token.
 */
let T0 = 0;

describe('admin enrolments (real Postgres, #602)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let repository: AdminEnrolmentsRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    repository = createAdminEnrolmentsRepository(ctx.database.db);
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
    T0 = Date.now();
  });

  function db() {
    if (!ctx) throw new Error('integration db not initialised');
    return ctx.database.db;
  }

  async function realm(name: string): Promise<string> {
    const [row] = await db().insert(realms).values({ name }).returning({ id: realms.id });
    return row.id;
  }

  async function account(realmId: string): Promise<string> {
    const [row] = await db().insert(users).values({ realmId }).returning({ id: users.id });
    return row.id;
  }

  async function issued(realmId: string, ttl = ADMIN_ENROLMENT_DEFAULT_TTL_MS) {
    return repository.issue({
      realmId,
      accountId: repository.newAccountId(),
      createdAt: T0,
      expiresAt: T0 + ttl,
    });
  }

  it('creates the account with no credential, stores only the hash of a 32-byte token, and redeems it once', async () => {
    const realmId = await realm('acme');
    const { token, enrolment, account: created } = await issued(realmId);
    const userId = created.id;
    expect(created).toEqual({ id: userId, realmId, createdAt: T0 });
    const [user] = await db().select().from(users).where(eq(users.id, userId));
    expect(user).toMatchObject({ realmId, enabled: true, isServiceAccount: false, createdAt: T0 });
    expect(
      await db().select().from(userCredentials).where(eq(userCredentials.userId, userId))
    ).toEqual([]);

    expect(Buffer.from(token, 'base64url')).toHaveLength(32);
    const [row] = await db()
      .select()
      .from(adminEnrolments)
      .where(eq(adminEnrolments.id, enrolment.id));
    expect(row).toEqual({
      id: enrolment.id,
      realmId,
      userId,
      tokenHash: createHash('sha256').update(Buffer.from(token, 'base64url')).digest(),
      createdAt: T0,
      expiresAt: T0 + ADMIN_ENROLMENT_DEFAULT_TTL_MS,
      usedAt: null,
    });
    // No column holds the token, in any spelling.
    const { rows } = await ctx!.database.pool.query<{ row: string }>(
      `SELECT row_to_json(e)::text AS row FROM admin_enrolments e`
    );
    expect(rows[0]?.row).not.toContain(token);
    expect(rows[0]?.row).not.toContain(Buffer.from(token, 'base64url').toString('hex'));

    expect(await repository.redeem(realmId, token, T0 + 1_000)).toEqual({
      id: enrolment.id,
      realmId,
      userId,
      expiresAt: T0 + ADMIN_ENROLMENT_DEFAULT_TTL_MS,
      usedAt: T0 + 1_000,
    });
    expect(await repository.redeem(realmId, token, T0 + 2_000)).toBeUndefined();
  });

  it('refuses an expired token, at its expiry and after, and leaves it unused', async () => {
    const realmId = await realm('acme');
    const { token, enrolment } = await issued(realmId, 60_000);

    expect(await repository.redeem(realmId, token, T0 + 60_000)).toBeUndefined();
    expect(await repository.redeem(realmId, token, T0 + 3_600_000)).toBeUndefined();
    expect((await repository.findByUser(realmId, enrolment.userId))?.usedAt).toBeNull();
    // One moment before it expires, it works.
    expect(await repository.redeem(realmId, token, T0 + 59_999)).toMatchObject({
      id: enrolment.id,
    });
  });

  it("refuses another realm's token, an unknown one and a malformed one alike", async () => {
    const acme = await realm('acme');
    const other = await realm('other');
    const { token } = await issued(acme);

    expect(await repository.redeem(other, token, T0 + 1)).toBeUndefined();
    const unknown = Buffer.alloc(32, 7).toString('base64url');
    expect(await repository.redeem(acme, unknown, T0 + 1)).toBeUndefined();
    for (const malformed of ['', 'x', `${token}=`, `${token}A`, token.slice(1), 'not-a-uuid']) {
      expect(await repository.redeem(acme, malformed, T0 + 1)).toBeUndefined();
    }
    expect(await repository.redeem('not-a-uuid', token, T0 + 1)).toBeUndefined();
    // Still unused for its own realm.
    expect(await repository.redeem(acme, token, T0 + 1)).toBeDefined();
  });

  it('refuses a redemption timed before the enrolment was made, without an error', async () => {
    const realmId = await realm('acme');
    const { token } = await issued(realmId);
    expect(await repository.redeem(realmId, token, T0 - 1)).toBeUndefined();
    expect(await repository.redeem(realmId, token, T0)).toBeDefined();
  });

  it('refuses a token the database’s clock finds expired, whatever time the writer gives', async () => {
    const realmId = await realm('acme');
    const userId = await account(realmId);
    const token = randomBytes(32).toString('base64url');
    const tokenHash = adminEnrolmentTokenHash(token);
    if (tokenHash === undefined) throw new Error('not a token');
    await db()
      .insert(adminEnrolments)
      .values({ realmId, userId, tokenHash, createdAt: T0 - 7_200_000, expiresAt: T0 - 3_600_000 });

    // The writer's clock says the token is still valid: the trigger refuses.
    await expect(repository.redeem(realmId, token, T0 - 5_400_000)).rejects.toMatchObject({
      cause: expect.objectContaining({ constraint: 'admin_enrolments_use_once' }),
    });
    expect((await repository.findByUser(realmId, userId))?.usedAt).toBeNull();
  });

  it('reads a redeemable token without spending it, and refuses what redeem refuses (#621)', async () => {
    const acme = await realm('acme');
    const other = await realm('other');
    const { token, enrolment } = await issued(acme, 60_000);
    const redeemable = {
      id: enrolment.id,
      realmId: acme,
      userId: enrolment.userId,
      createdAt: T0,
      expiresAt: T0 + 60_000,
    };

    expect(await repository.findRedeemable(acme, token, T0 + 1)).toEqual(redeemable);
    // Reading twice changes nothing.
    expect(await repository.findRedeemable(acme, token, T0 + 2)).toEqual(redeemable);
    expect((await repository.findByUser(acme, enrolment.userId))?.usedAt).toBeNull();

    // Another realm's, unknown, malformed, before it was made, at and after its expiry.
    expect(await repository.findRedeemable(other, token, T0 + 1)).toBeUndefined();
    const unknown = Buffer.alloc(32, 7).toString('base64url');
    expect(await repository.findRedeemable(acme, unknown, T0 + 1)).toBeUndefined();
    for (const malformed of ['', `${token}=`, token.slice(1)]) {
      expect(await repository.findRedeemable(acme, malformed, T0 + 1)).toBeUndefined();
    }
    expect(await repository.findRedeemable('not-a-uuid', token, T0 + 1)).toBeUndefined();
    expect(await repository.findRedeemable(acme, token, T0 - 1)).toBeUndefined();
    expect(await repository.findRedeemable(acme, token, T0 + 60_000)).toBeUndefined();

    // Used: no longer redeemable.
    expect(await repository.redeem(acme, token, T0 + 3)).toBeDefined();
    expect(await repository.findRedeemable(acme, token, T0 + 4)).toBeUndefined();
  });

  it('redeems an enrolment by its id once, for its own account and realm only (#621)', async () => {
    const acme = await realm('acme');
    const other = await realm('other');
    const stranger = await account(acme);
    const { enrolment } = await issued(acme, 60_000);
    const { id, userId } = enrolment;

    expect(await repository.redeemEnrolment(other, id, userId, T0 + 1)).toBeUndefined();
    expect(await repository.redeemEnrolment(acme, id, stranger, T0 + 1)).toBeUndefined();
    expect(await repository.redeemEnrolment(acme, id, userId, T0 - 1)).toBeUndefined();
    expect(await repository.redeemEnrolment(acme, id, userId, T0 + 60_000)).toBeUndefined();
    expect(await repository.redeemEnrolment(acme, 'not-a-uuid', userId, T0 + 1)).toBeUndefined();
    expect((await repository.findByUser(acme, userId))?.usedAt).toBeNull();

    expect(await repository.redeemEnrolment(acme, id, userId, T0 + 1_000)).toEqual({
      id,
      realmId: acme,
      userId,
      expiresAt: T0 + 60_000,
      usedAt: T0 + 1_000,
    });
    expect(await repository.redeemEnrolment(acme, id, userId, T0 + 2_000)).toBeUndefined();
  });

  it('lets two redemptions by id at once use the enrolment once (#621)', async () => {
    const realmId = await realm('acme');
    const { enrolment } = await issued(realmId);
    const results = await Promise.all(
      Array.from({ length: 5 }, () =>
        repository.redeemEnrolment(realmId, enrolment.id, enrolment.userId, T0 + 1)
      )
    );
    expect(results.filter((result) => result !== undefined)).toHaveLength(1);
  });

  it('lets two redemptions at once use the token once', async () => {
    const realmId = await realm('acme');
    const { token } = await issued(realmId);
    const results = await Promise.all(
      Array.from({ length: 5 }, () => repository.redeem(realmId, token, T0 + 1))
    );
    expect(results.filter((result) => result !== undefined)).toHaveLength(1);
  });

  it('refuses, in the database, every change but one redemption before expiry', async () => {
    const realmId = await realm('acme');
    const other = await account(realmId);
    const { enrolment } = await issued(realmId);
    const where = eq(adminEnrolments.id, enrolment.id);
    const refused = (change: Partial<typeof adminEnrolments.$inferInsert>) =>
      db().update(adminEnrolments).set(change).where(where);

    for (const change of [
      { expiresAt: T0 + 10 * ADMIN_ENROLMENT_DEFAULT_TTL_MS },
      { userId: other },
      { tokenHash: Buffer.alloc(32, 1) },
      { createdAt: T0 - 1 },
      { usedAt: T0 + ADMIN_ENROLMENT_DEFAULT_TTL_MS },
    ]) {
      await expect(refused(change)).rejects.toMatchObject({
        cause: expect.objectContaining({ constraint: 'admin_enrolments_use_once' }),
      });
    }
    await db()
      .update(adminEnrolments)
      .set({ usedAt: T0 + 5 })
      .where(where);
    // Used: made usable again, or used again, is refused.
    for (const change of [{ usedAt: null }, { usedAt: T0 + 6 }]) {
      await expect(refused(change)).rejects.toMatchObject({
        cause: expect.objectContaining({ constraint: 'admin_enrolments_use_once' }),
      });
    }
  });

  it('holds one enrolment per account, the account in the row’s realm, and a 32-byte hash', async () => {
    const acme = await realm('acme');
    const other = await realm('other');
    const { account: created } = await issued(acme);
    const row = (userId: string, realmId = acme, tokenHash = Buffer.alloc(32, 9)) =>
      db()
        .insert(adminEnrolments)
        .values({ realmId, userId, tokenHash, createdAt: T0, expiresAt: T0 + 1 });

    await expect(row(created.id)).rejects.toMatchObject({
      cause: expect.objectContaining({ constraint: 'admin_enrolments_user_id_unique' }),
    });
    await expect(row(await account(acme), other)).rejects.toMatchObject({
      cause: expect.objectContaining({ constraint: 'admin_enrolments_user_realm_fk' }),
    });
    await expect(row(await account(acme), acme, Buffer.alloc(16))).rejects.toMatchObject({
      cause: expect.objectContaining({ constraint: 'admin_enrolments_token_hash_sha256' }),
    });
    await expect(
      repository.issue({
        realmId: acme,
        accountId: repository.newAccountId(),
        createdAt: T0,
        expiresAt: T0,
      })
    ).rejects.toThrow(RangeError);
  });

  it('writes neither the account nor the enrolment when one of them fails', async () => {
    const acme = await realm('acme');
    const taken = await account(acme);
    await expect(
      repository.issue({ realmId: acme, accountId: taken, createdAt: T0, expiresAt: T0 + 1 })
    ).rejects.toThrow();
    const [{ count }] = await db()
      .select({ count: sql<number>`count(*)::int` })
      .from(adminEnrolments);
    expect(count).toBe(0);
  });

  it('goes with its account, and with its realm', async () => {
    const realmId = await realm('acme');
    const first = (await issued(realmId)).account.id;
    const second = (await issued(realmId)).account.id;

    await db().delete(users).where(eq(users.id, first));
    expect(await repository.findByUser(realmId, first)).toBeUndefined();
    expect(await repository.findByUser(realmId, second)).toBeDefined();

    await db().delete(realms).where(eq(realms.id, realmId));
    const [{ count }] = await db()
      .select({ count: sql<number>`count(*)::int` })
      .from(adminEnrolments);
    expect(count).toBe(0);
  });
});
