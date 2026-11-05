/**
 * Real-DB integration tests for the recovery-code repository (#649).
 *
 * Exercises what a recording client cannot: the one conditional `UPDATE`
 * that takes a code once, the replacement that ends every code of the old
 * set, the foreign key that holds a user to its realm, and the cascade from
 * the user.
 *
 * Requires Docker; self-skips without it and fails on CI
 * (`requireDockerOrSkip`).
 */
import { NotFoundError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { realms, userRecoveryCodes, users } from '../schema';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import {
  createUserRecoveryCodesRepository,
  type UserRecoveryCodesRepository,
} from './user-recovery-codes.repository';

const HASHES = Array.from({ length: 10 }, (_, index) => `$argon2id$v=19$hash-${index}`);

describe('recovery codes (real Postgres, #649)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let codes: UserRecoveryCodesRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    codes = createUserRecoveryCodesRepository(ctx.database.db);
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

  it('holds no set until one is issued, then 10 unused codes', async () => {
    const { realmId, userId } = await seedUser('realm-issue');
    await expect(codes.status(realmId, userId)).resolves.toEqual({ issued: false, unused: 0 });
    await expect(codes.findUnused(realmId, userId)).resolves.toEqual([]);

    await codes.replaceSet({ realmId, userId, codeHashes: HASHES, createdAt: 1_000 });
    await expect(codes.status(realmId, userId)).resolves.toEqual({ issued: true, unused: 10 });
    const unused = await codes.findUnused(realmId, userId);
    expect(unused.map((code) => code.codeHash).sort()).toEqual([...HASHES].sort());
  });

  it('takes a code once', async () => {
    const { realmId, userId } = await seedUser('realm-take');
    await codes.replaceSet({ realmId, userId, codeHashes: HASHES, createdAt: 1_000 });
    const [first] = await codes.findUnused(realmId, userId);
    if (first === undefined) throw new Error('no code');

    await expect(codes.markUsed({ realmId, userId, id: first.id, usedAt: 2_000 })).resolves.toBe(
      true
    );
    await expect(codes.markUsed({ realmId, userId, id: first.id, usedAt: 3_000 })).resolves.toBe(
      false
    );
    await expect(codes.status(realmId, userId)).resolves.toEqual({ issued: true, unused: 9 });
    const [row] = await db()
      .select({ usedAt: userRecoveryCodes.usedAt })
      .from(userRecoveryCodes)
      .where(eq(userRecoveryCodes.id, first.id));
    expect(row?.usedAt).toBe(2_000);
    // Two rounds racing for one code: one takes it.
    const [second] = await codes.findUnused(realmId, userId);
    if (second === undefined) throw new Error('no code');
    const raced = await Promise.all([
      codes.markUsed({ realmId, userId, id: second.id, usedAt: 4_000 }),
      codes.markUsed({ realmId, userId, id: second.id, usedAt: 4_001 }),
    ]);
    expect(raced.filter(Boolean)).toHaveLength(1);
  });

  it("never takes another account's code", async () => {
    const mine = await seedUser('realm-mine');
    const theirs = await seedUser('realm-theirs');
    await codes.replaceSet({ ...theirs, codeHashes: HASHES, createdAt: 1_000 });
    const [code] = await codes.findUnused(theirs.realmId, theirs.userId);
    if (code === undefined) throw new Error('no code');
    await expect(codes.markUsed({ ...mine, id: code.id, usedAt: 2_000 })).resolves.toBe(false);
    await expect(
      codes.markUsed({ realmId: mine.realmId, userId: theirs.userId, id: code.id, usedAt: 2_000 })
    ).resolves.toBe(false);
    await expect(codes.status(theirs.realmId, theirs.userId)).resolves.toEqual({
      issued: true,
      unused: 10,
    });
  });

  it('invalidates every code of the old set when a new one replaces it', async () => {
    const { realmId, userId } = await seedUser('realm-replace');
    await codes.replaceSet({ realmId, userId, codeHashes: HASHES, createdAt: 1_000 });
    const old = await codes.findUnused(realmId, userId);
    const [used] = old;
    if (used === undefined) throw new Error('no code');
    await codes.markUsed({ realmId, userId, id: used.id, usedAt: 2_000 });

    const fresh = HASHES.map((hash) => `${hash}-new`);
    await codes.replaceSet({ realmId, userId, codeHashes: fresh, createdAt: 3_000 });
    await expect(codes.status(realmId, userId)).resolves.toEqual({ issued: true, unused: 10 });
    const now = await codes.findUnused(realmId, userId);
    expect(now.map((code) => code.codeHash).sort()).toEqual([...fresh].sort());
    for (const code of old) {
      await expect(codes.markUsed({ realmId, userId, id: code.id, usedAt: 4_000 })).resolves.toBe(
        false
      );
    }
  });

  it('keeps one set when two replacements of an account race', async () => {
    const { realmId, userId } = await seedUser('realm-race');
    await Promise.all([
      codes.replaceSet({ realmId, userId, codeHashes: HASHES, createdAt: 1_000 }),
      codes.replaceSet({
        realmId,
        userId,
        codeHashes: HASHES.map((hash) => `${hash}-b`),
        createdAt: 1_001,
      }),
    ]);
    await expect(codes.status(realmId, userId)).resolves.toEqual({ issued: true, unused: 10 });
  });

  it('refuses a user of another realm, and writes nothing', async () => {
    const mine = await seedUser('realm-a');
    const other = await seedUser('realm-b');
    await expect(
      codes.replaceSet({
        realmId: other.realmId,
        userId: mine.userId,
        codeHashes: HASHES,
        createdAt: 1_000,
      })
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(codes.status(mine.realmId, mine.userId)).resolves.toEqual({
      issued: false,
      unused: 0,
    });
  });

  it('goes with its user', async () => {
    const { realmId, userId } = await seedUser('realm-cascade');
    await codes.replaceSet({ realmId, userId, codeHashes: HASHES, createdAt: 1_000 });
    await db().delete(users).where(eq(users.id, userId));
    await expect(codes.status(realmId, userId)).resolves.toEqual({ issued: false, unused: 0 });
  });
});
