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
/** A set id of the right form that names no set. */
const SOME_SET = '0190d3c4-5e6f-7a8b-9c0d-1e2f3a4b5c6d';

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
    await expect(codes.status(realmId, userId)).resolves.toEqual({
      issued: false,
      unused: 0,
      confirmed: false,
    });
    await expect(codes.findUnused(realmId, userId)).resolves.toEqual([]);

    await codes.replaceSet({ realmId, userId, codeHashes: HASHES, createdAt: 1_000 });
    await expect(codes.status(realmId, userId)).resolves.toEqual({
      issued: true,
      unused: 10,
      confirmed: false,
    });
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
    await expect(codes.status(realmId, userId)).resolves.toEqual({
      issued: true,
      unused: 9,
      confirmed: false,
    });
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
      confirmed: false,
    });
  });

  it('confirms the set the person saved, and a new set is unconfirmed until its own confirmation', async () => {
    const { realmId, userId } = await seedUser('realm-confirm');
    // No set: nothing to confirm, and nothing written.
    await expect(
      codes.confirmSet({ realmId, userId, setId: SOME_SET, confirmedAt: 1_500 })
    ).resolves.toBe(false);
    await expect(codes.status(realmId, userId)).resolves.toEqual({
      issued: false,
      unused: 0,
      confirmed: false,
    });

    const setId = await codes.replaceSet({
      realmId,
      userId,
      codeHashes: HASHES,
      createdAt: 1_000,
    });
    if (setId === null) throw new Error('no set');
    await expect(codes.confirmSet({ realmId, userId, setId, confirmedAt: 2_000 })).resolves.toBe(
      true
    );
    await expect(codes.status(realmId, userId)).resolves.toEqual({
      issued: true,
      unused: 10,
      confirmed: true,
    });
    // A second confirmation keeps the first one's time.
    await expect(codes.confirmSet({ realmId, userId, setId, confirmedAt: 3_000 })).resolves.toBe(
      true
    );
    const rows = await db()
      .select({ confirmedAt: userRecoveryCodes.confirmedAt })
      .from(userRecoveryCodes)
      .where(eq(userRecoveryCodes.userId, userId));
    expect(new Set(rows.map((row) => row.confirmedAt))).toEqual(new Set([2_000]));

    await codes.replaceSet({
      realmId,
      userId,
      codeHashes: HASHES.map((hash) => `${hash}-new`),
      createdAt: 4_000,
    });
    await expect(codes.status(realmId, userId)).resolves.toEqual({
      issued: true,
      unused: 10,
      confirmed: false,
    });
    await expect(codes.confirmSet({ realmId, userId, setId, confirmedAt: 0 })).rejects.toThrow(
      RangeError
    );
  });

  it('never confirms a set that replaced the one shown, nor one of another account', async () => {
    const { realmId, userId } = await seedUser('realm-confirm-replaced');
    const other = await seedUser('realm-confirm-other');
    const shown = await codes.replaceSet({ realmId, userId, codeHashes: HASHES, createdAt: 1_000 });
    if (shown === null) throw new Error('no set');
    // Another sign-in replaced the set shown: its confirmation names a set
    // the account no longer holds, and the replacement stays unconfirmed.
    await codes.replaceSet({
      realmId,
      userId,
      codeHashes: HASHES.map((hash) => `${hash}-b`),
      createdAt: 1_001,
    });
    await expect(
      codes.confirmSet({ realmId, userId, setId: shown, confirmedAt: 2_000 })
    ).resolves.toBe(false);
    await expect(codes.status(realmId, userId)).resolves.toMatchObject({ confirmed: false });

    const theirs = await codes.replaceSet({ ...other, codeHashes: HASHES, createdAt: 1_000 });
    if (theirs === null) throw new Error('no set');
    await expect(
      codes.confirmSet({ realmId, userId, setId: theirs, confirmedAt: 2_000 })
    ).resolves.toBe(false);
    await expect(
      codes.confirmSet({ realmId, userId, setId: 'not-a-set', confirmedAt: 2_000 })
    ).resolves.toBe(false);
    await expect(codes.status(other.realmId, other.userId)).resolves.toMatchObject({
      confirmed: false,
    });
  });

  it('keeps a confirmed set from an issuance that keeps one, and replaces it on a regeneration', async () => {
    const { realmId, userId } = await seedUser('realm-keep');
    // No set yet, and an unconfirmed one: an issuance that keeps a confirmed set writes.
    const first = await codes.replaceSet({
      realmId,
      userId,
      codeHashes: HASHES,
      createdAt: 1_000,
      keepConfirmed: true,
    });
    if (first === null) throw new Error('no set');
    const second = await codes.replaceSet({
      realmId,
      userId,
      codeHashes: HASHES.map((hash) => `${hash}-b`),
      createdAt: 1_001,
      keepConfirmed: true,
    });
    if (second === null) throw new Error('no set');
    expect(second).not.toBe(first);
    await codes.confirmSet({ realmId, userId, setId: second, confirmedAt: 2_000 });

    await expect(
      codes.replaceSet({
        realmId,
        userId,
        codeHashes: HASHES.map((hash) => `${hash}-c`),
        createdAt: 3_000,
        keepConfirmed: true,
      })
    ).resolves.toBeNull();
    const kept = await codes.findUnused(realmId, userId);
    expect(kept.map((code) => code.codeHash).sort()).toEqual(
      HASHES.map((hash) => `${hash}-b`).sort()
    );

    const regenerated = await codes.replaceSet({
      realmId,
      userId,
      codeHashes: HASHES.map((hash) => `${hash}-d`),
      createdAt: 4_000,
    });
    expect(regenerated).not.toBeNull();
    await expect(codes.status(realmId, userId)).resolves.toEqual({
      issued: true,
      unused: 10,
      confirmed: false,
    });
  });

  it('runs a confirmation and a replacement of one account one after the other', async () => {
    const { realmId, userId } = await seedUser('realm-confirm-race');
    const shown = await codes.replaceSet({ realmId, userId, codeHashes: HASHES, createdAt: 1_000 });
    if (shown === null) throw new Error('no set');
    const [confirmed, replaced] = await Promise.all([
      codes.confirmSet({ realmId, userId, setId: shown, confirmedAt: 2_000 }),
      codes.replaceSet({
        realmId,
        userId,
        codeHashes: HASHES.map((hash) => `${hash}-b`),
        createdAt: 2_001,
        keepConfirmed: true,
      }),
    ]);
    const status = await codes.status(realmId, userId);
    if (replaced === null) {
      // The confirmation came first: the issuance kept the confirmed set.
      expect(confirmed).toBe(true);
      expect(status).toEqual({ issued: true, unused: 10, confirmed: true });
    } else {
      // The replacement came first: the set shown is gone, and none is confirmed.
      expect(confirmed).toBe(false);
      expect(status).toEqual({ issued: true, unused: 10, confirmed: false });
    }
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
    await expect(codes.status(realmId, userId)).resolves.toEqual({
      issued: true,
      unused: 10,
      confirmed: false,
    });
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
    await expect(codes.status(realmId, userId)).resolves.toEqual({
      issued: true,
      unused: 10,
      confirmed: false,
    });
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
      confirmed: false,
    });
  });

  it('finds the account of an unused code by its lookup digest alone (#655)', async () => {
    const { realmId, userId } = await seedUser('realm-lookup');
    const digests = HASHES.map((_, index) => `lookup-${index}`);
    await codes.replaceSet({
      realmId,
      userId,
      codeHashes: HASHES,
      lookupDigests: digests,
      createdAt: 1_000,
    });
    await expect(codes.findByLookupDigest(realmId, 'lookup-3')).resolves.toEqual({ userId });
    await expect(codes.findByLookupDigest(realmId, 'lookup-x')).resolves.toBeNull();
    // Another realm's lookup finds nothing.
    const other = await seedUser('realm-lookup-other');
    await expect(codes.findByLookupDigest(other.realmId, 'lookup-3')).resolves.toBeNull();
    // A used code is found no more.
    const [row] = await db()
      .select({ id: userRecoveryCodes.id })
      .from(userRecoveryCodes)
      .where(eq(userRecoveryCodes.lookupDigest, 'lookup-3'));
    await codes.markUsed({ realmId, userId, id: row?.id ?? '', usedAt: 2_000 });
    await expect(codes.findByLookupDigest(realmId, 'lookup-3')).resolves.toBeNull();
    // A set issued without digests is never found by one.
    await codes.replaceSet({ realmId, userId, codeHashes: HASHES, createdAt: 3_000 });
    await expect(codes.findByLookupDigest(realmId, 'lookup-4')).resolves.toBeNull();
  });

  it('refuses a set whose lookup digests do not match its hashes', async () => {
    const { realmId, userId } = await seedUser('realm-lookup-mismatch');
    await expect(
      codes.replaceSet({
        realmId,
        userId,
        codeHashes: HASHES,
        lookupDigests: ['only-one'],
        createdAt: 1_000,
      })
    ).rejects.toThrow(RangeError);
    await expect(codes.status(realmId, userId)).resolves.toMatchObject({ issued: false });
  });

  it('goes with its user', async () => {
    const { realmId, userId } = await seedUser('realm-cascade');
    await codes.replaceSet({ realmId, userId, codeHashes: HASHES, createdAt: 1_000 });
    await db().delete(users).where(eq(users.id, userId));
    await expect(codes.status(realmId, userId)).resolves.toEqual({
      issued: false,
      unused: 0,
      confirmed: false,
    });
  });
});
