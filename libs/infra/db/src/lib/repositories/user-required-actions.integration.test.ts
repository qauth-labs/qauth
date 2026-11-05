/**
 * Real-DB integration tests for the required-actions repository (#635).
 *
 * Exercises what the recording-client tests cannot: the unique index that
 * makes a second write idempotent, the CHECKs that close `action` and
 * `source`, the foreign key that holds a user to its realm, and the cascade
 * from the user and the realm.
 *
 * Requires Docker; self-skips without it and fails on CI
 * (`requireDockerOrSkip`).
 */
import { NotFoundError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { realms, userRequiredActions, users } from '../schema';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import {
  createUserRequiredActionsRepository,
  type UserRequiredActionsRepository,
} from './user-required-actions.repository';

describe('user required actions repository integration (real Postgres, #635)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let repository: UserRequiredActionsRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    repository = createUserRequiredActionsRepository(ctx.database.db);
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

  it('adds an action and lists it', async () => {
    const { realmId, userId } = await seedUser('realm-add');

    await expect(
      repository.add({ realmId, userId, action: 'update_password', source: 'admin' })
    ).resolves.toBe(true);

    const pending = await repository.listForUser(realmId, userId);
    expect(pending).toEqual([
      { action: 'update_password', source: 'admin', createdAt: expect.any(Number) },
    ]);
  });

  it('keeps the first row when the same action is added again', async () => {
    const { realmId, userId } = await seedUser('realm-idempotent');
    await repository.add({ realmId, userId, action: 'update_password', source: 'admin' });
    const [first] = await repository.listForUser(realmId, userId);

    await expect(
      repository.add({ realmId, userId, action: 'update_password', source: 'user_report' })
    ).resolves.toBe(false);

    const rows = await repository.listForUser(realmId, userId);
    expect(rows).toEqual([first]);
    expect(rows[0].source).toBe('admin');
  });

  it('lists the pending actions of one user, oldest first', async () => {
    const { realmId, userId } = await seedUser('realm-order');
    const other = await seedUser('realm-order-other');
    await repository.add({ realmId, userId, action: 'setup_mfa', source: 'admin' });
    await repository.add({ realmId, userId, action: 'update_password', source: 'user_report' });
    await repository.add({
      realmId: other.realmId,
      userId: other.userId,
      action: 'complete_profile',
      source: 'admin',
    });
    // Equal clocks within a second must not reorder: the id breaks the tie.
    await db()
      .update(userRequiredActions)
      .set({ createdAt: 1_700_000_000_000 })
      .where(eq(userRequiredActions.userId, userId));

    const pending = await repository.listForUser(realmId, userId);

    expect(pending.map((row) => row.action)).toEqual(['setup_mfa', 'update_password']);
    expect(await repository.listForUser(realmId, randomMissingUser())).toEqual([]);
  });

  it("refuses a user that is not of the realm, and answers another realm's list as empty", async () => {
    const a = await seedUser('realm-a');
    const b = await seedUser('realm-b');

    await expect(
      repository.add({
        realmId: b.realmId,
        userId: a.userId,
        action: 'update_password',
        source: 'admin',
      })
    ).rejects.toBeInstanceOf(NotFoundError);
    expect(await db().select().from(userRequiredActions)).toHaveLength(0);

    await repository.add({
      realmId: a.realmId,
      userId: a.userId,
      action: 'update_password',
      source: 'admin',
    });
    expect(await repository.listForUser(b.realmId, a.userId)).toEqual([]);
    await expect(repository.remove(b.realmId, a.userId, 'update_password')).resolves.toBe(false);
    expect(await repository.listForUser(a.realmId, a.userId)).toHaveLength(1);
  });

  it('removes an action once, and says whether it deleted one', async () => {
    const { realmId, userId } = await seedUser('realm-remove');
    await repository.add({ realmId, userId, action: 'update_password', source: 'admin' });
    await repository.add({ realmId, userId, action: 'setup_mfa', source: 'admin' });

    await expect(repository.remove(realmId, userId, 'update_password')).resolves.toBe(true);
    await expect(repository.remove(realmId, userId, 'update_password')).resolves.toBe(false);

    expect((await repository.listForUser(realmId, userId)).map((row) => row.action)).toEqual([
      'setup_mfa',
    ]);
  });

  it('works inside a transaction, and a rollback takes the row with it', async () => {
    const { realmId, userId } = await seedUser('realm-tx');

    await db()
      .transaction(async (tx) => {
        await repository.add({ realmId, userId, action: 'update_password', source: 'admin' }, tx);
        expect(await repository.listForUser(realmId, userId, tx)).toHaveLength(1);
        throw new Error('rollback');
      })
      .catch(() => undefined);

    expect(await repository.listForUser(realmId, userId)).toEqual([]);
  });

  it('refuses an action or a source outside the closed sets', async () => {
    const { realmId, userId } = await seedUser('realm-closed');

    await expect(
      db()
        .insert(userRequiredActions)
        // @ts-expect-error not one of USER_REQUIRED_ACTIONS
        .values({ realmId, userId, action: 'reset_everything', source: 'admin' })
    ).rejects.toMatchObject({
      cause: { code: '23514', constraint: 'user_required_actions_action_known' },
    });
    await expect(
      db()
        .insert(userRequiredActions)
        // @ts-expect-error not one of USER_REQUIRED_ACTION_SOURCES
        .values({ realmId, userId, action: 'update_password', source: 'cron' })
    ).rejects.toMatchObject({
      cause: { code: '23514', constraint: 'user_required_actions_source_known' },
    });
  });

  it("refuses a row whose user is of another realm, even written past the repository's check", async () => {
    const a = await seedUser('realm-fk-a');
    const b = await seedUser('realm-fk-b');

    await expect(
      db().insert(userRequiredActions).values({
        realmId: b.realmId,
        userId: a.userId,
        action: 'update_password',
        source: 'admin',
      })
    ).rejects.toMatchObject({
      cause: { code: '23503', constraint: 'user_required_actions_user_realm_fk' },
    });
  });

  it('deletes the rows with the user and with the realm', async () => {
    const first = await seedUser('realm-cascade-user');
    const second = await seedUser('realm-cascade-realm');
    for (const { realmId, userId } of [first, second]) {
      await repository.add({ realmId, userId, action: 'update_password', source: 'admin' });
    }

    await db().delete(users).where(eq(users.id, first.userId));
    expect(await repository.listForUser(first.realmId, first.userId)).toEqual([]);
    expect(await repository.listForUser(second.realmId, second.userId)).toHaveLength(1);

    await db().delete(realms).where(eq(realms.id, second.realmId));
    expect(await db().select().from(userRequiredActions)).toHaveLength(0);
  });
});

/** A well-formed user id no row has. */
function randomMissingUser(): string {
  return '0190f5a8-7c3e-7d10-8a4b-3c2d1e0fffff';
}
