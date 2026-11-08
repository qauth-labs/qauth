/**
 * The host's `verify-account` command, against real Postgres (#1052), and the
 * columns of migration 0070 it writes.
 *
 * These cases pin what the command writes: the verification on the account,
 * its operator, and one `user.verified` event in the transaction of the
 * change; nothing for an account it refuses or one already verified; and
 * the CHECKs that keep the pair of columns whole and of the stored form.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createRealmsRepository, createUsersRepository } from '../repositories';
import { type IntegrationDb, setupIntegrationDb } from '../repositories/integration-setup';
import { users } from '../schema/core';
import { events } from '../schema/events';
import { verifyAccount } from './verify-account';

describe('verifyAccount (real Postgres)', () => {
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

  async function seed(realmName: string, enabled = true) {
    const realm = await createRealmsRepository(db()).create({ name: realmName });
    const user = await createUsersRepository(db()).create(
      { realmId: realm.id, enabled },
      testPrimaryCredential()
    );
    return { realm, user };
  }

  async function row(id: string) {
    const [r] = await db().select().from(users).where(eq(users.id, id));
    return r;
  }

  async function eventsOf(realmId: string) {
    return db().select().from(events).where(eq(events.realmId, realmId)).orderBy(events.seq);
  }

  it('verifies the account as the operating-system user and writes the event with it', async () => {
    const { realm, user } = await seed('verify-1');
    const before = Date.now();
    const result = await verifyAccount(db(), { realm: 'verify-1', userId: user.id }, 'ops');

    expect(result).toMatchObject({
      status: 'verified',
      userId: user.id,
      verifiedBy: 'operator_cli:ops',
    });
    const stored = await row(user.id);
    expect(stored.operatorVerifiedBy).toBe('operator_cli:ops');
    expect(stored.operatorVerifiedAt).toBeGreaterThanOrEqual(before);
    expect(stored.enabled).toBe(true);
    const recorded = await eventsOf(realm.id);
    expect(recorded).toHaveLength(1);
    expect(recorded[0]).toMatchObject({
      type: 'urn:qauth:event:user.verified:v1-rc.0',
      category: 'admin',
      actorType: 'operator_cli',
      actorId: 'ops',
      subjectType: 'user',
      subjectId: user.id,
      data: { method: 'operator_cli' },
    });
  });

  it('records the command alone when the host names no user', async () => {
    const { realm, user } = await seed('verify-2');
    await expect(
      verifyAccount(db(), { realm: 'verify-2', userId: user.id }, null)
    ).resolves.toMatchObject({ status: 'verified', verifiedBy: 'operator_cli' });
    expect((await row(user.id)).operatorVerifiedBy).toBe('operator_cli');
    const [event] = await eventsOf(realm.id);
    expect(event).toMatchObject({ actorType: 'operator_cli', actorId: null });
  });

  it('keeps the first verification, and writes nothing on a second run', async () => {
    const { realm, user } = await seed('verify-3');
    const first = await verifyAccount(db(), { realm: 'verify-3', userId: user.id }, 'ops');
    if (first.status !== 'verified') throw new Error(`expected verified, got ${first.status}`);
    const second = await verifyAccount(db(), { realm: 'verify-3', userId: user.id }, 'other');
    expect(second).toEqual({
      status: 'already_verified',
      userId: user.id,
      verifiedAt: first.verifiedAt,
      verifiedBy: 'operator_cli:ops',
    });
    expect(await eventsOf(realm.id)).toHaveLength(1);
  });

  it('refuses a disabled account, an account of another realm and an unknown realm, writing nothing', async () => {
    const disabled = await seed('verify-4', false);
    await expect(
      verifyAccount(db(), { realm: 'verify-4', userId: disabled.user.id }, 'ops')
    ).resolves.toEqual({ status: 'disabled', userId: disabled.user.id });
    expect((await row(disabled.user.id)).operatorVerifiedAt).toBeNull();

    const elsewhere = await seed('verify-5');
    await expect(
      verifyAccount(db(), { realm: 'verify-4', userId: elsewhere.user.id }, 'ops')
    ).resolves.toEqual({ status: 'user_not_found' });
    await expect(
      verifyAccount(db(), { realm: 'no-such-realm', userId: elsewhere.user.id }, 'ops')
    ).resolves.toEqual({ status: 'realm_not_found' });
    expect((await row(elsewhere.user.id)).operatorVerifiedAt).toBeNull();
    expect(await eventsOf(disabled.realm.id)).toHaveLength(0);
    expect(await eventsOf(elsewhere.realm.id)).toHaveLength(0);
  });

  it('holds the two columns together and to the stored form (migration 0070)', async () => {
    const { user } = await seed('verify-6');
    /** The CHECK that refused the update, or `undefined` when it was stored. */
    const refusedBy = async (at: number | null, by: string | null) =>
      db()
        .execute(
          sql`UPDATE users SET operator_verified_at = ${at}, operator_verified_by = ${by} WHERE id = ${user.id}`
        )
        .then(
          () => undefined,
          (error: unknown) => {
            // Drizzle wraps the driver's error in `cause`.
            const pg = ((error as { cause?: unknown }).cause ?? error) as {
              code?: string;
              constraint?: string;
            };
            return `${pg.code} ${pg.constraint}`;
          }
        );
    const PAIR = '23514 users_operator_verification_pair';
    const FORM = '23514 users_operator_verified_by_form';
    // One without the other.
    expect(await refusedBy(1, null)).toBe(PAIR);
    expect(await refusedBy(null, 'operator_cli')).toBe(PAIR);
    // A form no path writes: an upper-case id, another method, a control
    // character, an empty user.
    expect(await refusedBy(1, 'operator:018F2D6E-8A8B-7C3D-9E0F-1A2B3C4D5E6F')).toBe(FORM);
    expect(await refusedBy(1, 'admin:someone')).toBe(FORM);
    expect(await refusedBy(1, 'operator_cli:a\nb')).toBe(FORM);
    expect(await refusedBy(1, 'operator_cli:')).toBe(FORM);
    // The forms the admin API and the command write.
    expect(await refusedBy(1, 'operator:018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f')).toBeUndefined();
    expect(await refusedBy(1, 'operator_cli:ops')).toBeUndefined();
    expect(await refusedBy(null, null)).toBeUndefined();
  });
});
