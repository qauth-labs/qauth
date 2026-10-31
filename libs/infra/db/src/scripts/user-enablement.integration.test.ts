/**
 * The operator tool that disables and enables accounts, against real Postgres
 * (#748).
 *
 * These cases pin what the tool writes: the switch, the time the trigger
 * records on disable and keeps on enable, and one event per change in the
 * transaction of the change, with nothing for a run that changes nothing.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createRealmsRepository, createUsersRepository } from '../lib/repositories';
import { type IntegrationDb, setupIntegrationDb } from '../lib/repositories/integration-setup';
import { users } from '../lib/schema/core';
import { events } from '../lib/schema/events';
import { setUserEnabled } from './user-enablement';

describe('setUserEnabled (real Postgres)', () => {
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
    const user = await createUsersRepository(db()).create({ realmId: realm.id, enabled });
    return { realm, user };
  }

  async function row(id: string) {
    const [r] = await db().select().from(users).where(eq(users.id, id));
    return r;
  }

  /**
   * The database's clock, in epoch milliseconds, as the triggers read it: the
   * bounds of a recorded time, which the host's clock may disagree with.
   */
  async function dbNow(): Promise<number> {
    const { rows } = await db().execute<{ now: string }>(
      sql`SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint AS now`
    );
    return Number(rows[0].now);
  }

  async function eventsOf(realmId: string) {
    return db().select().from(events).where(eq(events.realmId, realmId)).orderBy(events.seq);
  }

  it('disables the account, records the time from the database clock, and writes the event', async () => {
    const { realm, user } = await seed('dis-1');

    const before = await dbNow();
    const result = await setUserEnabled(db(), { realm: 'dis-1', userId: user.id, enable: false });
    const after = await dbNow();

    if (result.status !== 'disabled') throw new Error(`expected disabled, got ${result.status}`);
    expect(result).toMatchObject({ userId: user.id, enabled: false });
    const stored = await row(user.id);
    expect(stored.enabled).toBe(false);
    expect(stored.notValidBefore).toBe(result.notValidBefore);
    expect(stored.notValidBefore).toBeGreaterThanOrEqual(before);
    expect(stored.notValidBefore).toBeLessThanOrEqual(after);
    // The record is an admin event in the realm, committed with the change.
    const recorded = await eventsOf(realm.id);
    expect(recorded).toHaveLength(1);
    expect(recorded[0]).toMatchObject({
      type: 'urn:qauth:event:user.disabled:v1-rc.0',
      category: 'admin',
      actorType: 'operator_cli',
      subjectType: 'user',
      subjectId: user.id,
      data: {},
    });
  });

  it('enables the account again and keeps the time, and changes nothing on a repeated run', async () => {
    const { realm, user } = await seed('dis-2');
    await setUserEnabled(db(), { realm: 'dis-2', userId: user.id, enable: false });
    const disabledAt = (await row(user.id)).notValidBefore;

    const again = await setUserEnabled(db(), { realm: 'dis-2', userId: user.id, enable: false });
    expect(again).toEqual({
      status: 'unchanged',
      userId: user.id,
      enabled: false,
      notValidBefore: disabledAt,
    });

    const enabled = await setUserEnabled(db(), { realm: 'dis-2', userId: user.id, enable: true });
    expect(enabled).toEqual({
      status: 'enabled',
      userId: user.id,
      enabled: true,
      notValidBefore: disabledAt,
    });
    expect(await row(user.id)).toMatchObject({ enabled: true, notValidBefore: disabledAt });
    // One event per change, none for the run that changed nothing.
    expect((await eventsOf(realm.id)).map((event) => event.type)).toEqual([
      'urn:qauth:event:user.disabled:v1-rc.0',
      'urn:qauth:event:user.enabled:v1-rc.0',
    ]);
  });

  it('enables an account that was never disabled through the tool without inventing a time', async () => {
    const { realm, user } = await seed('dis-3', false);

    const result = await setUserEnabled(db(), { realm: 'dis-3', userId: user.id, enable: true });

    expect(result).toMatchObject({ status: 'enabled', enabled: true, notValidBefore: null });
    expect((await eventsOf(realm.id)).map((event) => event.type)).toEqual([
      'urn:qauth:event:user.enabled:v1-rc.0',
    ]);
  });

  it('reports an unknown realm, an unknown user and another realm’s user without writing', async () => {
    const { realm, user } = await seed('dis-4');
    const other = await seed('dis-5');

    await expect(
      setUserEnabled(db(), { realm: 'nope', userId: user.id, enable: false })
    ).resolves.toEqual({ status: 'realm_not_found' });
    await expect(
      setUserEnabled(db(), {
        realm: 'dis-4',
        userId: '0199f9a1-0000-7000-8000-0000000000ff',
        enable: false,
      })
    ).resolves.toEqual({ status: 'user_not_found' });
    await expect(
      setUserEnabled(db(), { realm: 'dis-5', userId: user.id, enable: false })
    ).resolves.toEqual({ status: 'user_not_found' });

    expect(await row(user.id)).toMatchObject({ enabled: true, notValidBefore: null });
    expect(await eventsOf(realm.id)).toHaveLength(0);
    expect(await eventsOf(other.realm.id)).toHaveLength(0);
  });
});
