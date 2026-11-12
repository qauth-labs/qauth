/**
 * The operator tool that disables and enables accounts, against real Postgres
 * (#748).
 *
 * These cases pin what the tool writes: the switch, the time the trigger
 * records on disable and keeps on enable, and one event per change in the
 * transaction of the change, with nothing for a run that changes nothing;
 * and what a disablement ends with it (#893): the account's live browser
 * sessions, each with a `user.session_revoked` event and the back-channel
 * logout notices of the clients it served, its refresh tokens and its
 * unredeemed authorization codes, and nothing of another account's.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  createRealmsRepository,
  createRefreshTokensRepository,
  createSessionsRepository,
  createUsersRepository,
} from '../lib/repositories';
import { type IntegrationDb, setupIntegrationDb } from '../lib/repositories/integration-setup';
import { users } from '../lib/schema/core';
import { events } from '../lib/schema/events';
import { DISABLED_ACCOUNT_REVOKE_REASON, setUserEnabled } from './user-enablement';

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
  describe('what a disablement ends with it (#893)', () => {
    const HOUR = 3_600_000;

    async function one(statement: ReturnType<typeof sql>): Promise<string> {
      const { rows } = await db().execute<{ id: string }>(statement);
      return rows[0].id;
    }

    /** A client of the realm, with a back-channel logout URI when given. */
    async function seedClient(realmId: string, logoutUri: string | null): Promise<string> {
      return one(sql`
        INSERT INTO oauth_clients
          (realm_id, client_id, client_secret_hash, name, redirect_uris, backchannel_logout_uri)
        VALUES (${realmId}, ${`client-${Math.random().toString(36).slice(2)}`}, 'h', 'app',
                '["https://app.example.com/cb"]', ${logoutUri})
        RETURNING id::text AS id`);
    }

    async function seedSession(realmId: string, userId: string): Promise<string> {
      const now = Date.now();
      const created = await createSessionsRepository(db()).create({
        realmId,
        userId,
        authTime: now,
        amr: ['pwd'],
        ipAddress: '192.0.2.1',
        userAgent: 'test-agent',
        expiresAt: now + HOUR,
      });
      return created.id;
    }

    /** A live refresh token of a family of its own. */
    async function seedToken(userId: string, oauthClientId: string): Promise<string> {
      const created = await createRefreshTokensRepository(db()).create({
        tokenHash: `hash-${Math.random().toString(36).slice(2)}`,
        userId,
        oauthClientId,
        familyId: crypto.randomUUID(),
        familyCreatedAt: Date.now(),
        familySessionExpiresAt: null,
        authTime: null,
        amr: null,
        scopes: ['openid'],
        expiresAt: Date.now() + HOUR,
      });
      return created.id;
    }

    /** An unredeemed authorization code, of no session. */
    async function seedCode(oauthClientId: string, userId: string): Promise<string> {
      return one(sql`
        INSERT INTO authorization_codes
          (code, oauth_client_id, user_id, redirect_uri, code_challenge, expires_at)
        VALUES (${`code-${Math.random().toString(36).slice(2)}`}, ${oauthClientId}, ${userId},
                'https://app.example.com/cb', 'c', ${Date.now() + 60_000})
        RETURNING id::text AS id`);
    }

    async function sessionState(id: string) {
      const { rows } = await db().execute<{
        revoked_reason: string | null;
        clients: number;
      }>(sql`
        SELECT s.revoked_reason,
               (SELECT count(*)::int FROM session_clients c WHERE c.session_id = s.id) AS clients
        FROM sessions s WHERE s.id = ${id}`);
      return rows[0];
    }

    async function tokenState(id: string) {
      const { rows } = await db().execute<{ revoked: boolean; revoked_reason: string | null }>(
        sql`SELECT revoked, revoked_reason FROM refresh_tokens WHERE id = ${id}`
      );
      return rows[0];
    }

    async function codeUsed(id: string): Promise<boolean> {
      const { rows } = await db().execute<{ used: boolean }>(
        sql`SELECT used FROM authorization_codes WHERE id = ${id}`
      );
      return rows[0].used;
    }

    it('ends the sessions, refresh tokens and codes in the disabling transaction, with one user.session_revoked per session', async () => {
      const { realm, user } = await seed('dis-end-1');
      const other = await createUsersRepository(db()).create(
        { realmId: realm.id },
        testPrimaryCredential()
      );
      const notified = await seedClient(realm.id, 'https://app.example.com/logout');
      const quiet = await seedClient(realm.id, null);
      const sessions = createSessionsRepository(db());
      const first = await seedSession(realm.id, user.id);
      const second = await seedSession(realm.id, user.id);
      const signedOut = await seedSession(realm.id, user.id);
      await sessions.revoke(realm.id, signedOut, 'sign_out');
      const othersSession = await seedSession(realm.id, other.id);
      await db().transaction(async (tx) => {
        await sessions.recordClient(realm.id, first, notified, tx);
        await sessions.recordClient(realm.id, second, quiet, tx);
        await sessions.recordClient(realm.id, othersSession, notified, tx);
      });
      const token = await seedToken(user.id, quiet);
      const othersToken = await seedToken(other.id, quiet);
      const code = await seedCode(quiet, user.id);
      const othersCode = await seedCode(quiet, other.id);

      const result = await setUserEnabled(db(), {
        realm: 'dis-end-1',
        userId: user.id,
        enable: false,
      });

      expect(result).toMatchObject({ status: 'disabled', enabled: false, endedSessions: 2 });
      // The live sessions end as the auth server ends a disabled account's
      // session it meets, and hold no client any more; one that ended before
      // keeps its own reason.
      expect(await sessionState(first)).toEqual({ revoked_reason: 'admin', clients: 0 });
      expect(await sessionState(second)).toEqual({ revoked_reason: 'admin', clients: 0 });
      expect(await sessionState(signedOut)).toEqual({ revoked_reason: 'sign_out', clients: 0 });
      expect(await tokenState(token)).toEqual({
        revoked: true,
        revoked_reason: DISABLED_ACCOUNT_REVOKE_REASON,
      });
      expect(await codeUsed(code)).toBe(true);
      // Another account of the realm keeps what it holds.
      expect(await sessionState(othersSession)).toEqual({ revoked_reason: null, clients: 1 });
      expect(await tokenState(othersToken)).toEqual({ revoked: false, revoked_reason: null });
      expect(await codeUsed(othersCode)).toBe(false);

      // The disablement first, then the logout notice of the one client with
      // a logout URI, then a session_revoked naming each ended session: all
      // admin events but the notice, by the operator, about the user.
      const recorded = (await eventsOf(realm.id)).map((event) => ({
        type: event.type,
        category: event.category,
        actorType: event.actorType,
        subjectId: event.subjectId,
        clientId: event.clientId,
        data: event.data,
      }));
      const [first0, second0] = [first, second].sort();
      expect(recorded).toEqual([
        {
          type: 'urn:qauth:event:user.disabled:v1-rc.0',
          category: 'admin',
          actorType: 'operator_cli',
          subjectId: user.id,
          clientId: null,
          data: {},
        },
        {
          type: 'urn:qauth:event:user.client_session_ended:v1-rc.0',
          category: 'user',
          actorType: null,
          subjectId: user.id,
          clientId: expect.any(String),
          data: { sid: first, reason: 'admin' },
        },
        ...[first0, second0].map((sid) => ({
          type: 'urn:qauth:event:user.session_revoked:v1-rc.0',
          category: 'admin',
          actorType: 'operator_cli',
          subjectId: user.id,
          clientId: null,
          data: { sid, reason: 'account_disabled' },
        })),
      ]);
    });

    it('ends nothing when it enables the account, nor on a run that changes nothing', async () => {
      const { realm, user } = await seed('dis-end-2', false);
      const client = await seedClient(realm.id, null);
      const session = await seedSession(realm.id, user.id);
      const token = await seedToken(user.id, client);
      const code = await seedCode(client, user.id);

      expect(
        await setUserEnabled(db(), { realm: 'dis-end-2', userId: user.id, enable: false })
      ).toMatchObject({ status: 'unchanged' });
      expect(
        await setUserEnabled(db(), { realm: 'dis-end-2', userId: user.id, enable: true })
      ).toMatchObject({ status: 'enabled' });

      expect(await sessionState(session)).toEqual({ revoked_reason: null, clients: 0 });
      expect(await tokenState(token)).toEqual({ revoked: false, revoked_reason: null });
      expect(await codeUsed(code)).toBe(false);
      expect((await eventsOf(realm.id)).map((event) => event.type)).toEqual([
        'urn:qauth:event:user.enabled:v1-rc.0',
      ]);
    });
  });
});
