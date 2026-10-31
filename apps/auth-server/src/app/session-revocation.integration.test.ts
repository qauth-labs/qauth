import { cachePlugin } from '@qauth-labs/fastify-plugin-cache';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import {
  sessionCacheKey,
  type SessionsEndedNotice,
  sessionServicePlugin,
} from '@qauth-labs/fastify-plugin-sessions';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import Fastify, { type FastifyBaseLogger, type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { type E2eInfrastructure, startE2eInfrastructure } from '../testing/e2e-harness';
import { createManualClock } from '../testing/manual-clock';
import { createSessionExpiryJob } from './jobs/session-expiry';
import { createSessionPurgeJob } from './jobs/session-purge';
import { jobsPlugin } from './plugins/jobs';
import { metricsPlugin } from './plugins/metrics';

/**
 * SESSION LISTS AND REVOCATIONS ON A REAL POSTGRES AND REDIS (ADR-019
 * Decisions 3 and 4, issue #550).
 *
 * Each "node" is a Fastify instance with its own pool and Redis client, and
 * the database, cache, metrics and session service plugins as the
 * auth-server registers them: the same production adapters from the service
 * down to the SQL. A and B share Redis; C has a Redis database of its own
 * and a one-second cache time, as a node that never sees the other nodes'
 * tombstones.
 *
 * What it proves, one acceptance criterion of #550 per block: the list of a
 * user's sessions, the single revocation and its second call, sign out
 * everywhere (but one session, or only older ones), a realm of 10,000
 * sessions ended in batches of short transactions, the cache on this node
 * and on others, the listener hook, the purge job, and refresh-token
 * families left as they were.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** The actor of the suite's user revocations. */
const USER_ACTOR = { type: 'user', id: 'test-user' } as const;
const ADMIN_ACTOR = { type: 'user', id: 'test-admin' } as const;

interface NodeSettings {
  readonly databaseUrl: string;
  readonly redisUrl: string;
  /** Seconds; the service's default (60) when absent. */
  readonly cacheTtlSeconds?: number;
}

/** A node, as the auth-server builds the service. */
async function startNode(
  settings: NodeSettings,
  beforeReady?: (app: FastifyInstance) => Promise<void>,
  logLines?: Array<Record<string, unknown>>
): Promise<FastifyInstance> {
  const app = Fastify({
    logger:
      logLines === undefined
        ? false
        : {
            level: 'info',
            stream: {
              write(chunk: string) {
                logLines.push(JSON.parse(chunk) as Record<string, unknown>);
              },
            },
          },
  });
  await app.register(databasePlugin, {
    config: {
      connectionString: settings.databaseUrl,
      pool: { max: 20, connectionTimeoutMillis: 10_000 },
    },
  });
  await app.register(cachePlugin, {
    config: {
      url: settings.redisUrl,
      maxRetriesPerRequest: 3,
      connectTimeout: 10_000,
      commandTimeout: 5_000,
      lazyConnect: true,
    },
  });
  await app.register(metricsPlugin);
  await app.register(sessionServicePlugin, {
    settings: {
      defaultMaxLifespanSeconds: 86_400,
      lastSeenIntervalSeconds: 60,
      ...(settings.cacheTtlSeconds === undefined
        ? {}
        : { cacheTtlSeconds: settings.cacheTtlSeconds }),
    },
  });
  await beforeReady?.(app);
  await app.ready();
  return app;
}

async function stopNode(app: FastifyInstance | undefined): Promise<void> {
  if (app === undefined) return;
  app.redis.disconnect();
  await app.close().catch(() => undefined);
}

function random(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2)}`;
}

describe('session lists and revocations on a real Postgres and Redis (#550)', () => {
  let dockerUp = false;
  let infra: E2eInfrastructure | undefined;
  let nodeA: FastifyInstance | undefined;
  let nodeB: FastifyInstance | undefined;
  let nodeC: FastifyInstance | undefined;
  /** What each node's listener heard, by node. */
  const heard: Record<'a' | 'b' | 'c', SessionsEndedNotice[]> = { a: [], b: [], c: [] };

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    const shared = {
      databaseUrl: infra.postgres.connectionString,
      redisUrl: infra.redis.connectionUrl,
    };
    nodeA = await startNode(shared);
    nodeB = await startNode(shared);
    nodeC = await startNode({
      ...shared,
      redisUrl: infra.redis.connectionUrl.replace(/\/0$/, '/1'),
      cacheTtlSeconds: 1,
    });
    for (const [name, node] of [
      ['a', nodeA],
      ['b', nodeB],
      ['c', nodeC],
    ] as const) {
      node.sessionService.onSessionsEnded((notice) => {
        heard[name].push(notice);
      });
    }
  }, 240_000);

  afterAll(async () => {
    await Promise.all([stopNode(nodeA), stopNode(nodeB), stopNode(nodeC)]);
    await infra?.teardown();
  });

  beforeEach(() => {
    heard.a = [];
    heard.b = [];
    heard.c = [];
  });

  function nodes(): { a: FastifyInstance; b: FastifyInstance; c: FastifyInstance } {
    if (!nodeA || !nodeB || !nodeC) throw new Error('nodes not started');
    return { a: nodeA, b: nodeB, c: nodeC };
  }

  async function one<T = string>(sql: string, params: unknown[] = []): Promise<T> {
    const { rows } = await nodes().a.dbPool.query(sql, params);
    return rows[0].id as T;
  }

  async function seedRealm(lifetimes: { idleTimeout?: number } = {}): Promise<string> {
    return one(`INSERT INTO realms (name, sso_idle_timeout) VALUES ($1, $2) RETURNING id`, [
      random('realm'),
      lifetimes.idleTimeout ?? null,
    ]);
  }

  async function seedUser(realmId: string): Promise<string> {
    return one(`INSERT INTO users (realm_id) VALUES ($1) RETURNING id`, [realmId]);
  }

  async function seedClient(realmId: string, name = 'app'): Promise<string> {
    return one(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris)
       VALUES ($1, $2, 'h', $3, '["https://app.example.com/cb"]') RETURNING id`,
      [realmId, random('client'), name]
    );
  }

  /** Record that a session served a client, as the code mint does (#549). */
  async function served(sid: string, oauthClientId: string): Promise<void> {
    await nodes().a.dbPool.query(
      `INSERT INTO session_clients (session_id, oauth_client_id) VALUES ($1, $2)`,
      [sid, oauthClientId]
    );
  }

  /** A sign-in through the service, one millisecond after the previous one. */
  async function signIn(
    node: FastifyInstance,
    realmId: string,
    userId: string,
    issuedAt?: number
  ): Promise<string> {
    const { sid } = await node.sessionService.create({
      realmId,
      userId,
      authTime: Date.now(),
      amr: ['pwd'],
      ipAddress: '192.0.2.44',
      userAgent: 'Browser/44',
      ...(issuedAt === undefined ? {} : { issuedAt }),
    });
    await new Promise((resolve) => setTimeout(resolve, 2));
    return sid;
  }

  async function revokedReason(sid: string): Promise<string | null> {
    const { rows } = await nodes().a.dbPool.query(
      `SELECT revoked_reason FROM sessions WHERE id = $1`,
      [sid]
    );
    return rows[0].revoked_reason as string | null;
  }

  /** Every refresh token of `userId`, as stored. */
  async function refreshTokens(userId: string): Promise<unknown[]> {
    const { rows } = await nodes().a.dbPool.query(
      `SELECT * FROM refresh_tokens WHERE user_id = $1 ORDER BY id`,
      [userId]
    );
    return rows;
  }

  /** A live refresh-token family of the user at the client: two rotated tokens. */
  async function seedRefreshFamily(userId: string, oauthClientId: string): Promise<void> {
    const familyId = await one(`SELECT gen_random_uuid() AS id`);
    const now = Date.now();
    for (const revoked of [true, false]) {
      await nodes().a.dbPool.query(
        `INSERT INTO refresh_tokens
           (token_hash, user_id, oauth_client_id, family_id, family_created_at,
            family_session_expires_at, expires_at, revoked, revoked_at, revoked_reason)
         VALUES (md5(random()::text) || md5(random()::text), $1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          userId,
          oauthClientId,
          familyId,
          now,
          now + DAY,
          now + DAY,
          revoked,
          revoked ? now : null,
          revoked ? 'rotated' : null,
        ]
      );
    }
  }

  /** Wait until `read` answers null, for at most `limitMs`; the time it took. */
  async function absentWithin(read: () => Promise<unknown>, limitMs: number): Promise<number> {
    const started = Date.now();
    while (Date.now() - started < limitMs) {
      if ((await read()) === null) return Date.now() - started;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return Number.POSITIVE_INFINITY;
  }

  it('lists the user’s sessions with their clients, newest first, and never another realm’s', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a, b } = nodes();
    const realm = await seedRealm();
    const other = await seedRealm();
    const user = await seedUser(realm);
    const app = await seedClient(realm, 'App');
    const portal = await seedClient(realm, 'Portal');
    const first = await signIn(a, realm, user);
    const second = await signIn(b, realm, user);
    const third = await signIn(a, realm, user);
    await served(first, app);
    await served(first, portal);
    await served(third, app);
    // The same user id named in another realm, and another realm's session.
    const otherUser = await seedUser(other);
    await signIn(a, other, otherUser);

    const page = await b.sessionService.listForUser({ realmId: realm, userId: user });

    expect(page.nextCursor).toBeNull();
    expect(page.items.map((item) => item.sid)).toEqual([third, second, first]);
    expect(page.items[2]).toMatchObject({
      realmId: realm,
      userId: user,
      ipAddress: '192.0.2.44',
      userAgent: 'Browser/44',
      authTime: expect.any(Number),
      lastSeenAt: expect.any(Number),
      state: 'live',
    });
    expect(page.items[2].clients.map((client) => client.name).sort()).toEqual(['App', 'Portal']);
    expect(page.items[0].clients.map((client) => client.oauthClientId)).toEqual([app]);
    expect(page.items[1].clients).toEqual([]);

    // Paging gives the same order, and a cursor of this list is refused by
    // another realm's.
    const one1 = await a.sessionService.listForUser({
      realmId: realm,
      userId: user,
      page: { limit: 2 },
    });
    const rest = await a.sessionService.listForUser({
      realmId: realm,
      userId: user,
      page: { limit: 2, cursor: one1.nextCursor ?? '' },
    });
    expect([...one1.items, ...rest.items].map((item) => item.sid)).toEqual([third, second, first]);
    expect((await a.sessionService.listForUser({ realmId: other, userId: user })).items).toEqual(
      []
    );
    await expect(
      a.sessionService.listForUser({
        realmId: other,
        userId: user,
        page: { cursor: one1.nextCursor ?? '' },
      })
    ).rejects.toThrow('belongs to another list');

    // The client's list holds the sessions that served it.
    expect(
      (await a.sessionService.listForClient({ realmId: realm, oauthClientId: app })).items.map(
        (item) => item.sid
      )
    ).toEqual([third, first]);
  });

  it('revoke ends one session; a second call changes nothing and reports it', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a, b } = nodes();
    const realm = await seedRealm();
    const user = await seedUser(realm);
    const app = await seedClient(realm);
    const sid = await signIn(a, realm, user);
    const other = await signIn(a, realm, user);
    await served(sid, app);

    const first = await a.sessionService.revoke({
      realmId: realm,
      userId: user,
      sid,
      reason: 'sign_out',
      actor: USER_ACTOR,
    });
    const { rows: before } = await a.dbPool.query(`SELECT * FROM sessions WHERE id = $1`, [sid]);
    const second = await b.sessionService.revoke({
      realmId: realm,
      userId: user,
      sid,
      reason: 'admin',
      actor: ADMIN_ACTOR,
    });
    const { rows: after } = await a.dbPool.query(`SELECT * FROM sessions WHERE id = $1`, [sid]);

    expect(first).toMatchObject({
      outcome: 'ended',
      session: { id: sid, revokedReason: 'sign_out' },
      clients: [expect.objectContaining({ oauthClientId: app, name: 'app' })],
    });
    expect(second).toMatchObject({
      outcome: 'already_ended',
      session: { id: sid, revokedReason: 'sign_out' },
    });
    expect(after).toEqual(before);
    expect(await revokedReason(other)).toBeNull();
    expect(heard.a.flatMap((notice) => notice.sessions.map((s) => s.session.id))).toEqual([sid]);
    expect(heard.b).toEqual([]);
  });

  it('revokeAllForUser keeps the excepted session, and with createdBefore keeps the newer ones', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a } = nodes();
    const realm = await seedRealm();
    const user = await seedUser(realm);
    const bystander = await seedUser(realm);
    const older = await signIn(a, realm, user, Date.now() - HOUR);
    const current = await signIn(a, realm, user);
    const another = await signIn(a, realm, user);
    const theirs = await signIn(a, realm, bystander);

    const everywhereElse = await a.sessionService.revokeAllForUser({
      realmId: realm,
      userId: user,
      exceptSid: current,
      reason: 'sign_out_everywhere',
      actor: USER_ACTOR,
    });

    expect(everywhereElse.sessions.map((ended) => ended.session.id).sort()).toEqual(
      [older, another].sort()
    );
    expect(await revokedReason(current)).toBeNull();
    expect(await revokedReason(theirs)).toBeNull();

    // A password reset: the sessions created before it end, a sign-in after
    // it stays.
    const resetAt = Date.now();
    await new Promise((resolve) => setTimeout(resolve, 5));
    const afterReset = await signIn(a, realm, user);
    const reset = await a.sessionService.revokeAllForUser({
      realmId: realm,
      userId: user,
      createdBefore: resetAt,
      reason: 'reset',
      actor: USER_ACTOR,
    });

    expect(reset.sessions.map((ended) => ended.session.id)).toEqual([current]);
    expect(await revokedReason(current)).toBe('reset');
    expect(await revokedReason(afterReset)).toBeNull();
    // The sessions ended by the first call keep their first reason.
    expect(await revokedReason(older)).toBe('sign_out_everywhere');
  });

  it('revokeAllForRealm ends 10,000 sessions in batches, each its own short transaction', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a } = nodes();
    const realm = await seedRealm();
    const otherRealm = await seedRealm();
    const users: string[] = [];
    for (let i = 0; i < 20; i++) users.push(await seedUser(realm));
    const now = Date.now();
    await a.dbPool.query(
      `INSERT INTO sessions (realm_id, user_id, auth_time, expires_at, created_at, last_seen_at)
       SELECT $1, ($2::uuid[])[1 + (n % 20)], $3, $4, $3, $3
       FROM generate_series(1, 10000) AS n`,
      [realm, users, now - MINUTE, now + DAY]
    );
    const elsewhere = await signIn(a, otherRealm, await seedUser(otherRealm));

    const result = await a.sessionService.revokeAllForRealm({
      realmId: realm,
      reason: 'key_retired',
      actor: { type: 'operator_cli', id: 'root' },
    });

    expect(result).toEqual({ ended: 10_000, batches: 20 });
    // Each batch's UPDATE ran in a transaction of its own: the rows carry 20
    // different transaction ids, none for more than one batch of 500.
    const { rows } = await a.dbPool.query<{ transactions: number; largest: number }>(
      `SELECT count(*)::int AS transactions, max(n)::int AS largest
       FROM (SELECT xmin::text, count(*) AS n FROM sessions
             WHERE realm_id = $1 AND revoked_reason = 'key_retired' GROUP BY xmin::text) t`,
      [realm]
    );
    expect(rows[0]).toEqual({ transactions: 20, largest: 500 });
    const { rows: left } = await a.dbPool.query(
      `SELECT count(*)::int AS n FROM sessions WHERE realm_id = $1 AND revoked_at IS NULL`,
      [realm]
    );
    expect(left[0].n).toBe(0);
    expect(await revokedReason(elsewhere)).toBeNull();
    // The listeners heard each session once, batch by batch.
    const sids = heard.a.flatMap((notice) => notice.sessions.map((s) => s.session.id));
    expect(heard.a).toHaveLength(20);
    expect(sids).toHaveLength(10_000);
    expect(new Set(sids).size).toBe(10_000);
  }, 120_000);

  it('an ended session is absent from the cache on the same node at once, and on others within the cache time', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a, b, c } = nodes();
    const realm = await seedRealm();
    const user = await seedUser(realm);
    const sids = [await signIn(a, realm, user), await signIn(a, realm, user)];
    // Every node holds both sessions in its cache.
    for (const node of [a, b, c]) {
      for (const sid of sids) {
        expect(await node.sessionService.get({ realmId: realm, sid })).not.toBeNull();
      }
    }

    await a.sessionService.revokeAllForUser({
      realmId: realm,
      userId: user,
      reason: 'sign_out_everywhere',
      actor: USER_ACTOR,
    });

    for (const sid of sids) {
      // Same node, and a node sharing its Redis: at once.
      expect(await a.sessionService.get({ realmId: realm, sid })).toBeNull();
      expect(await b.sessionService.get({ realmId: realm, sid })).toBeNull();
      expect(await a.redis.exists(sessionCacheKey(realm, sid))).toBe(0);
      expect(await a.redis.exists(`${sessionCacheKey(realm, sid)}:revoked`)).toBe(1);
    }
    // A node whose cache never sees the tombstone: within its cache time (1 s).
    for (const sid of sids) {
      expect(
        await absentWithin(() => c.sessionService.get({ realmId: realm, sid }), 3_000)
      ).toBeLessThanOrEqual(1_500);
    }
  });

  it('the listener hook receives each ended session once, with its clients, whichever node ends it', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a, b } = nodes();
    const realm = await seedRealm();
    const user = await seedUser(realm);
    const app = await seedClient(realm);
    const sids: string[] = [];
    for (let i = 0; i < 12; i++) sids.push(await signIn(a, realm, user));
    for (const sid of sids) await served(sid, app);

    // Two nodes end the same sessions at once: one by one, and all at once.
    await Promise.all([
      ...sids.map((sid, i) =>
        (i % 2 === 0 ? a : b).sessionService.revoke({
          realmId: realm,
          userId: user,
          sid,
          reason: 'admin',
          actor: ADMIN_ACTOR,
        })
      ),
      a.sessionService.revokeAllForUser({
        realmId: realm,
        userId: user,
        reason: 'sign_out_everywhere',
        actor: USER_ACTOR,
      }),
      b.sessionService.revokeAllForRealm({
        realmId: realm,
        reason: 'key_retired',
        actor: { type: 'system' },
        batchSize: 5,
      }),
    ]);

    const notified = [...heard.a, ...heard.b].flatMap((notice) => notice.sessions);
    expect(notified.map((ended) => ended.session.id).sort()).toEqual([...sids].sort());
    for (const ended of notified) {
      expect(ended.clients.map((client) => client.oauthClientId)).toEqual([app]);
      // The notice's reason is the one stored: the call that ended it.
      expect(await revokedReason(ended.session.id)).toBe(ended.session.revokedReason);
    }
    const { rows } = await a.dbPool.query(
      `SELECT count(*)::int AS n FROM session_clients WHERE session_id = ANY($1::uuid[])`,
      [sids]
    );
    expect(rows[0].n).toBe(0);
  });

  it('the purge job ends lapsed sessions and deletes only rows older than the retention, leaving active sessions', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a } = nodes();
    const realm = await seedRealm({ idleTimeout: 600 });
    const user = await seedUser(realm);
    const app = await seedClient(realm);
    const now = Date.now();
    const live = await signIn(a, realm, user);
    const idle = await signIn(a, realm, user);
    await a.dbPool.query(`UPDATE sessions SET last_seen_at = $2 WHERE id = $1`, [
      idle,
      now - 11 * MINUTE,
    ]);
    await served(idle, app);
    const recentlyEnded = await signIn(a, realm, user);
    await a.sessionService.revoke({
      realmId: realm,
      userId: user,
      sid: recentlyEnded,
      reason: 'sign_out',
      actor: USER_ACTOR,
    });
    const longEnded = await signIn(a, realm, user);
    await a.sessionService.revoke({
      realmId: realm,
      userId: user,
      sid: longEnded,
      reason: 'sign_out',
      actor: USER_ACTOR,
    });
    await a.dbPool.query(`UPDATE sessions SET revoked_at = $2 WHERE id = $1`, [
      longEnded,
      now - 31 * DAY,
    ]);
    const longExpired = await one(
      `INSERT INTO sessions (realm_id, user_id, auth_time, expires_at, created_at, last_seen_at)
       VALUES ($1, $2, $3, $4, $3, $3) RETURNING id`,
      [realm, user, now - 32 * DAY, now - 31 * DAY]
    );
    // In use until a minute before its absolute end: it expired, not idled.
    const recentlyExpired = await one(
      `INSERT INTO sessions (realm_id, user_id, auth_time, expires_at, created_at, last_seen_at)
       VALUES ($1, $2, $3, $4, $3, $5) RETURNING id`,
      [realm, user, now - 2 * DAY, now - DAY, now - DAY - MINUTE]
    );
    const info: unknown[] = [];
    const context = {
      signal: new AbortController().signal,
      now: () => Date.now(),
      log: { info: (fields: unknown) => info.push(fields) } as unknown as FastifyBaseLogger,
    };

    // As the runner does: the expiry job marks, the purge job deletes.
    await createSessionExpiryJob({ sessions: a.sessionService }).run(context);
    await createSessionPurgeJob({ sessions: a.sessionService, retentionDays: 30 }).run(context);

    const { rows } = await a.dbPool.query<{ id: string; revoked_reason: string | null }>(
      `SELECT id, revoked_reason FROM sessions WHERE realm_id = $1`,
      [realm]
    );
    const left = new Map(rows.map((row) => [row.id, row.revoked_reason]));
    expect([...left.keys()].sort()).toEqual([live, idle, recentlyEnded, recentlyExpired].sort());
    expect(left.get(live)).toBeNull();
    expect(left.get(idle)).toBe('idle');
    expect(left.get(recentlyExpired)).toBe('expired');
    expect(left.has(longEnded)).toBe(false);
    expect(left.has(longExpired)).toBe(false);
    expect(await a.sessionService.get({ realmId: realm, sid: live })).not.toBeNull();
    // The idle session's end reached the listeners, with its client.
    const lapsed = heard.a.filter((notice) => notice.actor.type === 'system');
    const idleNotice = lapsed.find((notice) => notice.reason === 'idle');
    expect(idleNotice?.sessions.map((s) => [s.session.id, s.clients.length])).toContainEqual([
      idle,
      1,
    ]);
    expect(info).toContainEqual({ ended: expect.any(Number) });
    expect(info).toContainEqual({ deleted: expect.any(Number) });
  });

  it('runs the session expiry and purge jobs on the job runner of a web node', async (ctx) => {
    if (!dockerUp || !infra) return ctx.skip();
    const { a } = nodes();
    const realm = await seedRealm({ idleTimeout: 600 });
    const user = await seedUser(realm);
    const idle = await signIn(a, realm, user);
    await a.dbPool.query(`UPDATE sessions SET last_seen_at = $2 WHERE id = $1`, [
      idle,
      Date.now() - 11 * MINUTE,
    ]);
    const clock = createManualClock();
    const lines: Array<Record<string, unknown>> = [];
    // The server's own job list for the `web` role, its lock and its settings:
    // only the clock is injected.
    const web = await startNode(
      { databaseUrl: infra.postgres.connectionString, redisUrl: infra.redis.connectionUrl },
      async (app) => {
        await app.register(jobsPlugin, {
          roles: ['web'],
          clock,
          random: () => 0,
          sessionRetentionDays: 30,
        });
      },
      lines
    );
    try {
      // One slot at a time: a run takes its lock in real time, and a clock
      // moved past its slot first would make it skip the run.
      const logged = (msg: string) =>
        lines.find((line) => line.msg === msg)?.job as string | undefined;
      await clock.advanceTo(5 * 60_000);
      await vi.waitFor(() => expect(logged('lapsed sessions ended')).toBe('session-expiry'), {
        timeout: 15_000,
        interval: 50,
      });
      await clock.advanceTo(60 * 60_000);
      await vi.waitFor(() => expect(logged('old sessions purged')).toBe('session-purge'), {
        timeout: 15_000,
        interval: 50,
      });
      expect(await revokedReason(idle)).toBe('idle');
    } finally {
      await stopNode(web);
    }
  });

  it('leaves refresh-token families as they were after every one of these calls', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a } = nodes();
    const realm = await seedRealm({ idleTimeout: 600 });
    const user = await seedUser(realm);
    const app = await seedClient(realm);
    await seedRefreshFamily(user, app);
    await seedRefreshFamily(user, app);
    const before = await refreshTokens(user);
    expect(before).toHaveLength(4);
    const sids: string[] = [];
    for (let i = 0; i < 6; i++) sids.push(await signIn(a, realm, user));
    for (const sid of sids) await served(sid, app);

    await a.sessionService.revoke({
      realmId: realm,
      userId: user,
      sid: sids[0],
      reason: 'sign_out',
      actor: USER_ACTOR,
    });
    await a.sessionService.revokeAllForUser({
      realmId: realm,
      userId: user,
      exceptSid: sids[5],
      createdBefore: Date.now() - 1,
      reason: 'sign_out_everywhere',
      actor: USER_ACTOR,
    });
    await a.sessionService.revokeAllForRealm({
      realmId: realm,
      reason: 'key_retired',
      actor: { type: 'system' },
    });
    await a.sessionService.endLapsed();
    await a.sessionService.purge({ endedBefore: Date.now() + DAY });

    expect(await refreshTokens(user)).toEqual(before);
  });
});
