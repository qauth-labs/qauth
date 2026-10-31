import { CACHE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-cache';
import { DATABASE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-db';
import Fastify, { type FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { describe, expect, it, vi } from 'vitest';

import { repositorySessionStore, sessionServicePlugin } from './fastify-plugin-sessions';

const REALM = '0199a000-0000-7000-8000-00000000000a';
const SID = '0199a000-0000-7000-8000-0000000000c1';

type Repositories = Parameters<typeof repositorySessionStore>[0];

const ROW = {
  id: SID,
  realmId: REALM,
  userId: '0199a000-0000-7000-8000-0000000000aa',
  authTime: 1,
  amr: ['pwd'],
  assuranceLevel: null,
  ipAddress: null,
  userAgent: null,
  expiresAt: 10,
  revokedAt: null,
  revokedReason: null,
  createdAt: 1,
  lastSeenAt: 1,
};

/** A registry row as the repository returns it, with its client's identity. */
const CLIENT_ROW = {
  sessionId: SID,
  oauthClientId: 'client-row',
  firstSeenAt: 1,
  clientId: 'app',
  clientName: 'App',
};

/** The same client as the service sees it. */
const CLIENT = { oauthClientId: 'client-row', clientId: 'app', name: 'App', firstSeenAt: 1 };

/** Stand-in repositories: only the methods the store calls. */
function repositories(
  realm: { ssoMaxLifespan: number | null; ssoIdleTimeout: number | null } | undefined
) {
  const sessions = {
    create: vi.fn(async () => ROW),
    findById: vi.fn(async () => ROW),
    updateLastSeen: vi.fn(async () => true),
    revoke: vi.fn(async () => ({ session: ROW, clients: [CLIENT_ROW] })),
    revokeForUser: vi.fn(async () => [{ session: ROW, clients: [CLIENT_ROW] }]),
    revokeRealmBatch: vi.fn(async () => ({
      ended: [{ session: ROW, clients: [CLIENT_ROW] }],
      last: SID,
      selected: 1,
    })),
    revokeLapsedBatch: vi.fn(async () => ({ ended: [], last: null, selected: 0 })),
    listForUser: vi.fn(async () => [{ session: ROW, clients: [CLIENT_ROW] }]),
    listForClient: vi.fn(async () => [{ session: ROW, clients: [] }]),
    deleteEnded: vi.fn(async () => ({ deleted: 2, last: SID, selected: 2 })),
  };
  const realms = { findById: vi.fn(async () => realm) };
  return { sessions, realms, repos: { sessions, realms } as unknown as Repositories };
}

describe('repositorySessionStore', () => {
  it('reads the realm’s lifetimes from sso_max_lifespan and sso_idle_timeout', async () => {
    const { repos, realms } = repositories({ ssoMaxLifespan: 3600, ssoIdleTimeout: 600 });

    expect(await repositorySessionStore(repos).findRealmLifetimes(REALM)).toEqual({
      maxLifespanSeconds: 3600,
      idleTimeoutSeconds: 600,
    });
    expect(realms.findById).toHaveBeenCalledWith(REALM);
  });

  it('reads unset lifetimes as null, and no realm as undefined', async () => {
    expect(
      await repositorySessionStore(
        repositories({ ssoMaxLifespan: null, ssoIdleTimeout: null }).repos
      ).findRealmLifetimes(REALM)
    ).toEqual({ maxLifespanSeconds: null, idleTimeoutSeconds: null });
    expect(
      await repositorySessionStore(repositories(undefined).repos).findRealmLifetimes(REALM)
    ).toBeUndefined();
  });

  it('finds a session with its realm’s lifetimes, by realm and id', async () => {
    const { repos, sessions } = repositories({ ssoMaxLifespan: null, ssoIdleTimeout: 600 });

    expect(await repositorySessionStore(repos).find(REALM, SID)).toEqual({
      session: ROW,
      lifetimes: { maxLifespanSeconds: null, idleTimeoutSeconds: 600 },
    });
    expect(sessions.findById).toHaveBeenCalledWith(REALM, SID);
  });

  it('finds nothing when the session or the realm is missing', async () => {
    const missingSession = repositories({ ssoMaxLifespan: null, ssoIdleTimeout: null });
    missingSession.sessions.findById.mockResolvedValueOnce(undefined as never);
    expect(await repositorySessionStore(missingSession.repos).find(REALM, SID)).toBeUndefined();

    expect(await repositorySessionStore(repositories(undefined).repos).find(REALM, SID)).toBe(
      undefined
    );
  });

  it('passes the write interval to the conditional update, and the reason to the revocation', async () => {
    const { repos, sessions } = repositories({ ssoMaxLifespan: null, ssoIdleTimeout: null });
    const store = repositorySessionStore(repos);

    expect(await store.touchLastSeen(REALM, SID, 60_000)).toBe(true);
    expect(sessions.updateLastSeen).toHaveBeenCalledWith(REALM, SID, { minIntervalMs: 60_000 });

    expect(await store.revoke(REALM, SID, 'sign_out')).toEqual({ session: ROW, clients: [CLIENT] });
    expect(sessions.revoke).toHaveBeenCalledWith(REALM, SID, 'sign_out', {});
    await store.revoke(REALM, SID, 'sign_out', { userId: ROW.userId });
    expect(sessions.revoke).toHaveBeenLastCalledWith(REALM, SID, 'sign_out', {
      userId: ROW.userId,
    });
    sessions.revoke.mockResolvedValueOnce(undefined as never);
    expect(await store.revoke(REALM, SID, 'sign_out')).toBeUndefined();
  });

  it('passes a user revocation’s filter to the repository and keeps the clients each session served', async () => {
    const { repos, sessions } = repositories({ ssoMaxLifespan: null, ssoIdleTimeout: null });
    const store = repositorySessionStore(repos);

    expect(
      await store.revokeForUser(REALM, ROW.userId, 'reset', { exceptSid: SID, createdBefore: 5 })
    ).toEqual([{ session: ROW, clients: [CLIENT] }]);
    expect(sessions.revokeForUser).toHaveBeenCalledWith(REALM, ROW.userId, 'reset', {
      exceptId: SID,
      createdBefore: 5,
    });
    await store.revokeForUser(REALM, ROW.userId, 'sign_out_everywhere', {});
    expect(sessions.revokeForUser).toHaveBeenLastCalledWith(
      REALM,
      ROW.userId,
      'sign_out_everywhere',
      {}
    );
  });

  it('passes a batch’s place and bounds to the repository', async () => {
    const { repos, sessions } = repositories({ ssoMaxLifespan: null, ssoIdleTimeout: null });
    const store = repositorySessionStore(repos);

    expect(
      await store.revokeRealmBatch(REALM, 'key_retired', {
        after: null,
        createdThrough: 9,
        limit: 500,
      })
    ).toEqual({ ended: [{ session: ROW, clients: [CLIENT] }], last: SID, selected: 1 });
    expect(sessions.revokeRealmBatch).toHaveBeenCalledWith(REALM, 'key_retired', {
      createdThrough: 9,
      limit: 500,
    });
    await store.revokeRealmBatch(REALM, 'admin', {
      after: SID,
      createdThrough: 9,
      activeSince: 3,
      limit: 2,
    });
    expect(sessions.revokeRealmBatch).toHaveBeenLastCalledWith(REALM, 'admin', {
      after: SID,
      createdThrough: 9,
      activeSince: 3,
      limit: 2,
    });

    await store.revokeLapsedBatch({
      now: 7,
      defaultMaxLifespanSeconds: 86_400,
      after: SID,
      limit: 10,
    });
    // SESSION_COOKIE_TTL in seconds becomes milliseconds.
    expect(sessions.revokeLapsedBatch).toHaveBeenCalledWith({
      now: 7,
      defaultMaxLifespanMs: 86_400_000,
      after: SID,
      limit: 10,
    });

    expect(await store.deleteEnded({ before: 4, after: null, limit: 1000 })).toEqual({
      deleted: 2,
      last: SID,
      selected: 2,
    });
    expect(sessions.deleteEnded).toHaveBeenCalledWith({ before: 4, limit: 1000 });
  });

  it('lists a user’s or a client’s sessions with the realm’s lifetimes', async () => {
    const { repos, sessions } = repositories({ ssoMaxLifespan: 3600, ssoIdleTimeout: null });
    const store = repositorySessionStore(repos);

    expect(
      await store.list(
        REALM,
        { userId: ROW.userId },
        { limit: 3, after: { createdAt: 2, sid: SID } }
      )
    ).toEqual({
      lifetimes: { maxLifespanSeconds: 3600, idleTimeoutSeconds: null },
      sessions: [{ session: ROW, clients: [CLIENT] }],
    });
    expect(sessions.listForUser).toHaveBeenCalledWith(REALM, ROW.userId, {
      limit: 3,
      after: { createdAt: 2, id: SID },
    });

    await store.list(REALM, { oauthClientId: 'client-row' }, { limit: 3 });
    expect(sessions.listForClient).toHaveBeenCalledWith(REALM, 'client-row', { limit: 3 });

    expect(
      await repositorySessionStore(repositories(undefined).repos).list(
        REALM,
        { userId: ROW.userId },
        { limit: 3 }
      )
    ).toBeUndefined();
  });
});

describe('sessionServicePlugin', () => {
  /** Stand-ins for the database and cache plugins, under their names. */
  async function withDependencies(app: FastifyInstance): Promise<void> {
    await app.register(
      fp(
        async (instance) => {
          instance.decorate('repositories', repositories(undefined).repos as never);
        },
        { name: DATABASE_PLUGIN_NAME }
      )
    );
    await app.register(
      fp(
        async (instance) => {
          instance.decorate('redis', {} as never);
        },
        { name: CACHE_PLUGIN_NAME }
      )
    );
  }

  it('decorates the instance with the service, touching neither Postgres nor Redis', async () => {
    const app = Fastify({ logger: false });
    await withDependencies(app);
    await app.register(sessionServicePlugin, { settings: { defaultMaxLifespanSeconds: 86_400 } });
    await app.ready();

    expect(typeof app.sessionService.get).toBe('function');
    await app.close();
  });

  it('refuses to boot before the database and cache plugins', async () => {
    const app = Fastify({ logger: false });
    const boot = async () => {
      await app.register(sessionServicePlugin, { settings: { defaultMaxLifespanSeconds: 86_400 } });
      await app.ready();
    };

    await expect(boot()).rejects.toThrow(/fastify-plugin-db/);
  });

  it('refuses a setting that is not a positive number of seconds', async () => {
    const app = Fastify({ logger: false });
    await withDependencies(app);
    const boot = async () => {
      await app.register(sessionServicePlugin, { settings: { defaultMaxLifespanSeconds: 0 } });
      await app.ready();
    };

    await expect(boot()).rejects.toThrow(/defaultMaxLifespanSeconds/);
  });
});
