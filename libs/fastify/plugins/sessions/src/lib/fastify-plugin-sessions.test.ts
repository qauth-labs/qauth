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

/** Stand-in repositories: only the methods the store calls. */
function repositories(
  realm: { ssoMaxLifespan: number | null; ssoIdleTimeout: number | null } | undefined
) {
  const sessions = {
    create: vi.fn(async () => ROW),
    findById: vi.fn(async () => ROW),
    updateLastSeen: vi.fn(async () => true),
    revoke: vi.fn(async () => ROW),
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

    await store.revoke(REALM, SID, 'sign_out');
    expect(sessions.revoke).toHaveBeenCalledWith(REALM, SID, 'sign_out');
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
