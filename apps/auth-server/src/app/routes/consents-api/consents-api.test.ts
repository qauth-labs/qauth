import { JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

// The event emitter's module imports `helpers/realm` → `config/env`, which
// validates required env at module load. Stub it so the unit run needs no real
// environment (matches `routes/clients/clients.test.ts`).
vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
    DEFAULT_REALM_NAME: 'master',
  },
}));

// The management-token guard has its own tests (helpers/management-token.test.ts).
// Here it is a seam: every route must be registered behind exactly this guard.
const { managementGuard } = vi.hoisted(() => ({ managementGuard: vi.fn() }));
vi.mock('../../helpers/management-token', () => ({
  createRequireManagementJwt: () => managementGuard,
}));

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

import { testRealm } from '../../../testing/request-realm';
import { emitUserEvent } from '../../helpers/user-events';
import consentsApiRoute, { autoPrefix } from './index';

const emitUserEventMock = vi.mocked(emitUserEvent);

/** The realm the request resolved to; every consent lookup is scoped to it (#489). */
const REALM = testRealm({ id: 'realm-1' });

beforeEach(() => {
  emitUserEventMock.mockClear();
});

/**
 * `/api/consents` — the Bearer-authenticated consent surface the developer
 * portal actually reaches (issue #366).
 *
 * The properties worth asserting are the ones the cookie-authed `/consents`
 * cannot give the portal: it authenticates with a developer access token, it
 * scopes strictly to that token's `sub`, and it needs no CSRF header. The
 * ownership check itself lives in `helpers/consent-management` and is shared
 * with `/consents`; what is tested here is that this route routes through it
 * with the right user id and never with someone else's.
 */

interface TestContext {
  get?: (request: any, reply: any) => Promise<unknown>;
  delete?: (request: any, reply: any) => Promise<unknown>;
  routes: { method: string; url: string; preHandler: unknown }[];
}

function createReply() {
  const state: { statusCode?: number; headers: Record<string, string>; body?: unknown } = {
    headers: {},
  };
  const reply: any = {
    code(n: number) {
      state.statusCode = n;
      return reply;
    },
    header(k: string, v: string) {
      state.headers[k] = v;
      return reply;
    },
    send(body: unknown) {
      state.body = body;
      return body;
    },
  };
  return { reply, state };
}

const CONSENT_ROW = {
  id: '11111111-1111-4111-8111-111111111111',
  clientClientId: 'app-client-id',
  clientName: 'Some App',
  scopes: ['openid', 'profile'],
  grantedAt: 1_700_000_000_000,
  oauthClientId: 'client-row-1',
  realmId: REALM.id,
};

function makeFastify() {
  const ctx: TestContext = { routes: [] };
  const requireJwt = vi.fn();

  const fastify: any = {
    withTypeProvider: () => ({
      get: (url: string, opts: any, handler: any) => {
        ctx.routes.push({ method: 'GET', url, preHandler: opts?.preHandler });
        ctx.get = handler;
        return fastify;
      },
      delete: (url: string, opts: any, handler: any) => {
        ctx.routes.push({ method: 'DELETE', url, preHandler: opts?.preHandler });
        ctx.delete = handler;
        return fastify;
      },
    }),
    requireJwt,
    repositories: {
      oauthConsents: {
        listActiveForUserWithClient: vi.fn().mockResolvedValue([CONSENT_ROW]),
        revoke: vi.fn().mockResolvedValue(undefined),
      },
      authorizationCodes: { invalidateForUserAndClient: vi.fn().mockResolvedValue(0) },
      refreshTokens: { revokeAllForUserAndClient: vi.fn().mockResolvedValue(2) },
    },
    db: { transaction: vi.fn(async (cb: (tx: unknown) => Promise<unknown>) => cb('tx')) },
  };

  return { fastify: fastify as FastifyInstance, ctx, requireJwt };
}

function request(overrides: Record<string, unknown> = {}) {
  return {
    jwtPayload: { sub: 'user-1' },
    realm: REALM,
    params: {},
    ip: '127.0.0.1',
    headers: { 'user-agent': 'vitest' },
    ...overrides,
  };
}

describe('/api/consents', () => {
  it("mounts under /api/consents, beside the portal's other Bearer endpoints", () => {
    expect(autoPrefix).toBe('/api/consents');
  });

  it('gates BOTH endpoints on the management-token guard', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsApiRoute(fastify);
    expect(ctx.routes).toHaveLength(2);
    for (const route of ctx.routes) {
      expect(route.preHandler, `${route.method} ${route.url} is unauthenticated`).toBe(
        managementGuard
      );
    }
  });

  it('lists the consents of the token subject, and marks them uncacheable', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsApiRoute(fastify);
    const { reply, state } = createReply();

    const result = (await ctx.get!(request(), reply)) as { consents: unknown[] };

    expect(fastify.repositories.oauthConsents.listActiveForUserWithClient).toHaveBeenCalledWith(
      REALM.id,
      'user-1'
    );
    expect(state.headers['Cache-Control']).toBe('no-store');
    expect(result.consents).toEqual([
      {
        id: CONSENT_ROW.id,
        clientId: 'app-client-id',
        clientName: 'Some App',
        scopes: ['openid', 'profile'],
        grantedAt: CONSENT_ROW.grantedAt,
      },
    ]);
  });

  it('revokes a consent the caller owns, 204 with a consent.revoked event', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsApiRoute(fastify);
    const { reply, state } = createReply();

    await ctx.delete!(request({ params: { id: CONSENT_ROW.id } }), reply);

    // Owned in the request's realm, and revoked there (#489).
    expect(fastify.repositories.oauthConsents.listActiveForUserWithClient).toHaveBeenCalledWith(
      REALM.id,
      'user-1'
    );
    expect(fastify.repositories.oauthConsents.revoke).toHaveBeenCalledWith(
      REALM.id,
      CONSENT_ROW.id,
      'tx'
    );
    expect(state.statusCode).toBe(204);
    // In the revocation's transaction; the client by its public client_id.
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:consent.revoked:v1-rc.0',
      { consentId: CONSENT_ROW.id, revokedRefreshCount: 2 },
      { tx: 'tx', realmId: 'realm-1', userId: 'user-1', clientId: 'app-client-id', actor: 'user' }
    );
  });

  it('revokes the refresh tokens minted under the consent, in the same transaction', async () => {
    // A withdrawn grant must stop refreshing too — otherwise the client keeps
    // minting access tokens on a consent that no longer exists.
    const { fastify, ctx } = makeFastify();
    await consentsApiRoute(fastify);
    const { reply } = createReply();

    await ctx.delete!(request({ params: { id: CONSENT_ROW.id } }), reply);

    expect(fastify.repositories.refreshTokens.revokeAllForUserAndClient).toHaveBeenCalledWith(
      'user-1',
      CONSENT_ROW.oauthClientId,
      'consent_revoked',
      'tx'
    );
  });

  it('invalidates the unredeemed codes for the client before the sweep, in the same transaction', async () => {
    // A code redeemed after the sweep would mint a refresh token the withdrawn
    // grant no longer covers; one in flight holds its code row locked until
    // its refresh token is committed, so the sweep must come second.
    const { fastify, ctx } = makeFastify();
    await consentsApiRoute(fastify);
    const { reply } = createReply();

    await ctx.delete!(request({ params: { id: CONSENT_ROW.id } }), reply);

    expect(fastify.repositories.authorizationCodes.invalidateForUserAndClient).toHaveBeenCalledWith(
      'user-1',
      CONSENT_ROW.oauthClientId,
      'tx'
    );
    const invalidateOrder = (
      fastify.repositories.authorizationCodes.invalidateForUserAndClient as unknown as Mock
    ).mock.invocationCallOrder[0];
    const sweepOrder = (
      fastify.repositories.refreshTokens.revokeAllForUserAndClient as unknown as Mock
    ).mock.invocationCallOrder[0];
    expect(invalidateOrder).toBeLessThan(sweepOrder);
  });

  it('still revokes the refresh tokens when another tab already revoked the consent', async () => {
    const { fastify, ctx } = makeFastify();
    (fastify.repositories.oauthConsents.revoke as unknown as Mock).mockRejectedValue(
      new NotFoundError('OAuthConsent', CONSENT_ROW.id)
    );
    await consentsApiRoute(fastify);
    const { reply, state } = createReply();

    await ctx.delete!(request({ params: { id: CONSENT_ROW.id } }), reply);

    expect(state.statusCode).toBe(204);
    expect(fastify.repositories.refreshTokens.revokeAllForUserAndClient).toHaveBeenCalledOnce();
  });

  it("reports another user's consent as 404, never 403 (no enumeration)", async () => {
    const { fastify, ctx } = makeFastify();
    // The row exists, but not for THIS user — exactly what the ownership check
    // must not leak.
    (
      fastify.repositories.oauthConsents.listActiveForUserWithClient as unknown as Mock
    ).mockResolvedValue([]);
    await consentsApiRoute(fastify);
    const { reply } = createReply();

    await expect(ctx.delete!(request({ params: { id: CONSENT_ROW.id } }), reply)).rejects.toThrow(
      NotFoundError
    );
    expect(fastify.repositories.oauthConsents.revoke).not.toHaveBeenCalled();
    expect(emitUserEventMock).not.toHaveBeenCalled();
  });

  it("scopes the listing and the revoke to the request's realm (#489)", async () => {
    // The same subject id at another realm's host is looked up in THAT realm:
    // a consent of realm-1 is not in realm-2's listing, so it answers 404 like
    // an unknown id and is never revoked.
    const { fastify, ctx } = makeFastify();
    const otherRealm = testRealm({ id: 'realm-2' });
    const listing = fastify.repositories.oauthConsents
      .listActiveForUserWithClient as unknown as Mock;
    listing.mockImplementation(async (realmId: string) =>
      realmId === REALM.id ? [CONSENT_ROW] : []
    );
    await consentsApiRoute(fastify);

    const { reply: listReply } = createReply();
    const result = (await ctx.get!(request({ realm: otherRealm }), listReply)) as {
      consents: unknown[];
    };
    expect(result.consents).toEqual([]);

    const { reply } = createReply();
    await expect(
      ctx.delete!(request({ realm: otherRealm, params: { id: CONSENT_ROW.id } }), reply)
    ).rejects.toThrow(NotFoundError);

    expect(listing.mock.calls).toEqual([
      ['realm-2', 'user-1'],
      ['realm-2', 'user-1'],
    ]);
    expect(fastify.repositories.oauthConsents.revoke).not.toHaveBeenCalled();
    expect(emitUserEventMock).not.toHaveBeenCalled();
  });

  it('refuses a token with no subject rather than acting on undefined', async () => {
    // `requireJwt` should already have rejected this, so reaching a handler
    // without a `sub` is an invariant violation — fail closed, never fall
    // through to a repository call keyed on `undefined`.
    const { fastify, ctx } = makeFastify();
    await consentsApiRoute(fastify);
    const { reply } = createReply();

    await expect(ctx.get!(request({ jwtPayload: {} }), reply)).rejects.toThrow(JWTInvalidError);
    expect(fastify.repositories.oauthConsents.listActiveForUserWithClient).not.toHaveBeenCalled();
  });

  it('requires NO CSRF header — a Bearer token is not ambient authority', async () => {
    // `/consents` needs `X-CSRF-Token` because its cookie is attached by the
    // browser on a cross-site request. A Bearer token has to be put on the
    // request by code that already holds it, so demanding a CSRF token here
    // would be ceremony, and the portal page that failed to send one is exactly
    // what #366 was about.
    const { fastify, ctx } = makeFastify();
    await consentsApiRoute(fastify);
    const { reply, state } = createReply();

    await ctx.delete!(
      request({ params: { id: CONSENT_ROW.id }, headers: { 'user-agent': 'vitest' } }),
      reply
    );

    expect(state.statusCode).toBe(204);
  });
});
