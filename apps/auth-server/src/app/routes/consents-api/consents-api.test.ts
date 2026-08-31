import { JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

import consentsApiRoute, { autoPrefix } from './index';

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
        listActiveForUser: vi.fn().mockResolvedValue([CONSENT_ROW]),
        revoke: vi.fn().mockResolvedValue(undefined),
      },
      auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
    },
  };

  return { fastify: fastify as FastifyInstance, ctx, requireJwt };
}

function request(overrides: Record<string, unknown> = {}) {
  return {
    jwtPayload: { sub: 'user-1' },
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

  it('gates BOTH endpoints on requireJwt', async () => {
    const { fastify, ctx, requireJwt } = makeFastify();
    await consentsApiRoute(fastify);
    expect(ctx.routes).toHaveLength(2);
    for (const route of ctx.routes) {
      expect(route.preHandler, `${route.method} ${route.url} is unauthenticated`).toBe(requireJwt);
    }
  });

  it('lists the consents of the token subject, and marks them uncacheable', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsApiRoute(fastify);
    const { reply, state } = createReply();

    const result = (await ctx.get!(request(), reply)) as { consents: unknown[] };

    expect(fastify.repositories.oauthConsents.listActiveForUserWithClient).toHaveBeenCalledWith(
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

  it('revokes a consent the caller owns, 204 with an audit entry', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsApiRoute(fastify);
    const { reply, state } = createReply();

    await ctx.delete!(request({ params: { id: CONSENT_ROW.id } }), reply);

    expect(fastify.repositories.oauthConsents.revoke).toHaveBeenCalledWith(CONSENT_ROW.id);
    expect(state.statusCode).toBe(204);
    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        event: 'oauth.consent.revoked',
        success: true,
      })
    );
  });

  it("reports another user's consent as 404, never 403 (no enumeration)", async () => {
    const { fastify, ctx } = makeFastify();
    // The row exists, but not for THIS user — exactly what the ownership check
    // must not leak.
    (fastify.repositories.oauthConsents.listActiveForUser as unknown as Mock).mockResolvedValue([]);
    await consentsApiRoute(fastify);
    const { reply } = createReply();

    await expect(ctx.delete!(request({ params: { id: CONSENT_ROW.id } }), reply)).rejects.toThrow(
      NotFoundError
    );
    expect(fastify.repositories.oauthConsents.revoke).not.toHaveBeenCalled();
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
