import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { supplyRequestRealm, testRealm } from '../../../testing/request-realm';
import { emitUserEvent } from '../../helpers/user-events';
import upstreamUiRoutes from './upstream';

vi.mock('../../../config/env', () => ({
  env: {
    NODE_ENV: 'test',
    INTERACTION_UI_ENABLED: false,
    AUTHORIZE_RATE_LIMIT: 60,
    AUTHORIZE_RATE_LIMIT_LENIENT: 600,
    AUTHORIZE_RATE_WINDOW: 60,
    LOGIN_RATE_LIMIT: 5,
    LOGIN_RATE_WINDOW: 900,
  },
}));

vi.mock('../../helpers/user-events', () => ({ emitUserEvent: vi.fn(async () => undefined) }));

/**
 * A provider button of the sign-in page (#639): `GET /ui/upstream/<type>`
 * sends the browser back to the page's authorization request with the
 * routing parameter, reading a parked request without spending it. A
 * provider the realm has not, or has off, and a request the page no longer
 * has, answer the one error page with the trace id, audited.
 */
describe('GET /ui/upstream/:type (#639)', () => {
  const REALM = testRealm({ id: 'realm-1' });
  /** Where a parked authorization request is kept (`helpers/pending-authorization.ts`). */
  const PENDING_AUTHORIZATION_KEY_PREFIX = 'pending-authz:';
  const HANDLE = 'h'.repeat(43);
  const AUTHORIZE_URL = '/oauth/authorize?client_id=app&response_type=code&state=s';
  const PROVIDER_ROW = {
    id: 'provider-1',
    realmId: REALM.id,
    type: 'oidc_corp',
    displayName: 'Example Corp',
    displayOrder: 0,
    hidden: true,
    enabled: true,
    marksVerified: true,
    config: {},
  };

  let app: FastifyInstance;
  const sessions = new Map<string, unknown>();
  const getSession = vi.fn(async (key: string) => sessions.get(key) ?? null);
  const deleteSession = vi.fn(async () => undefined);
  const find = vi.fn(async (_realmId: string, type: string) =>
    type === PROVIDER_ROW.type ? PROVIDER_ROW : undefined
  );

  beforeEach(async () => {
    sessions.clear();
    sessions.set(`${PENDING_AUTHORIZATION_KEY_PREFIX}${HANDLE}`, {
      authorizeUrl: AUTHORIZE_URL,
      createdAt: Date.now(),
    });
    vi.mocked(emitUserEvent).mockClear();
    getSession.mockClear();
    deleteSession.mockClear();
    find.mockClear();

    app = Fastify({ logger: false });
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    app.decorate('repositories', {
      realmUpstreamProviders: { find, listByRealm: async () => [] },
    } as never);
    app.decorate('sessionUtils', { getSession, deleteSession } as never);
    app.decorateReply('cspNonce', null as never);
    app.addHook('onRequest', async (_request, reply) => {
      reply.cspNonce = { script: 'script-nonce', style: 'style-nonce' };
    });
    supplyRequestRealm(app, REALM);
    await app.register(upstreamUiRoutes, { prefix: '/ui' });
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  const button = (type: string, returnTo: string) =>
    app.inject({
      method: 'GET',
      url: `/ui/upstream/${type}?return_to=${encodeURIComponent(returnTo)}`,
    });

  it('routes a parked request to a provider the realm has on, hidden or not, and keeps the handle', async () => {
    const response = await button('oidc_corp', `/ui/resume/${HANDLE}`);

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe(`${AUTHORIZE_URL}&qauth_upstream=oidc_corp`);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(find).toHaveBeenCalledWith(REALM.id, 'oidc_corp');
    // Read, never spent: the page's own sign-in still has it.
    expect(deleteSession).not.toHaveBeenCalled();
    expect(sessions.has(`${PENDING_AUTHORIZATION_KEY_PREFIX}${HANDLE}`)).toBe(true);
  });

  it('routes an inline authorization request', async () => {
    const response = await button('oidc_corp', AUTHORIZE_URL);

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe(`${AUTHORIZE_URL}&qauth_upstream=oidc_corp`);
  });

  it.each([
    ['a provider the realm has not', 'oidc_other', `/ui/resume/${HANDLE}`, 'upstream_unavailable'],
    [
      'a parked request that is gone',
      'oidc_corp',
      `/ui/resume/${'x'.repeat(43)}`,
      'request_expired',
    ],
    ['a return_to that is no authorization request', 'oidc_corp', '/account', 'request_expired'],
    [
      'an off-site return_to',
      'oidc_corp',
      'https://evil.example/oauth/authorize',
      'request_expired',
    ],
  ])(
    'answers the error page with the trace id for %s, audited',
    async (_label, type, returnTo, reason) => {
      const response = await button(type, returnTo);

      expect(response.statusCode).toBe(400);
      expect(response.headers['content-type']).toContain('text/html');
      expect(response.headers.location).toBeUndefined();
      expect(response.body).toContain('We could not sign you in');
      expect(response.body).toMatch(/trace id: <code>req-[0-9a-z]+<\/code>/);
      expect(response.body).not.toContain('evil.example');
      expect(vi.mocked(emitUserEvent)).toHaveBeenCalledWith(
        expect.anything(),
        'urn:qauth:event:user.sign_in_failed:v1-rc.0',
        { method: 'upstream', reason },
        expect.objectContaining({ realmId: REALM.id, userId: null })
      );
    }
  );
});
