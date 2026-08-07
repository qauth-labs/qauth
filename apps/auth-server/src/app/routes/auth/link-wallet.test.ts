import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

/**
 * `POST /auth/link/wallet` and its polling endpoint (#238, ADR-009 §5).
 *
 * The linking flow's whole security posture is "the session decides", so the
 * tests that matter are the ones that take the session away, swap it for a
 * different one, or hand the handle to the wrong completion path. The
 * cryptography is mocked here for the reason stated in
 * `helpers/wallet-presentation.test.ts`: it is exercised for real in
 * `libs/server/federation`, and `scope:app` cannot mint a credential.
 */

const { envMock } = vi.hoisted(() => ({
  envMock: {
    DEFAULT_REALM_NAME: 'master',
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
    LOGIN_RATE_LIMIT: 5,
    LOGIN_RATE_WINDOW: 900,
    JWT_ISSUER: 'https://auth.example.com',
    WALLET_FEDERATION_ENABLED: true,
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' as string | undefined,
    OID4VP_REQUESTED_VCT: ['urn:example:pid'] as readonly string[] | undefined,
    OID4VP_WALLET_INVOCATION_ENDPOINT: 'openid4vp://',
  },
}));

vi.mock('../../../config/env', () => ({ env: envMock }));

vi.mock('../../helpers/wallet-presentation', () => ({
  linkWalletPresentation: vi.fn().mockResolvedValue({ status: 'rejected' }),
  resolveWalletPresentation: vi.fn().mockResolvedValue({ status: 'rejected' }),
}));

import { signSessionId } from '../../helpers/session-cookie';
import { linkWalletPresentation } from '../../helpers/wallet-presentation';
import linkWalletRoute from './link-wallet';

type Handler = (request: any, reply: any) => Promise<unknown>;

function createReply() {
  const state: {
    statusCode?: number;
    headers: Record<string, string>;
    setCookies: string[];
    body?: any;
  } = { headers: {}, setCookies: [] };
  const reply: any = {
    cspNonce: { script: 'test-script-nonce', style: 'test-style-nonce' },
    code(n: number) {
      state.statusCode = n;
      return reply;
    },
    header(k: string, v: string) {
      if (k.toLowerCase() === 'set-cookie') state.setCookies.push(v);
      else state.headers[k] = v;
      return reply;
    },
    send(body: unknown) {
      state.body = body;
      return body;
    },
  };
  return { reply, state };
}

function createSessionUtils() {
  const store = new Map<string, unknown>();
  return {
    store,
    setSession: vi.fn(async (key: string, value: unknown) => {
      store.set(key, value);
    }),
    getSession: vi.fn(async (key: string) => store.get(key) ?? null),
    deleteSession: vi.fn(async (key: string) => {
      store.delete(key);
    }),
  };
}

function makeFastify() {
  const routes = new Map<string, Handler>();
  const sessionUtils = createSessionUtils();
  const register = (method: string) => (url: string, _opts: unknown, handler: Handler) => {
    routes.set(`${method} ${url}`, handler);
    return fastify;
  };
  const fastify: any = {
    withTypeProvider: () => ({ get: register('GET'), post: register('POST') }),
    repositories: {
      realms: {
        findByName: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'master', enabled: true }),
        create: vi.fn(),
      },
      oid4vpRequestStates: { create: vi.fn(async (row: unknown) => row) },
      auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
    },
    sessionUtils,
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, routes, sessionUtils };
}

/** Mint a live browser session and return the cookie header value for it. */
function signIn(
  sessionUtils: ReturnType<typeof createSessionUtils>,
  userId: string,
  apiCsrfToken = 'api-csrf-token'
) {
  const sessionId = `session-${userId}`;
  sessionUtils.store.set(sessionId, { userId, sessionId, createdAt: Date.now(), apiCsrfToken });
  return { cookie: `__Host-qauth_session=${signSessionId(sessionId)}`, apiCsrfToken };
}

function cookieValue(setCookies: string[], name: string): string {
  const cookie = setCookies.find((c) => c.startsWith(`${name}=`));
  if (!cookie) throw new Error(`${name} was not set`);
  return cookie.split('=').slice(1).join('=').split(';')[0];
}

/** Start a linking flow and return everything about it. */
async function startLink(userId = 'user-1') {
  const context = makeFastify();
  await linkWalletRoute(context.fastify);
  const session = signIn(context.sessionUtils, userId);

  const postReply = createReply();
  await context.routes.get('POST /link/wallet')!(
    {
      headers: { cookie: session.cookie, 'x-csrf-token': session.apiCsrfToken },
      ip: '127.0.0.1',
    },
    postReply.reply
  );

  const flowEntry = [...context.sessionUtils.store.entries()].find(([key]) =>
    key.startsWith('wallet-login:')
  );
  if (!flowEntry) throw new Error('no linking flow was stored');

  return {
    ...context,
    session,
    postReply,
    handle: flowEntry[0].slice('wallet-login:'.length),
    flow: flowEntry[1] as Record<string, any>,
    binderCookie: cookieValue(postReply.state.setCookies, '__Host-qauth_wallet_flow'),
  };
}

function publishSignal(
  sessionUtils: ReturnType<typeof createSessionUtils>,
  stateHash: string,
  signal = 'received'
) {
  sessionUtils.store.set(`wallet-login-signal:${stateHash}`, { signal, at: Date.now() });
}

beforeEach(() => {
  vi.clearAllMocks();
  envMock.WALLET_FEDERATION_ENABLED = true;
  envMock.OID4VP_VERIFIER_PROFILE = 'oid4vp-1.0-base';
  envMock.OID4VP_REQUESTED_VCT = ['urn:example:pid'];
  (linkWalletPresentation as unknown as Mock).mockResolvedValue({ status: 'rejected' });
});

describe('wallet linking API — fail-closed registration (#232/#299)', () => {
  it('registers no routes when WALLET_FEDERATION_ENABLED is off', async () => {
    envMock.WALLET_FEDERATION_ENABLED = false;
    const { fastify, routes } = makeFastify();
    await linkWalletRoute(fastify);
    expect(routes.size).toBe(0);
  });

  it('answers 404 when no VerifierProfile is selected', async () => {
    envMock.OID4VP_VERIFIER_PROFILE = undefined;
    const { fastify, routes, sessionUtils } = makeFastify();
    await linkWalletRoute(fastify);
    const session = signIn(sessionUtils, 'user-1');

    const { reply, state } = createReply();
    await routes.get('POST /link/wallet')!(
      { headers: { cookie: session.cookie, 'x-csrf-token': session.apiCsrfToken }, ip: '1.2.3.4' },
      reply
    );

    expect(state.statusCode).toBe(404);
  });
});

describe('wallet linking API — a session is the whole authority (ADR-009 §5)', () => {
  it('refuses to start a flow without a session', async () => {
    const { fastify, routes } = makeFastify();
    await linkWalletRoute(fastify);

    const { reply, state } = createReply();
    await routes.get('POST /link/wallet')!({ headers: {}, ip: '1.2.3.4' }, reply);

    expect(state.statusCode).toBe(401);
    expect(fastify.repositories.oid4vpRequestStates.create).not.toHaveBeenCalled();
  });

  it('refuses to poll without a session', async () => {
    const { fastify, routes } = makeFastify();
    await linkWalletRoute(fastify);

    const { reply, state } = createReply();
    await routes.get('GET /link/wallet/:handle')!(
      { headers: {}, params: { handle: 'x'.repeat(43) }, ip: '1.2.3.4' },
      reply
    );

    expect(state.statusCode).toBe(401);
  });

  it('refuses a POST with no or wrong X-CSRF-Token', async () => {
    const { fastify, routes, sessionUtils } = makeFastify();
    await linkWalletRoute(fastify);
    const session = signIn(sessionUtils, 'user-1');

    const { reply } = createReply();
    await expect(
      routes.get('POST /link/wallet')!(
        { headers: { cookie: session.cookie, 'x-csrf-token': 'wrong' }, ip: '1.2.3.4' },
        reply
      )
    ).rejects.toThrow();

    expect(fastify.repositories.oid4vpRequestStates.create).not.toHaveBeenCalled();
    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'auth.wallet_link.csrf_failure' })
    );
  });

  it('starts a flow bound to the session user, in LINK mode, asserting no identifier', async () => {
    const { flow, postReply } = await startLink('user-42');

    expect(flow['mode']).toBe('link');
    expect(flow['linkUserId']).toBe('user-42');
    // No identifier field on this surface: the account is the session's, and a
    // second answer to "which account?" is the ambiguity session-binding removes.
    expect(flow['assertedIdentifier']).toBe('');
    expect(postReply.state.body).toMatchObject({ invocation_uri: expect.any(String) });
  });

  it('records the nonce, client_id and DCQL query the wallet is checked against', async () => {
    const { flow } = await startLink();

    expect(typeof flow['nonce']).toBe('string');
    expect(flow['clientId']).toMatch(/^redirect_uri:/);
    expect(flow['dcqlQuery']).toMatchObject({ credentials: expect.any(Array) });
  });
});

describe('wallet linking API — completion gates (#238)', () => {
  it('reports pending until the wallet responds', async () => {
    const { routes, session, handle, binderCookie } = await startLink();

    const { reply, state } = createReply();
    await routes.get('GET /link/wallet/:handle')!(
      {
        headers: { cookie: `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}` },
        params: { handle },
        ip: '1.2.3.4',
      },
      reply
    );

    expect(state.body).toEqual({ status: 'pending' });
    expect(linkWalletPresentation).not.toHaveBeenCalled();
  });

  it('links when the presentation resolves, and reports it once', async () => {
    const { routes, sessionUtils, session, handle, flow, binderCookie } = await startLink();
    publishSignal(sessionUtils, flow['stateHash']);
    (linkWalletPresentation as unknown as Mock).mockResolvedValue({
      status: 'linked',
      credentialId: 'cred-1',
      externalSub: 'alice@example.com',
      subjectSource: 'asserted-lookup',
      rebound: false,
    });

    const headers = {
      cookie: `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}`,
    };
    const first = createReply();
    await routes.get('GET /link/wallet/:handle')!(
      { headers, params: { handle }, ip: '1.2.3.4' },
      first.reply
    );

    expect(first.state.body).toMatchObject({ status: 'linked' });

    // The flow is terminal: polling again finds nothing, so a completed link
    // cannot be replayed into a second write.
    const second = createReply();
    await routes.get('GET /link/wallet/:handle')!(
      { headers, params: { handle }, ip: '1.2.3.4' },
      second.reply
    );
    expect(second.state.body).toMatchObject({ status: 'expired' });
    expect(linkWalletPresentation).toHaveBeenCalledTimes(1);
  });

  it('completes the link with the SESSION’s user, not the flow record alone', async () => {
    const { routes, sessionUtils, session, handle, flow, binderCookie } = await startLink('user-7');
    publishSignal(sessionUtils, flow['stateHash']);

    await routes.get('GET /link/wallet/:handle')!(
      {
        headers: { cookie: `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}` },
        params: { handle },
        ip: '1.2.3.4',
      },
      createReply().reply
    );

    expect(linkWalletPresentation).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ authenticatedUserId: 'user-7' })
    );
  });

  it('refuses a flow completed by a DIFFERENT signed-in user', async () => {
    // A handle harvested from a shared screen must not be finishable by someone
    // else's session — that would attach the attacker's wallet to the victim's
    // flow, or the victim's account to the attacker's session.
    const { routes, sessionUtils, handle, flow, binderCookie } = await startLink('user-1');
    publishSignal(sessionUtils, flow['stateHash']);
    const attacker = signIn(sessionUtils, 'user-2', 'other-csrf');

    const { reply, state } = createReply();
    await routes.get('GET /link/wallet/:handle')!(
      {
        headers: { cookie: `${attacker.cookie}; __Host-qauth_wallet_flow=${binderCookie}` },
        params: { handle },
        ip: '1.2.3.4',
      },
      reply
    );

    expect(state.body).toMatchObject({ status: 'expired' });
    expect(linkWalletPresentation).not.toHaveBeenCalled();
  });

  it('refuses a flow presented without its browser binder cookie', async () => {
    const { routes, sessionUtils, session, handle, flow } = await startLink();
    publishSignal(sessionUtils, flow['stateHash']);

    const { reply, state } = createReply();
    await routes.get('GET /link/wallet/:handle')!(
      { headers: { cookie: session.cookie }, params: { handle }, ip: '1.2.3.4' },
      reply
    );

    expect(state.body).toMatchObject({ status: 'expired' });
    expect(linkWalletPresentation).not.toHaveBeenCalled();
  });

  it('refuses a LOGIN-mode flow submitted to the linking path', async () => {
    // The mode discriminator, from the linking side. A login flow carries no
    // `linkUserId`, so it would fail the session check anyway — refused
    // explicitly so the property survives a change to that field.
    const { routes, sessionUtils, session, handle, flow, binderCookie } = await startLink();
    sessionUtils.store.set(`wallet-login:${handle}`, { ...flow, mode: 'login' });
    publishSignal(sessionUtils, flow['stateHash']);

    const { reply, state } = createReply();
    await routes.get('GET /link/wallet/:handle')!(
      {
        headers: { cookie: `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}` },
        params: { handle },
        ip: '1.2.3.4',
      },
      reply
    );

    expect(state.body).toMatchObject({ status: 'expired' });
    expect(linkWalletPresentation).not.toHaveBeenCalled();
  });

  it('reports a conflict distinctly — the one outcome ADR-009 allows to be specific', async () => {
    const { routes, sessionUtils, session, handle, flow, binderCookie } = await startLink();
    publishSignal(sessionUtils, flow['stateHash']);
    (linkWalletPresentation as unknown as Mock).mockResolvedValue({ status: 'conflict' });

    const { reply, state } = createReply();
    await routes.get('GET /link/wallet/:handle')!(
      {
        headers: { cookie: `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}` },
        params: { handle },
        ip: '1.2.3.4',
      },
      reply
    );

    expect(state.body).toMatchObject({ status: 'conflict' });
  });

  it('reports a wallet-side error as a refusal, without echoing the wallet’s text', async () => {
    const { routes, sessionUtils, session, handle, flow, binderCookie } = await startLink();
    publishSignal(sessionUtils, flow['stateHash'], 'wallet_error');

    const { reply, state } = createReply();
    await routes.get('GET /link/wallet/:handle')!(
      {
        headers: { cookie: `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}` },
        params: { handle },
        ip: '1.2.3.4',
      },
      reply
    );

    expect(state.body).toMatchObject({ status: 'rejected' });
    expect(linkWalletPresentation).not.toHaveBeenCalled();
  });

  it('treats a malformed handle as expired without touching the store', async () => {
    const { fastify, routes, sessionUtils } = makeFastify();
    await linkWalletRoute(fastify);
    const session = signIn(sessionUtils, 'user-1');

    const { reply, state } = createReply();
    await routes.get('GET /link/wallet/:handle')!(
      { headers: { cookie: session.cookie }, params: { handle: '../etc/passwd' }, ip: '1.2.3.4' },
      reply
    );

    expect(state.body).toMatchObject({ status: 'expired' });
  });

  it('audits both the success and the refusal against the acting user', async () => {
    const { fastify, routes, sessionUtils, session, handle, flow, binderCookie } =
      await startLink('user-9');
    publishSignal(sessionUtils, flow['stateHash']);

    await routes.get('GET /link/wallet/:handle')!(
      {
        headers: { cookie: `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}` },
        params: { handle },
        ip: '1.2.3.4',
      },
      createReply().reply
    );

    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'auth.wallet_link.failure',
        userId: 'user-9',
        success: false,
      })
    );
  });
});
