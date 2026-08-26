import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

/**
 * The wallet-LINKING screens (#238) — the UI affordance ADR-004's account
 * linking needs.
 *
 * The screens are thin; the properties are not. Every one of them requires a
 * session, none of them offers an identifier field (ADR-009 §5 — the account is
 * the session's, and a second answer would be an ambiguity), and the state-
 * changing POST carries the same login-CSRF cookie the wallet-login form does.
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
    // The verifier-identity variables at their parsed DEFAULTS (#377). Stated
    // rather than omitted because the request path now resolves the profile with
    // the deployment's provisioned material, and
    // `resolveVerifierCertificateChainPems` reads `.length` off the array forms —
    // which the real parsed env always supplies (Zod defaults them to `[]`) and
    // an env stub silently would not.
    OID4VP_VERIFIER_SIGNING_KEY: undefined as string | undefined,
    OID4VP_VERIFIER_SIGNING_KEY_PATH: undefined as string | undefined,
    OID4VP_VERIFIER_CERTIFICATE_CHAIN: [] as readonly string[],
    OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: [] as readonly string[],
    OID4VP_VERIFIER_TRUST_ANCHORS: [] as readonly string[],
    OID4VP_VERIFIER_TRUST_ANCHORS_PATH: [] as readonly string[],
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
import walletLinkRoute from './wallet-link';

type Handler = (request: any, reply: any) => Promise<unknown>;

function createReply() {
  const state: {
    statusCode?: number;
    headers: Record<string, string>;
    setCookies: string[];
    redirected?: string;
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
    redirect(url: string, code: number) {
      state.redirected = url;
      state.statusCode = code;
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

function signIn(sessionUtils: ReturnType<typeof createSessionUtils>, userId = 'user-1') {
  const sessionId = `session-${userId}`;
  sessionUtils.store.set(sessionId, { userId, sessionId, createdAt: Date.now() });
  return `__Host-qauth_session=${signSessionId(sessionId)}`;
}

function cookieValue(setCookies: string[], name: string): string {
  const cookie = setCookies.find((c) => c.startsWith(`${name}=`));
  if (!cookie) throw new Error(`${name} was not set`);
  return cookie.split('=').slice(1).join('=').split(';')[0];
}

/** GET then POST, producing a started linking flow. */
async function startLink(userId = 'user-1') {
  const context = makeFastify();
  await walletLinkRoute(context.fastify);
  const sessionCookie = signIn(context.sessionUtils, userId);

  const getReply = createReply();
  await context.routes.get('GET /wallet-link')!(
    { headers: { cookie: sessionCookie }, ip: '127.0.0.1' },
    getReply.reply
  );
  const csrfCookie = cookieValue(getReply.state.setCookies, '__Host-qauth_login_csrf');
  const csrfToken = csrfCookie.split('.')[0];

  const postReply = createReply();
  await context.routes.get('POST /wallet-link')!(
    {
      body: { csrf_token: csrfToken },
      headers: { cookie: `${sessionCookie}; __Host-qauth_login_csrf=${csrfCookie}` },
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
    sessionCookie,
    getReply,
    postReply,
    handle: flowEntry[0].slice('wallet-login:'.length),
    flow: flowEntry[1] as Record<string, any>,
    binderCookie: cookieValue(postReply.state.setCookies, '__Host-qauth_wallet_flow'),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  envMock.WALLET_FEDERATION_ENABLED = true;
  envMock.OID4VP_VERIFIER_PROFILE = 'oid4vp-1.0-base';
  envMock.OID4VP_REQUESTED_VCT = ['urn:example:pid'];
  (linkWalletPresentation as unknown as Mock).mockResolvedValue({ status: 'rejected' });
});

describe('wallet-link UI — registration and availability (#232/#296)', () => {
  it('registers no routes when WALLET_FEDERATION_ENABLED is off', async () => {
    envMock.WALLET_FEDERATION_ENABLED = false;
    const { fastify, routes } = makeFastify();
    await walletLinkRoute(fastify);
    expect(routes.size).toBe(0);
  });

  it('renders a 404 screen when no VerifierProfile is selected', async () => {
    envMock.OID4VP_VERIFIER_PROFILE = undefined;
    const { fastify, routes, sessionUtils } = makeFastify();
    await walletLinkRoute(fastify);
    const cookie = signIn(sessionUtils);

    const { reply, state } = createReply();
    await routes.get('GET /wallet-link')!({ headers: { cookie }, ip: '1.2.3.4' }, reply);

    expect(state.statusCode).toBe(404);
    expect(String(state.body)).toContain('not currently accepting wallet credentials');
  });
});

describe('wallet-link UI — signed in, or nothing (ADR-009 §5)', () => {
  it.each([
    ['GET /wallet-link', { headers: {}, ip: '1.2.3.4' }],
    ['POST /wallet-link', { body: { csrf_token: 'x' }, headers: {}, ip: '1.2.3.4' }],
    [
      'GET /wallet-link/:handle',
      { params: { handle: 'x'.repeat(43) }, headers: {}, ip: '1.2.3.4' },
    ],
  ] as const)('redirects %s to the password login when there is no session', async (route, req) => {
    const { fastify, routes } = makeFastify();
    await walletLinkRoute(fastify);

    const { reply, state } = createReply();
    await routes.get(route)!(req, reply);

    expect(state.redirected).toBe('/ui/login?return_to=%2Fui%2Fwallet-link');
    expect(fastify.repositories.oid4vpRequestStates.create).not.toHaveBeenCalled();
  });

  it('offers no identifier field — the account is the session’s', async () => {
    const { getReply } = await startLink();

    expect(String(getReply.state.body)).not.toContain('name="identifier"');
  });

  it('refuses a POST whose login-CSRF token does not match the cookie', async () => {
    const { fastify, routes, sessionUtils } = makeFastify();
    await walletLinkRoute(fastify);
    const cookie = signIn(sessionUtils);

    const getReply = createReply();
    await routes.get('GET /wallet-link')!({ headers: { cookie }, ip: '1.2.3.4' }, getReply.reply);
    const csrfCookie = cookieValue(getReply.state.setCookies, '__Host-qauth_login_csrf');

    const { reply, state } = createReply();
    await routes.get('POST /wallet-link')!(
      {
        body: { csrf_token: 'forged' },
        headers: { cookie: `${cookie}; __Host-qauth_login_csrf=${csrfCookie}` },
        ip: '1.2.3.4',
      },
      reply
    );

    expect(state.statusCode).toBe(403);
    expect(fastify.repositories.oid4vpRequestStates.create).not.toHaveBeenCalled();
    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'auth.wallet_link.csrf_failure' })
    );
  });
});

describe('wallet-link UI — the pending screen and completion', () => {
  it('renders a QR code and polls the authenticated status endpoint', async () => {
    const { postReply, handle } = await startLink();
    const body = String(postReply.state.body);

    expect(body).toContain('<svg');
    expect(body).toContain(`/auth/link/wallet/${handle}`);
  });

  it('binds the flow to this browser and to this user', async () => {
    const { flow, binderCookie } = await startLink('user-77');

    expect(flow['mode']).toBe('link');
    expect(flow['linkUserId']).toBe('user-77');
    expect(binderCookie.length).toBeGreaterThan(0);
  });

  it('renders the success screen once the credential is linked', async () => {
    const { routes, sessionUtils, sessionCookie, handle, flow, binderCookie } = await startLink();
    sessionUtils.store.set(`wallet-login-signal:${flow['stateHash']}`, {
      signal: 'received',
      at: Date.now(),
    });
    (linkWalletPresentation as unknown as Mock).mockResolvedValue({
      status: 'linked',
      credentialId: 'cred-1',
      externalSub: 'alice@example.com',
      subjectSource: 'asserted-lookup',
      rebound: false,
    });

    const { reply, state } = createReply();
    await routes.get('GET /wallet-link/:handle')!(
      {
        headers: { cookie: `${sessionCookie}; __Host-qauth_wallet_flow=${binderCookie}` },
        params: { handle },
        ip: '1.2.3.4',
      },
      reply
    );

    expect(String(state.body)).toContain('now linked to this account');
  });

  it('renders the conflict screen with a 409 — the one specific outcome', async () => {
    const { routes, sessionUtils, sessionCookie, handle, flow, binderCookie } = await startLink();
    sessionUtils.store.set(`wallet-login-signal:${flow['stateHash']}`, {
      signal: 'received',
      at: Date.now(),
    });
    (linkWalletPresentation as unknown as Mock).mockResolvedValue({ status: 'conflict' });

    const { reply, state } = createReply();
    await routes.get('GET /wallet-link/:handle')!(
      {
        headers: { cookie: `${sessionCookie}; __Host-qauth_wallet_flow=${binderCookie}` },
        params: { handle },
        ip: '1.2.3.4',
      },
      reply
    );

    expect(state.statusCode).toBe(409);
    expect(String(state.body)).toContain('already linked to a different account');
  });

  it('renders one refusal for a rejected link', async () => {
    const { routes, sessionUtils, sessionCookie, handle, flow, binderCookie } = await startLink();
    sessionUtils.store.set(`wallet-login-signal:${flow['stateHash']}`, {
      signal: 'received',
      at: Date.now(),
    });

    const { reply, state } = createReply();
    await routes.get('GET /wallet-link/:handle')!(
      {
        headers: { cookie: `${sessionCookie}; __Host-qauth_wallet_flow=${binderCookie}` },
        params: { handle },
        ip: '1.2.3.4',
      },
      reply
    );

    expect(state.statusCode).toBe(401);
    expect(String(state.body)).toContain('We could not link that credential');
  });
});
