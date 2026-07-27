import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

/**
 * The wallet-login screens (#239), exercised against a MOCKED presentation
 * resolver.
 *
 * That mock is the point rather than a shortcut: presentation validation (#234),
 * issuer trust (#236) and subject resolution (#300) are unbuilt, and the real
 * seam in `helpers/wallet-presentation.ts` refuses unconditionally (its own test
 * pins that). Mocking it is what lets this suite prove the property the issue
 * actually asks for — that a user can complete a wallet sign-in through the UI —
 * without any test pretending those three exist.
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

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../helpers/wallet-presentation', () => ({
  resolveWalletPresentation: vi.fn().mockResolvedValue({ status: 'rejected' }),
}));

import {
  readWalletFlowBindings,
  WALLET_FLOW_COOKIE_MAX_BINDINGS,
} from '../../helpers/session-cookie';
import { resolveWalletPresentation } from '../../helpers/wallet-presentation';
import loginRoute from './login';
import walletLoginRoute, { WALLET_LOGIN_EXPIRED, WALLET_LOGIN_REFUSAL } from './wallet-login';

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
      if (k.toLowerCase() === 'set-cookie') {
        state.setCookies.push(v);
      } else {
        state.headers[k] = v;
      }
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

/** In-memory stand-in for the Redis-backed session store. */
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
      users: {
        findById: vi.fn().mockResolvedValue({ id: 'user-1', enabled: true }),
        updateLastLogin: vi.fn().mockResolvedValue(undefined),
      },
      userCredentials: {
        findByRealmProviderSub: vi.fn(),
        findById: vi.fn(),
      },
      oid4vpRequestStates: {
        create: vi.fn(async (row: unknown) => row),
      },
      auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
    },
    passwordHasher: { verifyPassword: vi.fn() },
    providerRegistry: { resolve: vi.fn(), has: vi.fn().mockReturnValue(true), register: vi.fn() },
    sessionUtils,
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, routes, sessionUtils };
}

function cookieValue(setCookies: string[], name: string): string {
  const cookie = setCookies.find((c) => c.startsWith(`${name}=`));
  if (!cookie) throw new Error(`${name} was not set`);
  return cookie.split('=').slice(1).join('=').split(';')[0];
}

/** Drive GET then POST to obtain a started flow, and return everything about it. */
async function startFlow(
  overrides: {
    identifier?: string;
    returnTo?: string;
    /** Reuse an already-registered server, to start a SECOND flow against it. */
    context?: ReturnType<typeof makeFastify>;
    /** The wallet-flow cookie this browser already holds, if any. */
    walletFlowCookie?: string;
  } = {}
) {
  const context = overrides.context ?? makeFastify();
  const { fastify, routes, sessionUtils } = context;
  if (overrides.context === undefined) await walletLoginRoute(fastify);

  const getReply = createReply();
  await routes.get('GET /wallet-login')!(
    { query: { return_to: overrides.returnTo }, headers: {}, ip: '127.0.0.1' },
    getReply.reply
  );
  const csrfCookie = cookieValue(getReply.state.setCookies, '__Host-qauth_login_csrf');
  const csrfToken = csrfCookie.split('.')[0];

  const cookies = [`__Host-qauth_login_csrf=${csrfCookie}`];
  if (overrides.walletFlowCookie !== undefined) {
    cookies.push(`__Host-qauth_wallet_flow=${overrides.walletFlowCookie}`);
  }

  const knownKeys = new Set(sessionUtils.store.keys());
  const postReply = createReply();
  await routes.get('POST /wallet-login')!(
    {
      body: {
        identifier: overrides.identifier ?? 'user@example.com',
        csrf_token: csrfToken,
        return_to: overrides.returnTo,
      },
      headers: { cookie: cookies.join('; ') },
      ip: '127.0.0.1',
    },
    postReply.reply
  );

  const binderCookie = cookieValue(postReply.state.setCookies, '__Host-qauth_wallet_flow');
  const flowEntry = [...sessionUtils.store.entries()].find(
    ([key]) => key.startsWith('wallet-login:') && !knownKeys.has(key)
  );
  if (!flowEntry) throw new Error('no wallet-login flow was stored');
  const handle = flowEntry[0].slice('wallet-login:'.length);
  const flow = flowEntry[1] as Record<string, any>;

  return { context, fastify, routes, sessionUtils, postReply, handle, flow, binderCookie };
}

/** Simulate the direct_post endpoint publishing its transport signal. */
function publishSignal(
  sessionUtils: ReturnType<typeof createSessionUtils>,
  stateHash: string,
  signal: string
) {
  sessionUtils.store.set(`wallet-login-signal:${stateHash}`, { signal, at: Date.now() });
}

beforeEach(() => {
  vi.clearAllMocks();
  envMock.WALLET_FEDERATION_ENABLED = true;
  envMock.OID4VP_VERIFIER_PROFILE = 'oid4vp-1.0-base';
  envMock.OID4VP_REQUESTED_VCT = ['urn:example:pid'];
  envMock.OID4VP_WALLET_INVOCATION_ENDPOINT = 'openid4vp://';
  (resolveWalletPresentation as unknown as Mock).mockResolvedValue({ status: 'rejected' });
});

describe('wallet login — fail-closed availability (#296, #299)', () => {
  it('registers no routes at all when WALLET_FEDERATION_ENABLED is off', async () => {
    envMock.WALLET_FEDERATION_ENABLED = false;
    const { fastify, routes } = makeFastify();
    await walletLoginRoute(fastify);
    expect(routes.size).toBe(0);
  });

  it('refuses the screen (404) when no VerifierProfile is selected', async () => {
    envMock.OID4VP_VERIFIER_PROFILE = undefined;
    const { fastify, routes } = makeFastify();
    await walletLoginRoute(fastify);

    const { reply, state } = createReply();
    await routes.get('GET /wallet-login')!({ query: {}, headers: {}, ip: '127.0.0.1' }, reply);

    expect(state.statusCode).toBe(404);
    expect(state.body as string).toContain('not available');
    expect(state.body as string).not.toContain('name="identifier"');
  });

  it('refuses to start a flow when no credential type is configured', async () => {
    envMock.OID4VP_REQUESTED_VCT = undefined;
    const { fastify, routes } = makeFastify();
    await walletLoginRoute(fastify);

    const { reply, state } = createReply();
    await routes.get('POST /wallet-login')!(
      { body: { identifier: 'a@b.example', csrf_token: 'x' }, headers: {}, ip: '127.0.0.1' },
      reply
    );

    expect(state.statusCode).toBe(404);
    expect(fastify.repositories.oid4vpRequestStates.create).not.toHaveBeenCalled();
  });

  it('offers the login-page entry point only when the flow can be served', async () => {
    const offered = makeFastify();
    await loginRoute(offered.fastify);
    const shown = createReply();
    await offered.routes.get('GET /login')!(
      { query: {}, headers: {}, ip: '127.0.0.1' },
      shown.reply
    );
    expect(shown.state.body as string).toContain('/ui/wallet-login');

    envMock.OID4VP_VERIFIER_PROFILE = undefined;
    const hidden = makeFastify();
    await loginRoute(hidden.fastify);
    const notShown = createReply();
    await hidden.routes.get('GET /login')!(
      { query: {}, headers: {}, ip: '127.0.0.1' },
      notShown.reply
    );
    expect(notShown.state.body as string).not.toContain('/ui/wallet-login');
  });
});

describe('wallet login — the asserted identifier (ADR-009 §1)', () => {
  it('renders a REQUIRED identifier field: there is no usernameless wallet login', async () => {
    const { fastify, routes } = makeFastify();
    await walletLoginRoute(fastify);

    const { reply, state } = createReply();
    await routes.get('GET /wallet-login')!({ query: {}, headers: {}, ip: '127.0.0.1' }, reply);

    const body = state.body as string;
    expect(body).toContain('name="identifier"');
    expect(body).toContain('required');
    expect(body).toContain('name="csrf_token"');
  });

  it('normalizes the asserted identifier the way the password provider does', async () => {
    const { flow } = await startFlow({ identifier: '  User@Example.COM ' });
    expect(flow.assertedIdentifier).toBe('user@example.com');
  });

  it('never looks the identifier up while starting the flow (no account oracle)', async () => {
    const { fastify } = await startFlow({ identifier: 'nobody@example.com' });
    expect(fastify.repositories.userCredentials.findByRealmProviderSub).not.toHaveBeenCalled();
    expect(fastify.repositories.users.findById).not.toHaveBeenCalled();
  });
});

describe('wallet login — CSRF and the browser binder', () => {
  it('rejects a POST whose CSRF token does not match the cookie, before any DB write', async () => {
    const { fastify, routes } = makeFastify();
    await walletLoginRoute(fastify);

    const { reply, state } = createReply();
    await routes.get('POST /wallet-login')!(
      {
        body: { identifier: 'user@example.com', csrf_token: 'forged' },
        headers: {},
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.statusCode).toBe(403);
    expect(fastify.repositories.oid4vpRequestStates.create).not.toHaveBeenCalled();
    const events = (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls.map(
      (c) => (c[0] as { event: string }).event
    );
    expect(events).toContain('ui.wallet_login.csrf_failure');
  });

  it('binds the flow to the browser: another browser cannot advance it', async () => {
    const { routes, sessionUtils, handle, flow } = await startFlow();
    publishSignal(sessionUtils, flow.stateHash, 'received');
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue({
      status: 'authenticated',
      userId: 'user-1',
      externalSub: 'user@example.com',
    });

    const { reply, state } = createReply();
    await routes.get('GET /wallet-login/:handle/status')!(
      { params: { handle }, headers: {}, ip: '203.0.113.9' },
      reply
    );

    // No binder cookie: indistinguishable from an expired flow, and no session.
    expect(state.body.status).toBe('expired');
    expect(resolveWalletPresentation).not.toHaveBeenCalled();
  });

  it('treats a valid-looking but wrong binder as expired', async () => {
    const { routes, handle } = await startFlow();

    const { reply, state } = createReply();
    await routes.get('GET /wallet-login/:handle/status')!(
      {
        params: { handle },
        headers: { cookie: '__Host-qauth_wallet_flow=someoneelse.badsignature' },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.body.status).toBe('expired');
  });
});

describe('wallet login — the wallet invocation (QR + deep link)', () => {
  it('renders a QR code and a deep link carrying the invocation the backend built', async () => {
    const { postReply, flow } = await startFlow();
    const body = postReply.state.body as string;

    expect(flow.invocationUri.startsWith('openid4vp://?')).toBe(true);
    expect(flow.invocationUri).toContain('response_type=vp_token');
    expect(flow.invocationUri).toContain('response_mode=direct_post');
    // OID4VP 1.0 §8.2 — direct_post carries response_uri and never redirect_uri
    // as a parameter (the prefix inside client_id is a different thing).
    expect(flow.invocationUri).toContain('response_uri=');
    expect(flow.invocationUri).not.toContain('&redirect_uri=');

    expect(body).toContain('<svg ');
    expect(body).toContain('role="img"');
    // The deep link is the same opaque URI, HTML-escaped into the href.
    expect(body).toContain('Open my wallet');
    expect(body).toContain('openid4vp://?');
  });

  it.each([
    'openid4vp://',
    'haip://',
    'eudi-wallet://authorize',
    'https://wallet.example/authorize',
  ])('keeps the deep link for the genuine wallet scheme %j', async (endpoint) => {
    envMock.OID4VP_WALLET_INVOCATION_ENDPOINT = endpoint;
    const { postReply } = await startFlow();
    const body = postReply.state.body as string;

    // The point of the denylist: an open-ended set of wallet schemes still
    // renders. A fix that only permitted https would delete the feature.
    expect(body).toContain('Open my wallet');
    expect(body).toContain(`href="${endpoint}`);
  });

  /**
   * `OID4VP_WALLET_INVOCATION_ENDPOINT` is interpolated straight into this
   * screen's `href`, and `esc()` does nothing to `javascript:alert(1)` — it
   * contains no character HTML-escaping touches. `federationEnvSchema` refuses
   * such a value at boot, so this can only be reached by feeding the screen a
   * URI from elsewhere; the render path must refuse it on its own regardless.
   */
  it.each([
    'javascript:alert(document.domain)//',
    'JavaScript:alert(1)//',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
    'java\tscript:alert(1)//',
    '&#106;avascript:alert(1)//',
    'javascript&colon;alert(1)//',
  ])('never renders %j as a clickable href', async (endpoint) => {
    envMock.OID4VP_WALLET_INVOCATION_ENDPOINT = endpoint;
    const { postReply } = await startFlow();
    const body = postReply.state.body as string;

    expect(body).not.toContain('Open my wallet');
    expect(body).not.toContain(`href="${endpoint}`);
    expect(body).not.toMatch(/href="[^"]*(?:javascript|vbscript|data)/i);
    // The screen still renders rather than 500ing — it just offers no link.
    expect(body).toContain('Present a credential');
  });

  it('persists the request state hashed, with the profile and DCQL query it sent', async () => {
    const { fastify, flow } = await startFlow();
    const row = (fastify.repositories.oid4vpRequestStates.create as unknown as Mock).mock
      .calls[0][0];

    expect(row.realmId).toBe('realm-1');
    expect(row.stateHash).toBe(flow.stateHash);
    expect(row.stateHash).toMatch(/^[0-9a-f]{64}$/);
    expect(row.verifierProfile).toBe('oid4vp-1.0-base');
    expect(row.responseMode).toBe('direct_post');
    expect(row.dcqlQuery.credentials[0].meta.vct_values).toEqual(['urn:example:pid']);
    // The raw `state` is never handed to the repository.
    expect(JSON.stringify(row)).not.toContain(
      flow.invocationUri.split('state=')[1]?.split('&')[0] ?? 'unreachable'
    );
  });

  it('polls a same-origin status endpoint from a nonced inline script', async () => {
    const { postReply, handle } = await startFlow();
    const body = postReply.state.body as string;
    expect(body).toContain('<script nonce="test-script-nonce">');
    expect(body).toContain(`/ui/wallet-login/${handle}/status`);
    expect(body).toContain('<noscript>');
    expect(body).toContain('aria-live="polite"');
  });
});

describe('wallet login — completion', () => {
  it('completes the sign-in when the presentation resolves to an enabled user', async () => {
    const { fastify, routes, sessionUtils, handle, flow, binderCookie } = await startFlow({
      returnTo: '/ui/consent?client_id=abc',
    });
    publishSignal(sessionUtils, flow.stateHash, 'received');
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue({
      status: 'authenticated',
      userId: 'user-1',
      externalSub: 'user@example.com',
    });

    const { reply, state } = createReply();
    await routes.get('GET /wallet-login/:handle/status')!(
      {
        params: { handle },
        headers: { cookie: `__Host-qauth_wallet_flow=${binderCookie}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.body.status).toBe('complete');
    expect(state.body.redirect_to).toBe('/ui/consent?client_id=abc');
    expect(state.setCookies.some((c) => c.startsWith('__Host-qauth_session='))).toBe(true);
    expect(fastify.repositories.users.updateLastLogin).toHaveBeenCalledWith('user-1');

    const events = (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls.map(
      (c) => (c[0] as { event: string }).event
    );
    expect(events).toContain('ui.wallet_login.success');

    // Terminal: the flow and its signal are gone, so it cannot be replayed.
    expect([...sessionUtils.store.keys()].some((k) => k.startsWith('wallet-login:'))).toBe(false);
    expect([...sessionUtils.store.keys()].some((k) => k.startsWith('wallet-login-signal:'))).toBe(
      false
    );
  });

  it('mints a FRESH session id rather than reusing anything the browser had', async () => {
    const { fastify, routes, sessionUtils, handle, flow, binderCookie } = await startFlow();
    publishSignal(sessionUtils, flow.stateHash, 'received');
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue({
      status: 'authenticated',
      userId: 'user-1',
      externalSub: 'user@example.com',
    });

    const { reply } = createReply();
    await routes.get('GET /wallet-login/:handle/status')!(
      {
        params: { handle },
        headers: {
          cookie: `__Host-qauth_wallet_flow=${binderCookie}; __Host-qauth_session=attacker-fixed.sig`,
        },
        ip: '127.0.0.1',
      },
      reply
    );

    const [sessionId, payload] = (fastify.sessionUtils.setSession as unknown as Mock).mock.calls
      .map((c) => [c[0], c[1]] as [string, any])
      .find(([key]) => !key.startsWith('wallet-login'))!;
    expect(sessionId).not.toBe('attacker-fixed');
    expect(payload.userId).toBe('user-1');
    expect(payload.email).toBe('user@example.com');
  });

  it('redirects on the no-JavaScript refresh path instead of answering JSON', async () => {
    const { routes, sessionUtils, handle, flow, binderCookie } = await startFlow();
    publishSignal(sessionUtils, flow.stateHash, 'received');
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue({
      status: 'authenticated',
      userId: 'user-1',
      externalSub: 'user@example.com',
    });

    const { reply, state } = createReply();
    await routes.get('GET /wallet-login/:handle')!(
      {
        params: { handle },
        headers: { cookie: `__Host-qauth_wallet_flow=${binderCookie}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.statusCode).toBe(302);
    expect(state.redirected).toBe('/');
  });

  it('reports pending while no wallet response has arrived', async () => {
    const { routes, handle, binderCookie } = await startFlow();

    const { reply, state } = createReply();
    await routes.get('GET /wallet-login/:handle/status')!(
      {
        params: { handle },
        headers: { cookie: `__Host-qauth_wallet_flow=${binderCookie}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.body).toEqual({ status: 'pending' });
    expect(resolveWalletPresentation).not.toHaveBeenCalled();
  });
});

/**
 * Two flows, one browser.
 *
 * The binder is per FLOW, not per browser. A single cookie value would be
 * overwritten by the second `POST /ui/wallet-login` — and since a MISSING binder
 * and a WRONG one are deliberately indistinguishable from an expiry, the first
 * flow would then answer "this sign-in request has expired" while its QR was
 * still on screen and its presentation request still live. Scanning that QR
 * burns the single-use `state` for a flow no surface can read, so the user is
 * never signed in and cannot retry the code in front of them.
 */
describe('wallet login — concurrent flows in one browser', () => {
  it('leaves BOTH flows pollable, re-renderable and completable', async () => {
    const first = await startFlow({ returnTo: '/first' });
    const second = await startFlow({
      context: first.context,
      returnTo: '/second',
      walletFlowCookie: first.binderCookie,
    });

    expect(second.handle).not.toBe(first.handle);
    const { routes, sessionUtils } = first.context;
    const cookie = `__Host-qauth_wallet_flow=${second.binderCookie}`;

    // (1) The FIRST flow still polls as pending — it was not unbound.
    for (const handle of [first.handle, second.handle]) {
      const polled = createReply();
      await routes.get('GET /wallet-login/:handle/status')!(
        { params: { handle }, headers: { cookie }, ip: '127.0.0.1' },
        polled.reply
      );
      expect(polled.state.body).toEqual({ status: 'pending' });
    }

    // (2) The noscript refresh path re-renders each of them from its record.
    for (const handle of [first.handle, second.handle]) {
      const rendered = createReply();
      await routes.get('GET /wallet-login/:handle')!(
        { params: { handle }, headers: { cookie }, ip: '127.0.0.1' },
        rendered.reply
      );
      expect(rendered.state.body as string).toContain('Present a credential');
      expect(rendered.state.body as string).toContain(`/ui/wallet-login/${handle}/status`);
    }

    // (3) Either wallet may answer first, and completing one must not strand
    // the other: only the completed flow's binding is burned.
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue({
      status: 'authenticated',
      userId: 'user-1',
      externalSub: 'user@example.com',
    });

    publishSignal(sessionUtils, first.flow.stateHash, 'received');
    const firstDone = createReply();
    await routes.get('GET /wallet-login/:handle/status')!(
      { params: { handle: first.handle }, headers: { cookie }, ip: '127.0.0.1' },
      firstDone.reply
    );
    expect(firstDone.state.body).toEqual({ status: 'complete', redirect_to: '/first' });

    const survivingCookie = cookieValue(firstDone.state.setCookies, '__Host-qauth_wallet_flow');
    publishSignal(sessionUtils, second.flow.stateHash, 'received');
    const secondDone = createReply();
    await routes.get('GET /wallet-login/:handle/status')!(
      {
        params: { handle: second.handle },
        headers: { cookie: `__Host-qauth_wallet_flow=${survivingCookie}` },
        ip: '127.0.0.1',
      },
      secondDone.reply
    );
    expect(secondDone.state.body).toEqual({ status: 'complete', redirect_to: '/second' });
  });

  it('bounds the cookie: the oldest binding is evicted, never appended forever', async () => {
    let cookie: string | undefined;
    const handles: string[] = [];
    const context = makeFastify();
    await walletLoginRoute(context.fastify);

    for (let i = 0; i < WALLET_FLOW_COOKIE_MAX_BINDINGS + 1; i += 1) {
      const started = await startFlow({ context, walletFlowCookie: cookie });
      handles.push(started.handle);
      cookie = started.binderCookie;
    }

    const bindings = readWalletFlowBindings(cookie);
    expect(bindings).toHaveLength(WALLET_FLOW_COOKIE_MAX_BINDINGS);
    expect(bindings.map((b) => b.handle)).toEqual(handles.slice(1));
  });
});

describe('wallet login — refusals do not enumerate or leak (#236)', () => {
  it('gives an unresolvable presentation, a disabled user and a wallet error the same answer', async () => {
    const answers: string[] = [];

    // (1) The presentation cannot be resolved (today: always).
    {
      const { routes, sessionUtils, handle, flow, binderCookie } = await startFlow();
      publishSignal(sessionUtils, flow.stateHash, 'received');
      const { reply, state } = createReply();
      await routes.get('GET /wallet-login/:handle/status')!(
        {
          params: { handle },
          headers: { cookie: `__Host-qauth_wallet_flow=${binderCookie}` },
          ip: '127.0.0.1',
        },
        reply
      );
      answers.push(`${state.body.status}:${state.body.message}`);
    }

    // (2) It resolves, but to a disabled account.
    {
      const { fastify, routes, sessionUtils, handle, flow, binderCookie } = await startFlow();
      publishSignal(sessionUtils, flow.stateHash, 'received');
      (resolveWalletPresentation as unknown as Mock).mockResolvedValue({
        status: 'authenticated',
        userId: 'user-1',
        externalSub: 'user@example.com',
      });
      (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
        id: 'user-1',
        enabled: false,
      });
      const { reply, state } = createReply();
      await routes.get('GET /wallet-login/:handle/status')!(
        {
          params: { handle },
          headers: { cookie: `__Host-qauth_wallet_flow=${binderCookie}` },
          ip: '127.0.0.1',
        },
        reply
      );
      answers.push(`${state.body.status}:${state.body.message}`);
      expect(state.setCookies.some((c) => c.startsWith('__Host-qauth_session='))).toBe(false);
    }

    // (3) The wallet itself returned an error.
    {
      const { routes, sessionUtils, handle, flow, binderCookie } = await startFlow();
      publishSignal(sessionUtils, flow.stateHash, 'wallet_error');
      const { reply, state } = createReply();
      await routes.get('GET /wallet-login/:handle/status')!(
        {
          params: { handle },
          headers: { cookie: `__Host-qauth_wallet_flow=${binderCookie}` },
          ip: '127.0.0.1',
        },
        reply
      );
      answers.push(`${state.body.status}:${state.body.message}`);
    }

    expect(new Set(answers).size).toBe(1);
    expect(answers[0]).toBe(`rejected:${WALLET_LOGIN_REFUSAL}`);
  });

  it('reports an expired flow for an unknown handle and for a real expired one alike', async () => {
    const { fastify, routes } = makeFastify();
    await walletLoginRoute(fastify);

    const unknown = createReply();
    await routes.get('GET /wallet-login/:handle/status')!(
      { params: { handle: 'A'.repeat(43) }, headers: {}, ip: '127.0.0.1' },
      unknown.reply
    );

    const expired = await startFlow();
    (expired.flow as Record<string, unknown>).expiresAt = Date.now() - 1;
    const timedOut = createReply();
    await expired.routes.get('GET /wallet-login/:handle/status')!(
      {
        params: { handle: expired.handle },
        headers: { cookie: `__Host-qauth_wallet_flow=${expired.binderCookie}` },
        ip: '127.0.0.1',
      },
      timedOut.reply
    );

    expect(unknown.state.body).toEqual(timedOut.state.body);
    expect(timedOut.state.body).toEqual({ status: 'expired', message: WALLET_LOGIN_EXPIRED });
  });

  it('never echoes the asserted identifier into a terminal page', async () => {
    const { routes, sessionUtils, handle, flow, binderCookie } = await startFlow({
      identifier: 'victim@example.com',
    });
    publishSignal(sessionUtils, flow.stateHash, 'received');

    const { reply, state } = createReply();
    await routes.get('GET /wallet-login/:handle')!(
      {
        params: { handle },
        headers: { cookie: `__Host-qauth_wallet_flow=${binderCookie}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.statusCode).toBe(401);
    expect(state.body as string).toContain(WALLET_LOGIN_REFUSAL);
    expect(state.body as string).not.toContain('victim@example.com');
  });
});

describe('wallet login — return_to open-redirect guard', () => {
  const UNSAFE = [
    'https://evil.example/steal',
    '//evil.example',
    '/\\evil.example',
    // The URL parser strips tab/LF/CR before parsing, so these read as a single
    // leading `/` here and are protocol-relative by the time a browser resolves
    // them. See `helpers/return-to.test.ts`.
    '/\t/evil.example',
    '/\n/evil.example',
    '/\r/evil.example',
    '/\t\\evil.example',
    'nope',
    '',
  ];

  it.each(UNSAFE)('falls back to "/" for return_to=%j', async (returnTo) => {
    const { flow } = await startFlow({ returnTo });
    expect(flow.returnTo).toBe('/');
  });

  it('keeps a safe relative path', async () => {
    const { flow } = await startFlow({ returnTo: '/oauth/authorize?client_id=abc' });
    expect(flow.returnTo).toBe('/oauth/authorize?client_id=abc');
  });
});

describe('wallet login — a LINK flow may never complete here (#238)', () => {
  it('refuses a link-mode flow instead of minting a session for its user', async () => {
    // The mode discriminator, from the login side. A linking flow is started by
    // an already-authenticated session, so its handle is not a login proof —
    // completing it here would sign this browser in as the linking user with no
    // credential of that account having been checked.
    const { routes, sessionUtils, handle, flow, binderCookie } = await startFlow();
    sessionUtils.store.set(`wallet-login:${handle}`, {
      ...flow,
      mode: 'link',
      linkUserId: 'user-1',
    });
    publishSignal(sessionUtils, flow.stateHash, 'received');
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue({
      status: 'authenticated',
      userId: 'user-1',
      externalSub: 'user@example.com',
    });

    const { reply, state } = createReply();
    await routes.get('GET /wallet-login/:handle')!(
      {
        params: { handle },
        headers: { cookie: `__Host-qauth_wallet_flow=${binderCookie}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.statusCode).toBe(401);
    expect(resolveWalletPresentation).not.toHaveBeenCalled();
    expect(state.setCookies.some((c) => c.startsWith('__Host-qauth_session='))).toBe(false);
  });

  it('still completes an ordinary login flow, so the guard refuses only what it should', async () => {
    const { routes, sessionUtils, handle, flow, binderCookie } = await startFlow();
    publishSignal(sessionUtils, flow.stateHash, 'received');
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue({
      status: 'authenticated',
      userId: 'user-1',
      externalSub: 'user@example.com',
    });

    const { reply, state } = createReply();
    await routes.get('GET /wallet-login/:handle')!(
      {
        params: { handle },
        headers: { cookie: `__Host-qauth_wallet_flow=${binderCookie}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.statusCode).toBe(302);
    expect(state.setCookies.some((c) => c.startsWith('__Host-qauth_session='))).toBe(true);
  });
});
