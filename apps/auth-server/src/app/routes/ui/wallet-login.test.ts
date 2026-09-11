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

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../helpers/wallet-presentation', () => ({
  resolveWalletPresentation: vi.fn().mockResolvedValue({ status: 'rejected' }),
}));

import {
  generateOid4vpResponseCode,
  hashOid4vpResponseCode,
} from '@qauth-labs/fastify-plugin-federation';

import { WALLET_RETURN_CODE_TTL_MS } from '../../constants';
import {
  readWalletFlowBindings,
  WALLET_FLOW_COOKIE_MAX_BINDINGS,
} from '../../helpers/session-cookie';
import { WALLET_LOGIN_RETURN_PATH } from '../../helpers/wallet-login-request';
import { resolveWalletPresentation } from '../../helpers/wallet-presentation';
import {
  WALLET_RETURN_REFUSAL,
  walletReturnRefusalPage,
  walletSignedInPage,
  walletTerminalPage,
} from '../../helpers/wallet-ui';
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

/**
 * Stand-in for the repository's `redeemResponseCode` (#405): ONE guarded
 * consume, keyed by the code's sha256 digest exactly as the real statement is.
 * Single-use (the entry is deleted on the first hit), deadline-checked, and
 * `undefined` for anything else — unknown, expired and replayed are one answer,
 * as the repository's own tests pin. `sameDevice` is not modelled here: the
 * route never learns it, and the repository test is where that predicate lives.
 */
function createResponseCodes() {
  const codes = new Map<string, { stateHash: string; expiresAt: number }>();
  return {
    codes,
    redeemResponseCode: vi.fn(async (codeHash: string) => {
      const entry = codes.get(codeHash);
      if (entry === undefined || entry.expiresAt <= Date.now()) return undefined;
      codes.delete(codeHash);
      return { stateHash: entry.stateHash };
    }),
  };
}

function makeFastify() {
  const routes = new Map<string, Handler>();
  const sessionUtils = createSessionUtils();
  const responseCodes = createResponseCodes();
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
        redeemResponseCode: responseCodes.redeemResponseCode,
      },
      auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
    },
    passwordHasher: { verifyPassword: vi.fn() },
    providerRegistry: { resolve: vi.fn(), has: vi.fn().mockReturnValue(true), register: vi.fn() },
    sessionUtils,
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, routes, sessionUtils, responseCodes };
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
    /** Which submit button was pressed (#405). Absent = the field was not sent. */
    device?: 'this' | 'other';
  } = {}
) {
  const context = overrides.context ?? makeFastify();
  const { fastify, routes, sessionUtils, responseCodes } = context;
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
        ...(overrides.device === undefined ? {} : { device: overrides.device }),
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

  return {
    context,
    fastify,
    routes,
    sessionUtils,
    responseCodes,
    postReply,
    handle,
    flow,
    binderCookie,
  };
}

/**
 * Simulate the direct_post endpoint publishing its transport signal. `at`
 * defaults to now; a test that needs the same-device deadline to have passed
 * backdates it rather than faking the clock.
 */
function publishSignal(
  sessionUtils: ReturnType<typeof createSessionUtils>,
  stateHash: string,
  signal: string,
  at: number = Date.now()
) {
  sessionUtils.store.set(`wallet-login-signal:${stateHash}`, { signal, at });
}

/**
 * Simulate the direct_post endpoint minting a Response Code for a same-device
 * row (#405): the code the wallet is handed in `redirect_uri`, whose DIGEST the
 * repository holds. Returns the raw code, as the wallet's browser would carry it.
 */
function issueResponseCode(
  responseCodes: ReturnType<typeof createResponseCodes>,
  stateHash: string,
  expiresAt: number = Date.now() + WALLET_RETURN_CODE_TTL_MS
): string {
  const code = generateOid4vpResponseCode();
  responseCodes.codes.set(hashOid4vpResponseCode(code), { stateHash, expiresAt });
  return code;
}

/** Drive the wallet's browser onto the return leg. */
async function followReturn(routes: Map<string, Handler>, responseCode: unknown, cookie?: string) {
  const { reply, state } = createReply();
  await routes.get('GET /wallet-login/return')!(
    {
      query: responseCode === undefined ? {} : { response_code: responseCode },
      headers: cookie === undefined ? {} : { cookie },
      ip: '127.0.0.1',
    },
    reply
  );
  return state;
}

/** Poll the status endpoint as the ORIGINAL tab. */
async function pollStatus(routes: Map<string, Handler>, handle: string, cookie?: string) {
  const { reply, state } = createReply();
  await routes.get('GET /wallet-login/:handle/status')!(
    { params: { handle }, headers: cookie === undefined ? {} : { cookie }, ip: '127.0.0.1' },
    reply
  );
  return state;
}

/** The one refusal page the return route renders, with the stub's nonces. */
const REFUSAL_PAGE = walletReturnRefusalPage({
  cspNonce: 'test-style-nonce',
  scriptNonce: 'test-script-nonce',
  returnPath: WALLET_LOGIN_RETURN_PATH,
});

const AUTHENTICATED = {
  status: 'authenticated',
  userId: 'user-1',
  externalSub: 'user@example.com',
};

/** Session-store writes that are browser SESSIONS, not flow/marker records. */
function sessionMints(fastify: FastifyInstance): string[] {
  return (fastify.sessionUtils.setSession as unknown as Mock).mock.calls
    .map((c) => c[0] as string)
    .filter((key) => !key.startsWith('wallet-'));
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
  it('renders a QR code carrying the invocation the backend built (cross-device)', async () => {
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
  });

  it('renders a deep link carrying the same opaque invocation (same-device)', async () => {
    const { postReply, flow } = await startFlow({ device: 'this' });
    const body = postReply.state.body as string;

    // The deep link is the same opaque URI, HTML-escaped into the href.
    expect(body).toContain('Open my wallet');
    expect(body).toContain('openid4vp://?');
    expect(body).toContain(`href="${flow.invocationUri.replace(/&/g, '&amp;')}"`);
  });

  it.each([
    'openid4vp://',
    'haip://',
    'eudi-wallet://authorize',
    'https://wallet.example/authorize',
  ])('keeps the deep link for the genuine wallet scheme %j', async (endpoint) => {
    envMock.OID4VP_WALLET_INVOCATION_ENDPOINT = endpoint;
    const { postReply } = await startFlow({ device: 'this' });
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
    // Same-device: the one variant that renders an href at all.
    const { postReply } = await startFlow({ device: 'this' });
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

  it.each([
    ['high', 'high', 'high'],
    ['substantial', 'substantial', 'substantial'],
    // Nothing established → the field must be ABSENT, so the session is
    // indistinguishable from a password login and /oauth/authorize records
    // NULL. Storing `'low'` would give "no assurance" two representations.
    ['low', 'low', undefined],
    ['no level at all', undefined, undefined],
  ])(
    'carries an assurance level of %s from the presentation onto the browser session (#237)',
    async (_label, resolved, expected) => {
      const { fastify, routes, sessionUtils, handle, flow, binderCookie } = await startFlow();
      publishSignal(sessionUtils, flow.stateHash, 'received');
      (resolveWalletPresentation as unknown as Mock).mockResolvedValue({
        status: 'authenticated',
        userId: 'user-1',
        externalSub: 'user@example.com',
        ...(resolved === undefined ? {} : { assuranceLevel: resolved }),
      });

      const { reply } = createReply();
      await routes.get('GET /wallet-login/:handle/status')!(
        {
          params: { handle },
          headers: { cookie: `__Host-qauth_wallet_flow=${binderCookie}` },
          ip: '127.0.0.1',
        },
        reply
      );

      const [, payload] = (fastify.sessionUtils.setSession as unknown as Mock).mock.calls
        .map((c) => [c[0], c[1]] as [string, any])
        .find(([key]) => !key.startsWith('wallet-login'))!;
      expect(payload.assuranceLevel).toBe(expected);
    }
  );

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

/**
 * The same-device return leg (#405, ADR-013).
 *
 * Titles are conformance evidence: each cites the spec alias and section the
 * matrix row pins, and the assertions are the observable form of that row.
 * The Response Endpoint is not driven here — its own suite pins that it hands
 * a `redirect_uri` only to a same-device row — so a wallet answering is
 * simulated by `publishSignal` + `issueResponseCode`, and the wallet's browser
 * following the redirect by `followReturn`.
 */
describe('wallet login — the device choice at flow start (#405)', () => {
  it('defaults an absent device field to cross-device', async () => {
    const { fastify, flow } = await startFlow();
    const row = (fastify.repositories.oid4vpRequestStates.create as unknown as Mock).mock
      .calls[0][0];

    expect(row.sameDevice).toBe(false);
    expect(flow.sameDevice).toBeUndefined();
  });

  it('(HAIP 1.0 §5.1) records the same-device choice on both the request-state row and the flow record', async () => {
    const { fastify, flow } = await startFlow({ device: 'this' });
    const row = (fastify.repositories.oid4vpRequestStates.create as unknown as Mock).mock
      .calls[0][0];

    expect(row.sameDevice).toBe(true);
    expect(flow.sameDevice).toBe(true);
    // Written together, from one choice: neither side can be same-device alone.
    expect(row.stateHash).toBe(flow.stateHash);
  });

  it('offers both device choices on the identifier form, as plain submit buttons', async () => {
    const { fastify, routes } = makeFastify();
    await walletLoginRoute(fastify);

    const { reply, state } = createReply();
    await routes.get('GET /wallet-login')!({ query: {}, headers: {}, ip: '127.0.0.1' }, reply);

    const body = state.body as string;
    expect(body).toContain('name="device" value="this"');
    expect(body).toContain('name="device" value="other"');
    expect(body).toContain('Use a wallet on this device');
    expect(body).toContain('Scan with a wallet on another device');
  });

  it('renders only the deep link for a same-device flow and only the QR for a cross-device flow', async () => {
    const same = await startFlow({ device: 'this', returnTo: '/after' });
    const cross = await startFlow({ device: 'other', returnTo: '/after' });
    const sameBody = same.postReply.state.body as string;
    const crossBody = cross.postReply.state.body as string;

    expect(sameBody).toContain('Open my wallet');
    expect(sameBody).toContain('href="openid4vp://?');
    expect(sameBody).not.toContain('<svg ');
    expect(sameBody).toContain('will bring you back here');

    expect(crossBody).toContain('<svg ');
    expect(crossBody).not.toContain('Open my wallet');
    expect(crossBody).not.toContain('href="openid4vp://');
    expect(crossBody).toContain('Waiting for your wallet');

    // Both variants: the poller, the password footer, and a way to start over
    // with the OTHER choice available.
    for (const body of [sameBody, crossBody]) {
      expect(body).toContain('/status');
      expect(body).toContain('Cancel and sign in with a password');
      expect(body).toContain('href="/ui/wallet-login?return_to=%2Fafter">Start again</a>');
    }

    // The noscript re-render keeps the variant the flow was started with.
    const rerender = createReply();
    await same.routes.get('GET /wallet-login/:handle')!(
      {
        params: { handle: same.handle },
        headers: { cookie: `__Host-qauth_wallet_flow=${same.binderCookie}` },
        ip: '127.0.0.1',
      },
      rerender.reply
    );
    expect(rerender.state.body as string).toContain('Open my wallet');
    expect(rerender.state.body as string).not.toContain('<svg ');
  });

  it('renders an explanation, not a deep link, when a cross-device request is too large for a QR code', async () => {
    // Past `QR_MAX_BYTES` (2331) by construction.
    envMock.OID4VP_WALLET_INVOCATION_ENDPOINT = `openid4vp://${'x'.repeat(2500)}`;
    const { postReply } = await startFlow({ device: 'other', returnTo: '/after' });
    const body = postReply.state.body as string;

    expect(body).not.toContain('<svg ');
    expect(body).not.toContain('Open my wallet');
    expect(body).toContain('too large to show as a code');
    expect(body).toContain('href="/ui/wallet-login?return_to=%2Fafter"');
    expect(body).toContain('Present a credential');
  });
});

describe('wallet login — same-device flows never complete by polling (#405)', () => {
  it('(OID4VP 1.0 §14.2) the poll never completes a same-device flow — it stays pending after the presentation arrives until the return leg lands', async () => {
    const { fastify, routes, sessionUtils, handle, flow, binderCookie } = await startFlow({
      device: 'this',
    });
    publishSignal(sessionUtils, flow.stateHash, 'received');
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue(AUTHENTICATED);
    const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;

    // JSON poll and the noscript re-render alike.
    const polled = await pollStatus(routes, handle, cookie);
    expect(polled.body).toEqual({ status: 'pending' });

    const rerender = createReply();
    await routes.get('GET /wallet-login/:handle')!(
      { params: { handle }, headers: { cookie }, ip: '127.0.0.1' },
      rerender.reply
    );
    expect(rerender.state.body as string).toContain('Present a credential');

    expect(resolveWalletPresentation).not.toHaveBeenCalled();
    expect(sessionMints(fastify)).toEqual([]);
    expect(polled.setCookies.some((c) => c.startsWith('__Host-qauth_session='))).toBe(false);
    // The flow and its signal are still there: nothing was terminated.
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(true);
    expect(sessionUtils.store.has(`wallet-login-signal:${flow.stateHash}`)).toBe(true);
  });

  it('(HAIP 1.0 §5.1) rejects a same-device presentation whose redirect was never followed once the Response Code deadline passes', async () => {
    const { fastify, routes, sessionUtils, handle, flow, binderCookie } = await startFlow({
      device: 'this',
    });
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue(AUTHENTICATED);
    const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;

    // One millisecond inside the window: still waiting for the wallet.
    publishSignal(
      sessionUtils,
      flow.stateHash,
      'received',
      Date.now() - WALLET_RETURN_CODE_TTL_MS + 1000
    );
    expect((await pollStatus(routes, handle, cookie)).body).toEqual({ status: 'pending' });

    // Past it: the code the wallet was handed can no longer be redeemed, so
    // the presentation is rejected — actively, with a reason in the log.
    publishSignal(
      sessionUtils,
      flow.stateHash,
      'received',
      Date.now() - WALLET_RETURN_CODE_TTL_MS - 1
    );
    const rejected = await pollStatus(routes, handle, cookie);
    expect(rejected.body).toEqual({ status: 'rejected', message: WALLET_LOGIN_REFUSAL });
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.anything(),
      'same-device presentation rejected: redirect not followed'
    );

    expect(resolveWalletPresentation).not.toHaveBeenCalled();
    expect(sessionMints(fastify)).toEqual([]);
    // Terminal: flow, signal and stash are gone.
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
    expect(sessionUtils.store.has(`wallet-login-signal:${flow.stateHash}`)).toBe(false);
    expect((await pollStatus(routes, handle, cookie)).body.status).toBe('expired');
  });

  it('surfaces a wallet error on a same-device flow via the poll', async () => {
    const { routes, sessionUtils, handle, flow, binderCookie } = await startFlow({
      device: 'this',
    });
    publishSignal(sessionUtils, flow.stateHash, 'wallet_error');

    const polled = await pollStatus(routes, handle, `__Host-qauth_wallet_flow=${binderCookie}`);
    expect(polled.body).toEqual({ status: 'rejected', message: WALLET_LOGIN_REFUSAL });
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
  });

  it('cross-device flows still complete via the poll exactly as before', async () => {
    const { fastify, routes, sessionUtils, handle, flow, binderCookie } = await startFlow({
      device: 'other',
      returnTo: '/after',
    });
    publishSignal(sessionUtils, flow.stateHash, 'received');
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue(AUTHENTICATED);

    const polled = await pollStatus(routes, handle, `__Host-qauth_wallet_flow=${binderCookie}`);
    expect(polled.body).toEqual({ status: 'complete', redirect_to: '/after' });
    expect(polled.setCookies.some((c) => c.startsWith('__Host-qauth_session='))).toBe(true);
    // The binding is burned by the poll, as it always was.
    expect(polled.setCookies.some((c) => c.startsWith('__Host-qauth_wallet_flow='))).toBe(true);
    // No Response Code exists for a cross-device flow, and none is looked for.
    expect(fastify.repositories.oid4vpRequestStates.redeemResponseCode).not.toHaveBeenCalled();
    expect([...sessionUtils.store.keys()].some((k) => k.startsWith('wallet-login-done:'))).toBe(
      false
    );
  });
});

describe('wallet login — the return leg (#405)', () => {
  it('(OID4VP 1.0 §14.2, §14.3.3) the return leg completes a same-device flow only with the browser binder and a spent-once Response Code', async () => {
    const { fastify, routes, sessionUtils, responseCodes, handle, flow, binderCookie } =
      await startFlow({ device: 'this', returnTo: '/ui/consent?client_id=abc' });
    publishSignal(sessionUtils, flow.stateHash, 'received');
    const code = issueResponseCode(responseCodes, flow.stateHash);
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue(AUTHENTICATED);

    const landed = await followReturn(routes, code, `__Host-qauth_wallet_flow=${binderCookie}`);

    // The code was redeemed by DIGEST — the raw value never reaches the
    // repository — and exactly once.
    expect(fastify.repositories.oid4vpRequestStates.redeemResponseCode).toHaveBeenCalledTimes(1);
    expect(fastify.repositories.oid4vpRequestStates.redeemResponseCode).toHaveBeenCalledWith(
      hashOid4vpResponseCode(code)
    );
    expect(hashOid4vpResponseCode(code)).toMatch(/^[0-9a-f]{64}$/);

    // The session was minted exactly as by polling.
    expect(landed.statusCode).toBe(200);
    expect(landed.setCookies.some((c) => c.startsWith('__Host-qauth_session='))).toBe(true);
    expect(sessionMints(fastify)).toHaveLength(1);
    expect(fastify.repositories.users.updateLastLogin).toHaveBeenCalledWith('user-1');
    const events = (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls.map(
      (c) => (c[0] as { event: string }).event
    );
    expect(events).toContain('ui.wallet_login.success');

    // The signed-in page, byte for byte, with the ORIGINAL tab's continuation
    // only as a secondary link.
    expect(landed.body).toBe(
      walletSignedInPage({
        cspNonce: 'test-style-nonce',
        scriptNonce: 'test-script-nonce',
        redirectTo: '/ui/consent?client_id=abc',
        returnPath: WALLET_LOGIN_RETURN_PATH,
      })
    );
    expect(landed.redirected).toBeUndefined();
    expect(landed.body as string).toContain('history.replaceState');

    // The done-marker was written for the original tab, and the binding was
    // NOT dropped: that tab must still be able to prove it holds the flow.
    expect(sessionUtils.store.get(`wallet-login-done:${handle}`)).toEqual({
      binder: flow.binder,
      mode: 'login',
      redirectTo: '/ui/consent?client_id=abc',
    });
    expect(landed.setCookies.some((c) => c.startsWith('__Host-qauth_wallet_flow='))).toBe(false);

    // The flow itself is terminal.
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
    expect(sessionUtils.store.has(`wallet-login-signal:${flow.stateHash}`)).toBe(false);
  });

  it("(OID4VP 1.0 §14.2) the original tab's poll consumes the done-marker once — complete with redirect_to, then expired", async () => {
    const { fastify, routes, sessionUtils, responseCodes, handle, flow, binderCookie } =
      await startFlow({ device: 'this', returnTo: '/after' });
    publishSignal(sessionUtils, flow.stateHash, 'received');
    const code = issueResponseCode(responseCodes, flow.stateHash);
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue(AUTHENTICATED);
    const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;

    await followReturn(routes, code, cookie);
    expect(sessionMints(fastify)).toHaveLength(1);

    // A poll WITHOUT the binder learns nothing and burns nothing.
    expect((await pollStatus(routes, handle)).body.status).toBe('expired');
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(true);

    // The original tab: complete, with the flow's return_to, no second session,
    // and its binding dropped now that the marker is consumed.
    const first = await pollStatus(routes, handle, cookie);
    expect(first.body).toEqual({ status: 'complete', redirect_to: '/after' });
    expect(sessionMints(fastify)).toHaveLength(1);
    expect(first.setCookies.some((c) => c.startsWith('__Host-qauth_session='))).toBe(false);
    expect(first.setCookies.some((c) => c.startsWith('__Host-qauth_wallet_flow='))).toBe(true);
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(false);

    // Once.
    const second = await pollStatus(routes, handle, cookie);
    expect(second.body).toEqual({ status: 'expired', message: WALLET_LOGIN_EXPIRED });
  });

  it('refuses a malformed, unknown, expired or replayed Response Code with one identical page', async () => {
    const bodies: unknown[] = [];
    const statuses: unknown[] = [];

    // (1) Malformed: the repository is never asked.
    {
      const { fastify, routes, binderCookie } = await startFlow({ device: 'this' });
      for (const junk of [undefined, '', 'not-a-code', 'A'.repeat(42), 'A'.repeat(44)]) {
        const landed = await followReturn(routes, junk, `__Host-qauth_wallet_flow=${binderCookie}`);
        bodies.push(landed.body);
        statuses.push(landed.statusCode);
      }
      expect(fastify.repositories.oid4vpRequestStates.redeemResponseCode).not.toHaveBeenCalled();
    }

    // (2) Unknown: well-formed, never minted.
    {
      const { routes, binderCookie } = await startFlow({ device: 'this' });
      const landed = await followReturn(
        routes,
        generateOid4vpResponseCode(),
        `__Host-qauth_wallet_flow=${binderCookie}`
      );
      bodies.push(landed.body);
      statuses.push(landed.statusCode);
    }

    // (3) Expired: minted, but past its own deadline.
    {
      const { routes, sessionUtils, responseCodes, flow, binderCookie } = await startFlow({
        device: 'this',
      });
      publishSignal(sessionUtils, flow.stateHash, 'received');
      const code = issueResponseCode(responseCodes, flow.stateHash, Date.now() - 1);
      const landed = await followReturn(routes, code, `__Host-qauth_wallet_flow=${binderCookie}`);
      bodies.push(landed.body);
      statuses.push(landed.statusCode);
    }

    // (4) Replayed: a code that already completed its flow.
    {
      const { routes, sessionUtils, responseCodes, flow, binderCookie } = await startFlow({
        device: 'this',
      });
      publishSignal(sessionUtils, flow.stateHash, 'received');
      (resolveWalletPresentation as unknown as Mock).mockResolvedValue(AUTHENTICATED);
      const code = issueResponseCode(responseCodes, flow.stateHash);
      const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;
      expect((await followReturn(routes, code, cookie)).body as string).toContain('signed in');
      const landed = await followReturn(routes, code, cookie);
      bodies.push(landed.body);
      statuses.push(landed.statusCode);
    }

    expect(new Set(bodies).size).toBe(1);
    expect(bodies[0]).toBe(REFUSAL_PAGE);
    expect(new Set(statuses)).toEqual(new Set([200]));
    expect(REFUSAL_PAGE).toContain(WALLET_RETURN_REFUSAL.replace(/'/g, '&#39;'));
    expect(REFUSAL_PAGE).not.toContain('Try again');
    expect(REFUSAL_PAGE).toContain('Sign in with a password');
    expect(REFUSAL_PAGE).toContain('history.replaceState');
  });

  it('(HAIP 1.0 §5.1) rejects a presentation whose redirect back arrives in a different user session — spends the code, discards the presentation, and the initiating poll answers rejected', async () => {
    const { fastify, routes, sessionUtils, responseCodes, handle, flow, binderCookie } =
      await startFlow({ device: 'this' });
    publishSignal(sessionUtils, flow.stateHash, 'received');
    sessionUtils.store.set(`wallet-presentation:${flow.stateHash}`, {
      presentations: [{ format: 'dc+sd-jwt', compact: 'a.b.c' }],
      at: Date.now(),
    });
    const code = issueResponseCode(responseCodes, flow.stateHash);
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue(AUTHENTICATED);

    // The wallet opened a browser with an EMPTY cookie jar.
    const landed = await followReturn(routes, code);

    expect(landed.body).toBe(REFUSAL_PAGE);
    expect(landed.statusCode).toBe(200);
    expect(landed.setCookies.some((c) => c.startsWith('__Host-qauth_session='))).toBe(false);
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.anything(),
      'same-device return arrived in a foreign session'
    );

    // Spent: the same code in the RIGHT browser is refused too.
    expect(fastify.repositories.oid4vpRequestStates.redeemResponseCode).toHaveBeenCalledTimes(1);
    const replayed = await followReturn(routes, code, `__Host-qauth_wallet_flow=${binderCookie}`);
    expect(replayed.body).toBe(REFUSAL_PAGE);

    // Discarded: the parked bytes are gone and the signal says why.
    expect(sessionUtils.store.has(`wallet-presentation:${flow.stateHash}`)).toBe(false);
    expect(sessionUtils.store.get(`wallet-login-signal:${flow.stateHash}`)).toEqual({
      signal: 'return_rejected',
      at: expect.any(Number),
    });

    // The initiating tab is told, promptly, and nothing was ever minted.
    const polled = await pollStatus(routes, handle, `__Host-qauth_wallet_flow=${binderCookie}`);
    expect(polled.body).toEqual({ status: 'rejected', message: WALLET_LOGIN_REFUSAL });
    expect(resolveWalletPresentation).not.toHaveBeenCalled();
    expect(sessionMints(fastify)).toEqual([]);
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
  });

  it('refuses a login-mode return for a link-mode flow', async () => {
    const { fastify, routes, sessionUtils, responseCodes, handle, flow, binderCookie } =
      await startFlow({ device: 'this' });
    sessionUtils.store.set(`wallet-login:${handle}`, {
      ...flow,
      mode: 'link',
      linkUserId: 'user-1',
    });
    publishSignal(sessionUtils, flow.stateHash, 'received');
    const code = issueResponseCode(responseCodes, flow.stateHash);
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue(AUTHENTICATED);

    const landed = await followReturn(routes, code, `__Host-qauth_wallet_flow=${binderCookie}`);

    expect(landed.body).toBe(REFUSAL_PAGE);
    expect(landed.statusCode).toBe(200);
    expect(resolveWalletPresentation).not.toHaveBeenCalled();
    expect(sessionMints(fastify)).toEqual([]);
    expect(landed.setCookies.some((c) => c.startsWith('__Host-qauth_session='))).toBe(false);
    // The code is spent regardless: burn precedes bind.
    expect(fastify.repositories.oid4vpRequestStates.redeemResponseCode).toHaveBeenCalledTimes(1);
  });

  it('a rejected outcome after a spent code renders the existing refusal terminal page (401)', async () => {
    // The Response Endpoint hands out a redirect_uri on its wallet-error path
    // too (OID4VP 1.0 §8.2 "or for Error Responses"), so a same-device wallet
    // that declined still brings the browser here.
    const { fastify, routes, sessionUtils, responseCodes, handle, flow, binderCookie } =
      await startFlow({ device: 'this' });
    publishSignal(sessionUtils, flow.stateHash, 'wallet_error');
    const code = issueResponseCode(responseCodes, flow.stateHash);

    const landed = await followReturn(routes, code, `__Host-qauth_wallet_flow=${binderCookie}`);

    expect(landed.statusCode).toBe(401);
    expect(landed.body).toBe(
      walletTerminalPage({
        cspNonce: 'test-style-nonce',
        title: 'Sign-in was not completed',
        message: WALLET_LOGIN_REFUSAL,
        returnTo: '/',
        retry: true,
      })
    );
    expect(landed.setCookies.some((c) => c.startsWith('__Host-qauth_session='))).toBe(false);
    expect(sessionMints(fastify)).toEqual([]);
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);

    // Byte for byte what the page GET renders for the same outcome.
    const other = await startFlow({ device: 'this' });
    publishSignal(other.sessionUtils, other.flow.stateHash, 'wallet_error');
    const rendered = createReply();
    await other.routes.get('GET /wallet-login/:handle')!(
      {
        params: { handle: other.handle },
        headers: { cookie: `__Host-qauth_wallet_flow=${other.binderCookie}` },
        ip: '127.0.0.1',
      },
      rendered.reply
    );
    expect(rendered.state.statusCode).toBe(401);
    expect(rendered.state.body).toBe(landed.body);
  });

  it('sets Cache-Control: no-store and Referrer-Policy: no-referrer on every return-route response', async () => {
    const responses: ReturnType<typeof createReply>['state'][] = [];

    // Malformed, unknown and foreign refusals.
    {
      const { routes, sessionUtils, responseCodes, flow, binderCookie } = await startFlow({
        device: 'this',
      });
      responses.push(
        await followReturn(routes, 'junk', `__Host-qauth_wallet_flow=${binderCookie}`)
      );
      responses.push(
        await followReturn(
          routes,
          generateOid4vpResponseCode(),
          `__Host-qauth_wallet_flow=${binderCookie}`
        )
      );
      publishSignal(sessionUtils, flow.stateHash, 'received');
      responses.push(await followReturn(routes, issueResponseCode(responseCodes, flow.stateHash)));
    }
    // A completed return.
    {
      const { routes, sessionUtils, responseCodes, flow, binderCookie } = await startFlow({
        device: 'this',
      });
      publishSignal(sessionUtils, flow.stateHash, 'received');
      (resolveWalletPresentation as unknown as Mock).mockResolvedValue(AUTHENTICATED);
      responses.push(
        await followReturn(
          routes,
          issueResponseCode(responseCodes, flow.stateHash),
          `__Host-qauth_wallet_flow=${binderCookie}`
        )
      );
    }
    // A rejected return (401 terminal page).
    {
      const { routes, sessionUtils, responseCodes, flow, binderCookie } = await startFlow({
        device: 'this',
      });
      publishSignal(sessionUtils, flow.stateHash, 'wallet_error');
      responses.push(
        await followReturn(
          routes,
          issueResponseCode(responseCodes, flow.stateHash),
          `__Host-qauth_wallet_flow=${binderCookie}`
        )
      );
    }

    expect(responses).toHaveLength(5);
    for (const response of responses) {
      expect(response.headers['Cache-Control']).toBe('no-store');
      expect(response.headers['Referrer-Policy']).toBe('no-referrer');
    }
  });

  it('the return route never writes an audit row or a session on refusal', async () => {
    const { fastify, routes, sessionUtils, responseCodes, flow, binderCookie } = await startFlow({
      device: 'this',
    });
    const auditRowsAtStart = (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls
      .length;
    publishSignal(sessionUtils, flow.stateHash, 'received');
    (resolveWalletPresentation as unknown as Mock).mockResolvedValue(AUTHENTICATED);
    const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;

    const refusals = [
      await followReturn(routes, 'junk', cookie),
      await followReturn(routes, generateOid4vpResponseCode(), cookie),
      // Foreign landing: the initiating flow is rejected, and even that
      // rejection audits nothing here.
      await followReturn(routes, issueResponseCode(responseCodes, flow.stateHash)),
    ];

    for (const refusal of refusals) {
      expect(refusal.body).toBe(REFUSAL_PAGE);
      expect(refusal.setCookies).toEqual([]);
    }
    expect((fastify.repositories.auditLogs.create as unknown as Mock).mock.calls).toHaveLength(
      auditRowsAtStart
    );
    expect(sessionMints(fastify)).toEqual([]);
    expect(resolveWalletPresentation).not.toHaveBeenCalled();
  });
});
