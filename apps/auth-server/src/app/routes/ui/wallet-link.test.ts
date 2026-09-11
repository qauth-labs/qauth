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

import {
  generateOid4vpResponseCode,
  hashOid4vpResponseCode,
} from '@qauth-labs/fastify-plugin-federation';

import { WALLET_RETURN_CODE_TTL_MS } from '../../constants';
import { signSessionId } from '../../helpers/session-cookie';
import { WALLET_LINK_CONFLICT, WALLET_LINK_REFUSAL } from '../../helpers/wallet-link-flow';
import { WALLET_LOGIN_RETURN_PATH } from '../../helpers/wallet-login-request';
import {
  linkWalletPresentation,
  resolveWalletPresentation,
} from '../../helpers/wallet-presentation';
import {
  WALLET_LINK_CONFLICT_TITLE,
  WALLET_LINK_REJECTED_TITLE,
  WALLET_LINKED,
  walletLinkedPage,
  walletLinkTerminalPage,
  walletReturnRefusalPage,
} from '../../helpers/wallet-ui';
import walletLinkRoute from './wallet-link';
import walletLoginRoute from './wallet-login';

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

/**
 * Stand-in for the repository's `redeemResponseCode` (#405): ONE guarded
 * consume, keyed by the code's sha256 digest exactly as the real statement is.
 * Single-use, deadline-checked, and `undefined` for anything else — the same
 * stub the wallet-login suite uses, because the return route is the same route.
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
      oid4vpRequestStates: {
        create: vi.fn(async (row: unknown) => row),
        redeemResponseCode: responseCodes.redeemResponseCode,
      },
      auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
    },
    sessionUtils,
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, routes, sessionUtils, responseCodes };
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

/**
 * GET then POST, producing a started linking flow.
 *
 * Registers BOTH wallet route modules against one stub: the return leg a
 * same-device link ends on is `GET /ui/wallet-login/return`, which lives in
 * `wallet-login.ts` and dispatches on the flow's mode (#405). The two modules
 * register disjoint paths, so nothing collides.
 */
async function startLink(
  opts: {
    userId?: string;
    /** Which submit button was pressed (#405). Absent = the field was not sent. */
    device?: 'this' | 'other';
    /** Reuse an already-registered server, to start a SECOND flow against it. */
    context?: ReturnType<typeof makeFastify>;
    /** The wallet-flow cookie this browser already holds, if any. */
    walletFlowCookie?: string;
  } = {}
) {
  const context = opts.context ?? makeFastify();
  const userId = opts.userId ?? 'user-1';
  if (opts.context === undefined) {
    await walletLinkRoute(context.fastify);
    await walletLoginRoute(context.fastify);
  }
  const sessionCookie = signIn(context.sessionUtils, userId);

  const getReply = createReply();
  await context.routes.get('GET /wallet-link')!(
    { headers: { cookie: sessionCookie }, ip: '127.0.0.1' },
    getReply.reply
  );
  const csrfCookie = cookieValue(getReply.state.setCookies, '__Host-qauth_login_csrf');
  const csrfToken = csrfCookie.split('.')[0];

  const cookies = [sessionCookie, `__Host-qauth_login_csrf=${csrfCookie}`];
  if (opts.walletFlowCookie !== undefined) {
    cookies.push(`__Host-qauth_wallet_flow=${opts.walletFlowCookie}`);
  }

  const knownKeys = new Set(context.sessionUtils.store.keys());
  const postReply = createReply();
  await context.routes.get('POST /wallet-link')!(
    {
      body: {
        csrf_token: csrfToken,
        ...(opts.device === undefined ? {} : { device: opts.device }),
      },
      headers: { cookie: cookies.join('; ') },
      ip: '127.0.0.1',
    },
    postReply.reply
  );

  const flowEntry = [...context.sessionUtils.store.entries()].find(
    ([key]) => key.startsWith('wallet-login:') && !knownKeys.has(key)
  );
  if (!flowEntry) throw new Error('no linking flow was stored');

  return {
    ...context,
    userId,
    sessionCookie,
    getReply,
    postReply,
    handle: flowEntry[0].slice('wallet-login:'.length),
    flow: flowEntry[1] as Record<string, any>,
    row: (context.fastify.repositories.oid4vpRequestStates.create as unknown as Mock).mock.calls.at(
      -1
    )![0] as Record<string, any>,
    binderCookie: cookieValue(postReply.state.setCookies, '__Host-qauth_wallet_flow'),
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
 * row (#405). Returns the raw code, as the wallet's browser would carry it.
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

/** Re-render the linking page as the ORIGINAL tab's no-JavaScript refresh. */
async function renderLinkPage(routes: Map<string, Handler>, handle: string, cookie?: string) {
  const { reply, state } = createReply();
  await routes.get('GET /wallet-link/:handle')!(
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

const LINKED = {
  status: 'linked',
  credentialId: 'cred-1',
  externalSub: 'alice@example.com',
  subjectSource: 'asserted-lookup',
  rebound: false,
};

/** Session-store writes that are browser SESSIONS, not flow/marker records. */
function sessionMints(fastify: FastifyInstance): string[] {
  return (fastify.sessionUtils.setSession as unknown as Mock).mock.calls
    .map((c) => c[0] as string)
    .filter((key) => !key.startsWith('wallet-'));
}

function auditEvents(fastify: FastifyInstance): string[] {
  return (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls.map(
    (c) => (c[0] as { event: string }).event
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  envMock.WALLET_FEDERATION_ENABLED = true;
  envMock.OID4VP_VERIFIER_PROFILE = 'oid4vp-1.0-base';
  envMock.OID4VP_REQUESTED_VCT = ['urn:example:pid'];
  (linkWalletPresentation as unknown as Mock).mockResolvedValue({ status: 'rejected' });
  (resolveWalletPresentation as unknown as Mock).mockResolvedValue({ status: 'rejected' });
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
    const { flow, binderCookie } = await startLink({ userId: 'user-77' });

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

/**
 * The same-device leg of a link (#405, ADR-013): the device choice on the
 * confirmation form, the one-affordance pending page, and the return route —
 * `GET /ui/wallet-login/return`, registered by `wallet-login.ts` and driven
 * here against a LINK flow. Titles are conformance evidence: each cites the
 * spec alias and section the matrix row pins. The Response Endpoint is not
 * driven — its own suite pins that it hands a `redirect_uri` only to a
 * same-device row — so a wallet answering is simulated by `publishSignal` +
 * `issueResponseCode`, and the wallet's browser following the redirect by
 * `followReturn`.
 */
describe('wallet-link UI — the device choice at flow start (#405)', () => {
  it('offers both device choices on the confirmation form, as plain submit buttons', async () => {
    const { getReply } = await startLink();
    const body = String(getReply.state.body);

    expect(body).toContain('name="device" value="other"');
    expect(body).toContain('name="device" value="this"');
    expect(body).toContain('Scan with a wallet on another device');
    expect(body).toContain('Use a wallet on this device');
    // Still no identifier field: the account is the session's.
    expect(body).not.toContain('name="identifier"');
  });

  it('defaults an absent device field to cross-device (link)', async () => {
    const { row, flow, postReply } = await startLink();
    const body = String(postReply.state.body);

    expect(row['sameDevice']).toBe(false);
    expect(flow['sameDevice']).toBeUndefined();
    // The QR, and only the QR.
    expect(body).toContain('<svg');
    expect(body).not.toContain('Open my wallet');
    expect(body).not.toContain('href="openid4vp://');
    expect(body).toContain('Waiting for your wallet');
    expect(body).toContain('href="/ui/wallet-link">Start again</a>');
  });

  it('(HAIP 1.0 §5.1) records the same-device choice on the link row and flow', async () => {
    const { routes, row, flow, handle, postReply, sessionCookie, binderCookie } = await startLink({
      device: 'this',
    });
    const body = String(postReply.state.body);

    expect(row['sameDevice']).toBe(true);
    expect(flow['sameDevice']).toBe(true);
    // Written together, from one choice: neither side can be same-device alone.
    expect(row['stateHash']).toBe(flow['stateHash']);

    // The anchor, and only the anchor.
    expect(body).toContain('Open my wallet');
    expect(body).toContain('href="openid4vp://?');
    expect(body).not.toContain('<svg');
    expect(body).toContain('will bring you back here');
    expect(body).toContain(`/auth/link/wallet/${handle}`);
    expect(body).toContain('href="/ui/wallet-link">Start again</a>');

    // The noscript re-render keeps the variant the flow was started with.
    const rerender = await renderLinkPage(
      routes,
      handle,
      `${sessionCookie}; __Host-qauth_wallet_flow=${binderCookie}`
    );
    expect(String(rerender.body)).toContain('Open my wallet');
    expect(String(rerender.body)).not.toContain('<svg');
  });
});

describe('wallet-link UI — the return leg (#405)', () => {
  it('(OID4VP 1.0 §14.2, §14.3.3) the return leg completes a same-device link only with the browser binder, a live session for the same user, and a spent-once Response Code', async () => {
    const {
      fastify,
      routes,
      sessionUtils,
      responseCodes,
      handle,
      flow,
      sessionCookie,
      binderCookie,
    } = await startLink({ userId: 'user-9', device: 'this' });
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    const code = issueResponseCode(responseCodes, flow['stateHash']);
    (linkWalletPresentation as unknown as Mock).mockResolvedValue(LINKED);
    const cookie = `${sessionCookie}; __Host-qauth_wallet_flow=${binderCookie}`;

    const landed = await followReturn(routes, code, cookie);

    // The code was redeemed by DIGEST and exactly once.
    expect(fastify.repositories.oid4vpRequestStates.redeemResponseCode).toHaveBeenCalledTimes(1);
    expect(fastify.repositories.oid4vpRequestStates.redeemResponseCode).toHaveBeenCalledWith(
      hashOid4vpResponseCode(code)
    );

    // Linked for the SESSION's user, audited, and rendered as the link page
    // renders it — plus the address-bar scrub every page under this URL has.
    expect(landed.statusCode).toBe(200);
    expect(linkWalletPresentation).toHaveBeenCalledTimes(1);
    expect(linkWalletPresentation).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ authenticatedUserId: 'user-9', stateHash: flow['stateHash'] })
    );
    expect(auditEvents(fastify)).toContain('auth.wallet_link.success');
    expect(landed.body).toBe(
      walletLinkedPage({
        cspNonce: 'test-style-nonce',
        rebound: false,
        scrub: { scriptNonce: 'test-script-nonce', returnPath: WALLET_LOGIN_RETURN_PATH },
      })
    );
    expect(landed.body as string).toContain(WALLET_LINKED);
    expect(landed.body as string).toContain('history.replaceState');
    expect(landed.redirected).toBeUndefined();
    expect(landed.headers['Cache-Control']).toBe('no-store');
    expect(landed.headers['Referrer-Policy']).toBe('no-referrer');

    // No session was minted — the user already had one — and the login
    // machine was never entered.
    expect(sessionMints(fastify)).toEqual([]);
    expect(resolveWalletPresentation).not.toHaveBeenCalled();

    // The done-marker was written for the original tab, and the binding was
    // NOT dropped: that tab must still be able to prove it holds the flow.
    expect(sessionUtils.store.get(`wallet-login-done:${handle}`)).toEqual({
      binder: flow['binder'],
      mode: 'link',
      outcome: 'linked',
      linkUserId: 'user-9',
    });
    expect(landed.setCookies.some((c) => c.startsWith('__Host-qauth_wallet_flow='))).toBe(false);

    // The flow itself is terminal, and the code is spent: a replay is refused.
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
    expect(sessionUtils.store.has(`wallet-login-signal:${flow['stateHash']}`)).toBe(false);
    const replayed = await followReturn(routes, code, cookie);
    expect(replayed.body).toBe(REFUSAL_PAGE);
    expect(linkWalletPresentation).toHaveBeenCalledTimes(1);
  });

  it('refuses a link return without a session with the refusal page, discarding the presentation', async () => {
    // No session at all: the browser holds the binder, but a link flow was
    // initiated in a USER session, so this is a foreign landing in HAIP §5.1's
    // sense — the code is spent and the presentation discarded.
    {
      const {
        fastify,
        routes,
        sessionUtils,
        responseCodes,
        handle,
        flow,
        sessionCookie,
        binderCookie,
      } = await startLink({ device: 'this' });
      publishSignal(sessionUtils, flow['stateHash'], 'received');
      sessionUtils.store.set(`wallet-presentation:${flow['stateHash']}`, {
        presentations: [{ format: 'dc+sd-jwt', compact: 'a.b.c' }],
        at: Date.now(),
      });
      const code = issueResponseCode(responseCodes, flow['stateHash']);
      (linkWalletPresentation as unknown as Mock).mockResolvedValue(LINKED);
      const auditRowsAtStart = auditEvents(fastify).length;

      const landed = await followReturn(routes, code, `__Host-qauth_wallet_flow=${binderCookie}`);

      expect(landed.body).toBe(REFUSAL_PAGE);
      expect(landed.statusCode).toBe(200);
      expect(fastify.log.warn).toHaveBeenCalledWith(
        expect.anything(),
        'same-device return for a wallet LINK flow arrived without a session'
      );
      expect(linkWalletPresentation).not.toHaveBeenCalled();
      expect(auditEvents(fastify)).toHaveLength(auditRowsAtStart);
      expect(sessionMints(fastify)).toEqual([]);

      // Spent, and discarded: the parked bytes are gone and the signal says
      // why, so the original tab's poll (once it has a session again) is told.
      expect(fastify.repositories.oid4vpRequestStates.redeemResponseCode).toHaveBeenCalledTimes(1);
      expect(sessionUtils.store.has(`wallet-presentation:${flow['stateHash']}`)).toBe(false);
      expect(sessionUtils.store.get(`wallet-login-signal:${flow['stateHash']}`)).toEqual({
        signal: 'return_rejected',
        at: expect.any(Number),
      });
      const rendered = await renderLinkPage(
        routes,
        handle,
        `${sessionCookie}; __Host-qauth_wallet_flow=${binderCookie}`
      );
      expect(rendered.statusCode).toBe(401);
      expect(String(rendered.body)).toContain(WALLET_LINK_REFUSAL);
      expect(linkWalletPresentation).not.toHaveBeenCalled();
    }
  });

  it("(HAIP 1.0 §5.1) link return with another user's session discards the presentation and the original poll answers rejected", async () => {
    // The jar's session was replaced — a logout and a login in another tab —
    // while the wallet was open. The browser holds the binder, but this is
    // "a different user session to the one the request was initiated in":
    // handled like the no-session landing, not left to the same-user gate,
    // which would answer expired and leave the parked bytes addressable.
    const {
      fastify,
      routes,
      sessionUtils,
      responseCodes,
      handle,
      flow,
      sessionCookie,
      binderCookie,
    } = await startLink({ userId: 'user-1', device: 'this' });
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    sessionUtils.store.set(`wallet-presentation:${flow['stateHash']}`, {
      presentations: [{ format: 'dc+sd-jwt', compact: 'a.b.c' }],
      at: Date.now(),
    });
    const code = issueResponseCode(responseCodes, flow['stateHash']);
    (linkWalletPresentation as unknown as Mock).mockResolvedValue(LINKED);
    const other = signIn(sessionUtils, 'user-2');
    const auditRowsAtStart = auditEvents(fastify).length;

    const landed = await followReturn(
      routes,
      code,
      `${other}; __Host-qauth_wallet_flow=${binderCookie}`
    );

    expect(landed.body).toBe(REFUSAL_PAGE);
    expect(landed.statusCode).toBe(200);
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.anything(),
      'same-device return for a wallet LINK flow arrived in a different user session'
    );
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(auditEvents(fastify)).toHaveLength(auditRowsAtStart);
    expect(sessionMints(fastify)).toEqual([]);
    expect(landed.setCookies).toEqual([]);

    // Spent, and discarded: the parked bytes are gone, the signal says why,
    // the flow itself is left for its owner's poll, and no marker exists.
    expect(fastify.repositories.oid4vpRequestStates.redeemResponseCode).toHaveBeenCalledTimes(1);
    expect(sessionUtils.store.has(`wallet-presentation:${flow['stateHash']}`)).toBe(false);
    expect(sessionUtils.store.get(`wallet-login-signal:${flow['stateHash']}`)).toEqual({
      signal: 'return_rejected',
      at: expect.any(Number),
    });
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(true);
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(false);

    // The other user's poll in this browser learns nothing (the same-user
    // gate); the original user's poll is told, promptly, and nothing was linked.
    const foreign = await renderLinkPage(
      routes,
      handle,
      `${other}; __Host-qauth_wallet_flow=${binderCookie}`
    );
    expect(foreign.statusCode).toBe(410);
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(true);

    const rendered = await renderLinkPage(
      routes,
      handle,
      `${sessionCookie}; __Host-qauth_wallet_flow=${binderCookie}`
    );
    expect(rendered.statusCode).toBe(401);
    expect(String(rendered.body)).toContain(WALLET_LINK_REFUSAL);
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.anything(),
      'same-device presentation rejected: redirect landed in a foreign session'
    );
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
  });

  it('the original link tab consumes the done-marker once', async () => {
    const { routes, sessionUtils, responseCodes, handle, flow, sessionCookie, binderCookie } =
      await startLink({ device: 'this' });
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    const code = issueResponseCode(responseCodes, flow['stateHash']);
    (linkWalletPresentation as unknown as Mock).mockResolvedValue(LINKED);
    const cookie = `${sessionCookie}; __Host-qauth_wallet_flow=${binderCookie}`;

    await followReturn(routes, code, cookie);
    expect(linkWalletPresentation).toHaveBeenCalledTimes(1);

    // A poll WITHOUT the binder learns nothing and burns nothing.
    expect((await renderLinkPage(routes, handle, sessionCookie)).statusCode).toBe(410);
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(true);

    // The original tab: the linked page — the SAME bytes the return tab
    // rendered, minus the scrub that only the return URL needs — its binding
    // dropped now that the marker is consumed, and no second write.
    const first = await renderLinkPage(routes, handle, cookie);
    expect(first.statusCode).toBeUndefined();
    expect(first.body).toBe(walletLinkedPage({ cspNonce: 'test-style-nonce', rebound: false }));
    expect(first.setCookies.some((c) => c.startsWith('__Host-qauth_wallet_flow='))).toBe(true);
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(false);
    expect(linkWalletPresentation).toHaveBeenCalledTimes(1);

    // Once.
    expect((await renderLinkPage(routes, handle, cookie)).statusCode).toBe(410);
  });

  it('a link-mode Response Code cannot complete a login-mode flow and vice versa', async () => {
    // One browser, one signed-in user, a same-device LOGIN flow and a
    // same-device LINK flow both in flight. Each code names its own flow by
    // state hash, and the flow's mode picks the state machine; neither
    // machine ever sees the other's flow.
    async function startBoth() {
      const context = makeFastify();
      await walletLinkRoute(context.fastify);
      await walletLoginRoute(context.fastify);

      // The login flow first, through its own form.
      const loginGet = createReply();
      await context.routes.get('GET /wallet-login')!(
        { query: {}, headers: {}, ip: '127.0.0.1' },
        loginGet.reply
      );
      const loginCsrfCookie = cookieValue(loginGet.state.setCookies, '__Host-qauth_login_csrf');
      const loginPost = createReply();
      await context.routes.get('POST /wallet-login')!(
        {
          body: {
            identifier: 'user@example.com',
            csrf_token: loginCsrfCookie.split('.')[0],
            device: 'this',
          },
          headers: { cookie: `__Host-qauth_login_csrf=${loginCsrfCookie}` },
          ip: '127.0.0.1',
        },
        loginPost.reply
      );
      const loginEntry = [...context.sessionUtils.store.entries()].find(([key]) =>
        key.startsWith('wallet-login:')
      )!;
      const login = {
        handle: loginEntry[0].slice('wallet-login:'.length),
        flow: loginEntry[1] as Record<string, any>,
      };

      // Then the link flow, in the same jar (its binding is APPENDED).
      const link = await startLink({
        context,
        device: 'this',
        walletFlowCookie: cookieValue(loginPost.state.setCookies, '__Host-qauth_wallet_flow'),
      });
      expect(login.flow['mode']).toBe('login');
      expect(link.flow['mode']).toBe('link');

      return {
        ...context,
        login,
        link,
        cookie: `${link.sessionCookie}; __Host-qauth_wallet_flow=${link.binderCookie}`,
      };
    }

    // (1) A code minted for the LINK row: the link machine runs, the login
    // machine does not, and the login flow is still waiting.
    {
      const { fastify, routes, sessionUtils, responseCodes, login, link, cookie } =
        await startBoth();
      publishSignal(sessionUtils, link.flow['stateHash'], 'received');
      publishSignal(sessionUtils, login.flow['stateHash'], 'received');
      (linkWalletPresentation as unknown as Mock).mockResolvedValue(LINKED);
      (resolveWalletPresentation as unknown as Mock).mockResolvedValue({
        status: 'authenticated',
        userId: 'user-1',
        externalSub: 'user@example.com',
      });

      const landed = await followReturn(
        routes,
        issueResponseCode(responseCodes, link.flow['stateHash']),
        cookie
      );

      expect(landed.body as string).toContain(WALLET_LINKED);
      expect(linkWalletPresentation).toHaveBeenCalledTimes(1);
      expect(resolveWalletPresentation).not.toHaveBeenCalled();
      expect(sessionMints(fastify)).toEqual([]);
      expect(landed.setCookies.some((c) => c.startsWith('__Host-qauth_session='))).toBe(false);
      expect(auditEvents(fastify)).not.toContain('ui.wallet_login.success');
      // The login flow is untouched: same-device, so still pending by poll.
      const loginPoll = createReply();
      await routes.get('GET /wallet-login/:handle/status')!(
        { params: { handle: login.handle }, headers: { cookie }, ip: '127.0.0.1' },
        loginPoll.reply
      );
      expect(loginPoll.state.body).toEqual({ status: 'pending' });
    }

    // (2) A code minted for the LOGIN row: the login machine runs, the link
    // machine does not, and the link flow is still waiting.
    {
      const { fastify, routes, sessionUtils, responseCodes, login, link, cookie } =
        await startBoth();
      publishSignal(sessionUtils, link.flow['stateHash'], 'received');
      publishSignal(sessionUtils, login.flow['stateHash'], 'received');
      (linkWalletPresentation as unknown as Mock).mockClear().mockResolvedValue(LINKED);
      (resolveWalletPresentation as unknown as Mock)
        .mockClear()
        .mockResolvedValue({ status: 'rejected' });

      const landed = await followReturn(
        routes,
        issueResponseCode(responseCodes, login.flow['stateHash']),
        cookie
      );

      // The login machine took it (and refused it — the resolver is mocked to
      // reject — on the login surface's own 401 page).
      expect(landed.statusCode).toBe(401);
      expect(landed.body as string).toContain('Sign-in was not completed');
      expect(resolveWalletPresentation).toHaveBeenCalledTimes(1);
      expect(linkWalletPresentation).not.toHaveBeenCalled();
      expect(auditEvents(fastify)).not.toContain('auth.wallet_link.success');
      expect(auditEvents(fastify)).not.toContain('auth.wallet_link.failure');
      // The link flow is untouched: same-device, so still pending by poll.
      expect(sessionUtils.store.has(`wallet-login:${link.handle}`)).toBe(true);
      const rendered = await renderLinkPage(routes, link.handle, cookie);
      expect(String(rendered.body)).toContain('Present a credential');
    }
  });

  it("a rejected or conflicting same-device link renders the linking surface's own terminal page, byte for byte", async () => {
    // wallet_error: the Response Endpoint hands out a redirect_uri on its
    // error path too (OID4VP 1.0 §8.2 "or for Error Responses"), so a wallet
    // that declined still brings the browser here.
    {
      const {
        fastify,
        routes,
        sessionUtils,
        responseCodes,
        handle,
        flow,
        sessionCookie,
        binderCookie,
      } = await startLink({ device: 'this' });
      publishSignal(sessionUtils, flow['stateHash'], 'wallet_error');
      const code = issueResponseCode(responseCodes, flow['stateHash']);
      const cookie = `${sessionCookie}; __Host-qauth_wallet_flow=${binderCookie}`;

      const landed = await followReturn(routes, code, cookie);

      expect(landed.statusCode).toBe(401);
      expect(landed.body).toBe(
        walletLinkTerminalPage({
          cspNonce: 'test-style-nonce',
          title: WALLET_LINK_REJECTED_TITLE,
          message: WALLET_LINK_REFUSAL,
          retry: true,
        })
      );
      expect(linkWalletPresentation).not.toHaveBeenCalled();
      expect(sessionMints(fastify)).toEqual([]);
      expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
      // The word is left for the original tab, which renders the SAME page
      // — once — rather than "expired".
      expect(sessionUtils.store.get(`wallet-login-done:${handle}`)).toMatchObject({
        mode: 'link',
        outcome: 'rejected',
      });
      const original = await renderLinkPage(routes, handle, cookie);
      expect(original.statusCode).toBe(401);
      expect(original.body).toBe(landed.body);
      expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(false);
      expect((await renderLinkPage(routes, handle, cookie)).statusCode).toBe(410);

      // Byte for byte what the page GET renders for the same outcome.
      const other = await startLink({ device: 'this' });
      publishSignal(other.sessionUtils, other.flow['stateHash'], 'wallet_error');
      const rendered = await renderLinkPage(
        other.routes,
        other.handle,
        `${other.sessionCookie}; __Host-qauth_wallet_flow=${other.binderCookie}`
      );
      expect(rendered.statusCode).toBe(401);
      expect(rendered.body).toBe(landed.body);
    }

    // conflict: the one specific outcome, 409 on both surfaces.
    {
      const { routes, sessionUtils, responseCodes, handle, flow, sessionCookie, binderCookie } =
        await startLink({ device: 'this' });
      publishSignal(sessionUtils, flow['stateHash'], 'received');
      const code = issueResponseCode(responseCodes, flow['stateHash']);
      (linkWalletPresentation as unknown as Mock).mockResolvedValue({ status: 'conflict' });
      const cookie = `${sessionCookie}; __Host-qauth_wallet_flow=${binderCookie}`;

      const landed = await followReturn(routes, code, cookie);

      expect(landed.statusCode).toBe(409);
      expect(landed.body).toBe(
        walletLinkTerminalPage({
          cspNonce: 'test-style-nonce',
          title: WALLET_LINK_CONFLICT_TITLE,
          message: WALLET_LINK_CONFLICT,
          retry: false,
        })
      );
      // The original tab renders the same 409, once.
      expect(sessionUtils.store.get(`wallet-login-done:${handle}`)).toMatchObject({
        outcome: 'conflict',
      });
      const original = await renderLinkPage(routes, handle, cookie);
      expect(original.statusCode).toBe(409);
      expect(original.body).toBe(landed.body);
      expect((await renderLinkPage(routes, handle, cookie)).statusCode).toBe(410);

      // Byte for byte what the page GET renders for the same outcome — on a
      // CROSS-device flow, since a same-device one never resolves by polling.
      const other = await startLink({ device: 'other' });
      publishSignal(other.sessionUtils, other.flow['stateHash'], 'received');
      const rendered = await renderLinkPage(
        other.routes,
        other.handle,
        `${other.sessionCookie}; __Host-qauth_wallet_flow=${other.binderCookie}`
      );
      expect(rendered.statusCode).toBe(409);
      expect(rendered.body).toBe(landed.body);
    }
  });

  it('a foreign landing of a link code burns it and the original link tab is told', async () => {
    const {
      fastify,
      routes,
      sessionUtils,
      responseCodes,
      handle,
      flow,
      sessionCookie,
      binderCookie,
    } = await startLink({ device: 'this' });
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    const code = issueResponseCode(responseCodes, flow['stateHash']);
    (linkWalletPresentation as unknown as Mock).mockResolvedValue(LINKED);

    // The wallet opened a browser with an EMPTY cookie jar.
    const landed = await followReturn(routes, code);

    expect(landed.body).toBe(REFUSAL_PAGE);
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.anything(),
      'same-device return arrived in a foreign session'
    );
    expect(sessionUtils.store.get(`wallet-login-signal:${flow['stateHash']}`)).toEqual({
      signal: 'return_rejected',
      at: expect.any(Number),
    });

    // The initiating tab is told, promptly, and nothing was linked.
    const rendered = await renderLinkPage(
      routes,
      handle,
      `${sessionCookie}; __Host-qauth_wallet_flow=${binderCookie}`
    );
    expect(rendered.statusCode).toBe(401);
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.anything(),
      'same-device presentation rejected: redirect landed in a foreign session'
    );
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
  });

  it('a link return the state machine cannot advance (code spent, flow found, no signal) renders the one refusal page, byte for byte', async () => {
    // A signal write that had failed at the Response Endpoint: the code was
    // minted, the browser and the session are the right ones, but the machine
    // has nothing to advance on. `pending` on the return leg is the refusal
    // page — the same bytes as a foreign landing — and the code is spent.
    const { fastify, routes, responseCodes, handle, flow, sessionCookie, binderCookie } =
      await startLink({ device: 'this' });
    const code = issueResponseCode(responseCodes, flow['stateHash']);
    (linkWalletPresentation as unknown as Mock).mockResolvedValue(LINKED);
    const cookie = `${sessionCookie}; __Host-qauth_wallet_flow=${binderCookie}`;

    const landed = await followReturn(routes, code, cookie);

    expect(landed.body).toBe(REFUSAL_PAGE);
    expect(landed.statusCode).toBe(200);
    expect(fastify.repositories.oid4vpRequestStates.redeemResponseCode).toHaveBeenCalledTimes(1);
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(auditEvents(fastify)).toEqual([]);
    expect(landed.setCookies).toEqual([]);
    // The flow is still there for the original tab, which is still pending.
    expect(String((await renderLinkPage(routes, handle, cookie)).body)).toContain(
      'Present a credential'
    );
    // And the code is spent: the same landing again is the same page.
    expect((await followReturn(routes, code, cookie)).body).toBe(REFUSAL_PAGE);
  });
});
