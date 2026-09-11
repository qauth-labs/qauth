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

import { WALLET_RETURN_CODE_TTL_MS } from '../../constants';
import { signSessionId } from '../../helpers/session-cookie';
import { WALLET_LINK_EXPIRED, WALLET_LINK_REFUSAL } from '../../helpers/wallet-link-flow';
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

/**
 * Start a linking flow and return everything about it.
 *
 * `body` is what the POST carries (#405): absent by default, as every caller
 * built before #405 sends it — the stub hands the handler `undefined` where
 * Fastify would hand it `null` for a payload-less POST, and the route treats
 * the two alike.
 */
async function startLink(userId = 'user-1', body?: { device?: 'this' | 'other' }) {
  const context = makeFastify();
  await linkWalletRoute(context.fastify);
  const session = signIn(context.sessionUtils, userId);

  const postReply = createReply();
  await context.routes.get('POST /link/wallet')!(
    {
      ...(body === undefined ? {} : { body }),
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
    row: (context.fastify.repositories.oid4vpRequestStates.create as unknown as Mock).mock
      .calls[0][0] as Record<string, any>,
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
  signal = 'received',
  at: number = Date.now()
) {
  sessionUtils.store.set(`wallet-login-signal:${stateHash}`, { signal, at });
}

/** Poll the status endpoint as the ORIGINAL tab. */
async function pollStatus(routes: Map<string, Handler>, handle: string, cookie?: string) {
  const { reply, state } = createReply();
  await routes.get('GET /link/wallet/:handle')!(
    { params: { handle }, headers: cookie === undefined ? {} : { cookie }, ip: '127.0.0.1' },
    reply
  );
  return state;
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

/**
 * The same-device leg of a link (#405, ADR-013), as the JSON API sees it.
 *
 * Titles are conformance evidence: each cites the spec alias and section the
 * matrix row pins. The return route itself lives in `routes/ui/wallet-login.ts`
 * and is driven end to end in `routes/ui/wallet-link.test.ts`; what this
 * suite pins is that the poll — this endpoint — never completes a same-device
 * link, rejects one at the deadline, and reports the return leg's outcome
 * ONCE from the marker it leaves. The status JSON shape is unchanged.
 */
describe('wallet linking API — the device choice at flow start (#405)', () => {
  it('defaults an absent device field to cross-device (link)', async () => {
    // No body at all, an empty body, and an explicit `other` are one choice.
    for (const body of [undefined, {}, { device: 'other' as const }]) {
      const { row, flow } = await startLink('user-1', body);
      expect(row['sameDevice']).toBe(false);
      expect(flow['sameDevice']).toBeUndefined();
    }
  });

  it('(HAIP 1.0 §5.1) records the same-device choice on the link row and flow', async () => {
    const { row, flow, postReply } = await startLink('user-1', { device: 'this' });

    expect(row['sameDevice']).toBe(true);
    expect(flow['sameDevice']).toBe(true);
    // Written together, from one choice: neither side can be same-device alone.
    expect(row['stateHash']).toBe(flow['stateHash']);
    // The start response is unchanged in shape: the client renders the same
    // invocation URI either way, as an anchor rather than a QR.
    expect(postReply.state.body).toMatchObject({
      handle: expect.any(String),
      invocation_uri: expect.any(String),
      expires_at: expect.any(Number),
    });
  });
});

describe('wallet linking API — same-device links never complete by polling (#405)', () => {
  it('(OID4VP 1.0 §14.2) the link poll never completes a same-device link — pending until the return leg', async () => {
    const { routes, sessionUtils, session, handle, flow, binderCookie } = await startLink(
      'user-1',
      { device: 'this' }
    );
    publishSignal(sessionUtils, flow['stateHash']);
    (linkWalletPresentation as unknown as Mock).mockResolvedValue({
      status: 'linked',
      credentialId: 'cred-1',
      externalSub: 'alice@example.com',
      subjectSource: 'asserted-lookup',
      rebound: false,
    });

    const polled = await pollStatus(
      routes,
      handle,
      `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}`
    );

    expect(polled.body).toEqual({ status: 'pending' });
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(polled.setCookies).toEqual([]);
    // Nothing was terminated: the flow and its signal are still there.
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(true);
    expect(sessionUtils.store.has(`wallet-login-signal:${flow['stateHash']}`)).toBe(true);
  });

  it('(HAIP 1.0 §5.1) rejects a same-device link whose redirect was never followed after the deadline', async () => {
    const { fastify, routes, sessionUtils, session, handle, flow, binderCookie } = await startLink(
      'user-1',
      { device: 'this' }
    );
    const cookie = `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}`;

    // Inside the window: still waiting for the wallet to bring the browser back.
    publishSignal(
      sessionUtils,
      flow['stateHash'],
      'received',
      Date.now() - WALLET_RETURN_CODE_TTL_MS + 1000
    );
    expect((await pollStatus(routes, handle, cookie)).body).toEqual({ status: 'pending' });

    // Past it: rejected, actively, with a reason in the log.
    publishSignal(
      sessionUtils,
      flow['stateHash'],
      'received',
      Date.now() - WALLET_RETURN_CODE_TTL_MS - 1
    );
    const rejected = await pollStatus(routes, handle, cookie);
    expect(rejected.body).toEqual({ status: 'rejected', message: WALLET_LINK_REFUSAL });
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.anything(),
      'same-device presentation rejected: redirect not followed'
    );

    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
    expect((await pollStatus(routes, handle, cookie)).body).toEqual({
      status: 'expired',
      message: WALLET_LINK_EXPIRED,
    });
  });

  it('surfaces a wallet error on a same-device link via the poll', async () => {
    const { routes, sessionUtils, session, handle, flow, binderCookie } = await startLink(
      'user-1',
      { device: 'this' }
    );
    publishSignal(sessionUtils, flow['stateHash'], 'wallet_error');

    const polled = await pollStatus(
      routes,
      handle,
      `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}`
    );

    expect(polled.body).toEqual({ status: 'rejected', message: WALLET_LINK_REFUSAL });
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
  });

  it('cross-device links still complete via the poll exactly as before', async () => {
    const { routes, sessionUtils, session, handle, flow, binderCookie } = await startLink(
      'user-1',
      { device: 'other' }
    );
    publishSignal(sessionUtils, flow['stateHash']);
    (linkWalletPresentation as unknown as Mock).mockResolvedValue({
      status: 'linked',
      credentialId: 'cred-1',
      externalSub: 'alice@example.com',
      subjectSource: 'asserted-lookup',
      rebound: false,
    });

    const polled = await pollStatus(
      routes,
      handle,
      `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}`
    );

    expect(polled.body).toEqual({
      status: 'linked',
      message: 'Your wallet credential is now linked to this account.',
    });
    // The binding is burned by the poll, as it always was, and no marker exists.
    expect(polled.setCookies.some((c) => c.startsWith('__Host-qauth_wallet_flow='))).toBe(true);
    expect([...sessionUtils.store.keys()].some((k) => k.startsWith('wallet-login-done:'))).toBe(
      false
    );
  });
});

describe('wallet linking API — the done-marker the return leg leaves (#405)', () => {
  /** What a completed return leg leaves where the flow was (see wallet-link-flow.ts). */
  function completeOnReturnLeg(
    sessionUtils: ReturnType<typeof createSessionUtils>,
    handle: string,
    flow: Record<string, any>,
    outcome: 'linked' | 'rebound',
    linkUserId = flow['linkUserId'] as string
  ) {
    sessionUtils.store.delete(`wallet-login:${handle}`);
    sessionUtils.store.delete(`wallet-login-signal:${flow['stateHash']}`);
    sessionUtils.store.set(`wallet-login-done:${handle}`, {
      binder: flow['binder'],
      mode: 'link',
      outcome,
      linkUserId,
    });
  }

  it('the original link tab consumes the done-marker once', async () => {
    const { routes, sessionUtils, session, handle, flow, binderCookie } = await startLink(
      'user-1',
      { device: 'this' }
    );
    completeOnReturnLeg(sessionUtils, handle, flow, 'linked');
    const cookie = `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}`;

    // A poll WITHOUT the binder learns nothing and burns nothing.
    expect((await pollStatus(routes, handle, session.cookie)).body).toEqual({
      status: 'expired',
      message: WALLET_LINK_EXPIRED,
    });
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(true);

    // The original tab: linked, once, with its binding dropped and nothing
    // written — the credential row has existed since the return leg.
    const first = await pollStatus(routes, handle, cookie);
    expect(first.body).toEqual({
      status: 'linked',
      message: 'Your wallet credential is now linked to this account.',
    });
    expect(first.setCookies.some((c) => c.startsWith('__Host-qauth_wallet_flow='))).toBe(true);
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(false);
    expect(linkWalletPresentation).not.toHaveBeenCalled();

    // Once.
    expect((await pollStatus(routes, handle, cookie)).body).toEqual({
      status: 'expired',
      message: WALLET_LINK_EXPIRED,
    });
  });

  it('reports a rebound marker with the rebound sentence', async () => {
    const { routes, sessionUtils, session, handle, flow, binderCookie } = await startLink(
      'user-1',
      { device: 'this' }
    );
    completeOnReturnLeg(sessionUtils, handle, flow, 'rebound');

    const polled = await pollStatus(
      routes,
      handle,
      `${session.cookie}; __Host-qauth_wallet_flow=${binderCookie}`
    );

    expect(polled.body).toEqual({
      status: 'linked',
      message: 'Your wallet credential was updated.',
    });
  });

  it('refuses the marker to a different signed-in user, without burning it', async () => {
    const { routes, sessionUtils, handle, flow, binderCookie } = await startLink('user-1', {
      device: 'this',
    });
    completeOnReturnLeg(sessionUtils, handle, flow, 'linked');
    const other = signIn(sessionUtils, 'user-2', 'other-csrf');

    const polled = await pollStatus(
      routes,
      handle,
      `${other.cookie}; __Host-qauth_wallet_flow=${binderCookie}`
    );

    expect(polled.body).toEqual({ status: 'expired', message: WALLET_LINK_EXPIRED });
    expect(polled.setCookies).toEqual([]);
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(true);
  });
});
