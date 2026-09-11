import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

/**
 * The account-linking state machine (#238), and the same-device leg it grew
 * for #405 (ADR-013).
 *
 * Driven directly — no route module in between — so each property is pinned
 * where it lives. The route suites (`routes/ui/wallet-link.test.ts`,
 * `routes/auth/link-wallet.test.ts`) prove the surfaces call this with the
 * right `via`; this suite proves what each `via` does. The presentation seam
 * is mocked for the reason `helpers/wallet-presentation.test.ts` gives: the
 * cryptography is exercised for real in `libs/server/federation`, and
 * `scope:app` cannot mint a credential.
 *
 * Titles are conformance evidence: each cites the spec alias and section the
 * matrix row pins, and the assertions are the observable form of that row.
 */

const { envMock } = vi.hoisted(() => ({
  envMock: {
    DEFAULT_REALM_NAME: 'master',
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
    JWT_ISSUER: 'https://auth.example.com',
    WALLET_FEDERATION_ENABLED: true,
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' as string | undefined,
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

vi.mock('../../config/env', () => ({ env: envMock }));

vi.mock('./wallet-presentation', () => ({
  linkWalletPresentation: vi.fn().mockResolvedValue({ status: 'rejected' }),
  resolveWalletPresentation: vi.fn().mockResolvedValue({ status: 'rejected' }),
}));

import { WALLET_RETURN_CODE_TTL_MS } from '../constants';
import { readWalletFlowBindings } from './session-cookie';
import { advanceWalletLinkFlow, startWalletLinkFlow } from './wallet-link-flow';
import { linkWalletPresentation } from './wallet-presentation';

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
  const sessionUtils = createSessionUtils();
  const fastify: any = {
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
  return { fastify: fastify as FastifyInstance, sessionUtils };
}

/** A request as the state machine sees it: a cookie header and an address. */
function makeRequest(cookie?: string): any {
  return { headers: cookie === undefined ? {} : { cookie }, ip: '127.0.0.1' };
}

/** A reply that records only what the state machine touches: Set-Cookie. */
function makeReply() {
  const setCookies: string[] = [];
  const reply: any = {
    header(k: string, v: string) {
      if (k.toLowerCase() === 'set-cookie') setCookies.push(v);
      return reply;
    },
  };
  return { reply, setCookies };
}

function cookieValue(setCookies: string[], name: string): string {
  const cookie = setCookies.find((c) => c.startsWith(`${name}=`));
  if (!cookie) throw new Error(`${name} was not set`);
  return cookie.split('=').slice(1).join('=').split(';')[0];
}

/** Start a linking flow for `userId` and return everything about it. */
async function startLink(opts: { userId?: string; device?: 'this' | 'other' } = {}) {
  const context = makeFastify();
  const userId = opts.userId ?? 'user-1';
  const { reply, setCookies } = makeReply();

  const started = await startWalletLinkFlow(
    context.fastify,
    makeRequest(),
    reply,
    userId,
    opts.device === undefined ? {} : { device: opts.device }
  );
  if (started === undefined) throw new Error('the linking flow did not start');

  const flow = context.sessionUtils.store.get(`wallet-login:${started.handle}`) as Record<
    string,
    any
  >;
  const row = (context.fastify.repositories.oid4vpRequestStates.create as unknown as Mock).mock
    .calls[0][0] as Record<string, any>;

  return {
    ...context,
    userId,
    started,
    handle: started.handle,
    flow,
    row,
    binderCookie: cookieValue(setCookies, '__Host-qauth_wallet_flow'),
  };
}

function publishSignal(
  sessionUtils: ReturnType<typeof createSessionUtils>,
  stateHash: string,
  signal: string,
  at: number = Date.now()
) {
  sessionUtils.store.set(`wallet-login-signal:${stateHash}`, { signal, at });
}

/** Advance as one of the two surfaces would, with the given cookie jar. */
async function advance(
  fastify: FastifyInstance,
  handle: string,
  userId: string,
  opts: { cookie?: string; via?: 'poll' | 'return' } = {}
) {
  const { reply, setCookies } = makeReply();
  const outcome = await advanceWalletLinkFlow(
    fastify,
    makeRequest(opts.cookie),
    reply,
    handle,
    userId,
    opts.via === undefined ? {} : { via: opts.via }
  );
  return { outcome, setCookies };
}

const LINKED = {
  status: 'linked',
  credentialId: 'cred-1',
  externalSub: 'alice@example.com',
  subjectSource: 'asserted-lookup',
  rebound: false,
};

beforeEach(() => {
  vi.clearAllMocks();
  (linkWalletPresentation as unknown as Mock).mockResolvedValue({ status: 'rejected' });
});

describe('startWalletLinkFlow — the device choice (#405)', () => {
  it('defaults an absent device field to cross-device (link)', async () => {
    const absent = await startLink();
    expect(absent.row['sameDevice']).toBe(false);
    expect(absent.flow['sameDevice']).toBeUndefined();
    expect(absent.started.sameDevice).toBe(false);

    const other = await startLink({ device: 'other' });
    expect(other.row['sameDevice']).toBe(false);
    expect(other.flow['sameDevice']).toBeUndefined();

    // Anything that is not exactly `'this'` is cross-device, so a caller that
    // reached the helper around its schema still gets the QR path.
    const junk = await startLink({ device: 'THIS' as never });
    expect(junk.row['sameDevice']).toBe(false);
    expect(junk.flow['sameDevice']).toBeUndefined();
  });

  it('(HAIP 1.0 §5.1) records the same-device choice on the link row and flow', async () => {
    const { row, flow, started } = await startLink({ device: 'this' });

    expect(row['sameDevice']).toBe(true);
    expect(flow['sameDevice']).toBe(true);
    expect(started.sameDevice).toBe(true);
    // Written together, from one choice: neither side can be same-device alone.
    expect(row['stateHash']).toBe(flow['stateHash']);
    expect(flow['mode']).toBe('link');
  });
});

describe('advanceWalletLinkFlow — same-device links never complete by polling (#405)', () => {
  it('(OID4VP 1.0 §14.2) the link poll never completes a same-device link — pending until the return leg', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink({
      device: 'this',
    });
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    (linkWalletPresentation as unknown as Mock).mockResolvedValue(LINKED);
    const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;

    // Explicit `poll` and the default alike.
    const polled = await advance(fastify, handle, userId, { cookie, via: 'poll' });
    expect(polled.outcome.status).toBe('pending');
    const defaulted = await advance(fastify, handle, userId, { cookie });
    expect(defaulted.outcome.status).toBe('pending');

    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(fastify.repositories.auditLogs.create).not.toHaveBeenCalled();
    expect(polled.setCookies).toEqual([]);
    // Nothing was terminated: the flow and its signal are still there.
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(true);
    expect(sessionUtils.store.has(`wallet-login-signal:${flow['stateHash']}`)).toBe(true);

    // The return leg is what completes it.
    const returned = await advance(fastify, handle, userId, { cookie, via: 'return' });
    expect(returned.outcome).toEqual({ status: 'linked', rebound: false });
    expect(linkWalletPresentation).toHaveBeenCalledTimes(1);
    expect(linkWalletPresentation).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ authenticatedUserId: userId, stateHash: flow['stateHash'] })
    );
  });

  it('(HAIP 1.0 §5.1) rejects a same-device link whose redirect was never followed after the deadline', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink({
      device: 'this',
    });
    (linkWalletPresentation as unknown as Mock).mockResolvedValue(LINKED);
    const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;

    // Inside the window: still waiting for the wallet to bring the browser back.
    publishSignal(
      sessionUtils,
      flow['stateHash'],
      'received',
      Date.now() - WALLET_RETURN_CODE_TTL_MS + 1000
    );
    expect((await advance(fastify, handle, userId, { cookie })).outcome.status).toBe('pending');

    // Past it: the code the wallet was handed can no longer be redeemed, so
    // the presentation is rejected — actively, with a reason in the log.
    publishSignal(
      sessionUtils,
      flow['stateHash'],
      'received',
      Date.now() - WALLET_RETURN_CODE_TTL_MS - 1
    );
    const rejected = await advance(fastify, handle, userId, { cookie });
    expect(rejected.outcome).toEqual({ status: 'rejected' });
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.anything(),
      'same-device presentation rejected: redirect not followed'
    );

    expect(linkWalletPresentation).not.toHaveBeenCalled();
    // Terminal: flow, signal and stash are gone, and a later poll is expired.
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
    expect(sessionUtils.store.has(`wallet-login-signal:${flow['stateHash']}`)).toBe(false);
    expect((await advance(fastify, handle, userId, { cookie })).outcome.status).toBe('expired');
  });

  it('surfaces a wallet error on a same-device link via the poll', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink({
      device: 'this',
    });
    publishSignal(sessionUtils, flow['stateHash'], 'wallet_error');

    const { outcome } = await advance(fastify, handle, userId, {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
    });

    expect(outcome).toEqual({ status: 'rejected' });
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
  });

  it('(HAIP 1.0 §5.1) ends a same-device link as rejected when its redirect landed in a foreign session', async () => {
    // The return route writes `return_rejected` where the wallet's `received`
    // was; the original tab's next poll must say so, not wait for the deadline.
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink({
      device: 'this',
    });
    publishSignal(sessionUtils, flow['stateHash'], 'return_rejected');

    const { outcome } = await advance(fastify, handle, userId, {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
    });

    expect(outcome).toEqual({ status: 'rejected' });
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.anything(),
      'same-device presentation rejected: redirect landed in a foreign session'
    );
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
  });

  it('cross-device links still complete via the poll exactly as before', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    (linkWalletPresentation as unknown as Mock).mockResolvedValue(LINKED);

    const { outcome, setCookies } = await advance(fastify, handle, userId, {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
    });

    expect(outcome).toEqual({ status: 'linked', rebound: false });
    // The binding is burned by the poll, as it always was, and no marker exists.
    expect(setCookies.some((c) => c.startsWith('__Host-qauth_wallet_flow='))).toBe(true);
    expect([...sessionUtils.store.keys()].some((k) => k.startsWith('wallet-login-done:'))).toBe(
      false
    );
    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'auth.wallet_link.success', userId })
    );
  });
});

describe('advanceWalletLinkFlow — the return leg and the done-marker (#405)', () => {
  it('links on the return leg, keeps the binding, and leaves a marker for the original tab', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink({
      device: 'this',
    });
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    (linkWalletPresentation as unknown as Mock).mockResolvedValue({ ...LINKED, rebound: true });

    const { outcome, setCookies } = await advance(fastify, handle, userId, {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
      via: 'return',
    });

    expect(outcome).toEqual({ status: 'linked', rebound: true });
    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'auth.wallet_link.success',
        userId,
        metadata: expect.objectContaining({ rebound: true }),
      })
    );

    // The binding was NOT dropped — the original tab must still be able to
    // prove it holds the flow — and the marker records the word to show.
    expect(setCookies).toEqual([]);
    expect(sessionUtils.store.get(`wallet-login-done:${handle}`)).toEqual({
      binder: flow['binder'],
      mode: 'link',
      outcome: 'rebound',
      linkUserId: userId,
    });

    // The flow itself is terminal.
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
    expect(sessionUtils.store.has(`wallet-login-signal:${flow['stateHash']}`)).toBe(false);
  });

  it('the original link tab consumes the done-marker once', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink({
      device: 'this',
    });
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    (linkWalletPresentation as unknown as Mock).mockResolvedValue(LINKED);
    const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;

    await advance(fastify, handle, userId, { cookie, via: 'return' });
    expect(linkWalletPresentation).toHaveBeenCalledTimes(1);

    // A poll WITHOUT the binder learns nothing and burns nothing.
    expect((await advance(fastify, handle, userId)).outcome.status).toBe('expired');
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(true);

    // A poll by a DIFFERENT user in this browser learns nothing either.
    const other = await advance(fastify, handle, 'user-2', { cookie });
    expect(other.outcome.status).toBe('expired');
    expect(other.setCookies).toEqual([]);
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(true);
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.anything(),
      'wallet-link done-marker read by a different session than the link was made for'
    );

    // The original tab: linked, once, and its binding dropped now that the
    // marker is consumed. No second write, no second audit row.
    const first = await advance(fastify, handle, userId, { cookie });
    expect(first.outcome).toEqual({ status: 'linked', rebound: false });
    expect(first.setCookies.some((c) => c.startsWith('__Host-qauth_wallet_flow='))).toBe(true);
    expect(
      readWalletFlowBindings(cookieValue(first.setCookies, '__Host-qauth_wallet_flow'))
    ).toEqual([]);
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(false);
    expect(linkWalletPresentation).toHaveBeenCalledTimes(1);
    expect(
      (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls.filter(
        (c) => (c[0] as { event: string }).event === 'auth.wallet_link.success'
      )
    ).toHaveLength(1);

    // Once.
    const second = await advance(fastify, handle, userId, { cookie });
    expect(second.outcome).toEqual({ status: 'expired' });
  });

  it("a link poll never consumes a LOGIN flow's marker", async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink({
      device: 'this',
    });
    // A login return would leave this shape; the link page is waiting for a
    // different word and must not eat it.
    sessionUtils.store.delete(`wallet-login:${handle}`);
    sessionUtils.store.set(`wallet-login-done:${handle}`, {
      binder: flow['binder'],
      mode: 'login',
      redirectTo: '/after',
    });

    const { outcome, setCookies } = await advance(fastify, handle, userId, {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
    });

    expect(outcome).toEqual({ status: 'expired' });
    expect(setCookies).toEqual([]);
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(true);
  });

  it('applies the same-user gate on the return leg, without touching the flow', async () => {
    const { fastify, sessionUtils, handle, flow, binderCookie } = await startLink({
      userId: 'user-1',
      device: 'this',
    });
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    (linkWalletPresentation as unknown as Mock).mockResolvedValue(LINKED);

    const { outcome, setCookies } = await advance(fastify, handle, 'user-2', {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
      via: 'return',
    });

    expect(outcome).toEqual({ status: 'expired' });
    expect(setCookies).toEqual([]);
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(fastify.repositories.auditLogs.create).not.toHaveBeenCalled();
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(true);
    expect([...sessionUtils.store.keys()].some((k) => k.startsWith('wallet-login-done:'))).toBe(
      false
    );
  });

  it('leaves no marker for a conflict or a refusal on the return leg', async () => {
    for (const resolution of [{ status: 'conflict' }, { status: 'rejected' }]) {
      const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink({
        device: 'this',
      });
      publishSignal(sessionUtils, flow['stateHash'], 'received');
      (linkWalletPresentation as unknown as Mock).mockResolvedValue(resolution);

      const { outcome, setCookies } = await advance(fastify, handle, userId, {
        cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
        via: 'return',
      });

      expect(outcome).toEqual(resolution);
      expect(setCookies).toEqual([]);
      expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
      expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(false);
      expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
        expect.objectContaining({ event: 'auth.wallet_link.failure', userId })
      );
    }
  });
});
