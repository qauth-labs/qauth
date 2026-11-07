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

vi.mock('./user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./user-events')>();
  const { checkedEmitUserEvent } = await import('../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

import { createFakeCookieSigner } from '../../testing/cookie-keys';
import { testRealm } from '../../testing/request-realm';
import { WALLET_RETURN_CODE_TTL_MS } from '../constants';
import type { RealmRow } from './request-realm';
import { readWalletFlowBindings } from './session-cookie';
import { emitUserEvent } from './user-events';
import { advanceWalletLinkFlow, startWalletLinkFlow } from './wallet-link-flow';
import {
  linkWalletPresentation,
  type WalletLinked,
  type WalletLinkInput,
  type WalletLinkTransaction,
} from './wallet-presentation';

const emitUserEventMock = vi.mocked(emitUserEvent);

const WALLET_LINKED = 'urn:qauth:event:wallet.linked:v1-rc.0';
const WALLET_LINK_FAILED = 'urn:qauth:event:wallet.link_failed:v1-rc.0';

/** The realm the realm resolver (#486) decorated every request with. */
const REALM = testRealm({ id: 'realm-1' });

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
 * In-memory stand-in for the one raw Redis command the flow machines use: the
 * `SET … NX` that claims a parked presentation for exactly one validation.
 */
function createRedis() {
  const store = new Map<string, string>();
  return {
    store,
    set: vi.fn(async (key: string, value: string, ...args: unknown[]) => {
      if (args.includes('NX') && store.has(key)) return null;
      store.set(key, value);
      return 'OK';
    }),
  };
}

function makeFastify() {
  const sessionUtils = createSessionUtils();
  const fastify: any = {
    repositories: {
      oid4vpRequestStates: { create: vi.fn(async (row: unknown) => row) },
    },
    sessionUtils,
    redis: createRedis(),
    // The wallet-flow cookie is signed with the realm's cookie key (#493).
    signer: createFakeCookieSigner(),
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, sessionUtils };
}

/**
 * A request as the state machine sees it: a cookie header, an address and the
 * realm of its host.
 */
function makeRequest(cookie?: string, realm: RealmRow = REALM): any {
  return { headers: cookie === undefined ? {} : { cookie }, ip: '127.0.0.1', realm };
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

/**
 * Start a linking flow for `userId` and return everything about it. Every
 * flow the helper starts is same-device (ADR-013 as amended 2026-11-07).
 */
async function startLink(opts: { userId?: string } = {}) {
  const context = makeFastify();
  const userId = opts.userId ?? 'user-1';
  const { reply, setCookies } = makeReply();

  const started = await startWalletLinkFlow(context.fastify, makeRequest(), reply, userId);
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

/**
 * Rewrite a started flow into the record a CROSS-device link left before
 * linking became same-device only (ADR-013 as amended 2026-11-07): the
 * record carried no `sameDevice` at all. This is the shape a flow still
 * pending across the upgrade has, and the only way one can exist now.
 */
function makeCrossDeviceFlow(sessionUtils: ReturnType<typeof createSessionUtils>, handle: string) {
  const key = `wallet-login:${handle}`;
  const { sameDevice: _sameDevice, ...legacy } = sessionUtils.store.get(key) as Record<
    string,
    unknown
  >;
  sessionUtils.store.set(key, legacy);
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
  opts: { cookie?: string; via?: 'poll' | 'return'; realm?: RealmRow } = {}
) {
  const { reply, setCookies } = makeReply();
  const outcome = await advanceWalletLinkFlow(
    fastify,
    makeRequest(opts.cookie, opts.realm),
    reply,
    handle,
    userId,
    opts.via === undefined ? {} : { via: opts.via }
  );
  return { outcome, setCookies };
}

const LINKED: WalletLinked = {
  status: 'linked',
  credentialId: 'cred-1',
  externalSub: 'alice@example.com',
  subjectSource: 'asserted-lookup',
  rebound: false,
};

/** The transaction the stubbed link runs its `onLinked` hook in. */
const LINK_TX = { name: 'link-transaction' } as unknown as WalletLinkTransaction;

/**
 * Stub the link as `linkWalletPresentation` completes one: the caller's
 * `onLinked` hook runs in the link's transaction, then the result returns.
 */
function linkAs(resolution: WalletLinked) {
  (linkWalletPresentation as unknown as Mock).mockImplementation(
    async (_fastify: FastifyInstance, input: WalletLinkInput) => {
      await input.onLinked?.(LINK_TX, resolution);
      return resolution;
    }
  );
}

/** The `wallet.linked` / `wallet.link_failed` events written so far. */
function eventsOf(type: string) {
  return emitUserEventMock.mock.calls.filter((call) => call[1] === type);
}

beforeEach(() => {
  vi.clearAllMocks();
  (linkWalletPresentation as unknown as Mock).mockResolvedValue({ status: 'rejected' });
});

describe('startWalletLinkFlow — same-device only (ADR-013 as amended 2026-11-07)', () => {
  it('(HAIP 1.0 §5.1) records the link as same-device on the link row and flow', async () => {
    const { row, flow } = await startLink();

    expect(row['sameDevice']).toBe(true);
    expect(flow['sameDevice']).toBe(true);
    // Written together, from one constant: neither side can be cross-device alone.
    expect(row['stateHash']).toBe(flow['stateHash']);
    expect(flow['mode']).toBe('link');
  });

  it('starts a same-device flow whatever device a caller passes around its types', async () => {
    // The helper takes no device: a caller that reached it with the old
    // option, or with anything else, still gets the only mode there is.
    for (const device of ['other', 'THIS', undefined]) {
      const context = makeFastify();
      const { reply } = makeReply();
      const started = await (
        startWalletLinkFlow as unknown as (
          ...args: unknown[]
        ) => ReturnType<typeof startWalletLinkFlow>
      )(context.fastify, makeRequest(), reply, 'user-1', { device });
      if (started === undefined) throw new Error('the linking flow did not start');

      const row = (context.fastify.repositories.oid4vpRequestStates.create as unknown as Mock).mock
        .calls[0][0] as Record<string, unknown>;
      const flow = context.sessionUtils.store.get(`wallet-login:${started.handle}`) as Record<
        string,
        unknown
      >;
      expect(row['sameDevice']).toBe(true);
      expect(flow['sameDevice']).toBe(true);
    }
  });
});

describe('advanceWalletLinkFlow — same-device links never complete by polling (#405)', () => {
  it('(OID4VP 1.0 §14.2) the link poll never completes a same-device link — pending until the return leg', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    linkAs(LINKED);
    const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;

    // Explicit `poll` and the default alike.
    const polled = await advance(fastify, handle, userId, { cookie, via: 'poll' });
    expect(polled.outcome.status).toBe('pending');
    const defaulted = await advance(fastify, handle, userId, { cookie });
    expect(defaulted.outcome.status).toBe('pending');

    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(emitUserEventMock).not.toHaveBeenCalled();
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
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
    linkAs(LINKED);
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
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
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
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
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
});

/**
 * A cross-device link completed by polling, and nothing on that path tied the
 * wallet that answered to the browser that asked. Such a flow can now exist
 * only as one still pending from before the upgrade, and it must bind nothing,
 * by either surface, whoever's wallet answered it.
 */
describe('advanceWalletLinkFlow — a cross-device link binds nothing (ADR-013 as amended 2026-11-07)', () => {
  it('refuses a cross-device link another wallet answered, on the starter’s poll: no link, no event, the flow ended', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink({
      userId: 'starter',
    });
    makeCrossDeviceFlow(sessionUtils, handle);
    // A wallet answered the request: any wallet, on any device.
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    sessionUtils.store.set(`wallet-presentation:${flow['stateHash']}`, {
      presentations: [{ queryId: 'q', format: 'dc+sd-jwt', presentation: 'someone-else' }],
    });
    linkAs(LINKED);

    // The starter's browser holds the binder and the session: every gate but
    // the device one passes.
    const { outcome } = await advance(fastify, handle, userId, {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
    });

    expect(outcome).toEqual({ status: 'rejected' });
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(emitUserEventMock).not.toHaveBeenCalled();
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.anything(),
      'cross-device wallet link refused: linking is same-device only'
    );
    // Terminal: the flow, its signal and the parked presentation are gone, and
    // a later poll is expired.
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
    expect(sessionUtils.store.has(`wallet-login-signal:${flow['stateHash']}`)).toBe(false);
    expect(sessionUtils.store.has(`wallet-presentation:${flow['stateHash']}`)).toBe(false);
    expect(
      (
        await advance(fastify, handle, userId, {
          cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
        })
      ).outcome.status
    ).toBe('expired');
  });

  it('refuses a pending cross-device link on its first poll, before any wallet answered', async () => {
    const { fastify, sessionUtils, handle, userId, binderCookie } = await startLink();
    makeCrossDeviceFlow(sessionUtils, handle);

    const { outcome } = await advance(fastify, handle, userId, {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
    });

    expect(outcome).toEqual({ status: 'rejected' });
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
  });

  it('refuses a cross-device link on the return leg too, leaving a rejected marker', async () => {
    // Unreachable through the routes — a cross-device row's Response Code is
    // never handed out or redeemed — and refused here all the same.
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
    makeCrossDeviceFlow(sessionUtils, handle);
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    linkAs(LINKED);

    const { outcome } = await advance(fastify, handle, userId, {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
      via: 'return',
    });

    expect(outcome).toEqual({ status: 'rejected' });
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(sessionUtils.store.get(`wallet-login-done:${handle}`)).toMatchObject({
      mode: 'link',
      outcome: 'rejected',
    });
  });

  it('hands the writer the recorded device mode, so it can refuse on its own', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    linkAs(LINKED);

    await advance(fastify, handle, userId, {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
      via: 'return',
    });

    expect(linkWalletPresentation).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ sameDevice: true })
    );
  });
});

describe('advanceWalletLinkFlow — a flow of another realm (#489)', () => {
  it('answers it exactly as an unknown flow, and leaves it to its own realm', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    linkAs(LINKED);
    const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;

    // At a host of another realm, with the browser's own binder: the answer
    // of an unknown handle, and the presentation is not looked at.
    const unknown = await advance(fastify, 'A'.repeat(43), userId, { cookie });
    const foreign = await advance(fastify, handle, userId, {
      cookie,
      realm: testRealm({ id: 'realm-2' }),
    });
    expect(foreign.outcome).toEqual(unknown.outcome);
    expect(foreign.setCookies).toEqual(unknown.setCookies);
    expect(linkWalletPresentation).not.toHaveBeenCalled();

    // The flow is untouched: at its own realm's host its return leg still links.
    const own = await advance(fastify, handle, userId, { cookie, via: 'return' });
    expect(own.outcome).toEqual({ status: 'linked', rebound: false });
  });
});

describe('advanceWalletLinkFlow — concurrent polls validate a presentation once (ANT-2026-IOU62CQU)', () => {
  it('links a parked presentation ONCE however many completions are in flight', async () => {
    // A link completes only on the return leg (ADR-013 as amended
    // 2026-11-07), so the concurrent callers are return-leg requests.
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
    publishSignal(sessionUtils, flow['stateHash'], 'received');

    const held: Array<(value: unknown) => void> = [];
    (linkWalletPresentation as unknown as Mock).mockImplementation(
      () => new Promise((resolve) => held.push(resolve))
    );

    const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;
    const polls = Array.from({ length: 3 }, () =>
      advance(fastify, handle, userId, { cookie, via: 'return' })
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    for (const release of held) release(LINKED);
    const results = await Promise.all(polls);

    expect(linkWalletPresentation).toHaveBeenCalledTimes(1);
    const statuses = results.map((r) => r.outcome.status).sort();
    expect(statuses).toEqual(['linked', 'pending', 'pending']);
  });
});

describe('advanceWalletLinkFlow — the return leg and the done-marker (#405)', () => {
  it('links on the return leg, keeps the binding, and leaves a marker for the original tab', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    linkAs({ ...LINKED, rebound: true });

    const { outcome, setCookies } = await advance(fastify, handle, userId, {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
      via: 'return',
    });

    expect(outcome).toEqual({ status: 'linked', rebound: true });
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      WALLET_LINKED,
      expect.objectContaining({ rebound: true }),
      expect.objectContaining({ tx: LINK_TX, userId, actor: 'user' })
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
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    linkAs(LINKED);
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
    // marker is consumed. No second write, no second event.
    const first = await advance(fastify, handle, userId, { cookie });
    expect(first.outcome).toEqual({ status: 'linked', rebound: false });
    expect(first.setCookies.some((c) => c.startsWith('__Host-qauth_wallet_flow='))).toBe(true);
    expect(
      await readWalletFlowBindings(
        fastify,
        REALM.id,
        cookieValue(first.setCookies, '__Host-qauth_wallet_flow')
      )
    ).toEqual([]);
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(false);
    expect(linkWalletPresentation).toHaveBeenCalledTimes(1);
    expect(eventsOf(WALLET_LINKED)).toHaveLength(1);

    // Once.
    const second = await advance(fastify, handle, userId, { cookie });
    expect(second.outcome).toEqual({ status: 'expired' });
  });

  it("a link poll never consumes a LOGIN flow's marker", async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
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
    });
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    linkAs(LINKED);

    const { outcome, setCookies } = await advance(fastify, handle, 'user-2', {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
      via: 'return',
    });

    expect(outcome).toEqual({ status: 'expired' });
    expect(setCookies).toEqual([]);
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(emitUserEventMock).not.toHaveBeenCalled();
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(true);
    expect([...sessionUtils.store.keys()].some((k) => k.startsWith('wallet-login-done:'))).toBe(
      false
    );
  });

  it('leaves a marker carrying the word for a conflict or a refusal on the return leg, which the original tab reads once', async () => {
    for (const resolution of [{ status: 'conflict' }, { status: 'rejected' }] as const) {
      const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
      publishSignal(sessionUtils, flow['stateHash'], 'received');
      (linkWalletPresentation as unknown as Mock).mockResolvedValue(resolution);
      const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;

      const { outcome, setCookies } = await advance(fastify, handle, userId, {
        cookie,
        via: 'return',
      });

      expect(outcome).toEqual(resolution);
      expect(setCookies).toEqual([]);
      expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
      expect(sessionUtils.store.get(`wallet-login-done:${handle}`)).toEqual({
        binder: flow['binder'],
        mode: 'link',
        outcome: resolution.status,
        linkUserId: userId,
      });
      // A refusal changes nothing: its event is written on its own.
      expect(emitUserEventMock).toHaveBeenCalledWith(
        expect.anything(),
        WALLET_LINK_FAILED,
        { reason: resolution.status, verifierProfile: 'oid4vp-1.0-base' },
        { realmId: 'realm-1', userId, actor: 'user' }
      );

      // The original tab is told the SAME word the return tab showed — not
      // "expired" — once, with its binding dropped and no second event.
      const first = await advance(fastify, handle, userId, { cookie });
      expect(first.outcome).toEqual(resolution);
      expect(first.setCookies.some((c) => c.startsWith('__Host-qauth_wallet_flow='))).toBe(true);
      expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(false);
      expect(linkWalletPresentation).toHaveBeenCalledTimes(1);
      expect(eventsOf(WALLET_LINK_FAILED)).toHaveLength(1);
      expect((await advance(fastify, handle, userId, { cookie })).outcome).toEqual({
        status: 'expired',
      });
      // The seam mocks are shared across iterations; their call counts are not.
      (linkWalletPresentation as unknown as Mock).mockClear();
      emitUserEventMock.mockClear();
    }
  });

  it('a wallet error on the return leg is reported to the original tab as rejected, once', async () => {
    // The Response Endpoint hands out a redirect_uri on its wallet-error path
    // too (OID4VP 1.0 §8.2 "or for Error Responses"); the user who declined
    // is looking at the original tab, and it must say what the return tab said.
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
    publishSignal(sessionUtils, flow['stateHash'], 'wallet_error');
    const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;

    const returned = await advance(fastify, handle, userId, { cookie, via: 'return' });
    expect(returned.outcome).toEqual({ status: 'rejected' });
    expect(linkWalletPresentation).not.toHaveBeenCalled();
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(false);
    expect(sessionUtils.store.get(`wallet-login-done:${handle}`)).toEqual({
      binder: flow['binder'],
      mode: 'link',
      outcome: 'rejected',
      linkUserId: userId,
    });

    const first = await advance(fastify, handle, userId, { cookie });
    expect(first.outcome).toEqual({ status: 'rejected' });
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(false);
    expect((await advance(fastify, handle, userId, { cookie })).outcome).toEqual({
      status: 'expired',
    });
  });

  it('a marker carrying a word this machine does not know reads as rejected, never as linked', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
    sessionUtils.store.delete(`wallet-login:${handle}`);
    sessionUtils.store.set(`wallet-login-done:${handle}`, {
      binder: flow['binder'],
      mode: 'link',
      outcome: 'complete',
      linkUserId: userId,
    });

    const { outcome } = await advance(fastify, handle, userId, {
      cookie: `__Host-qauth_wallet_flow=${binderCookie}`,
    });

    expect(outcome).toEqual({ status: 'rejected' });
    expect(sessionUtils.store.has(`wallet-login-done:${handle}`)).toBe(false);
  });

  it('writes the marker BEFORE deleting the flow, so a poll mid-completion is pending, never expired', async () => {
    const { fastify, sessionUtils, handle, flow, userId, binderCookie } = await startLink();
    publishSignal(sessionUtils, flow['stateHash'], 'received');
    linkAs(LINKED);
    const cookie = `__Host-qauth_wallet_flow=${binderCookie}`;

    // Hold the return leg between the credential write and its conclusion:
    // the event, in the link's transaction, is the last thing before the
    // marker and the deletion.
    let releaseEvent!: () => void;
    const eventHeld = new Promise<string>((resolve) => {
      releaseEvent = () => resolve('event-id');
    });
    emitUserEventMock.mockImplementationOnce(() => eventHeld);
    const returning = advance(fastify, handle, userId, { cookie, via: 'return' });
    await vi.waitFor(() => expect(emitUserEventMock).toHaveBeenCalled());

    // The original tab polls while the return leg is mid-completion: the flow
    // is still there, so it is `pending` — and the poll resolves nothing.
    const polled = await advance(fastify, handle, userId, { cookie });
    expect(polled.outcome.status).toBe('pending');
    expect(linkWalletPresentation).toHaveBeenCalledTimes(1);
    expect(sessionUtils.store.has(`wallet-login:${handle}`)).toBe(true);

    releaseEvent();
    expect((await returning).outcome).toEqual({ status: 'linked', rebound: false });

    // Spy call order: the marker was set before the flow was deleted.
    const markerWrite = sessionUtils.setSession.mock.calls.findIndex(
      (c) => c[0] === `wallet-login-done:${handle}`
    );
    const flowDelete = sessionUtils.deleteSession.mock.calls.findIndex(
      (c) => c[0] === `wallet-login:${handle}`
    );
    expect(markerWrite).toBeGreaterThanOrEqual(0);
    expect(flowDelete).toBeGreaterThanOrEqual(0);
    expect(sessionUtils.setSession.mock.invocationCallOrder[markerWrite]).toBeLessThan(
      sessionUtils.deleteSession.mock.invocationCallOrder[flowDelete]
    );

    // And the first poll after the deletion finds the marker.
    expect((await advance(fastify, handle, userId, { cookie })).outcome).toEqual({
      status: 'linked',
      rebound: false,
    });
  });
});
