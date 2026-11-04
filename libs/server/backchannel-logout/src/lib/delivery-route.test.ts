import { EgressError, type EgressRequest } from '@qauth-labs/server-egress';
import type { Delivery, DeliverySigner } from '@qauth-labs/server-event-delivery';
import { type EventEnvelope, getEventType } from '@qauth-labs/shared-events';
import { describe, expect, it, vi } from 'vitest';

import {
  BACKCHANNEL_LOGOUT_DELIVERY_KIND,
  BACKCHANNEL_LOGOUT_EVENT,
  CLIENT_SESSION_ENDED_EVENT,
} from './constants';
import {
  type BackchannelLogoutClient,
  type BackchannelLogoutClientSource,
  createBackchannelLogoutRoute,
} from './delivery-route';

const REALM = '0192a000-0000-7000-8000-000000000001';
const OTHER_REALM = '0192a000-0000-7000-8000-000000000002';
const CLIENT_ROW = '0192a000-0000-7000-8000-0000000000cc';
const USER = '0192a000-0000-7000-8000-0000000000bb';
const SID = '0192a000-0000-7000-8000-0000000000aa';
const EVENT_ID = '0192a000-0000-7000-8000-0000000000ee';
const DELIVERY_ID = '0192a000-0000-7000-8000-0000000000dd';
const NOW = Date.UTC(2026, 10, 4, 9, 0, 0);

function client(overrides: Partial<BackchannelLogoutClient> = {}): BackchannelLogoutClient {
  return {
    id: CLIENT_ROW,
    realmId: REALM,
    clientId: 'rp',
    uri: 'https://rp.example/backchannel',
    uriSource: 'client',
    sessionRequired: false,
    active: true,
    realmName: 'acme',
    ...overrides,
  };
}

function ended(overrides: Partial<EventEnvelope> = {}): EventEnvelope {
  return {
    id: EVENT_ID,
    type: CLIENT_SESSION_ENDED_EVENT,
    time: '2026-11-04T09:00:00.000Z',
    realm: REALM,
    category: 'user',
    subject: { type: 'user', id: USER },
    client: { id: 'rp' },
    data: { sid: SID, reason: 'sign_out' },
    ...overrides,
  } as EventEnvelope;
}

const delivery: Delivery = {
  id: DELIVERY_ID,
  destinationKind: BACKCHANNEL_LOGOUT_DELIVERY_KIND,
  destinationId: CLIENT_ROW,
  realmId: REALM,
  eventId: EVENT_ID,
  attempt: 1,
};

function egressError(reason: 'address' | 'scheme' | 'timeout', outcome: 'blocked' | 'failed') {
  return new EgressError({
    reason,
    outcome,
    purpose: 'backchannel-logout',
    host: 'rp.example',
    message: `${outcome}: ${reason}`,
  });
}

function setup(
  options: {
    found?: BackchannelLogoutClient | undefined;
    respond?: (request: EgressRequest) => Promise<{ status: number; body?: Buffer }>;
  } = {}
) {
  const found = 'found' in options ? options.found : client();
  const clients: BackchannelLogoutClientSource = {
    listDestinations: vi.fn(async () => [{ id: CLIENT_ROW, realmId: REALM, clientId: 'rp' }]),
    findForDelivery: vi.fn(async () => found),
  };
  const request = vi.fn(async (call: EgressRequest) => {
    const answer = options.respond ? await options.respond(call) : { status: 200 };
    return {
      status: answer.status,
      headers: {},
      body: answer.body ?? Buffer.alloc(0),
      url: String(call.url),
      redirects: 0,
    };
  });
  const signer: DeliverySigner = {
    signWebhook: vi.fn(),
    signEventToken: vi.fn(async () => 'signed.logout.token'),
    decrypt: vi.fn(),
  };
  const route = createBackchannelLogoutRoute({ clients, egress: { request }, now: () => NOW });
  const context = { signal: new AbortController().signal, signer };
  return { route, clients, request, signer, context };
}

describe('createBackchannelLogoutRoute (OpenID Connect Back-Channel Logout 1.0, #624)', () => {
  it('names an event type the registry defines', () => {
    expect(getEventType(CLIENT_SESSION_ENDED_EVENT)?.name).toBe('user.client_session_ended');
  });

  it('lists each client with a URI, taking only the events that name it', async () => {
    const { route } = setup();

    expect(route.kind).toBe('backchannel_logout');
    expect(await route.destinations()).toEqual([
      {
        id: CLIENT_ROW,
        realmId: REALM,
        types: [CLIENT_SESSION_ENDED_EVENT],
        typeRules: { [CLIENT_SESSION_ENDED_EVENT]: { clientId: 'rp' } },
      },
    ]);
  });

  it('signs a logout token through the signer handle and POSTs it as the logout_token form parameter (§2.5)', async () => {
    const { route, request, signer, context } = setup();

    const outcome = await route.deliver(delivery, ended(), context);

    expect(outcome).toEqual({ ok: true, statusCode: 200 });
    expect(signer.signEventToken).toHaveBeenCalledWith({
      realmId: REALM,
      typ: 'logout+jwt',
      claims: {
        aud: 'rp',
        iat: NOW / 1000,
        exp: NOW / 1000 + 120,
        jti: DELIVERY_ID,
        events: { [BACKCHANNEL_LOGOUT_EVENT]: {} },
        sub: USER,
        sid: SID,
      },
    });
    expect(request).toHaveBeenCalledTimes(1);
    expect(request).toHaveBeenCalledWith({
      method: 'POST',
      url: 'https://rp.example/backchannel',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'logout_token=signed.logout.token',
      purpose: 'backchannel-logout',
      source: 'client',
      realm: 'acme',
      limits: { maxRedirects: 0, maxResponseBytes: 64 * 1024 },
    });
  });

  it('lets only a URI an admin set use the egress allowlist (ADR-019 Decision 8)', async () => {
    const { route, request, context } = setup({ found: client({ uriSource: 'admin' }) });

    await route.deliver(delivery, ended(), context);

    expect(request.mock.calls[0][0].source).toBe('admin');
  });

  it('keeps the jti of a delivery across its retries, and signs a fresh iat and exp each time', async () => {
    let now = NOW;
    const clients: BackchannelLogoutClientSource = {
      listDestinations: vi.fn(async () => []),
      findForDelivery: vi.fn(async () => client()),
    };
    const signEventToken = vi.fn(async () => 't');
    const route = createBackchannelLogoutRoute({
      clients,
      egress: {
        request: vi.fn(async () => ({
          status: 503,
          headers: {},
          body: Buffer.alloc(0),
          url: '',
          redirects: 0,
        })),
      },
      now: () => now,
    });
    const context = {
      signal: new AbortController().signal,
      signer: { signWebhook: vi.fn(), signEventToken, decrypt: vi.fn() },
    };

    await route.deliver(delivery, ended(), context);
    now += 3_600_000;
    await route.deliver({ ...delivery, attempt: 2 }, ended(), context);

    const [first, second] = signEventToken.mock.calls.map(
      (call) =>
        (call as unknown as [{ claims: { jti: string; iat: number; exp: number } }])[0].claims
    );
    expect(second.jti).toBe(first.jti);
    expect(second.iat).toBe(first.iat + 3_600);
    expect(second.exp - second.iat).toBe(120);
  });

  it.each([
    [500, true],
    [502, true],
    [503, true],
    [408, true],
    [429, true],
    [400, false],
    [401, false],
    [404, false],
    [301, false],
  ])('a receiver answering %i is retried: %s (§2.5)', async (status, retry) => {
    const { route, context } = setup({ respond: async () => ({ status }) });

    expect(await route.deliver(delivery, ended(), context)).toEqual({
      ok: false,
      statusCode: status,
      errorClass: 'http_status',
      retry,
    });
  });

  it('a 204 delivers', async () => {
    const { route, context } = setup({ respond: async () => ({ status: 204 }) });
    expect(await route.deliver(delivery, ended(), context)).toEqual({ ok: true, statusCode: 204 });
  });

  it('a URI the egress client refuses for its address is retried, since the name may resolve elsewhere later', async () => {
    const { route, context } = setup({
      respond: async () => {
        throw egressError('address', 'blocked');
      },
    });

    expect(await route.deliver(delivery, ended(), context)).toEqual({
      ok: false,
      errorClass: 'destination_blocked',
      retry: true,
    });
  });

  it('a URI the egress client refuses for its form is not retried', async () => {
    const { route, context } = setup({
      respond: async () => {
        throw egressError('scheme', 'blocked');
      },
    });

    expect(await route.deliver(delivery, ended(), context)).toEqual({
      ok: false,
      errorClass: 'destination_blocked',
      retry: false,
    });
  });

  it('a timeout is retried', async () => {
    const { route, context } = setup({
      respond: async () => {
        throw egressError('timeout', 'failed');
      },
    });

    expect(await route.deliver(delivery, ended(), context)).toEqual({
      ok: false,
      errorClass: 'timeout',
    });
  });

  it('an error that is not the egress client’s is thrown to the delivery role', async () => {
    const { route, context } = setup({
      respond: async () => {
        throw new Error('bug');
      },
    });

    await expect(route.deliver(delivery, ended(), context)).rejects.toThrow('bug');
  });

  it.each([
    ['a deleted client', { found: undefined }, ended(), 'client_deleted'],
    [
      'a disabled or suspended client',
      { found: client({ active: false }) },
      ended(),
      'client_inactive',
    ],
    [
      'a client whose URI was removed',
      { found: client({ uri: null, uriSource: null }) },
      ended(),
      'logout_uri_removed',
    ],
    [
      'a client of another realm',
      { found: client({ realmId: OTHER_REALM }) },
      ended(),
      'realm_mismatch',
    ],
    ['an event of another realm', {}, ended({ realm: OTHER_REALM }), 'realm_mismatch'],
    [
      'an event that names another client',
      {},
      ended({ client: { id: 'other' } }),
      'event_not_offered',
    ],
    [
      'an event of another type',
      {},
      ended({ type: 'urn:qauth:event:user.signed_out:v1-rc.0' }),
      'event_not_offered',
    ],
    [
      'a client that needs sid, for an event without one (§2.2)',
      { found: client({ sessionRequired: true }) },
      ended({ data: { reason: 'sign_out' } } as Partial<EventEnvelope>),
      'sid_unavailable',
    ],
  ])('sends nothing to %s, and does not retry', async (_label, options, event, errorClass) => {
    const { route, request, signer, context } = setup(options);

    expect(await route.deliver(delivery, event, context)).toEqual({
      ok: false,
      errorClass,
      retry: false,
    });
    expect(signer.signEventToken).not.toHaveBeenCalled();
    expect(request).not.toHaveBeenCalled();
  });

  it('sends sub alone to a client that does not need sid, when the event has none', async () => {
    const { route, signer, context } = setup();

    await route.deliver(
      delivery,
      ended({ data: { reason: 'sign_out' } } as Partial<EventEnvelope>),
      context
    );

    const claims = vi.mocked(signer.signEventToken).mock.calls[0][0].claims;
    expect(claims['sub']).toBe(USER);
    expect(claims).not.toHaveProperty('sid');
  });
});
