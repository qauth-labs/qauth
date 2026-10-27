import { EgressError, type EgressRequest } from '@qauth-labs/server-egress';
import type { Delivery, DeliverySigner } from '@qauth-labs/server-event-delivery';
import { type EventEnvelope, ssfStreamVerificationRequested } from '@qauth-labs/shared-events';
import { describe, expect, it, vi } from 'vitest';

import { SSF_VERIFICATION_EVENT } from './constants';
import {
  createSsfDeliveryRoute,
  receiverErrorClass,
  type SsfDeliveryStream,
  type SsfStreamSource,
} from './delivery-route';

const REALM = '0192a000-0000-7000-8000-000000000001';
const OTHER_REALM = '0192a000-0000-7000-8000-000000000002';
const STREAM = '0192a000-0000-7000-8000-0000000000aa';
const EVENT_ID = '0192a000-0000-7000-8000-0000000000ee';

function egressError(reason: 'address' | 'timeout', outcome: 'blocked' | 'failed') {
  return new EgressError({
    reason,
    outcome,
    purpose: 'ssf_push',
    host: 'receiver.example',
    message: `${outcome}: ${reason}`,
  });
}

function stream(overrides: Partial<SsfDeliveryStream> = {}): SsfDeliveryStream {
  return {
    id: STREAM,
    realmId: REALM,
    audience: 'receiver',
    endpointUrl: 'https://receiver.example/events',
    authorizationHeader: null,
    status: 'enabled',
    active: true,
    ...overrides,
  };
}

function verification(overrides: Partial<EventEnvelope> = {}): EventEnvelope {
  return {
    id: EVENT_ID,
    type: ssfStreamVerificationRequested.type,
    time: '2026-10-25T10:00:00.000Z',
    realm: REALM,
    category: 'user',
    subject: { type: 'ssf_stream', id: STREAM },
    data: { state: 'abc' },
    ...overrides,
  } as EventEnvelope;
}

const delivery: Delivery = {
  id: 'd1',
  destinationKind: 'ssf',
  destinationId: STREAM,
  realmId: REALM,
  eventId: EVENT_ID,
  attempt: 1,
};

function setup(
  options: {
    stream?: SsfDeliveryStream | undefined;
    answer?: (request: EgressRequest) => { status: number; body?: string } | Error;
  } = {}
) {
  const requests: EgressRequest[] = [];
  const egress = {
    request: vi.fn(async (request: EgressRequest) => {
      requests.push(request);
      const answer = options.answer?.(request) ?? { status: 202 };
      if (answer instanceof Error) throw answer;
      return {
        status: answer.status,
        headers: {},
        body: Buffer.from(answer.body ?? ''),
        url: String(request.url),
        redirects: 0,
      };
    }),
  };
  const streams: SsfStreamSource = {
    listDestinations: async () => [
      { id: STREAM, realmId: REALM, eventsRequested: [], subjects: [{ type: 'user', id: 'u1' }] },
    ],
    findForDelivery: async () => ('stream' in options ? options.stream : stream()),
  };
  const signer = {
    signWebhook: vi.fn(async () => 'v1,x'),
    signEventToken: vi.fn<DeliverySigner['signEventToken']>(async () => 'h.p.s'),
    decrypt: vi.fn<DeliverySigner['decrypt']>(async () => new TextEncoder().encode('Bearer t')),
  };
  const route = createSsfDeliveryRoute({ streams, egress });
  const context = { signal: new AbortController().signal, signer };
  return { route, requests, signer, context };
}

describe('createSsfDeliveryRoute', () => {
  it('lists each stream with the types it requested and its subjects', async () => {
    const { route } = setup();
    expect(route.kind).toBe('ssf');
    expect(await route.destinations()).toEqual([
      { id: STREAM, realmId: REALM, types: [], subjects: [{ type: 'user', id: 'u1' }] },
    ]);
  });

  it('pushes a signed verification SET whose jti is the event id', async () => {
    const { route, requests, signer, context } = setup();
    const outcome = await route.deliver(delivery, verification(), context);
    expect(outcome).toEqual({ ok: true, statusCode: 202 });
    expect(signer.signEventToken).toHaveBeenCalledWith({
      realmId: REALM,
      typ: 'secevent+jwt',
      claims: {
        jti: EVENT_ID,
        iat: Date.parse('2026-10-25T10:00:00.000Z') / 1000,
        aud: 'receiver',
        sub_id: { format: 'opaque', id: STREAM },
        events: { [SSF_VERIFICATION_EVENT]: { state: 'abc' } },
      },
    });
    expect(requests).toEqual([
      {
        method: 'POST',
        url: 'https://receiver.example/events',
        headers: { 'content-type': 'application/secevent+jwt', accept: 'application/json' },
        body: 'h.p.s',
        purpose: 'ssf_push',
        source: 'client',
        limits: { maxRedirects: 0, maxResponseBytes: 65536 },
      },
    ]);
    expect(signer.decrypt).not.toHaveBeenCalled();
  });

  it('sends the receiver header, decrypted for the attempt under its stream context', async () => {
    const { route, requests, signer, context } = setup({
      stream: stream({ authorizationHeader: 'v1.k.i.c' }),
    });
    await route.deliver(delivery, verification(), context);
    expect(signer.decrypt).toHaveBeenCalledWith({
      realmId: REALM,
      ciphertext: 'v1.k.i.c',
      context: `delivery:ssf_streams.authorization_header:${STREAM}`,
    });
    expect(requests[0].headers).toMatchObject({ authorization: 'Bearer t' });
  });

  it.each([
    [{ status: 503 }, { ok: false, statusCode: 503, errorClass: 'http_status' }],
    [{ status: 401 }, { ok: false, statusCode: 401, errorClass: 'http_status' }],
    [
      { status: 400, body: '{"err":"invalid_audience"}' },
      { ok: false, statusCode: 400, errorClass: 'set_invalid_audience', retry: false },
    ],
    [
      { status: 400, body: '{"err":"invalid_key"}' },
      { ok: false, statusCode: 400, errorClass: 'set_invalid_key', retry: true },
    ],
    // A 400 without a known `err` says nothing about the SET: retried.
    [
      { status: 400, body: 'not json' },
      { ok: false, statusCode: 400, errorClass: 'http_status' },
    ],
    [
      { status: 400, body: '{"err":"something_else"}' },
      { ok: false, statusCode: 400, errorClass: 'http_status' },
    ],
    [
      egressError('address', 'blocked'),
      { ok: false, errorClass: 'destination_blocked', retry: true },
    ],
    [egressError('timeout', 'failed'), { ok: false, errorClass: 'timeout' }],
  ])('turns %o into %o', async (answer, outcome) => {
    const { route, context } = setup({ answer: () => answer });
    expect(await route.deliver(delivery, verification(), context)).toEqual(outcome);
  });

  it.each([
    ['a deleted stream', undefined, 'stream_deleted', false],
    ['an inactive stream', stream({ active: false }), 'stream_inactive', false],
    ['a disabled stream', stream({ status: 'disabled' }), 'stream_disabled', false],
    ['a stream of another realm', stream({ realmId: OTHER_REALM }), 'realm_mismatch', false],
  ])('ends a delivery to %s without sending', async (_label, found, errorClass, retry) => {
    const { route, requests, signer, context } = setup({ stream: found });
    expect(await route.deliver(delivery, verification(), context)).toEqual({
      ok: false,
      errorClass,
      retry,
    });
    expect(requests).toEqual([]);
    expect(signer.signEventToken).not.toHaveBeenCalled();
  });

  it('holds the events of a paused stream: no attempt spent, nothing sent', async () => {
    const { route, requests, context } = setup({ stream: stream({ status: 'paused' }) });
    expect(await route.deliver(delivery, verification(), context)).toEqual({
      ok: false,
      hold: true,
    });
    expect(requests).toEqual([]);
  });

  it("never sends another stream's verification, nor an event it does not offer", async () => {
    const { route, requests, context } = setup();
    const other = verification({ subject: { type: 'ssf_stream', id: 'another-stream' } });
    expect(await route.deliver(delivery, other, context)).toMatchObject({
      errorClass: 'event_not_offered',
      retry: false,
    });
    const signIn = verification({ type: 'urn:qauth:event:user.signed_in:v1-rc.0' });
    expect(await route.deliver(delivery, signIn, context)).toMatchObject({
      errorClass: 'event_not_offered',
    });
    expect(requests).toEqual([]);
  });

  it('shows a receiver one class for an endpoint refused and one not reached', () => {
    expect(receiverErrorClass('destination_blocked')).toBe('destination_unreachable');
    expect(receiverErrorClass('network')).toBe('destination_unreachable');
    for (const kept of ['http_status', 'timeout', 'set_invalid_key', 'attempt_interrupted']) {
      expect(receiverErrorClass(kept)).toBe(kept);
    }
  });

  it('lets an unexpected failure through as a thrown error', async () => {
    const { route, context } = setup({ answer: () => new Error('boom') });
    await expect(route.deliver(delivery, verification(), context)).rejects.toThrow('boom');
  });
});
