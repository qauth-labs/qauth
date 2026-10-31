import { EgressError, type EgressRequest } from '@qauth-labs/server-egress';
import type { Delivery, DeliverySigner } from '@qauth-labs/server-event-delivery';
import {
  CAEP_CREDENTIAL_CHANGE,
  CAEP_SESSION_REVOKED,
  CAEP_TOKEN_CLAIMS_CHANGE,
  EVENT_TYPES,
  type EventEnvelope,
  QAUTH_KEY_EMERGENCY_RETIRED,
  QAUTH_TOKEN_REVOKED,
  ssfStreamVerificationRequested,
} from '@qauth-labs/shared-events';
import { describe, expect, it, vi } from 'vitest';

import { SSF_VERIFICATION_EVENT } from './constants';
import {
  createSsfDeliveryRoute,
  receiverErrorClass,
  type SsfDeliveryStream,
  type SsfStreamSource,
} from './delivery-route';
import { ssfEventsSupported } from './event-types';

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
    // Every event QAuth sends: a test that drops one says so.
    eventsRequested: ssfEventsSupported(),
    active: true,
    issuer: 'https://auth.example.com',
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
    /** Whether the stream still has the subject an event is about; it has, by default. */
    hasSubject?: boolean;
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
      {
        id: STREAM,
        realmId: REALM,
        audience: 'receiver',
        eventsRequested: [],
        subjects: [{ type: 'user', id: 'u1' }],
      },
    ],
    findForDelivery: async () => ('stream' in options ? options.stream : stream()),
    hasSubject: vi.fn(async () => options.hasSubject ?? true),
  };
  const signer = {
    signWebhook: vi.fn(async () => 'v1,x'),
    signEventToken: vi.fn<DeliverySigner['signEventToken']>(async () => 'h.p.s'),
    decrypt: vi.fn<DeliverySigner['decrypt']>(async () => new TextEncoder().encode('Bearer t')),
  };
  const route = createSsfDeliveryRoute({ streams, egress });
  const context = { signal: new AbortController().signal, signer };
  return { route, requests, signer, context, streams };
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
    // A stream gets its verification whatever events it requests and
    // subjects it has (SSF 1.0 §8.1.4).
    const { route, requests, signer, context, streams } = setup({
      stream: stream({ eventsRequested: [] }),
      hasSubject: false,
    });
    const outcome = await route.deliver(delivery, verification(), context);
    expect(outcome).toEqual({ ok: true, statusCode: 202 });
    expect(streams.hasSubject).not.toHaveBeenCalled();
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

describe('the SETs of mapped event types (#540)', () => {
  const typeOf = (name: string) => ({ type: `urn:qauth:event:${name}:v1-rc.0` });
  const userSignedOut = typeOf('user.signed_out');
  const consentRevoked = typeOf('consent.revoked');
  const tokenFamilyRevoked = typeOf('token.family_revoked');
  const tokenRevoked = typeOf('token.revoked');
  const clientSecretRotated = typeOf('client.secret_rotated');
  const apiKeyCreated = typeOf('api_key.created');
  const apiKeyRevoked = typeOf('api_key.revoked');
  const walletLinked = typeOf('wallet.linked');
  const keyEmergencyRetired = typeOf('key.emergency_retired');
  const ISSUER = 'https://auth.example.com';
  const USER = '0192a000-0000-7000-8000-0000000000b1';
  const TIME = '2026-10-30T09:30:00.900Z';
  const SECONDS = Math.floor(Date.parse(TIME) / 1000);

  /** An event of `type` as the store hands it over; the fields a type needs are in `overrides`. */
  function event(type: string, overrides: Partial<EventEnvelope> = {}): EventEnvelope {
    return {
      id: EVENT_ID,
      type,
      time: TIME,
      realm: REALM,
      category: 'user',
      actor: { type: 'user', id: USER },
      subject: { type: 'user', id: USER },
      data: {},
      ...overrides,
    } as EventEnvelope;
  }

  /**
   * One event of every mapped type, as QAuth emits it; the last test fails
   * when a type gains a mapping and no sample here.
   */
  const SAMPLES: Record<string, EventEnvelope> = {
    [userSignedOut.type]: event(userSignedOut.type),
    [consentRevoked.type]: event(consentRevoked.type, {
      client: { id: 'receiver' },
      data: { consentId: '0192a000-0000-7000-8000-0000000000c1', revokedRefreshCount: 2 },
    }),
    [tokenFamilyRevoked.type]: event(tokenFamilyRevoked.type, {
      actor: { type: 'client', id: 'receiver' },
      client: { id: 'receiver' },
      data: {
        reason: 'refresh_replay',
        refreshFamilyId: '0192a000-0000-7000-8000-0000000000f1',
        revokedRefreshCount: 3,
      },
    }),
    [tokenRevoked.type]: event(tokenRevoked.type, {
      actor: { type: 'client', id: 'receiver' },
      client: { id: 'receiver' },
      data: { typeHint: 'refresh_token' },
    }),
    // A client's credential events reach the client's own stream only: the
    // receiver here.
    [clientSecretRotated.type]: event(clientSecretRotated.type, {
      subject: { type: 'client', id: 'receiver' },
      client: { id: 'receiver' },
    }),
    [apiKeyCreated.type]: event(apiKeyCreated.type, {
      subject: { type: 'api_key', id: '0192a000-0000-7000-8000-0000000000a1' },
      client: { id: 'receiver' },
    }),
    [apiKeyRevoked.type]: event(apiKeyRevoked.type, {
      subject: { type: 'api_key', id: '0192a000-0000-7000-8000-0000000000a1' },
      client: { id: 'receiver' },
    }),
    [walletLinked.type]: event(walletLinked.type, {
      data: {
        credentialId: 'cred-1',
        subjectSource: 'issuer_scoped_claim',
        rebound: false,
        verifierProfile: 'haip-1.0',
      },
    }),
    [keyEmergencyRetired.type]: event(keyEmergencyRetired.type, {
      category: 'admin',
      actor: { type: 'operator_cli', id: 'root' },
      subject: undefined,
      data: { keyId: 'kid-7', purpose: 'token_signing' },
    }),
  };

  /** Deliver `delivered` and return the claims the route asked the signer to sign. */
  async function signed(
    delivered: EventEnvelope,
    streamOverrides: Partial<SsfDeliveryStream> = {},
    options: { hasSubject?: boolean } = {}
  ) {
    const { route, signer, context, requests, streams } = setup({
      stream: stream(streamOverrides),
      ...options,
    });
    const outcome = await route.deliver(delivery, delivered, context);
    const claims = signer.signEventToken.mock.calls[0]?.[0].claims as
      | Record<string, unknown>
      | undefined;
    return { outcome, claims, signer, requests, hasSubject: streams.hasSubject };
  }

  it('sends a sign-out as CAEP session-revoked about the user, iss_sub under the realm issuer', async () => {
    const { outcome, claims, hasSubject } = await signed(SAMPLES[userSignedOut.type]);
    expect(outcome).toEqual({ ok: true, statusCode: 202 });
    // Sent once the stream was found to have the user still.
    expect(hasSubject).toHaveBeenCalledWith(STREAM, { type: 'user', id: USER });
    expect(claims).toEqual({
      jti: EVENT_ID,
      iat: SECONDS,
      aud: 'receiver',
      sub_id: { format: 'iss_sub', iss: ISSUER, sub: USER },
      events: {
        [CAEP_SESSION_REVOKED]: { event_timestamp: SECONDS, initiating_entity: 'user' },
      },
    });
  });

  it('sends an API key change as CAEP credential-change about the key’s client, by its administrator', async () => {
    const { claims } = await signed(SAMPLES[apiKeyRevoked.type]);
    expect(claims).toMatchObject({
      sub_id: { format: 'opaque', id: 'receiver' },
      events: {
        [CAEP_CREDENTIAL_CHANGE]: {
          credential_type: 'api-key',
          change_type: 'revoke',
          event_timestamp: SECONDS,
          initiating_entity: 'admin',
        },
      },
    });
  });

  it('sends a client’s credential change to that client’s own stream only', async () => {
    for (const type of [clientSecretRotated.type, apiKeyRevoked.type]) {
      const other = await signed(
        event(type, {
          subject:
            type === clientSecretRotated.type
              ? { type: 'client', id: 'notes-app' }
              : { type: 'api_key', id: '0192a000-0000-7000-8000-0000000000a1' },
          client: { id: 'notes-app' },
        })
      );
      expect(other.outcome, type).toEqual({
        ok: false,
        errorClass: 'event_not_offered',
        retry: false,
      });
      expect(other.requests).toHaveLength(0);
    }
  });

  it('sends nothing for a client-subject event without a client', async () => {
    const { outcome, requests } = await signed(
      event(apiKeyRevoked.type, {
        subject: { type: 'api_key', id: '0192a000-0000-7000-8000-0000000000a1' },
      })
    );
    expect(outcome).toEqual({ ok: false, errorClass: 'event_not_offered', retry: false });
    expect(requests).toHaveLength(0);
  });

  it('names a client whose client_id is a URL by uri', async () => {
    const url = 'https://agent.example.com/client.json';
    const { claims } = await signed(
      event(clientSecretRotated.type, {
        subject: { type: 'client', id: url },
        client: { id: url },
      }),
      { audience: url }
    );
    expect(claims?.['sub_id']).toEqual({ format: 'uri', uri: url });
  });

  it('sends a withdrawn consent as CAEP token-claims-change, to the consent’s own client only', async () => {
    const { claims } = await signed(SAMPLES[consentRevoked.type]);
    expect(claims?.['events']).toEqual({
      [CAEP_TOKEN_CLAIMS_CHANGE]: {
        claims: { scope: '' },
        event_timestamp: SECONDS,
        initiating_entity: 'user',
      },
    });
    const other = await signed(
      event(consentRevoked.type, {
        client: { id: 'another-client' },
        data: { consentId: '0192a000-0000-7000-8000-0000000000c1' },
      })
    );
    expect(other.outcome).toEqual({ ok: false, errorClass: 'event_not_offered', retry: false });
    expect(other.requests).toHaveLength(0);
  });

  it('sends an RFC 7009 revocation as the QAuth-defined token-revoked event', async () => {
    const { claims } = await signed(SAMPLES[tokenRevoked.type]);
    expect(QAUTH_TOKEN_REVOKED).toMatch(/^urn:qauth:secevent:token-revoked:v1(-rc\.\d+)?$/);
    expect(claims?.['events']).toEqual({
      [QAUTH_TOKEN_REVOKED]: { token_type_hint: 'refresh_token', event_timestamp: SECONDS },
    });
  });

  it('sends a replay’s family revocation as session-revoked by policy, with the reason', async () => {
    const { claims } = await signed(SAMPLES[tokenFamilyRevoked.type]);
    expect(claims?.['events']).toEqual({
      [CAEP_SESSION_REVOKED]: {
        reason_admin: { en: expect.stringContaining('refresh token') },
        event_timestamp: SECONDS,
        initiating_entity: 'policy',
      },
    });
  });

  it('sends an emergency key retirement about the key, naming its kid', async () => {
    const { claims } = await signed(SAMPLES[keyEmergencyRetired.type]);
    expect(claims).toMatchObject({
      sub_id: { format: 'opaque', id: 'kid-7' },
      events: {
        [QAUTH_KEY_EMERGENCY_RETIRED]: {
          kid: 'kid-7',
          purpose: 'token_signing',
          initiating_entity: 'admin',
        },
      },
    });
  });

  // A delivery waits in the queue: held while its stream is paused, retried
  // for hours. It is sent as the stream is at the attempt, not as it was at
  // the fan-out.
  it('sends nothing the receiver stopped requesting since the fan-out', async () => {
    const dropped = await signed(SAMPLES[userSignedOut.type], {
      eventsRequested: [CAEP_CREDENTIAL_CHANGE],
    });
    expect(dropped.outcome).toEqual({ ok: false, errorClass: 'event_not_offered', retry: false });
    expect(dropped.requests).toHaveLength(0);
    expect(dropped.signer.signEventToken).not.toHaveBeenCalled();
    // A stream that still requests the event gets it.
    const kept = await signed(SAMPLES[userSignedOut.type], {
      eventsRequested: [CAEP_SESSION_REVOKED],
    });
    expect(kept.outcome).toEqual({ ok: true, statusCode: 202 });
  });

  it('sends nothing about a subject the receiver removed since the fan-out', async () => {
    for (const [type, subject] of [
      [userSignedOut.type, { type: 'user', id: USER }],
      [tokenRevoked.type, { type: 'user', id: USER }],
      // A client's credential event was matched on its client.
      [apiKeyRevoked.type, { type: 'client', id: 'receiver' }],
      [clientSecretRotated.type, { type: 'client', id: 'receiver' }],
    ] as const) {
      const removed = await signed(SAMPLES[type], {}, { hasSubject: false });
      expect(removed.outcome, type).toEqual({
        ok: false,
        errorClass: 'event_not_offered',
        retry: false,
      });
      expect(removed.hasSubject, type).toHaveBeenCalledWith(STREAM, subject);
      expect(removed.requests, type).toHaveLength(0);
      expect(removed.signer.signEventToken, type).not.toHaveBeenCalled();
    }
  });

  it('sends a key event whatever subjects the stream has', async () => {
    const { outcome, hasSubject } = await signed(
      SAMPLES[keyEmergencyRetired.type],
      {},
      { hasSubject: false }
    );
    expect(outcome).toEqual({ ok: true, statusCode: 202 });
    expect(hasSubject).not.toHaveBeenCalled();
  });

  it('sends nothing for an event without the subject its mapping names', async () => {
    const noSubject = await signed(
      event(tokenRevoked.type, { subject: undefined, client: { id: 'receiver' } })
    );
    expect(noSubject.outcome).toEqual({ ok: false, errorClass: 'event_not_offered', retry: false });
    const noIssuer = await signed(SAMPLES[userSignedOut.type], { issuer: null });
    expect(noIssuer.outcome).toEqual({ ok: false, errorClass: 'event_not_offered', retry: false });
    expect([...noSubject.requests, ...noIssuer.requests]).toHaveLength(0);
  });

  it('lists each stream with the rules its mapped types need', async () => {
    const streams: SsfStreamSource = {
      listDestinations: async () => [
        {
          id: STREAM,
          realmId: REALM,
          audience: 'receiver',
          eventsRequested: [
            CAEP_SESSION_REVOKED,
            CAEP_CREDENTIAL_CHANGE,
            QAUTH_KEY_EMERGENCY_RETIRED,
          ],
          subjects: [{ type: 'user', id: USER }],
        },
      ],
      findForDelivery: async () => stream(),
      hasSubject: async () => true,
    };
    const route = createSsfDeliveryRoute({ streams, egress: { request: vi.fn() } });
    const [listed] = await route.destinations();
    expect(listed.types).toEqual(
      expect.arrayContaining([
        userSignedOut.type,
        tokenFamilyRevoked.type,
        apiKeyRevoked.type,
        keyEmergencyRetired.type,
      ])
    );
    expect(listed.typeRules).toEqual({
      [tokenFamilyRevoked.type]: { clientId: 'receiver' },
      [clientSecretRotated.type]: { clientId: 'receiver' },
      [apiKeyCreated.type]: { subjectFrom: 'client', clientId: 'receiver' },
      [apiKeyRevoked.type]: { subjectFrom: 'client', clientId: 'receiver' },
      [keyEmergencyRetired.type]: { subjectFrom: 'none' },
    });
  });

  // RFC 8417 §2.2 and §2.3, and SSF 1.0 §4.1: what every SET carries. The
  // signer adds `iss` (its own tests show it); the route builds the rest.
  describe('RFC 8417 §2.2 — the claims of every mapped type’s SET', () => {
    const mapped = EVENT_TYPES.filter((definition) => typeof definition.ssf === 'object');

    it.each(mapped.map((definition) => [definition.type] as const))(
      '%s carries iat, jti and one event object, and no sub or exp (§2.2, §2.3)',
      async (type) => {
        const { claims, signer } = await signed(SAMPLES[type]);
        expect(claims, `no SET for ${type}`).toBeDefined();
        expect(signer.signEventToken.mock.calls[0][0].typ).toBe('secevent+jwt');
        expect(claims?.['iat']).toBe(SECONDS);
        expect(claims?.['jti']).toBe(EVENT_ID);
        const events = claims?.['events'] as Record<string, unknown>;
        expect(Object.keys(events)).toHaveLength(1);
        const [member] = Object.values(events);
        expect(member).toBeTypeOf('object');
        expect(Array.isArray(member)).toBe(false);
        expect(claims).not.toHaveProperty('sub');
        expect(claims).not.toHaveProperty('exp');
        expect(claims).not.toHaveProperty('iss');
      }
    );

    it('has a sample of every mapped type', () => {
      expect(Object.keys(SAMPLES).sort()).toEqual(
        mapped.map((definition) => definition.type).sort()
      );
    });
  });
});
