import { defineEventType, EVENT_TYPES } from '@qauth-labs/shared-events';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { SSF_PUSH_METHOD, SSF_VERIFICATION_EVENT } from './constants';
import { eventTypesFor, ssfEventsSupported } from './event-types';
import { buildTransmitterMetadata, issuerBase } from './metadata';
import { setClaims, verificationSetClaims } from './set';
import {
  assertTransmitterMembers,
  checkDelivery,
  keptDescription,
  SsfRequestError,
  streamConfiguration,
} from './stream-config';
import {
  canonicalSubject,
  canonicalSubjectKey,
  eventSubjectOf,
  ssfSubjectOf,
  subjectIdentifierSchema,
} from './subjects';

const ISSUER = 'https://auth.example.com';

describe('buildTransmitterMetadata (SSF 1.0 §7.1)', () => {
  it('names the issuer as stored and builds every URL from it', () => {
    expect(buildTransmitterMetadata(`${ISSUER}/`)).toEqual({
      spec_version: '1_0',
      issuer: `${ISSUER}/`,
      // The transmitter's own JWKS, not the realm JWKS of the token keys.
      jwks_uri: `${ISSUER}/ssf/jwks.json`,
      delivery_methods_supported: [SSF_PUSH_METHOD],
      configuration_endpoint: `${ISSUER}/ssf/stream`,
      status_endpoint: `${ISSUER}/ssf/status`,
      add_subject_endpoint: `${ISSUER}/ssf/subjects/add`,
      remove_subject_endpoint: `${ISSUER}/ssf/subjects/remove`,
      verification_endpoint: `${ISSUER}/ssf/verify`,
      authorization_schemes: [{ spec_urn: 'urn:ietf:rfc:6749' }],
      default_subjects: 'NONE',
    });
  });

  it('drops every trailing slash of the issuer and nothing else', () => {
    expect(issuerBase(ISSUER)).toBe(ISSUER);
    expect(issuerBase(`${ISSUER}///`)).toBe(ISSUER);
    expect(issuerBase(`${ISSUER}/realm/`)).toBe(`${ISSUER}/realm`);
    expect(issuerBase('///')).toBe('');
  });

  it('stays linear on a long run of slashes that does not end the issuer', () => {
    // The input that made `/\/+$/` backtrack quadratically (CodeQL js/polynomial-redos).
    const issuer = `${ISSUER}${'/'.repeat(200_000)}x`;
    expect(issuerBase(issuer)).toBe(issuer);
  });
});

describe('subject identifiers (RFC 9493)', () => {
  it.each([
    { format: 'iss_sub', iss: ISSUER, sub: 'u1' },
    { format: 'email', email: 'a@example.com' },
    { format: 'opaque', id: 'x' },
    { format: 'uri', uri: 'https://agent.example/client' },
    { format: 'account', uri: 'acct:a@example.com' },
    { format: 'aliases', identifiers: [{ format: 'opaque', id: 'x' }] },
    { format: 'complex', user: { format: 'opaque', id: 'x' } },
    { format: 'jwt_id', iss: ISSUER, jti: 'j' },
  ])('accepts %o', (subject) => {
    expect(subjectIdentifierSchema.safeParse(subject).success).toBe(true);
  });

  it.each([
    { format: 'opaque' },
    { format: 'unknown', id: 'x' },
    { format: 'opaque', id: 'x', extra: 1 },
    { format: 'account', uri: 'mailto:a@example.com' },
    { format: 'complex' },
    { format: 'aliases', identifiers: [{ format: 'aliases', identifiers: [] }] },
  ])('refuses %o', (subject) => {
    expect(subjectIdentifierSchema.safeParse(subject).success).toBe(false);
  });

  it('gives a subject the same key whatever its member order', () => {
    expect(canonicalSubjectKey({ sub: 'u1', iss: ISSUER, format: 'iss_sub' } as never)).toBe(
      canonicalSubjectKey({ format: 'iss_sub', iss: ISSUER, sub: 'u1' })
    );
    expect(canonicalSubjectKey({ format: 'opaque', id: 'x' })).toBe('{"format":"opaque","id":"x"}');
  });

  it('maps event subjects to the formats #410 chose, and back', () => {
    expect(ssfSubjectOf({ type: 'user', id: 'u1' }, ISSUER)).toEqual({
      format: 'iss_sub',
      iss: ISSUER,
      sub: 'u1',
    });
    expect(ssfSubjectOf({ type: 'client', id: 'https://agent.example/c' }, ISSUER)).toEqual({
      format: 'uri',
      uri: 'https://agent.example/c',
    });
    expect(ssfSubjectOf({ type: 'client', id: 'my-client' }, ISSUER)).toEqual({
      format: 'opaque',
      id: 'my-client',
    });
    expect(ssfSubjectOf({ type: 'ssf_stream', id: 's' }, ISSUER)).toEqual({
      format: 'opaque',
      id: 's',
    });
    expect(ssfSubjectOf({ type: 'api_key', id: 'k' }, ISSUER)).toBeUndefined();

    for (const subject of [
      { type: 'user', id: 'u1' },
      { type: 'client', id: 'https://agent.example/c' },
      { type: 'client', id: 'my-client' },
    ]) {
      const ssf = ssfSubjectOf(subject, ISSUER);
      expect(ssf && eventSubjectOf(ssf, ISSUER)).toEqual(subject);
    }
  });

  // The event store holds a user id in lower case, and the fan-out compares
  // it as text: a user added with an upper-case UUID must match the user's
  // events, and be the same subject as the lower-case spelling.
  it('names a user by a lower-case UUID, however the receiver spelled it', () => {
    const USER = '0192a000-0000-7000-8000-0000000000b1';
    const upper = { format: 'iss_sub', iss: ISSUER, sub: USER.toUpperCase() } as const;
    const lower = { format: 'iss_sub', iss: ISSUER, sub: USER } as const;
    expect(eventSubjectOf(upper, ISSUER)).toEqual({ type: 'user', id: USER });
    expect(canonicalSubject(upper, ISSUER)).toEqual(lower);
    expect(canonicalSubjectKey(canonicalSubject(upper, ISSUER))).toBe(
      canonicalSubjectKey(canonicalSubject(lower, ISSUER))
    );
    // Inside aliases and complex subjects too.
    expect(
      canonicalSubject(
        { format: 'aliases', identifiers: [upper, { format: 'email', email: 'A@example.com' }] },
        ISSUER
      )
    ).toEqual({
      format: 'aliases',
      identifiers: [lower, { format: 'email', email: 'A@example.com' }],
    });
    expect(
      canonicalSubject(
        subjectIdentifierSchema.parse({
          format: 'complex',
          user: upper,
          application: { format: 'opaque', id: 'App' },
        }),
        ISSUER
      )
    ).toEqual({ format: 'complex', user: lower, application: { format: 'opaque', id: 'App' } });
    // What is not this realm's user id is kept as given: another issuer's
    // `sub`, an id that is not a UUID, and a client_id.
    const foreign = { format: 'iss_sub', iss: 'https://other', sub: USER.toUpperCase() } as const;
    expect(canonicalSubject(foreign, ISSUER)).toEqual(foreign);
    expect(canonicalSubject({ format: 'iss_sub', iss: ISSUER, sub: 'User-1' }, ISSUER)).toEqual({
      format: 'iss_sub',
      iss: ISSUER,
      sub: 'User-1',
    });
    expect(eventSubjectOf({ format: 'iss_sub', iss: ISSUER, sub: 'User-1' }, ISSUER)).toEqual({
      type: 'user',
      id: 'User-1',
    });
    expect(canonicalSubject({ format: 'opaque', id: 'My-Client' }, ISSUER)).toEqual({
      format: 'opaque',
      id: 'My-Client',
    });
  });

  it('places no subject of another issuer, another format, or too long an id', () => {
    expect(eventSubjectOf({ format: 'iss_sub', iss: 'https://other', sub: 'u1' }, ISSUER)).toBe(
      null
    );
    expect(eventSubjectOf({ format: 'email', email: 'a@example.com' }, ISSUER)).toBeNull();
    expect(
      eventSubjectOf({ format: 'uri', uri: `https://agent.example/${'a'.repeat(300)}` }, ISSUER)
    ).toBeNull();
  });
});

describe('stream configuration (SSF 1.0 §8.1.1)', () => {
  const stored = {
    id: 'stream-1',
    audience: 'receiver',
    eventsRequested: ['https://example/b', 'https://example/a'],
    deliveryMethod: SSF_PUSH_METHOD,
    endpointUrl: 'https://receiver.example/events',
    description: null,
  };

  it('delivers the requested events the transmitter supports, and never the header', () => {
    expect(streamConfiguration(stored, ISSUER, ['https://example/a'])).toEqual({
      stream_id: 'stream-1',
      iss: ISSUER,
      aud: 'receiver',
      events_supported: ['https://example/a'],
      events_requested: ['https://example/b', 'https://example/a'],
      events_delivered: ['https://example/a'],
      delivery: { method: SSF_PUSH_METHOD, endpoint_url: 'https://receiver.example/events' },
      min_verification_interval: 10,
    });
  });

  it('takes transmitter-supplied members only when they match', () => {
    const current = streamConfiguration(stored, ISSUER, ['https://example/a']);
    expect(() =>
      assertTransmitterMembers(
        { iss: ISSUER, aud: 'receiver', events_delivered: ['https://example/a'] },
        current
      )
    ).not.toThrow();
    expect(() => assertTransmitterMembers({ aud: 'someone-else' }, current)).toThrow(
      /aud is supplied by the transmitter/
    );
    expect(() => assertTransmitterMembers({ min_verification_interval: 1 }, current)).toThrow(
      SsfRequestError
    );
    expect(() => assertTransmitterMembers({ inactivity_timeout: 60 }, current)).toThrow(
      SsfRequestError
    );
  });

  it('takes push to an https URL, and refuses poll, other methods and odd URLs', () => {
    expect(
      checkDelivery({
        method: SSF_PUSH_METHOD,
        endpoint_url: 'https://receiver.example/events',
        authorization_header: 'Bearer abc',
      })
    ).toEqual({
      method: SSF_PUSH_METHOD,
      endpointUrl: 'https://receiver.example/events',
      authorizationHeader: 'Bearer abc',
    });
    for (const delivery of [
      undefined,
      { method: 'urn:ietf:rfc:8936' },
      { method: 'urn:example:other', endpoint_url: 'https://receiver.example/' },
      { method: SSF_PUSH_METHOD },
      { method: SSF_PUSH_METHOD, endpoint_url: 'http://receiver.example/' },
      { method: SSF_PUSH_METHOD, endpoint_url: 'https://user:pw@receiver.example/' },
      { method: SSF_PUSH_METHOD, endpoint_url: 'https://receiver.example/#frag' },
      { method: SSF_PUSH_METHOD, endpoint_url: 'not a url' },
      {
        method: SSF_PUSH_METHOD,
        endpoint_url: 'https://receiver.example/',
        authorization_header: 'Bearer a\r\nX-Injected: 1',
      },
    ]) {
      expect(() => checkDelivery(delivery), JSON.stringify(delivery)).toThrow(SsfRequestError);
    }
  });

  it('refuses with a 400 wherever the refusal is thrown', () => {
    // The auth server answers it as the `bad_request` problem document (#513)
    // without catching it first.
    const refusal = new SsfRequestError('push delivery needs an endpoint_url');
    expect(refusal.statusCode).toBe(400);
    expect(refusal.name).toBe('SsfRequestError');
    expect(refusal).toBeInstanceOf(Error);
  });

  it('cuts a description to 1024 characters without splitting a pair', () => {
    expect(keptDescription(undefined)).toBeNull();
    expect(keptDescription('x'.repeat(2000))).toHaveLength(1024);
    expect(keptDescription(`${'x'.repeat(1023)}😀`)).toHaveLength(1023);
  });
});

describe('SET claims (RFC 8417, SSF 1.0 §4)', () => {
  const event = { id: '01920000-0000-7000-8000-000000000001', time: '2026-10-25T10:00:00.900Z' };

  it('takes jti from the event id and iat from its time, so a retry repeats both', () => {
    const claims = verificationSetClaims(event, 'receiver', 'stream-1', 'abc');
    expect(claims).toEqual({
      jti: event.id,
      iat: Math.floor(Date.parse(event.time) / 1000),
      aud: 'receiver',
      sub_id: { format: 'opaque', id: 'stream-1' },
      events: { [SSF_VERIFICATION_EVENT]: { state: 'abc' } },
    });
    expect(verificationSetClaims(event, 'receiver', 'stream-1', 'abc')).toEqual(claims);
    expect(Object.keys(claims)).not.toContain('sub');
    expect(Object.keys(claims)).not.toContain('exp');
  });

  it('sends an empty verification event without a state', () => {
    expect(verificationSetClaims(event, 'r', 's', undefined).events).toEqual({
      [SSF_VERIFICATION_EVENT]: {},
    });
  });

  it('refuses an event time that is not a time', () => {
    expect(() =>
      setClaims({ id: 'x', time: 'never' }, 'r', { format: 'opaque', id: 's' }, {})
    ).toThrow(TypeError);
  });
});

describe('event types offered to streams', () => {
  it('offers the SSF events the registry maps, and never the verification event (#540)', () => {
    expect(ssfEventsSupported()).toEqual([
      'https://schemas.openid.net/secevent/caep/event-type/credential-change',
      'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
      'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
      'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
      'https://schemas.openid.net/secevent/risc/event-type/account-enabled',
      'urn:qauth:secevent:key-emergency-retired:v1-rc.0',
      'urn:qauth:secevent:token-revoked:v1-rc.0',
    ]);
    expect(eventTypesFor([SSF_VERIFICATION_EVENT])).toEqual([]);
    expect(
      eventTypesFor(['https://schemas.openid.net/secevent/caep/event-type/session-revoked'])
    ).toEqual([
      'urn:qauth:event:user.signed_out:v1-rc.0',
      'urn:qauth:event:token.family_revoked:v1-rc.0',
    ]);
    expect(EVENT_TYPES.some((definition) => typeof definition.ssf === 'object')).toBe(true);
  });

  it('offers a mapped type to a stream that requested its SSF event', () => {
    const mapped = defineEventType({
      name: 'test.mapped',
      version: 1,
      description: 'A test type.',
      category: 'user',
      severity: 'info',
      since: 'v0.2.0',
      data: z.strictObject({}),
      ssf: { event: 'https://example/caep/session-revoked' },
    });
    const unmapped = defineEventType({
      name: 'test.unmapped',
      version: 1,
      description: 'A test type.',
      category: 'user',
      severity: 'info',
      since: 'v0.2.0',
      data: z.strictObject({}),
      ssf: 'none',
    });
    expect(ssfEventsSupported([mapped, unmapped])).toEqual([
      'https://example/caep/session-revoked',
    ]);
    expect(eventTypesFor(['https://example/caep/session-revoked'], [mapped, unmapped])).toEqual([
      mapped.type,
    ]);
    expect(eventTypesFor([], [mapped, unmapped])).toEqual([]);
  });
});
