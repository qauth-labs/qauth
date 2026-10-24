import { ROOT_CONTEXT, trace, TraceFlags } from '@opentelemetry/api';
import { SeverityNumber } from '@opentelemetry/api-logs';
import { EVENT_SEVERITIES, EventValidationError } from '@qauth-labs/shared-events';
import { describe, expect, it } from 'vitest';

import { EVENT_LOG_ATTRIBUTES, EVENT_SEVERITY_NUMBERS, eventLogRecord } from './event-log-record';

/**
 * The event → OpenTelemetry log record mapping (issue #541): the body, the
 * attributes, the severity from the registry, the trace context or the
 * request id, and the contract check that runs before anything is exported.
 */

const REALM_ID = '0192f1c4-1111-7000-8000-000000000001';
const USER_ID = '0192f1c4-4444-7000-8000-000000000004';

/** A stored sign-in, as the event store hands it to the sink. */
const SIGNED_IN = Object.freeze({
  id: '0192f1c4-5555-7000-8000-000000000005',
  type: 'urn:qauth:event:user.signed_in:v1-rc.0',
  time: '2026-10-24T12:00:00.000Z',
  realm: REALM_ID,
  category: 'user',
  actor: { type: 'user', id: USER_ID },
  subject: { type: 'user', id: USER_ID },
  client: { id: 'portal' },
  request: { traceId: 'req-42', ip: '203.0.113.5', userAgent: 'Mozilla/5.0' },
  data: { method: 'password' },
});

/** A refused CSRF check: severity `warning`, no subject and no client. */
const CSRF_REJECTED = Object.freeze({
  id: '0192f1c4-6666-7000-8000-000000000006',
  type: 'urn:qauth:event:request.csrf_rejected:v1-rc.0',
  time: '2026-10-24T12:00:01.000Z',
  realm: REALM_ID,
  category: 'user',
  data: { form: 'sign_in' },
});

/** A context with an active, sampled span. */
const SPAN = {
  traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
  spanId: '00f067aa0ba902b7',
  traceFlags: TraceFlags.SAMPLED,
};
const SPAN_CONTEXT = trace.setSpanContext(ROOT_CONTEXT, SPAN);

/** A JWS in compact form: the shape the payload scanner refuses anywhere in an event. */
const JWS_SHAPED = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlLXZhbHVl';

describe('eventLogRecord', () => {
  it('carries the envelope as its JSON body, the event attributes, the registry severity and the event time', () => {
    const record = eventLogRecord(SIGNED_IN, ROOT_CONTEXT);

    expect(JSON.parse(record.body as string)).toEqual(SIGNED_IN);
    expect(record.attributes).toEqual({
      'qauth.event.id': SIGNED_IN.id,
      'qauth.event.type': SIGNED_IN.type,
      'qauth.event.category': 'user',
      'qauth.realm': REALM_ID,
      'qauth.subject.id': USER_ID,
      'qauth.client.id': 'portal',
      'qauth.request.id': 'req-42',
    });
    expect(record.severityNumber).toBe(SeverityNumber.INFO);
    expect(record.severityText).toBe('info');
    expect(record.eventName).toBe(SIGNED_IN.type);
    expect(record.timestamp).toEqual(new Date(SIGNED_IN.time));
  });

  it('leaves out the subject and the client when the event has none, and takes the type’s severity', () => {
    const record = eventLogRecord(CSRF_REJECTED, ROOT_CONTEXT);

    expect(record.attributes).toEqual({
      'qauth.event.id': CSRF_REJECTED.id,
      'qauth.event.type': CSRF_REJECTED.type,
      'qauth.event.category': 'user',
      'qauth.realm': REALM_ID,
    });
    expect(record.severityNumber).toBe(SeverityNumber.WARN);
    expect(record.severityText).toBe('warning');
  });

  it('names every registry severity, critical as ERROR2', () => {
    expect(Object.keys(EVENT_SEVERITY_NUMBERS).sort()).toEqual([...EVENT_SEVERITIES].sort());
    expect(EVENT_SEVERITY_NUMBERS.critical).toBe(SeverityNumber.ERROR2);
  });

  it('leaves the request id out when a span is active, whose ids the SDK puts on the record', () => {
    const record = eventLogRecord(SIGNED_IN, SPAN_CONTEXT);

    expect(record.attributes).not.toHaveProperty(EVENT_LOG_ATTRIBUTES.requestId);
    expect(record.context).toBe(SPAN_CONTEXT);
    expect(trace.getSpanContext(record.context as typeof SPAN_CONTEXT)).toEqual(SPAN);
  });

  it('carries no request id for an event that names no request', () => {
    const { request: _request, ...withoutRequest } = SIGNED_IN;
    void _request;
    const record = eventLogRecord(withoutRequest, ROOT_CONTEXT);
    expect(record.attributes).not.toHaveProperty(EVENT_LOG_ATTRIBUTES.requestId);
  });

  describe('fails the payload scanner before anything is exported', () => {
    it.each([
      ['a token-shaped user agent', { ...SIGNED_IN, request: { userAgent: JWS_SHAPED } }],
      ['a token-shaped actor id', { ...SIGNED_IN, actor: { type: 'user', id: JWS_SHAPED } }],
      [
        'a PEM block as the subject id',
        {
          ...SIGNED_IN,
          subject: {
            type: 'user',
            id: '-----BEGIN PRIVATE KEY-----\nMC4=\n-----END PRIVATE KEY-----',
          },
        },
      ],
    ])('%s', (_case, event) => {
      expect(() => eventLogRecord(event, ROOT_CONTEXT)).toThrow(EventValidationError);
      expect(() => eventLogRecord(event, ROOT_CONTEXT)).toThrow(/shaped like a token/);
    });

    it('a payload member its type does not declare, such as an access token', () => {
      const leaking = { ...SIGNED_IN, data: { method: 'password', accessToken: 'abc' } };
      expect(() => eventLogRecord(leaking, ROOT_CONTEXT)).toThrow(EventValidationError);
    });

    it('an event of an unregistered type', () => {
      const unknown = { ...SIGNED_IN, type: 'urn:qauth:event:user.teleported:v1-rc.0' };
      expect(() => eventLogRecord(unknown, ROOT_CONTEXT)).toThrow(/unknown event type/);
    });
  });
});
