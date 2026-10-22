import { describe, expect, it } from 'vitest';

import { eventRequest, requestSchema, USER_AGENT_MAX } from './envelope';

describe('eventRequest', () => {
  it('keeps values that fit', () => {
    expect(
      eventRequest({ traceId: 'req-7f3a', ip: '2001:db8::1', userAgent: 'Mozilla/5.0' })
    ).toEqual({ traceId: 'req-7f3a', ip: '2001:db8::1', userAgent: 'Mozilla/5.0' });
  });

  it('cuts an over-long User-Agent and trace id instead of failing the event', () => {
    const request = eventRequest({ traceId: 't'.repeat(500), userAgent: 'A'.repeat(5000) });
    expect(request?.userAgent).toHaveLength(USER_AGENT_MAX);
    expect(request?.traceId).toHaveLength(128);
    expect(requestSchema.safeParse(request).success).toBe(true);
  });

  it('does not split a surrogate pair when it cuts', () => {
    const userAgent = `${'A'.repeat(USER_AGENT_MAX - 1)}😀tail`;
    const cut = eventRequest({ userAgent })?.userAgent ?? '';
    expect(cut).toBe('A'.repeat(USER_AGENT_MAX - 1));
  });

  it('writes an IPv4-mapped address in its IPv4 form, which the published pattern accepts', () => {
    expect(requestSchema.safeParse({ ip: '::ffff:203.0.113.5' }).success).toBe(false);
    expect(eventRequest({ ip: '::ffff:203.0.113.5' })).toEqual({ ip: '203.0.113.5' });
  });

  it('leaves out an address in no published form', () => {
    expect(eventRequest({ ip: 'not-an-address', traceId: 'req-1' })).toEqual({ traceId: 'req-1' });
    expect(eventRequest({ ip: '203.0.113.5, 198.51.100.1' })).toBeUndefined();
  });

  it('returns undefined when there is nothing to record', () => {
    expect(eventRequest({})).toBeUndefined();
    expect(eventRequest({ traceId: null, ip: '', userAgent: undefined })).toBeUndefined();
  });
});
