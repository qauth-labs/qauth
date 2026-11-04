import { describe, expect, it } from 'vitest';

import { checkSendCapPolicy, retryAfterSeconds, SEND_CAP_POLICY } from '../lib/send-caps';
import { createMemorySendCaps } from './memory-send-caps';
import { describeSendCapStore } from './send-cap-store-contract';

describeSendCapStore('the memory store', async () => {
  let clock = Date.UTC(2026, 10, 4);
  return {
    store: createMemorySendCaps(() => clock),
    advance: (ms: number) => {
      clock += ms;
    },
  };
});

describe('checkSendCapPolicy (#637)', () => {
  it('accepts the policy of ADR-017 Decision 5', () => {
    expect(checkSendCapPolicy(SEND_CAP_POLICY)).toBe(SEND_CAP_POLICY);
  });

  it.each([
    ['a limit below 1', { ceiling: { limit: 0, windowMs: 60_000 } }],
    ['a window under a second', { endUserIp: { limit: 1, windowMs: 999 } }],
    [
      'a short window that outlasts the long one',
      { addressIpShort: { limit: 3, windowMs: 2 * 86_400_000 } },
    ],
    [
      'a quiet tier that admits more than the ceiling',
      { addressIpLong: { limit: 31, windowMs: 86_400_000 } },
    ],
    ['a pass valid past 24 hours', { passTtlMs: 86_400_001 }],
    ['a notice interval under a minute', { noticeIntervalMs: 1 }],
  ])('refuses %s', (_label, change) => {
    expect(() => checkSendCapPolicy({ ...SEND_CAP_POLICY, ...change })).toThrow();
  });

  it('rounds Retry-After up to whole seconds, at least one', () => {
    expect(retryAfterSeconds(0)).toBe(1);
    expect(retryAfterSeconds(1_001)).toBe(2);
    expect(retryAfterSeconds(86_400_000)).toBe(86_400);
  });
});
