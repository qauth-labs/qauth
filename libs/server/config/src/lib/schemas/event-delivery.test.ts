import { describe, expect, it } from 'vitest';

import { eventDeliveryEnvSchema } from './event-delivery';

describe('eventDeliveryEnvSchema (#460)', () => {
  it('defaults to 12 attempts, 30 seconds first and 6 hours at most', () => {
    expect(eventDeliveryEnvSchema.parse({})).toEqual({
      EVENT_DELIVERY_MAX_ATTEMPTS: 12,
      EVENT_DELIVERY_RETRY_INITIAL_DELAY: 30,
      EVENT_DELIVERY_RETRY_MAX_DELAY: 21_600,
    });
  });

  it('reads whole numbers', () => {
    expect(
      eventDeliveryEnvSchema.parse({
        EVENT_DELIVERY_MAX_ATTEMPTS: '5',
        EVENT_DELIVERY_RETRY_INITIAL_DELAY: '10',
        EVENT_DELIVERY_RETRY_MAX_DELAY: '600',
      })
    ).toEqual({
      EVENT_DELIVERY_MAX_ATTEMPTS: 5,
      EVENT_DELIVERY_RETRY_INITIAL_DELAY: 10,
      EVENT_DELIVERY_RETRY_MAX_DELAY: 600,
    });
  });

  it.each([
    ['no attempt', { EVENT_DELIVERY_MAX_ATTEMPTS: '0' }],
    ['more than 100 attempts', { EVENT_DELIVERY_MAX_ATTEMPTS: '101' }],
    ['a fraction', { EVENT_DELIVERY_RETRY_INITIAL_DELAY: '1.5' }],
    ['a wait over 7 days', { EVENT_DELIVERY_RETRY_MAX_DELAY: '604801' }],
    ['a word', { EVENT_DELIVERY_RETRY_MAX_DELAY: 'six hours' }],
  ])('refuses %s', (_label, input) => {
    expect(eventDeliveryEnvSchema.safeParse(input).success).toBe(false);
  });
});
