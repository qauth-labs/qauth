import { describe, expect, it } from 'vitest';

import { eventRetentionEnvSchema } from './event-retention';

describe('eventRetentionEnvSchema (#536)', () => {
  it('seeds 90 days of user events and 365 days of admin events by default', () => {
    expect(eventRetentionEnvSchema.parse({})).toEqual({
      EVENT_RETENTION_USER_DAYS: 90,
      EVENT_RETENTION_ADMIN_DAYS: 365,
    });
  });

  it('reads whole numbers of days', () => {
    expect(
      eventRetentionEnvSchema.parse({
        EVENT_RETENTION_USER_DAYS: '30',
        EVENT_RETENTION_ADMIN_DAYS: '90',
      })
    ).toEqual({ EVENT_RETENTION_USER_DAYS: 30, EVENT_RETENTION_ADMIN_DAYS: 90 });
  });

  it.each([
    ['admin events kept 89 days', { EVENT_RETENTION_ADMIN_DAYS: '89' }],
    ['user events kept 0 days', { EVENT_RETENTION_USER_DAYS: '0' }],
    ['a fraction', { EVENT_RETENTION_USER_DAYS: '1.5' }],
    ['more than 36500 days', { EVENT_RETENTION_ADMIN_DAYS: '36501' }],
    ['a word', { EVENT_RETENTION_USER_DAYS: 'forever' }],
  ])('refuses %s', (_label, input) => {
    expect(eventRetentionEnvSchema.safeParse(input).success).toBe(false);
  });
});
