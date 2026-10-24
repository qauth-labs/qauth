import { describe, expect, it } from 'vitest';

import {
  ADMIN_EVENT_RETENTION_DEFAULT_DAYS,
  ADMIN_EVENT_RETENTION_MIN_DAYS,
  DEFAULT_EVENT_RETENTION_POLICY,
  EVENT_RETENTION_MAX_DAYS,
  eventRetentionProblems,
  USER_EVENT_RETENTION_DEFAULT_DAYS,
} from './event-retention';

describe('event retention policy (#536)', () => {
  it('keeps user events 90 days and admin events 365 days by default', () => {
    expect(USER_EVENT_RETENTION_DEFAULT_DAYS).toBe(90);
    expect(ADMIN_EVENT_RETENTION_DEFAULT_DAYS).toBe(365);
    expect(eventRetentionProblems(DEFAULT_EVENT_RETENTION_POLICY)).toEqual([]);
  });

  it('refuses an admin retention of 89 days and accepts 90', () => {
    expect(ADMIN_EVENT_RETENTION_MIN_DAYS).toBe(90);
    expect(eventRetentionProblems({ adminEventRetentionDays: 89 })).toEqual([
      'adminEventRetentionDays: must be at least 90 days',
    ]);
    expect(eventRetentionProblems({ adminEventRetentionDays: 90 })).toEqual([]);
  });

  it('accepts a user retention down to one day', () => {
    expect(eventRetentionProblems({ userEventRetentionDays: 1 })).toEqual([]);
    expect(eventRetentionProblems({ userEventRetentionDays: 0 })).toEqual([
      'userEventRetentionDays: must be at least 1 day',
    ]);
  });

  it.each([1.5, Number.NaN, Number.POSITIVE_INFINITY, '90', null])(
    'refuses %s days, which is not a whole number',
    (value) => {
      expect(
        eventRetentionProblems({
          userEventRetentionDays: value as number,
          adminEventRetentionDays: value as number,
        })
      ).toEqual([
        'userEventRetentionDays: must be a whole number of days',
        'adminEventRetentionDays: must be a whole number of days',
      ]);
    }
  );

  it('refuses a retention past the maximum', () => {
    expect(
      eventRetentionProblems({
        userEventRetentionDays: EVENT_RETENTION_MAX_DAYS + 1,
        adminEventRetentionDays: EVENT_RETENTION_MAX_DAYS,
      })
    ).toEqual([`userEventRetentionDays: must be at most ${EVENT_RETENTION_MAX_DAYS} days`]);
  });

  it('checks only the fields it is given', () => {
    expect(eventRetentionProblems({})).toEqual([]);
    expect(eventRetentionProblems({ userEventRetentionDays: 7 })).toEqual([]);
  });
});
