import { describe, expect, it } from 'vitest';

import { formatDuration } from './format-duration';

describe('formatDuration', () => {
  it('should format the default verification token expiry as 24 hours', () => {
    expect(formatDuration(86400)).toBe('24 hours');
  });

  it('should format the minimum configurable expiry as a single hour', () => {
    expect(formatDuration(3600)).toBe('1 hour');
  });

  it('should format whole hours in the plural', () => {
    expect(formatDuration(7200)).toBe('2 hours');
    expect(formatDuration(43200)).toBe('12 hours');
  });

  it('should combine hours and minutes for non-whole hours', () => {
    expect(formatDuration(5400)).toBe('1 hour and 30 minutes');
    expect(formatDuration(3660)).toBe('1 hour and 1 minute');
  });

  it('should format sub-hour durations in minutes', () => {
    expect(formatDuration(60)).toBe('1 minute');
    expect(formatDuration(1800)).toBe('30 minutes');
  });

  it('should format sub-minute durations in seconds', () => {
    expect(formatDuration(0)).toBe('0 seconds');
    expect(formatDuration(1)).toBe('1 second');
    expect(formatDuration(59)).toBe('59 seconds');
  });

  it('should switch to days only from two days upward', () => {
    // 86400 must stay "24 hours" so the default copy is unchanged.
    expect(formatDuration(86400)).toBe('24 hours');
    expect(formatDuration(172800)).toBe('2 days');
    expect(formatDuration(259200)).toBe('3 days');
  });

  it('should emit at most two units', () => {
    // 3 days, 1 hour, 1 minute -> minutes are dropped.
    expect(formatDuration(259200 + 3600 + 60)).toBe('3 days and 1 hour');
  });

  it('should combine days and minutes when there is no whole hour', () => {
    expect(formatDuration(172800 + 1800)).toBe('2 days and 30 minutes');
  });

  it('should truncate rather than round up, never overstating validity', () => {
    expect(formatDuration(7199)).toBe('1 hour and 59 minutes');
    expect(formatDuration(3599)).toBe('59 minutes');
  });

  it('should treat invalid input as zero', () => {
    expect(formatDuration(-100)).toBe('0 seconds');
    expect(formatDuration(Number.NaN)).toBe('0 seconds');
    expect(formatDuration(Number.POSITIVE_INFINITY)).toBe('0 seconds');
  });
});
