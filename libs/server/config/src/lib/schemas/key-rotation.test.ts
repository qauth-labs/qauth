import { describe, expect, it } from 'vitest';

import { keyRotationEnvSchema, keyRotationProblems } from './key-rotation';

describe('keyRotationEnvSchema (#542)', () => {
  it('rotates every 90 days, publishes 7 days ahead and keeps a retired key 14 days by default', () => {
    expect(keyRotationEnvSchema.parse({})).toEqual({
      KEY_ROTATION_PERIOD_DAYS: 90,
      KEY_PREPUBLISH_DAYS: 7,
      KEY_RETIRED_RETENTION_DAYS: 14,
    });
  });

  it('reads whole numbers of days', () => {
    expect(
      keyRotationEnvSchema.parse({
        KEY_ROTATION_PERIOD_DAYS: '30',
        KEY_PREPUBLISH_DAYS: '2',
        KEY_RETIRED_RETENTION_DAYS: '0',
      })
    ).toEqual({
      KEY_ROTATION_PERIOD_DAYS: 30,
      KEY_PREPUBLISH_DAYS: 2,
      KEY_RETIRED_RETENTION_DAYS: 0,
    });
  });

  it.each([
    ['a zero period', { KEY_ROTATION_PERIOD_DAYS: '0' }],
    ['no pre-publication', { KEY_PREPUBLISH_DAYS: '0' }],
    ['a negative retention', { KEY_RETIRED_RETENTION_DAYS: '-1' }],
    ['a fraction', { KEY_ROTATION_PERIOD_DAYS: '1.5' }],
    ['a period over ten years', { KEY_ROTATION_PERIOD_DAYS: '3651' }],
    ['a word', { KEY_PREPUBLISH_DAYS: 'week' }],
  ])('refuses %s', (_label, input) => {
    expect(keyRotationEnvSchema.safeParse(input).success).toBe(false);
  });
});

describe('keyRotationProblems (#542)', () => {
  it('refuses a period shorter than the pre-publication window', () => {
    const [problem, ...rest] = keyRotationProblems({
      KEY_ROTATION_PERIOD_DAYS: 6,
      KEY_PREPUBLISH_DAYS: 7,
    });
    expect(rest).toEqual([]);
    expect(problem).toContain(
      'KEY_ROTATION_PERIOD_DAYS (6) is shorter than KEY_PREPUBLISH_DAYS (7)'
    );
  });

  it('accepts a period as long as the window, or longer', () => {
    expect(keyRotationProblems({ KEY_ROTATION_PERIOD_DAYS: 7, KEY_PREPUBLISH_DAYS: 7 })).toEqual(
      []
    );
    expect(keyRotationProblems({ KEY_ROTATION_PERIOD_DAYS: 90, KEY_PREPUBLISH_DAYS: 7 })).toEqual(
      []
    );
  });
});
