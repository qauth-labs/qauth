import { describe, expect, it } from 'vitest';

import {
  MAX_FAILED_LOGIN_LOCKOUT_SECONDS,
  MAX_FAILED_LOGIN_WINDOW_SECONDS,
  observabilityEnvSchema,
} from './observability';

/** The paths of the variables `env` is refused for, or `[]` when it parses. */
function refusedPaths(env: Record<string, string>): string[] {
  const result = observabilityEnvSchema.safeParse(env);
  return result.success ? [] : result.error.issues.map((issue) => issue.path.join('.'));
}

describe('observabilityEnvSchema failed-login throttling (#517)', () => {
  it('bounds the window and the lockout at a day', () => {
    expect(MAX_FAILED_LOGIN_WINDOW_SECONDS).toBe(86_400);
    expect(MAX_FAILED_LOGIN_LOCKOUT_SECONDS).toBe(86_400);
  });

  it('takes a day and refuses a second more', () => {
    expect(
      refusedPaths({ FAILED_LOGIN_WINDOW: '86400', FAILED_LOGIN_LOCKOUT_DURATION: '86400' })
    ).toEqual([]);
    expect(refusedPaths({ FAILED_LOGIN_WINDOW: '86401' })).toEqual(['FAILED_LOGIN_WINDOW']);
    expect(refusedPaths({ FAILED_LOGIN_LOCKOUT_DURATION: '86401' })).toEqual([
      'FAILED_LOGIN_LOCKOUT_DURATION',
    ]);
  });

  it('keeps the defaults', () => {
    const parsed = observabilityEnvSchema.parse({});
    expect(parsed.FAILED_LOGIN_WINDOW).toBe(900);
    expect(parsed.FAILED_LOGIN_LOCKOUT_DURATION).toBe(900);
  });
});
