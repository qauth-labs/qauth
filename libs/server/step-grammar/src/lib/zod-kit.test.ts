import { stepNamed } from '@qauth-labs/shared-interaction-contract';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { STEP_GRAMMAR } from './steps';

/**
 * A value over its maximum length is refused by that check alone: no later
 * check reads it, neither a pattern nor a `format` nor the JSON parse of a
 * WebAuthn response. Zod runs every check in turn unless one aborts, so
 * without it a 5 MB answer would be parsed as JSON after its length had
 * already failed.
 */

const codesOf = (result: { success: boolean; error?: { issues: { code: string }[] } }) =>
  result.success ? [] : (result.error?.issues ?? []).map((issue) => issue.code);

afterEach(() => {
  vi.restoreAllMocks();
});

describe('a value over its maximum length', () => {
  it('is refused before a WebAuthn response string is parsed as JSON', () => {
    const parse = vi.spyOn(JSON, 'parse');
    const answer = STEP_GRAMMAR.webauthn_get.answer;
    const oversized = `{"id":"${'a'.repeat(5 * 1024 * 1024)}"}`;
    expect(codesOf(answer.safeParse({ webauthn_response: oversized }))).toEqual(['too_big']);
    expect(parse).not.toHaveBeenCalled();
    // At its maximum, the string is parsed and checked as before.
    expect(codesOf(answer.safeParse({ webauthn_response: 'x'.repeat(8192) }))).toEqual(['custom']);
    expect(parse).toHaveBeenCalledTimes(1);
  });

  it('is refused before the pattern and the uri check of a resource indicator', () => {
    const params = stepNamed('consent').example.step.params as Record<string, unknown>;
    const result = STEP_GRAMMAR.consent.params.safeParse({
      ...params,
      resources: [`javascript:${'<x>'.repeat(1000)}`],
    });
    expect(codesOf(result)).toEqual(['too_big']);
  });

  it('is refused before the pattern and the uri check of an otpauth URI', () => {
    const personal = stepNamed('totp_setup').example.personal as Record<string, unknown>;
    const result = STEP_GRAMMAR.totp_setup.personal.safeParse({
      ...personal,
      otpauth_uri: `otpauth://totp/${' '.repeat(2000)}`,
    });
    expect(codesOf(result)).toEqual(['too_big']);
  });

  it('is refused before the pattern and the date-time check of a time', () => {
    const params = stepNamed('device_confirm').example.step.params as Record<string, unknown>;
    const result = STEP_GRAMMAR.device_confirm.params.safeParse({
      ...params,
      requested_at: '9'.repeat(4096),
    });
    expect(codesOf(result)).toEqual(['too_big']);
  });

  it('within its maximum, still meets every later check', () => {
    const params = stepNamed('device_confirm').example.step.params as Record<string, unknown>;
    expect(
      STEP_GRAMMAR.device_confirm.params.safeParse({
        ...params,
        requested_at: '2026-02-30T09:30:00Z',
      }).success
    ).toBe(false);
    expect(STEP_GRAMMAR.device_confirm.params.safeParse(params).success).toBe(true);
  });
});
