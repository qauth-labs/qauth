import { describe, expect, it } from 'vitest';

import { uniqueEmail } from '../../fixtures/users';
import { expectProblem } from '../../helpers/error-shape';
import { call } from '../../helpers/operations';

/**
 * The one password policy at registration, as a default deployment applies it
 * (#634): a new password of fewer than 15 characters, or equal to a common
 * password, is refused with the `weak_password` problem, and its `reasons`
 * extension member lists every reason found, in the order the policy checks
 * them. One over 256 UTF-16 code units never reaches the policy: the request
 * schema refuses it first, as it did before. Every request here is refused, so no account is created:
 * the suite's users still come from `fixtures/users.ts` only.
 */

function register(password: string): Promise<Response> {
  return call('POST /auth/register', { json: { email: uniqueEmail(), password } });
}

async function reasonsOf(response: Response): Promise<unknown> {
  const problem = await expectProblem(response, { status: 422, code: 'weak_password' });
  return (problem as unknown as Record<string, unknown>)['reasons'];
}

describe('[POST /auth/register] RFC 9457 §3.2 — a refused password answers weak_password with its reasons', () => {
  it('refuses a strong 14-character password as too_short at the default minimum', async () => {
    expect(await reasonsOf(await register('Kx9#mQ2$vL7!pR'))).toEqual(['too_short']);
  });

  it('refuses a 257-character password at the request schema, before the policy runs', async () => {
    await expectProblem(await register('a'.repeat(257)), { status: 400, code: 'validation_error' });
  });

  it('refuses a common password as blocklisted, after its length and before its score', async () => {
    expect(await reasonsOf(await register('password'))).toEqual([
      'too_short',
      'blocklisted',
      'too_weak',
    ]);
  });
});
