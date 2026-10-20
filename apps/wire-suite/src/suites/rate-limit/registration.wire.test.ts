import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { createUser } from '../../fixtures/users';
import { expectStandardError } from '../../helpers/error-shape';

const { baseUrl } = wireConfig();
const registerUrl = serverPath(baseUrl, '/auth/register');

/**
 * Highest registration limit this test will spend. CI raises the limits so the
 * rest of the suite is not throttled; this bounds how far, so the raise can
 * never quietly turn into "off".
 */
const MAX_SPENDABLE_LIMIT = 1000;

/** A body the schema rejects: counted by the limiter, never hashed or stored. */
function invalidRegistration(): Promise<Response> {
  return fetch(registerUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
    redirect: 'manual',
  });
}

function header(response: Response, name: string): number {
  const value = response.headers.get(name);
  expect(value, `${name} header on ${response.status}`).toMatch(/^\d+$/);
  return Number(value);
}

/**
 * Runs in the `wire-budget` project, after every other wire test
 * (`sequence.groupOrder` in vitest.wire.config.ts): it spends the registration
 * budget of the address the suite connects from, and anything that registered
 * a user after it would be refused for the rest of the window.
 */
describe('the registration rate limit, with the limits raised for the run (RFC 6585 §4)', () => {
  it('still answers 429 with Retry-After and the standard JSON error once the budget is spent', async () => {
    // A real registration first: the users fixture works and is counted.
    await createUser();

    const probe = await invalidRegistration();
    expect(probe.status, 'an invalid body is refused by the schema, not the limiter').toBe(400);
    await probe.body?.cancel();
    const limit = header(probe, 'x-ratelimit-limit');
    let remaining = header(probe, 'x-ratelimit-remaining');
    expect(limit, `REGISTRATION_RATE_LIMIT is ${limit}`).toBeLessThanOrEqual(MAX_SPENDABLE_LIMIT);
    expect(remaining).toBeLessThan(limit);

    while (remaining > 0) {
      const response = await invalidRegistration();
      expect(response.status, `refused early with ${remaining} left`).toBe(400);
      await response.body?.cancel();
      remaining = header(response, 'x-ratelimit-remaining');
    }

    const refused = await invalidRegistration();
    expect(refused.headers.get('retry-after') ?? '').toMatch(/^\d+$/);
    await expectStandardError(refused, { status: 429 });
  });
});
