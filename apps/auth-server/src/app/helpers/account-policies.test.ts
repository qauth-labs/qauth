import { defaultsFromEnv } from '@qauth-labs/fastify-plugin-realm-policy';
import { describe, expect, it, vi } from 'vitest';

import { testRealm } from '../../testing/request-realm';
import { accountPoliciesOf } from './account-policies';

describe('accountPoliciesOf (#528)', () => {
  /** A store whose snapshot holds the policies an environment of `keys` seeds. */
  function sources(keys: Record<string, string> = {}) {
    const policies = defaultsFromEnv(keys);
    return { policyStore: { ofRealm: vi.fn(() => ({ policies }) as never) } };
  }

  it('reads the verified-account gate, the password score and the brute-force policy from the row it is given', () => {
    const from = sources({
      REQUIRE_VERIFIED_ACCOUNT: 'false',
      PASSWORD_MIN_SCORE: '3',
      FAILED_LOGIN_TRACKING_ENABLED: 'true',
      FAILED_LOGIN_MAX_ATTEMPTS: '7',
      FAILED_LOGIN_WINDOW: '120',
      FAILED_LOGIN_LOCKOUT_DURATION: '60',
    });
    const realm = testRealm({ id: 'r', policiesVersion: 3 });

    expect(accountPoliciesOf(from, realm)).toEqual({
      requireVerifiedAccount: false,
      passwordMinScore: 3,
      bruteForce: { enabled: true, maxAttempts: 7, windowSeconds: 120, lockoutSeconds: 60 },
    });
    // The resolver's row, read once: no query.
    expect(from.policyStore.ofRealm).toHaveBeenCalledTimes(1);
    expect(from.policyStore.ofRealm).toHaveBeenCalledWith(realm);
  });

  it("reads a realm's own policies, so two realms differ", () => {
    const strict = accountPoliciesOf(
      sources({ PASSWORD_MIN_SCORE: '4' }),
      testRealm({ id: 'a', policiesVersion: 1 })
    );
    const lax = accountPoliciesOf(
      sources({ REQUIRE_VERIFIED_ACCOUNT: 'false', FAILED_LOGIN_TRACKING_ENABLED: 'false' }),
      testRealm({ id: 'b', policiesVersion: 1 })
    );

    expect(strict).toMatchObject({ requireVerifiedAccount: true, passwordMinScore: 4 });
    expect(strict.bruteForce.enabled).toBe(true);
    expect(lax).toMatchObject({ requireVerifiedAccount: false, passwordMinScore: 2 });
    expect(lax.bruteForce.enabled).toBe(false);
  });

  it("gives a realm seeded with no key the server's defaults of before #528: verified accounts, score 2, 5 failures in 900 s lock for 900 s", () => {
    expect(accountPoliciesOf(sources(), testRealm({ id: 'r', policiesVersion: 1 }))).toEqual({
      requireVerifiedAccount: true,
      passwordMinScore: 2,
      bruteForce: { enabled: true, maxAttempts: 5, windowSeconds: 900, lockoutSeconds: 900 },
    });
  });

  it('reads the old name REQUIRE_EMAIL_VERIFIED as the seed of the gate, as the server did', () => {
    const policies = accountPoliciesOf(
      sources({ REQUIRE_EMAIL_VERIFIED: 'false' }),
      testRealm({ id: 'r', policiesVersion: 1 })
    );

    expect(policies.requireVerifiedAccount).toBe(false);
  });

  it('hands out frozen objects', () => {
    const policies = accountPoliciesOf(sources(), testRealm({ id: 'r', policiesVersion: 2 }));

    expect(Object.isFrozen(policies)).toBe(true);
    expect(Object.isFrozen(policies.bruteForce)).toBe(true);
  });

  it('lets a store refusal of invalid stored policies through, rather than guess a policy', () => {
    const from = sources();
    from.policyStore.ofRealm.mockImplementation(() => {
      throw new Error('The stored policies are not valid');
    });

    expect(() => accountPoliciesOf(from, testRealm({ id: 'r', policiesVersion: 2 }))).toThrow(
      'The stored policies are not valid'
    );
  });
});
