import type {
  RealmPolicies,
  RealmPolicyStoreOfRealms,
} from '@qauth-labs/fastify-plugin-realm-policy';

import type { RealmRow } from './request-realm';

// The account policies' reader lives apart from `realm-policy-readers.ts`,
// whose token reader reads `fastify.jwtUtils`: the sign-in, verification and
// registration routes read only these, and need no JWT plugin in a process
// that serves them (`route-manifest.ts`).

/**
 * A realm's failed sign-in throttling (`bruteForce`, #528): whether repeated
 * failures lock an identifier out, after how many within which window, and
 * for how long. What `helpers/failed-login.ts` counts with.
 */
export type BruteForcePolicy = Readonly<RealmPolicies['bruteForce']>;

/**
 * A realm's account policies (#528): what the password sign-ins, the email
 * verification and the registration read.
 */
export interface AccountPolicies {
  /**
   * `accounts.requireVerifiedAccount`: an unverified account's password
   * sign-in is refused, with the answer a wrong password gets.
   */
  readonly requireVerifiedAccount: boolean;
  /** `password.minScore`: the lowest zxcvbn score, 0 to 4, a new password may have. */
  readonly passwordMinScore: number;
  /** `bruteForce`: the failed-login lockout of the realm's identifiers. */
  readonly bruteForce: BruteForcePolicy;
}

/**
 * A realm's verified-account, password and brute-force policy (ADR-019
 * Decision 10, #528), from the realm row the flow already loaded (the realm
 * resolver's): no query. So two realms of one deployment can differ: one may
 * let an unverified account sign in and another refuse it, ask new passwords
 * for different strengths, and lock an identifier out after a different
 * count, or never. A change of a realm's policies reaches its next request
 * once the row is read again (the resolver's cache time), without a restart.
 *
 * `REQUIRE_VERIFIED_ACCOUNT`, `PASSWORD_MIN_SCORE` and the `FAILED_LOGIN_*`
 * keys only seed these policies. A realm with none yet (counter 0: created by
 * a node of the previous release during a rolling upgrade, until a boot fills
 * it) reads the environment's seeds, which are what the server read before
 * #528 and what its fill will store, so nothing changes when the fill lands.
 *
 * As for the token lifetimes, the store reads the whole document, so a value
 * the schema refuses in any group fails the request (a server error, logged)
 * rather than let the server guess what the realm meant.
 *
 * @throws PolicyValidationError when the realm's stored policies are not a
 *   valid policy document
 */
export function accountPoliciesOf(
  sources: { readonly policyStore: Pick<RealmPolicyStoreOfRealms, 'ofRealm'> },
  realm: RealmRow
): AccountPolicies {
  const { accounts, password, bruteForce } = sources.policyStore.ofRealm(realm).policies;
  return Object.freeze({
    requireVerifiedAccount: accounts.requireVerifiedAccount,
    passwordMinScore: password.minScore,
    bruteForce: Object.freeze({
      enabled: bruteForce.enabled,
      maxAttempts: bruteForce.maxAttempts,
      windowSeconds: bruteForce.windowSeconds,
      lockoutSeconds: bruteForce.lockoutSeconds,
    }),
  });
}
