/**
 * THE FAILURE LADDER'S RULES (PRO-12, #615; ADR-017 Decision 7, NIST SP
 * 800-63B-4 §3.2.2): how many failures an authenticator gets before each
 * attempt must wait, how the wait grows, and when the hard action fires. The
 * store that counts (the auth server's is a Redis script in
 * `@qauth-labs/fastify-plugin-sign-in-engine`) applies them; this module only
 * says what they are, so every store and every test reads one source.
 *
 * A ladder counts the consecutive failures of one authenticator of one
 * account, keyed on the identifier's keyed HMAC whether or not an account
 * holds it. A success of that authenticator clears its counter and no other.
 */

/** The rules of one ladder. Times are in milliseconds. */
export interface LadderPolicy {
  /**
   * The consecutive counted failures with no wait: from this many on, the
   * next attempt waits. ADR-017 Decision 7: 5.
   */
  readonly freeFailures: number;
  /** The first wait, after the `freeFailures`-th failure; each further failure doubles it. */
  readonly firstWaitMs: number;
  /** The longest wait. ADR-017 Decision 7: 15 minutes. */
  readonly maxWaitMs: number;
  /**
   * The consecutive counted failures at which the hard action fires, or
   * `null` for a ladder with none (the email-code counter, ADR-017
   * Decision 5). NIST SP 800-63B-4 §3.2.2: at most 100.
   */
  readonly hardCeiling: number | null;
  /**
   * How long a successful sign-in from an end-user IP makes that IP known to
   * the account: a known IP skips the wait while the run has fewer than
   * `knownIpFreeFailures` counted failures, and every attempt of it still
   * counts toward the hard ceiling. `0` for a ladder with no exemption (a
   * second factor: only a holder of the first factor reaches it).
   */
  readonly knownIpMs: number;
  /**
   * The consecutive counted failures a known IP may make with no wait: from
   * this many on, its next attempt waits as any other address's does (#968).
   * Many clients can share one address (a carrier or office NAT, a VPN exit,
   * a reverse proxy's own address while `TRUST_PROXY` is unset), so after
   * one sign-in of the owner an unbounded exemption let anyone behind it
   * guess the account's password with no wait, up to the hard ceiling within
   * seconds. `freeFailures` makes the exemption skip nothing. With a hard
   * ceiling, a known IP must still meet at least half of the waits any other
   * address meets before it, so it reaches the ceiling in no less than half
   * that time. ADR-017 Decision 7: 20.
   */
  readonly knownIpFreeFailures: number;
  /**
   * How long a run that has reached a wait (`freeFailures` counted failures
   * or more) is kept after its last counted failure; each counted failure
   * starts it again. A run ends at a success, at the owner's reset, or after
   * its retention with no counted failure. ADR-017 Decision 7: 30 days.
   */
  readonly retentionMs: number;
  /**
   * How long a run still within its free failures (fewer than `freeFailures`,
   * so no wait yet) is kept after its last counted failure: short, so a spray
   * of made-up identifiers, each tried a few times, leaves no key for long
   * (#969). From the failure that sets its first wait the run is kept
   * `retentionMs`. Both retentions depend on the count alone, the same for
   * every identifier, held by an account or not, so the decay tells nothing
   * about who exists.
   *
   * A guesser who stays below the ladder gets `freeFailures − 1` tries per
   * `freeRetentionMs`, and never meets a wait or the hard ceiling. So it is
   * at least `freeFailures − 1` longest waits (no faster than the ladder's
   * steady pace) and, with a hard ceiling, long enough that those tries are
   * no more than the `hardCeiling − 1` a run can spend per `retentionMs`
   * without firing it; at most `retentionMs`. A counter only a holder of the
   * first factor reaches (a second factor) gains nothing from a short one and
   * sets it to `retentionMs`. ADR-017 Decision 7: 2 days.
   */
  readonly freeRetentionMs: number;
  /**
   * What a success does to the counter that reserved it: `clear` ends the
   * run (a correct answer of the authenticator the counter is for); `withdraw`
   * only takes the attempt back, for a counter of failures alone that a
   * success of something else must not reset (ADR-017 Decision 7: "counters of
   * failures alone take the attempt back"). A wait the attempt set stays.
   */
  readonly onSuccess: 'clear' | 'withdraw';
}

/** One day, in milliseconds. */
const DAY_MS = 86_400_000;

/**
 * The password ladder (ADR-017 Decision 7): from 5 consecutive failures the
 * next attempt waits 2^(n−5) seconds, capped at 15 minutes; 100 consecutive
 * counted failures fire the hard action; an IP with a successful sign-in to
 * the account in the last 30 days skips the wait while the run has fewer
 * than 20 counted failures, and from then on waits as any other address
 * does; a run is kept after its last counted failure 2 days while it has
 * fewer than 5, and 30 days once it has reached a wait. `development` may
 * relax these (ADR-008 §5); `staging` and `production` keep them.
 */
export const PASSWORD_LADDER_POLICY: LadderPolicy = Object.freeze({
  freeFailures: 5,
  firstWaitMs: 1_000,
  maxWaitMs: 15 * 60_000,
  hardCeiling: 100,
  knownIpMs: 30 * DAY_MS,
  knownIpFreeFailures: 20,
  retentionMs: 30 * DAY_MS,
  freeRetentionMs: 2 * DAY_MS,
  onSuccess: 'clear',
});

/** The largest doubling the wait is computed through: past it every wait is `maxWaitMs`. */
const MAX_DOUBLINGS = 40;

/**
 * The wait the `failures`-th consecutive counted failure sets for the next
 * attempt, in milliseconds: none below `freeFailures`, then `firstWaitMs`
 * doubled for each failure past it, capped at `maxWaitMs`. With the password
 * policy: the 5th failure sets 1 s, the 6th 2 s, the 15th and every later one
 * 15 minutes.
 */
export function ladderWaitMs(failures: number, policy: LadderPolicy): number {
  if (!Number.isFinite(failures) || failures < policy.freeFailures) return 0;
  const doublings = failures - policy.freeFailures;
  if (doublings >= MAX_DOUBLINGS) return policy.maxWaitMs;
  return Math.min(policy.firstWaitMs * 2 ** doublings, policy.maxWaitMs);
}

/**
 * The waits a run meets on its way from `from` consecutive counted failures to
 * `to`: the sum of the waits its failures `from` … `to − 1` set, in ms.
 */
function waitsBetween(from: number, to: number, policy: LadderPolicy): number {
  // Past MAX_DOUBLINGS every wait is the longest: those are counted at once.
  const capped = policy.freeFailures + MAX_DOUBLINGS;
  let total = 0;
  let n = Math.max(from, policy.freeFailures);
  for (; n < to && n < capped; n += 1) total += ladderWaitMs(n, policy);
  if (to > n) total += (to - n) * policy.maxWaitMs;
  return total;
}

/** Check a policy's numbers, so a store never runs a ladder that cannot hold. */
export function checkLadderPolicy(policy: LadderPolicy): LadderPolicy {
  const whole = (value: number, min: number) => Number.isSafeInteger(value) && value >= min;
  if (!whole(policy.freeFailures, 1)) throw new Error('ladder policy: freeFailures below 1');
  if (!whole(policy.firstWaitMs, 1)) throw new Error('ladder policy: firstWaitMs below 1 ms');
  if (!whole(policy.maxWaitMs, policy.firstWaitMs)) {
    throw new Error('ladder policy: maxWaitMs below firstWaitMs');
  }
  if (policy.hardCeiling !== null && !whole(policy.hardCeiling, policy.freeFailures)) {
    throw new Error('ladder policy: hardCeiling below freeFailures');
  }
  if (!whole(policy.knownIpMs, 0)) throw new Error('ladder policy: knownIpMs is not a time');
  if (!whole(policy.knownIpFreeFailures, policy.freeFailures)) {
    throw new Error('ladder policy: knownIpFreeFailures below freeFailures');
  }
  // A known IP may be shared by many clients: it must not run free to the
  // hard ceiling. The waits it still meets before the ceiling are at least
  // the ones it skips, so it takes at least half the time any other address
  // takes to fire it (#968).
  if (
    policy.hardCeiling !== null &&
    waitsBetween(policy.knownIpFreeFailures, policy.hardCeiling, policy) <
      waitsBetween(0, policy.knownIpFreeFailures, policy)
  ) {
    throw new Error(
      'ladder policy: knownIpFreeFailures skips more than half the waits before the hard ceiling'
    );
  }
  if (!whole(policy.retentionMs, policy.maxWaitMs)) {
    throw new Error('ladder policy: retentionMs shorter than the longest wait');
  }
  // Staying below the ladder must not pay: its `freeFailures − 1` tries per
  // `freeRetentionMs` are no faster than one try per longest wait on it...
  const freeFloor = Math.max(policy.maxWaitMs, (policy.freeFailures - 1) * policy.maxWaitMs);
  if (!whole(policy.freeRetentionMs, freeFloor)) {
    throw new Error('ladder policy: freeRetentionMs shorter than the free failures’ longest waits');
  }
  // ...and, with a hard ceiling, no more than the `hardCeiling − 1` tries a
  // run may spend per `retentionMs` without firing it.
  if (
    policy.hardCeiling !== null &&
    (policy.freeFailures - 1) * policy.retentionMs >
      (policy.hardCeiling - 1) * policy.freeRetentionMs
  ) {
    throw new Error('ladder policy: freeRetentionMs gives more tries below the hard ceiling');
  }
  if (policy.freeRetentionMs > policy.retentionMs) {
    throw new Error('ladder policy: freeRetentionMs longer than retentionMs');
  }
  if (policy.onSuccess !== 'clear' && policy.onSuccess !== 'withdraw') {
    throw new Error('ladder policy: onSuccess is neither clear nor withdraw');
  }
  return policy;
}
