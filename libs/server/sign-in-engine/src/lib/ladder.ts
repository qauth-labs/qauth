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
   * the account: a known IP skips the wait and still counts toward the hard
   * ceiling. `0` for a ladder with no exemption (a second factor: only a
   * holder of the first factor reaches it).
   */
  readonly knownIpMs: number;
  /**
   * How long a run of failures is kept after its last counted failure. A run
   * ends at a success, at the owner's reset, or after this long with no
   * counted failure. The same for every identifier, held by an account or
   * not, so the decay tells nothing about who exists.
   */
  readonly retentionMs: number;
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
 * the account in the last 30 days skips the wait. `development` may relax
 * these (ADR-008 §5); `staging` and `production` keep them.
 */
export const PASSWORD_LADDER_POLICY: LadderPolicy = Object.freeze({
  freeFailures: 5,
  firstWaitMs: 1_000,
  maxWaitMs: 15 * 60_000,
  hardCeiling: 100,
  knownIpMs: 30 * DAY_MS,
  retentionMs: 30 * DAY_MS,
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
  if (!whole(policy.retentionMs, policy.maxWaitMs)) {
    throw new Error('ladder policy: retentionMs shorter than the longest wait');
  }
  if (policy.onSuccess !== 'clear' && policy.onSuccess !== 'withdraw') {
    throw new Error('ladder policy: onSuccess is neither clear nor withdraw');
  }
  return policy;
}
