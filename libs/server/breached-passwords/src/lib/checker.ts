import type { BreachListSource } from '@qauth-labs/shared-validation';

import { passwordSha1 } from './digest';
import { type BreachCheckFailureReason, isBreachLookupError } from './errors';
import type { ReloadableBreachList } from './operator-list';
import type { BreachRangeLookup } from './range-lookup';

/** A source that checks something: every {@link BreachListSource} but `off`. */
export type ActiveBreachListSource = Exclude<BreachListSource, 'off'>;

/** What a breach check found (#635). */
export type BreachCheckResult =
  /** The realm's source is `off`: nothing was checked and nothing was sent. */
  | { readonly kind: 'off' }
  /** The password is on the breach list. */
  | { readonly kind: 'listed'; readonly source: ActiveBreachListSource }
  /** The password is not on the breach list. */
  | { readonly kind: 'not_listed'; readonly source: ActiveBreachListSource }
  /** The check could not answer. It never blocks a sign-in: the caller counts and records it. */
  | {
      readonly kind: 'failed';
      readonly source: ActiveBreachListSource;
      readonly reason: BreachCheckFailureReason;
    };

/** Every result but `off`: what {@link BreachedPasswordCheckerOptions.onResult} is told. */
export type BreachCheckOutcome = Exclude<BreachCheckResult, { kind: 'off' }>;

/** The question "is this password on the realm's breach list?" (#635, ADR-017 Decision 8). */
export interface BreachedPasswordChecker {
  /**
   * Check `password` against `source`. Never throws for a lookup or list
   * problem: those are `failed`, so a caller can let the sign-in proceed.
   * `realm` is the realm's NAME, passed to the egress client as its `realm`
   * so the deployment allowlist entries naming it apply to an internal
   * mirror.
   *
   * The password is hashed here with SHA-1 and goes nowhere: the local list
   * is searched in memory, and the range lookup sends the digest's first
   * five hex characters only.
   *
   * @throws TypeError when `source` is not one of `BREACH_LIST_SOURCES`
   */
  check(input: {
    readonly source: BreachListSource;
    readonly password: string;
    readonly realm?: string;
  }): Promise<BreachCheckResult>;
}

export interface BreachedPasswordCheckerOptions {
  /** The operator's local list, when `BREACHED_PASSWORD_LIST_PATH` is set. */
  readonly localList?: ReloadableBreachList;
  /** The range lookup, when `BREACHED_PASSWORD_RANGE_URL` is set. */
  readonly rangeLookup?: BreachRangeLookup;
  /**
   * Told every result except `off`, for the caller's metric (hits, misses,
   * failures). Whatever it throws is dropped: it never changes a check.
   */
  readonly onResult?: (result: BreachCheckOutcome) => void;
}

const OFF: BreachCheckResult = Object.freeze({ kind: 'off' });

/**
 * The breach check of a deployment: the realm names the source in
 * `password.breachListSource`, the deployment provides what it has of the
 * local list and the range lookup.
 *
 * A source the deployment has not set up is `failed` with `not_configured`;
 * a configured local list that has not loaded is `failed` with
 * `list_not_loaded`; a range lookup that could not answer is `failed` with
 * its reason. None of them blocks a sign-in (#635: "A lookup failure never
 * blocks sign-in").
 */
export function createBreachedPasswordChecker(
  options: BreachedPasswordCheckerOptions
): BreachedPasswordChecker {
  const { localList, rangeLookup, onResult } = options;

  const report = (result: BreachCheckOutcome): BreachCheckOutcome => {
    try {
      onResult?.(result);
    } catch {
      // A metric that throws must not turn a check into an error.
    }
    return result;
  };

  const failed = (
    source: ActiveBreachListSource,
    reason: BreachCheckFailureReason
  ): BreachCheckOutcome => report(Object.freeze({ kind: 'failed', source, reason }));

  const answered = (source: ActiveBreachListSource, listed: boolean): BreachCheckOutcome =>
    report(Object.freeze({ kind: listed ? 'listed' : 'not_listed', source }));

  const checkLocal = (password: string): BreachCheckOutcome => {
    if (localList === undefined) return failed('local', 'not_configured');
    const list = localList.current();
    if (list === null) return failed('local', 'list_not_loaded');
    return answered('local', list.has(passwordSha1(password)));
  };

  const checkRange = async (password: string, realm: string | undefined) => {
    if (rangeLookup === undefined) return failed('k_anonymity', 'not_configured');
    try {
      const answer = await rangeLookup.lookup(
        passwordSha1(password),
        realm === undefined ? undefined : { realm }
      );
      return answered('k_anonymity', answer === 'listed');
    } catch (error) {
      return failed('k_anonymity', isBreachLookupError(error) ? error.reason : 'lookup_failed');
    }
  };

  return Object.freeze({
    async check({ source, password, realm }): Promise<BreachCheckResult> {
      switch (source) {
        case 'off':
          return OFF;
        case 'local':
          return checkLocal(password);
        case 'k_anonymity':
          return checkRange(password, realm);
        default:
          throw new TypeError('a breach check names one of the breach list sources');
      }
    },
  } satisfies BreachedPasswordChecker);
}
