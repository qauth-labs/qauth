/**
 * Event retention, a realm policy (ADR-020 §3, ADR-019 Decisions 7 and 10,
 * issue #536): how many days a realm keeps its events before the retention
 * job deletes them.
 *
 * - User events are kept {@link USER_EVENT_RETENTION_DEFAULT_DAYS} days by
 *   default, and at least {@link USER_EVENT_RETENTION_MIN_DAYS}.
 * - Admin events are kept {@link ADMIN_EVENT_RETENTION_DEFAULT_DAYS} days by
 *   default, and never fewer than {@link ADMIN_EVENT_RETENTION_MIN_DAYS}: the
 *   admin log is the record of who changed what, and a realm admin cannot cut
 *   it short.
 *
 * The values live on the realm row (`realms.user_event_retention_days`,
 * `realms.admin_event_retention_days`); the environment only seeds a new
 * realm's. The environment schema, the realms repository and the row's CHECK
 * constraints all hold these limits, so none of them accepts what another
 * refuses.
 */

/** Days a realm keeps its user events unless its policy says otherwise. */
export const USER_EVENT_RETENTION_DEFAULT_DAYS = 90;

/** The fewest days a realm may keep its user events. */
export const USER_EVENT_RETENTION_MIN_DAYS = 1;

/** Days a realm keeps its admin events unless its policy says otherwise. */
export const ADMIN_EVENT_RETENTION_DEFAULT_DAYS = 365;

/** The fewest days a realm may keep its admin events (ADR-020 §3). */
export const ADMIN_EVENT_RETENTION_MIN_DAYS = 90;

/**
 * The most days either retention may be: about a hundred years, so that a
 * retention in milliseconds stays far inside a safe integer.
 */
export const EVENT_RETENTION_MAX_DAYS = 36_500;

/** One day, in milliseconds: the unit the retention job turns days into. */
export const DAY_MS = 24 * 60 * 60 * 1000;

/** A realm's event retention, in whole days. */
export interface EventRetentionPolicy {
  /** `realms.user_event_retention_days`. */
  readonly userEventRetentionDays: number;
  /** `realms.admin_event_retention_days`. */
  readonly adminEventRetentionDays: number;
}

/** The retention a realm gets when nothing seeds or sets another. */
export const DEFAULT_EVENT_RETENTION_POLICY: EventRetentionPolicy = Object.freeze({
  userEventRetentionDays: USER_EVENT_RETENTION_DEFAULT_DAYS,
  adminEventRetentionDays: ADMIN_EVENT_RETENTION_DEFAULT_DAYS,
});

function daysProblem(field: string, value: unknown, min: number): string | undefined {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    return `${field}: must be a whole number of days`;
  }
  if (value < min) return `${field}: must be at least ${min} ${min === 1 ? 'day' : 'days'}`;
  if (value > EVENT_RETENTION_MAX_DAYS) {
    return `${field}: must be at most ${EVENT_RETENTION_MAX_DAYS} days`;
  }
  return undefined;
}

/**
 * What is wrong with the retention fields of a realm policy, one line per
 * field; empty when nothing is. A field left out is not checked, so a change
 * of one field is checked alone.
 *
 * @example
 * ```typescript
 * eventRetentionProblems({ adminEventRetentionDays: 89 });
 * // ['adminEventRetentionDays: must be at least 90 days']
 * eventRetentionProblems({ adminEventRetentionDays: 90 }); // []
 * ```
 */
export function eventRetentionProblems(policy: Partial<EventRetentionPolicy>): string[] {
  const problems: string[] = [];
  if (policy.userEventRetentionDays !== undefined) {
    const problem = daysProblem(
      'userEventRetentionDays',
      policy.userEventRetentionDays,
      USER_EVENT_RETENTION_MIN_DAYS
    );
    if (problem) problems.push(problem);
  }
  if (policy.adminEventRetentionDays !== undefined) {
    const problem = daysProblem(
      'adminEventRetentionDays',
      policy.adminEventRetentionDays,
      ADMIN_EVENT_RETENTION_MIN_DAYS
    );
    if (problem) problems.push(problem);
  }
  return problems;
}
