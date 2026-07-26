const SECONDS_PER_MINUTE = 60;
const SECONDS_PER_HOUR = 3600;
const SECONDS_PER_DAY = 86400;

/**
 * Threshold at which the duration is expressed in days rather than hours.
 *
 * Kept at two full days so the common 86400s configuration keeps rendering as
 * "24 hours" (the copy operators and users are used to) instead of "1 day".
 */
const DAYS_THRESHOLD_SECONDS = 2 * SECONDS_PER_DAY;

function pluralize(value: number, unit: string): string {
  return `${value} ${unit}${value === 1 ? '' : 's'}`;
}

/**
 * Format a duration in seconds as human-readable English prose.
 *
 * Deliberately trivial and local: email copy needs "1 hour" / "24 hours" /
 * "3 days", not a full i18n-aware duration library. At most two units are
 * emitted so the sentence stays readable, and the remainder is truncated
 * rather than rounded up — an email must never overstate how long a link
 * remains valid.
 *
 * @param seconds - Duration in seconds. Non-finite or negative input is
 *   treated as zero.
 * @returns Human-readable duration, e.g. `"1 hour"`, `"24 hours"`,
 *   `"1 hour and 30 minutes"`, `"3 days"`.
 */
export function formatDuration(seconds: number): string {
  const total = Number.isFinite(seconds) ? Math.max(0, Math.floor(seconds)) : 0;

  if (total < SECONDS_PER_MINUTE) {
    return pluralize(total, 'second');
  }

  const parts: string[] = [];
  let remaining = total;

  if (total >= DAYS_THRESHOLD_SECONDS) {
    const days = Math.floor(remaining / SECONDS_PER_DAY);
    remaining -= days * SECONDS_PER_DAY;
    parts.push(pluralize(days, 'day'));
  }

  const hours = Math.floor(remaining / SECONDS_PER_HOUR);
  remaining -= hours * SECONDS_PER_HOUR;
  if (hours > 0) {
    parts.push(pluralize(hours, 'hour'));
  }

  const minutes = Math.floor(remaining / SECONDS_PER_MINUTE);
  if (minutes > 0 && parts.length < 2) {
    parts.push(pluralize(minutes, 'minute'));
  }

  return parts.slice(0, 2).join(' and ');
}
