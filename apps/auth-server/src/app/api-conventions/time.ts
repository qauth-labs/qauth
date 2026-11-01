/**
 * A time of the admin, account and developer APIs (#506): an RFC 3339 string
 * in UTC, such as `2026-10-22T09:30:00.000Z`, never an epoch number. The
 * database keeps epoch milliseconds; a representation converts them here.
 */
export function rfc3339(epochMs: number): string {
  return new Date(epochMs).toISOString();
}

/** {@link rfc3339}, or `null` for a time that is not set. */
export function rfc3339OrNull(epochMs: number | null): string | null {
  return epochMs === null ? null : rfc3339(epochMs);
}
