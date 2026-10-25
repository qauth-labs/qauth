/**
 * The reserved `urn:qauth:aud:` audience namespace (ADR-019 Decision 7, issue
 * #509).
 *
 * QAuth's API families take tokens for their own audiences:
 * `urn:qauth:aud:admin:v1-rc.0`, `urn:qauth:aud:account:v1-rc.0` and
 * `urn:qauth:aud:developer:v1-rc.0`. Every value in the namespace is QAuth's,
 * so no client obtains one on its own say-so: dynamic registration and Client
 * ID Metadata Documents refuse it as an `audience` or `resource`, an operator
 * cannot grant it to a CIMD client through the seed manifest, and the token
 * endpoint issues it only to a client whose `audience` lists it.
 *
 * The prefix is matched after any leading whitespace and without regard to the
 * case of its ASCII letters. RFC 8141 makes `urn` and the namespace id
 * case-insensitive, and QAuth owns the rest of the prefix, so
 * `URN:QAuth:aud:` names the same reserved value. Without the `u` flag, `i`
 * folds no character outside ASCII onto an ASCII letter, so the match does not
 * depend on a locale.
 */

/** The prefix of every audience QAuth defines. */
export const RESERVED_AUDIENCE_PREFIX = 'urn:qauth:aud:';

const RESERVED_AUDIENCE = /^\s*urn:qauth:aud:/i;

/** Whether `value` is an audience in QAuth's reserved namespace, in any case. */
export function isReservedAudience(value: string): boolean {
  return RESERVED_AUDIENCE.test(value);
}

/**
 * The reserved audiences in a metadata value: a string, or a list whose string
 * entries are checked. Any other value holds none. Meant for metadata a client
 * wrote about itself (`audience`, `resource`), which QAuth otherwise ignores,
 * so its shape is not validated here.
 */
export function reservedAudiencesIn(value: unknown): string[] {
  const values: unknown[] = Array.isArray(value) ? value : [value];
  return values.filter(
    (entry): entry is string => typeof entry === 'string' && isReservedAudience(entry)
  );
}
