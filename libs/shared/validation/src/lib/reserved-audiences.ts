/**
 * The reserved `urn:qauth:aud:` audience namespace (ADR-019 Decision 7, issue
 * #509).
 *
 * QAuth's API families take tokens for their own audiences:
 * `urn:qauth:aud:admin:v1-rc.0`, `urn:qauth:aud:account:v1-rc.0` and
 * `urn:qauth:aud:developer:v1-rc.0`. Every value in the namespace is QAuth's,
 * so no client obtains one on its own say-so, by the rule the reserved
 * `qauth:` scopes follow: dynamic registration and Client ID Metadata
 * Documents never store one (an `audience` or `resource` there is ignored), an
 * operator cannot grant one to a CIMD client through the seed manifest, and
 * the token endpoint issues one only to a client an operator set up to list
 * it in its `audience`, never to a CIMD or dynamically registered client.
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
