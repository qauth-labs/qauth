/**
 * The form a `backchannel_logout_uri` must take (OpenID Connect Back-Channel
 * Logout 1.0 §2.2, issue #624), before anything resolves its host.
 *
 * The spec asks for an absolute URI without a fragment, that SHOULD use
 * `https` and MAY use `http` for a confidential client when the OP allows it.
 * QAuth does not: every logout token is POSTed through the egress client,
 * which reaches `https` only (ADR-019 Decision 8), so an `http` URI could
 * never be delivered to. The other rules are the egress client's too, checked
 * here so a registration path can refuse the URI with a reason before it asks
 * the egress client to resolve the host:
 *
 * - at most {@link BACKCHANNEL_LOGOUT_URI_MAX_LENGTH} characters, printable
 *   ASCII (an IDN host is written in its `xn--` form), no tab or line break;
 * - an absolute `https` URL with a host;
 * - no user name or password, and no fragment.
 *
 * Whether the host resolves to a public address is not a question of form:
 * the egress client answers it at registration (`validateDestination`) and
 * again before every delivery.
 */

/** The longest `backchannel_logout_uri`, as the other registered URIs are bounded. */
export const BACKCHANNEL_LOGOUT_URI_MAX_LENGTH = 2048;

/** Printable ASCII, the space excluded: the characters an RFC 3986 URI is written in. */
const URI_CHARACTERS = /^[\x21-\x7e]+$/;

/**
 * Why `uri` cannot be a `backchannel_logout_uri`, in words a registration
 * error can carry, or `undefined` when its form is acceptable.
 */
export function backchannelLogoutUriProblem(uri: string): string | undefined {
  if (uri.length === 0 || uri.length > BACKCHANNEL_LOGOUT_URI_MAX_LENGTH) {
    return `must be 1 to ${BACKCHANNEL_LOGOUT_URI_MAX_LENGTH} characters`;
  }
  // Checked before the parse: `new URL()` drops a tab or a line break, and is
  // slow on many distinct non-ASCII characters in a host.
  if (!URI_CHARACTERS.test(uri)) {
    return 'must be printable ASCII, with no space, tab or line break';
  }
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return 'is not an absolute URI';
  }
  if (parsed.protocol !== 'https:') return 'must use https';
  if (parsed.hostname === '') return 'must name a host';
  if (parsed.username !== '' || parsed.password !== '') {
    return 'must not carry a user name or password';
  }
  // `new URL()` drops an empty fragment from `hash`, so the raw text decides.
  if (uri.includes('#')) return 'must not include a fragment';
  return undefined;
}
