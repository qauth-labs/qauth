import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import { summarizeConfiguredValue } from '../trust/configured-value';

/**
 * The SSRF boundary of the status path (issue #297).
 *
 * ## Why this module has to exist
 *
 * Every other input on the wallet path is data QAuth parses. The status list
 * URI is different in kind: it is an attacker-supplied string that QAuth is
 * asked to make an OUTBOUND HTTP REQUEST to. A credential is trivially minted
 * with `status.status_list.uri = "https://169.254.169.254/latest/meta-data/"`,
 * and the fetch happens BEFORE any signature has been checked — signature
 * verification needs the fetched document. There is no ordering that makes the
 * request safe; the URI has to be constrained before it is dialled.
 *
 * So: an operator-configured prefix allowlist, and no fetch to anything outside
 * it. Not a blocklist. A blocklist of "internal" addresses is a losing game
 * (DNS names resolving to RFC 1918, IPv6-mapped IPv4, redirects, rebinding),
 * and this is a case where the legitimate set is small and known — a deployment
 * federates with a handful of credential issuers whose status endpoints the
 * operator can name.
 *
 * ## Unconditional refusals, on top of the allowlist
 *
 * The allowlist is the decision; the checks below are the floor beneath it, so
 * a misconfigured prefix cannot open a hole the allowlist appears to have
 * closed:
 *
 *  - **non-HTTPS** — a status answer fetched in the clear is attacker-writable,
 *    which makes revocation checking worse than not doing it;
 *  - **IP literals** — no legitimate status endpoint is named by a bare address,
 *    and every classic SSRF target (`127.0.0.1`, `169.254.169.254`, `[::1]`,
 *    `[::ffff:127.0.0.1]`) is one. Refusing the whole literal FORM is a check
 *    that cannot be bypassed by a novel encoding of a private range, which a
 *    range-based blocklist cannot claim;
 *  - **`localhost` and its subdomains** — the one hostname guaranteed to resolve
 *    to the loopback;
 *  - **userinfo** — `https://status.trusted.example@evil.example/` is read by a
 *    human, and by a naive prefix check, as the trusted host;
 *  - **fragment** — never sent on the wire, so it can only exist to make two
 *    different-looking URIs fetch the same thing (or to defeat a prefix match).
 *
 * A query string IS allowed: draft-14 places no structure on the URI, and
 * issuers do shard lists by query parameter. It is covered by the prefix match
 * only in the sense that the ORIGIN and PATH prefix must still match.
 *
 * ## What this module does NOT solve, and where that is handled
 *
 * A hostname on the allowlist that RESOLVES to a private address (DNS
 * rebinding) is not defended here — that needs a connection-level check inside
 * the HTTP agent, which this pure `scope:server` library has no access to.
 * `fetchStatusListToken` therefore refuses REDIRECTS outright, which removes
 * the cheap version of the attack (allowlisted host 302s to the metadata
 * service). The residual risk is documented on that function.
 */

/** Longest allowlist entry accepted, in characters. Mirrors the URI cap. */
const MAX_PREFIX_LENGTH = 2048;

/**
 * Hostnames refused whatever the allowlist says.
 *
 * Matched on the full host and on any subdomain of it, because `localhost` is
 * routinely wildcarded into `anything.localhost` by resolvers.
 */
const ALWAYS_REFUSED_HOST_SUFFIXES = Object.freeze(['localhost'] as const);

/** Whether `hostname` is a bare IPv6 literal as `URL` reports it (`[::1]`). */
function isIpv6Literal(hostname: string): boolean {
  return hostname.startsWith('[') && hostname.endsWith(']');
}

/**
 * Whether `hostname` is a bare IPv4 literal.
 *
 * Deliberately loose — anything made only of digits and dots is treated as a
 * literal even when it is not a well-formed address, because `URL` and the
 * platform resolver between them accept several shorthand forms (`127.1`,
 * `0x7f.1`, `2130706433`) that a strict dotted-quad test would wave through.
 * A real hostname never has a purely numeric final label, so nothing
 * legitimate is caught.
 */
function isIpv4Literal(hostname: string): boolean {
  if (/^[\d.]+$/.test(hostname)) return true;
  const lastLabel = hostname.slice(hostname.lastIndexOf('.') + 1);
  return /^(?:\d+|0[xX][\da-fA-F]+)$/.test(lastLabel);
}

/** Whether `hostname` is, or is a subdomain of, an always-refused name. */
function isAlwaysRefusedHost(hostname: string): boolean {
  return ALWAYS_REFUSED_HOST_SUFFIXES.some(
    (suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`)
  );
}

/**
 * Parse a candidate status list URI, applying the unconditional refusals.
 *
 * @param raw - the URI as it appeared in the credential.
 * @returns the parsed `URL`, or `undefined` when the URI is refused outright.
 */
function parseFetchableHttpsUrl(raw: string): URL | undefined {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return undefined;
  }

  if (url.protocol !== 'https:') return undefined;
  if (url.username !== '' || url.password !== '') return undefined;
  if (url.hash !== '') return undefined;
  if (url.hostname === '') return undefined;
  if (isIpv6Literal(url.hostname) || isIpv4Literal(url.hostname)) return undefined;
  if (isAlwaysRefusedHost(url.hostname)) return undefined;

  return url;
}

/**
 * A compiled, operator-configured allowlist of status list URI prefixes.
 *
 * Opaque by design: a caller holds one and asks it questions, and cannot read
 * back the configured prefixes to put them in an error message.
 */
export interface StatusListUriAllowlist {
  /**
   * @param uri - the raw `status_list.uri` from a credential.
   * @returns `true` only if fetching that exact URI is permitted.
   */
  permits(uri: string): boolean;
}

/**
 * An allowlist that permits nothing.
 *
 * What an unconfigured or unparseable deployment resolves to, so "we do not
 * know where status lists may live" and "status lists may live nowhere" are the
 * same object — the same shape `DENY_ALL_TRUST_REGISTRY` gives issuer trust.
 */
export const DENY_ALL_STATUS_LIST_URI_ALLOWLIST: StatusListUriAllowlist = Object.freeze({
  permits: (): boolean => false,
});

/** One compiled prefix: the origin it pins and the path it pins under it. */
interface CompiledPrefix {
  readonly origin: string;
  /** Path with any trailing slash removed; `''` means "the whole origin". */
  readonly path: string;
}

/**
 * Compile an operator-supplied prefix list into a matcher (#297).
 *
 * ## Matching rule
 *
 * A candidate is permitted when its origin equals the prefix's origin AND its
 * path is either exactly the prefix path or continues it at a SEGMENT
 * boundary. The segment boundary is the whole point: a naive
 * `uri.startsWith(prefix)` lets `https://issuer.example/status-evil/...`
 * through a `https://issuer.example/status` prefix, and lets
 * `https://issuer.example.attacker.test/` through a
 * `https://issuer.example` one. Comparing a parsed origin and a
 * segment-anchored path makes both impossible.
 *
 * An empty prefix path pins the whole origin, which is the common
 * configuration.
 *
 * Comparison happens on `URL`-normalised values on BOTH sides — host
 * lowercased and punycoded, default port dropped, `.` and `..` segments
 * resolved, reserved characters percent-normalised — so a prefix and a
 * candidate that denote the same location match regardless of how each was
 * written.
 *
 * ## Throwing on a bad entry
 *
 * Same posture, and the same reasoning, as `createStaticIssuerAllowlist`: a
 * malformed entry is an OPERATOR error, and silently dropping it would leave
 * the operator believing an endpoint is reachable when it is not. It throws
 * `InvalidConfigurationError` with the offending value on `details`, never in
 * the message, so the value cannot reach a response body or a log line that
 * quotes the message.
 *
 * @param prefixes - `https://` URI prefixes status lists may be fetched from;
 * an empty list yields an allowlist that permits nothing.
 * @returns a frozen matcher.
 * @throws InvalidConfigurationError when an entry is not a usable HTTPS
 * prefix. The entry is on `details`, not in the message.
 */
export function createStatusListUriAllowlist(prefixes: readonly string[]): StatusListUriAllowlist {
  if (!Array.isArray(prefixes)) {
    throw new InvalidConfigurationError(
      'Status list URI allowlist must be an array of https:// prefixes (#297).'
    );
  }

  const compiled: CompiledPrefix[] = [];
  for (const [index, entry] of prefixes.entries()) {
    const parsed =
      typeof entry === 'string' &&
      entry.trim().length > 0 &&
      entry.trim().length <= MAX_PREFIX_LENGTH
        ? parseFetchableHttpsUrl(entry.trim())
        : undefined;

    // A prefix carrying a query string is refused rather than ignored: it
    // reads as constraining the query, which this matcher does not do, and
    // accepting it would silently permit every query on that path.
    if (parsed === undefined || parsed.search !== '') {
      throw new InvalidConfigurationError(
        'A status list URI allowlist entry is not a usable https:// prefix (#297). Entries must be absolute https:// URLs with a named host, no userinfo, no query string and no fragment. See this error\'s "details" for the position and the value.',
        { index, entry: summarizeConfiguredValue(entry) }
      );
    }

    compiled.push({ origin: parsed.origin, path: parsed.pathname.replace(/\/+$/, '') });
  }

  if (compiled.length === 0) return DENY_ALL_STATUS_LIST_URI_ALLOWLIST;

  return Object.freeze({
    permits(uri: string): boolean {
      if (typeof uri !== 'string') return false;
      const candidate = parseFetchableHttpsUrl(uri);
      if (candidate === undefined) return false;

      const candidatePath = candidate.pathname.replace(/\/+$/, '');
      return compiled.some(
        (prefix) =>
          prefix.origin === candidate.origin &&
          (prefix.path === '' ||
            candidatePath === prefix.path ||
            candidatePath.startsWith(`${prefix.path}/`))
      );
    },
  });
}
