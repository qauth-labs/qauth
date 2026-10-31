/**
 * Where an authorization code goes, as a screen shows it (ADR-019 Decision 6,
 * issue #593): a web host, "this device" for a loopback address, or a native
 * app's own URI scheme. The Interaction API's `ClientDisplay.redirect` has this
 * shape, and its schema bounds the host and the scheme.
 *
 * The same rule serves two places, so they can never disagree: the display
 * code builds the screen's data with it, and every registration path refuses a
 * redirect URI it cannot describe (dynamic registration, the developer API,
 * CIMD documents and the operator's seed manifest). A client can therefore
 * never reach a consent screen that has to refuse it for want of a way to say
 * where its code goes.
 */

/**
 * A host in the contract's form (its `host` schema): lower-case DNS labels in
 * ASCII, 1-63 characters each with inner hyphens only, or a dotted IPv4
 * address. No port, no brackets, no underscore.
 */
export const DISPLAY_HOST_PATTERN =
  '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$';

/** Longest host the contract carries: a DNS name in ASCII (RFC 1035 §2.3.4). */
export const DISPLAY_HOST_MAX_LENGTH = 253;

/** A URI scheme in the contract's form (its `redirect.scheme` schema). */
export const DISPLAY_SCHEME_PATTERN = '^[a-z][a-z0-9+.-]*$';

/** Longest scheme the contract carries. */
export const DISPLAY_SCHEME_MAX_LENGTH = 64;

const DISPLAY_HOST = new RegExp(DISPLAY_HOST_PATTERN);
const DISPLAY_SCHEME = new RegExp(DISPLAY_SCHEME_PATTERN);

/** Where the code goes. */
export type RedirectTarget =
  | { target: 'host'; host: string }
  | { target: 'this_device' }
  | { target: 'app'; scheme: string };

/**
 * True when `hostname` (as `URL.hostname` writes it) reaches the user's own
 * device: `localhost` and names under it (RFC 6761 §6.3), the whole IPv4
 * loopback block `127.0.0.0/8` (RFC 1122 §3.2.1.3), `::1`, an IPv4-mapped
 * loopback address, and the unspecified addresses `0.0.0.0` and `::`, which a
 * local client connects to as this machine. The URL parser has already
 * written every IPv4 form (`127.1`, `0x7f.1`) in dotted decimal and every IPv6
 * form compressed.
 */
export function isLoopbackHost(hostname: string): boolean {
  const host = hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === '::1' || host === '::') return true;
  // `[::ffff:127.0.0.1]` is written `[::ffff:7f00:1]`.
  if (/^::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}$/.test(host)) return true;
  const octets = host.split('.');
  if (octets.length !== 4 || !octets.every((octet) => /^\d{1,3}$/.test(octet))) return false;
  return octets[0] === '127' || host === '0.0.0.0';
}

/**
 * Where a redirect URI sends the code, in the contract's form.
 *
 * @returns `undefined` when the URI cannot be described that way: it does not
 * parse, its host is an IPv6 address that is not loopback or is not a DNS name
 * of valid labels (an underscore, an empty label, a label over 63 characters
 * or with an outer hyphen), or its scheme is longer than
 * {@link DISPLAY_SCHEME_MAX_LENGTH}.
 */
export function redirectTarget(redirectUri: string): RedirectTarget | undefined {
  let url: URL;
  try {
    url = new URL(redirectUri);
  } catch {
    return undefined;
  }
  if (url.protocol === 'https:' || url.protocol === 'http:') {
    if (isLoopbackHost(url.hostname)) return { target: 'this_device' };
    // The URL parser writes the host lower case, with an IDN in `xn--` form.
    // A trailing dot names the same DNS name.
    const host = url.hostname.replace(/\.$/, '');
    if (host.length > DISPLAY_HOST_MAX_LENGTH || !DISPLAY_HOST.test(host)) return undefined;
    return { target: 'host', host };
  }
  // A private-use scheme (RFC 8252 §7.1), which the URL parser writes lower case.
  const scheme = url.protocol.slice(0, -1);
  if (scheme.length > DISPLAY_SCHEME_MAX_LENGTH || !DISPLAY_SCHEME.test(scheme)) return undefined;
  return { target: 'app', scheme };
}
