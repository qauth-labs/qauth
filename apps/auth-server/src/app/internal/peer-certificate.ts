import {
  type InternalPeerRoles,
  type PeerSan,
  peerSanKey,
  type ServiceRole,
} from '@qauth-labs/server-config';

/**
 * WHO A CERTIFICATE NAMES (ADR-019 Decision 8, issue #496).
 *
 * The internal listener knows a peer by a subject alternative name (SAN) of
 * the certificate it presented, and the internal client knows the server the
 * same way: a DNS name or a URI, such as a SPIFFE ID. Never by the subject's
 * common name, never by an IP address, and never by a wildcard: a DNS SAN
 * `*.internal` is compared as the literal text it is, and nothing configures
 * one.
 */

/** A JSON string literal, as Node.js writes an escaped SAN value (its own `lib/tls.js` pattern). */
// eslint-disable-next-line no-control-regex -- a JSON string literal excludes the control characters
const JSON_STRING = /^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/;

/**
 * Split Node.js's `subjectAltName` text into its entries, `TYPE:value` each.
 *
 * Node.js joins the entries with `, ` and writes a value as a JSON string
 * literal when it would be ambiguous otherwise (CVE-2021-44532): a value may
 * hold `, ` or a quote. This reads it the way Node.js's own
 * `checkServerIdentity` does (`splitEscapedAltNames` in `lib/tls.js`), so a
 * value never splits into two entries, and an entry never runs into the next.
 *
 * @throws Error when a quoted value is not a JSON string literal
 */
export function splitSubjectAltName(text: string): string[] {
  const entries: string[] = [];
  let current = '';
  let offset = 0;
  while (offset !== text.length) {
    const separator = text.indexOf(', ', offset);
    const quote = text.indexOf('"', offset);
    if (quote !== -1 && (separator === -1 || quote < separator)) {
      current += text.slice(offset, quote);
      const literal = JSON_STRING.exec(text.slice(quote));
      if (literal === null) {
        throw new Error(
          'The certificate subject alternative name is not in the form Node.js writes'
        );
      }
      current += JSON.parse(literal[0]) as string;
      offset = quote + literal[0].length;
    } else if (separator !== -1) {
      current += text.slice(offset, separator);
      entries.push(current);
      current = '';
      offset = separator + 2;
    } else {
      current += text.slice(offset);
      offset = text.length;
    }
  }
  entries.push(current);
  return entries;
}

/**
 * The DNS and URI SANs of a certificate, from Node.js's `subjectAltName`
 * text (`X509Certificate.subjectAltName`, or `subjectaltname` on a peer
 * certificate object). Other kinds (IP addresses, e-mail addresses,
 * directory names) are left out: no peer is known by them. `[]` for a
 * certificate with no SAN, or one whose text cannot be read.
 */
export function certificateSans(subjectAltName: string | undefined): PeerSan[] {
  if (subjectAltName === undefined || subjectAltName === '') return [];
  let entries: string[];
  try {
    entries = splitSubjectAltName(subjectAltName);
  } catch {
    return [];
  }
  const sans: PeerSan[] = [];
  for (const entry of entries) {
    if (entry.startsWith('DNS:')) sans.push({ type: 'dns', value: entry.slice(4) });
    else if (entry.startsWith('URI:')) sans.push({ type: 'uri', value: entry.slice(4) });
  }
  return sans;
}

/** Whether `sans` holds `expected`: a DNS name without regard to case, a URI exactly. */
export function holdsSan(sans: readonly PeerSan[], expected: PeerSan): boolean {
  const key = peerSanKey(expected);
  return sans.some((san) => peerSanKey(san) === key);
}

/** Why a peer has no role on the internal listener. */
export type PeerRefusal =
  /** No certificate: a plain-HTTP connection, or none was presented. */
  | 'no-certificate'
  /** No SAN of the certificate is in INTERNAL_PEER_ROLES. */
  | 'unknown'
  /** Its SANs map to two roles or more: a peer calls as one role. */
  | 'ambiguous';

/** The role a peer calls the internal listener as, or why it has none. */
export type PeerRoleResolution = { readonly role: ServiceRole } | { readonly refused: PeerRefusal };

/**
 * The role a certificate's SANs map to in `peerRoles`. Every SAN the map
 * knows must name the same role: a certificate that two roles' entries match
 * is refused rather than given either, so a peer never calls as a role its
 * operator did not mean.
 */
export function resolvePeerRole(
  sans: readonly PeerSan[],
  peerRoles: InternalPeerRoles
): PeerRoleResolution {
  const roles = new Set<ServiceRole>();
  for (const san of sans) {
    const role = peerRoles.get(peerSanKey(san));
    if (role !== undefined) roles.add(role);
  }
  if (roles.size === 0) return { refused: 'unknown' };
  if (roles.size > 1) return { refused: 'ambiguous' };
  const [role] = roles;
  return { role };
}

/** At most this many SANs, each cut to this length, go into a refusal's log line. */
const LOGGED_SANS = 8;
const LOGGED_SAN_LENGTH = 256;

/** A certificate's SANs for a log line: bounded, so a certificate cannot flood the log. */
export function loggableSans(sans: readonly PeerSan[]): string[] {
  return sans
    .slice(0, LOGGED_SANS)
    .map((san) => `${san.type}:${san.value.slice(0, LOGGED_SAN_LENGTH)}`);
}
