import { isIP } from 'node:net';

import { z } from 'zod';

import { isServiceRole, SERVICE_ROLE_NAMES, type ServiceRole } from './service-roles';

/**
 * The internal listener (ADR-019 Decision 8, issue #496).
 *
 * A distributed deployment's roles call one another on a second HTTP server
 * of the process, apart from the public one: the signer service first (#497).
 * It binds to INTERNAL_HOST and INTERNAL_PORT, and with the internal TLS files
 * (`INTERNAL_TLS_CERT_PATH`, `INTERNAL_TLS_KEY_PATH`, `INTERNAL_TLS_CA_PATH`,
 * `serviceRolesEnvSchema`) it serves mutual TLS only: a peer presents a
 * certificate the CA file issued, and INTERNAL_PEER_ROLES maps a subject
 * alternative name (SAN) of that certificate to the role the peer calls as. A
 * mesh's or SPIFFE's certificates are files like any other, so both work.
 *
 * A plain `z.object`, so the auth server can spread its `.shape`.
 */

/** The address the internal listener binds to when `INTERNAL_HOST` is unset: loopback only. */
export const DEFAULT_INTERNAL_HOST = '127.0.0.1';

/**
 * The port the internal listener binds to when `INTERNAL_PORT` is unset: the
 * one the documentation's `SIGNER_URL` examples name.
 */
export const DEFAULT_INTERNAL_PORT = 3443;

/** How many SANs `INTERNAL_PEER_ROLES` may map. */
const MAX_PEER_SANS = 256;

/** The longest SAN `INTERNAL_PEER_ROLES` takes. */
const MAX_PEER_SAN_LENGTH = 2048;

/**
 * The kinds of subject alternative name a peer is known by: a DNS name
 * (`dNSName`) or a URI (`uniformResourceIdentifier`), such as a SPIFFE ID.
 */
export type PeerSanType = 'dns' | 'uri';

/** One subject alternative name of a peer certificate. */
export interface PeerSan {
  readonly type: PeerSanType;
  readonly value: string;
}

/**
 * The key a SAN is looked up by in {@link InternalPeerRoles}: its kind and its
 * value, a DNS name in lower case (RFC 5280 §7.2 compares DNS names without
 * regard to case), a URI exactly as written.
 */
export function peerSanKey(san: PeerSan): string {
  return san.type === 'dns' ? `dns:${san.value.toLowerCase()}` : `uri:${san.value}`;
}

/**
 * The role each known peer SAN calls the internal listener as, keyed by
 * {@link peerSanKey}. Empty when `INTERNAL_PEER_ROLES` is unset.
 */
export type InternalPeerRoles = ReadonlyMap<string, ServiceRole>;

/** One DNS label: letters, digits and inner hyphens, 1 to 63 characters. */
const DNS_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/** A URI scheme (RFC 3986 §3.1), then the rest, with no white space or control character. */
const URI_SAN = /^[a-z][a-z0-9+.-]*:[^\s\p{Cc}]+$/iu;

/**
 * Read a SAN as an operator writes it: a value with a `:` is a URI SAN (a
 * DNS name never holds one), anything else a DNS name.
 *
 * - A URI needs a scheme and must parse as a URL; it is compared exactly.
 * - A DNS name is ASCII letters, digits, hyphens and dots, at most 253
 *   characters, with no wildcard: a peer is one workload, never a pattern.
 * - An IP address is refused: peers are known by name, not by address.
 *
 * @returns the SAN, or the problem with the value
 */
export function parsePeerSan(
  text: string
): { readonly san: PeerSan } | { readonly problem: string } {
  if (text.length === 0 || text.length > MAX_PEER_SAN_LENGTH) {
    return { problem: `a SAN is 1 to ${MAX_PEER_SAN_LENGTH} characters long` };
  }
  if (isIP(text) !== 0 || isIP(text.replace(/^\[|\]$/g, '')) !== 0) {
    return {
      problem:
        'an IP address is not a peer name: map the DNS name or the URI its certificate holds',
    };
  }
  if (text.includes(':')) {
    if (!URI_SAN.test(text) || !URL.canParse(text)) {
      return {
        problem:
          'a SAN with a ":" is a URI, such as spiffe://example.org/qauth/web, and this one does not parse as one',
      };
    }
    return { san: { type: 'uri', value: text } };
  }
  const name = text.toLowerCase();
  if (name.length > 253 || !name.split('.').every((label) => DNS_LABEL.test(label))) {
    return {
      problem:
        'a SAN without a ":" is a DNS name: letters, digits, hyphens and dots, with no wildcard',
    };
  }
  return { san: { type: 'dns', value: name } };
}

/** No peer is known: the value of an unset variable. */
const NO_PEERS: InternalPeerRoles = new Map();

/** The example every refusal of `INTERNAL_PEER_ROLES` shows. */
const PEER_ROLES_EXAMPLE = '{"spiffe://example.org/qauth/web":"web","api.qauth.internal":"api"}';

/**
 * Parse `INTERNAL_PEER_ROLES`: a JSON object from a peer SAN to the service
 * role it calls as. Unset or blank is no peer.
 *
 * Refuses the boot, naming the entry, for a SAN {@link parsePeerSan} refuses,
 * a value that is not one role, `signer` (the role that serves the internal
 * listener never calls one as a peer, so no certificate may call as the
 * keys' holder), and two spellings of one DNS name that name two roles.
 */
function parseInternalPeerRoles(raw: string | undefined, ctx: z.RefinementCtx): InternalPeerRoles {
  if (raw === undefined || raw.trim() === '') return NO_PEERS;

  let decoded: unknown;
  try {
    decoded = JSON.parse(raw) as unknown;
  } catch {
    ctx.addIssue({
      code: 'custom',
      message: `INTERNAL_PEER_ROLES must be a JSON object from a peer certificate's SAN to its role, such as ${PEER_ROLES_EXAMPLE}`,
    });
    return z.NEVER;
  }
  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) {
    ctx.addIssue({
      code: 'custom',
      message: `INTERNAL_PEER_ROLES must be a JSON object keyed by SAN, such as ${PEER_ROLES_EXAMPLE}`,
    });
    return z.NEVER;
  }

  // `Object.entries` reads own keys, an own `__proto__` from `JSON.parse`
  // included; `parsePeerSan` refuses it (an underscore is no DNS label), and
  // the result is a Map, so no key ever reaches a prototype.
  const entries = Object.entries(decoded as Record<string, unknown>);
  if (entries.length > MAX_PEER_SANS) {
    ctx.addIssue({
      code: 'custom',
      message: `INTERNAL_PEER_ROLES maps ${entries.length} SANs, more than the ${MAX_PEER_SANS} it takes`,
    });
    return z.NEVER;
  }

  const roles = new Map<string, ServiceRole>();
  let valid = true;
  for (const [text, role] of entries) {
    const parsed = parsePeerSan(text);
    if ('problem' in parsed) {
      ctx.addIssue({
        code: 'custom',
        message: `INTERNAL_PEER_ROLES entry ${JSON.stringify(text)}: ${parsed.problem}`,
      });
      valid = false;
      continue;
    }
    if (typeof role !== 'string' || !isServiceRole(role)) {
      ctx.addIssue({
        code: 'custom',
        message: `INTERNAL_PEER_ROLES entry ${JSON.stringify(text)} must name one role: ${SERVICE_ROLE_NAMES.join(', ')}`,
      });
      valid = false;
      continue;
    }
    if (role === 'signer') {
      ctx.addIssue({
        code: 'custom',
        message: `INTERNAL_PEER_ROLES entry ${JSON.stringify(text)} names signer: the signer serves the internal listener and never calls it as a peer; map the peer to the role it runs, such as web or api`,
      });
      valid = false;
      continue;
    }
    const key = peerSanKey(parsed.san);
    const earlier = roles.get(key);
    if (earlier !== undefined && earlier !== role) {
      ctx.addIssue({
        code: 'custom',
        message: `INTERNAL_PEER_ROLES maps the DNS name ${parsed.san.value} to both ${earlier} and ${role}; a DNS name is compared without regard to case`,
      });
      valid = false;
      continue;
    }
    roles.set(key, role);
  }
  return valid ? roles : z.NEVER;
}

/** Blank is unset, as `${VAR:-}` in a Compose file expands to. */
function blankAsUnset<T extends z.ZodType>(schema: T) {
  return z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    schema
  );
}

/**
 * Internal listener environment configuration schema.
 */
export const internalListenerEnvSchema = z.object({
  /** The address the internal listener binds to. Loopback by default. */
  INTERNAL_HOST: blankAsUnset(z.string().trim().min(1).default(DEFAULT_INTERNAL_HOST)),
  /** The TCP port the internal listener binds to. */
  INTERNAL_PORT: blankAsUnset(
    z.coerce.number().int().min(1).max(65535).default(DEFAULT_INTERNAL_PORT)
  ),
  /** Peer SAN → the role it calls the internal listener as, as a JSON object. */
  INTERNAL_PEER_ROLES: z.string().optional().transform(parseInternalPeerRoles),
});

export type InternalListenerEnv = z.infer<typeof internalListenerEnvSchema>;
