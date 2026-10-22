/**
 * Realm host normalisation (ADR-019 Decision 1, issue #470).
 *
 * A request belongs to the realm whose primary host, or one of whose endpoint
 * hosts, equals the request's authority. The match is exact and
 * case-insensitive, on the port-less ASCII form of the host. This module is the
 * one place that form is computed: the repository normalises every host it
 * stores, and the realm resolver normalises the `Host` header the same way
 * before the lookup, so the two can never disagree.
 *
 * ## Why the WHATWG URL parser does the IDNA step
 *
 * Converting a Unicode host to its ASCII (punycode) form is UTS #46 processing:
 * case folding, width mapping (`ｅｘａｍｐｌｅ` → `example`), the ideographic full
 * stop as a label separator, and Punycode. `new URL()` does exactly what a
 * browser does before it sends the `Host` header, and it exists in every
 * runtime this library runs in. It is also lenient where a host must not be:
 * it keeps wildcards, empty labels and a trailing dot, and it would accept a
 * userinfo, a path or a percent-encoded host. So the checks around it are
 * strict, and only the bare host reaches it.
 */
import { z } from 'zod';

/**
 * The two kinds of realm host.
 *
 * - `primary` — the realm's issuer host. One per realm, permanent once set, and
 *   the default passkey RP ID, so never an IP literal.
 * - `endpoint` — an extra name a server-to-server caller uses to reach the
 *   realm, such as the Compose service name in `AUTH_SERVER_URL`. It answers
 *   API routes only, and may be an IP literal.
 */
export const REALM_HOST_KINDS = ['primary', 'endpoint'] as const;

export type RealmHostKind = (typeof REALM_HOST_KINDS)[number];

/** Longest host name DNS allows, in ASCII, without the trailing dot (RFC 1035 §2.3.4). */
export const REALM_HOST_MAX_LENGTH = 253;

/** Longest DNS label (RFC 1035 §2.3.4). */
const REALM_HOST_MAX_LABEL_LENGTH = 63;

/**
 * Why {@link normaliseRealmHost} refused a value.
 *
 * - `empty` — nothing left once the port and trailing dot are gone.
 * - `whitespace` — a space, tab, line break or other Unicode white space.
 * - `wildcard` — a `*` anywhere. A realm owns exact hosts only.
 * - `empty_label` — two dots in a row, or a leading dot.
 * - `too_long` — more than {@link REALM_HOST_MAX_LENGTH} ASCII characters.
 * - `ip_literal` — an IPv4 or IPv6 address given as a primary host.
 * - `invalid_port` — a port that is not 1–5 digits up to 65535.
 * - `malformed` — anything else that is not a host name or IP literal: a path,
 *   a userinfo, percent-encoding, an unbracketed IPv6 address, a label that
 *   starts or ends with a hyphen or is longer than 63 characters, or a value
 *   the IDNA step rejects.
 */
export type InvalidRealmHostReason =
  | 'empty'
  | 'whitespace'
  | 'wildcard'
  | 'empty_label'
  | 'too_long'
  | 'ip_literal'
  | 'invalid_port'
  | 'malformed';

/**
 * Thrown by {@link normaliseRealmHost} for a value that cannot be a realm host.
 * `reason` is stable and safe to branch on; the message is for operators and
 * repeats the value, so do not echo it to an anonymous caller.
 */
export class InvalidRealmHostError extends Error {
  readonly code = 'INVALID_REALM_HOST';

  constructor(
    public readonly reason: InvalidRealmHostReason,
    message: string
  ) {
    super(message);
    this.name = 'InvalidRealmHostError';
    Object.setPrototypeOf(this, InvalidRealmHostError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidRealmHostError);
    }
  }
}

/**
 * Characters that would make the URL parser read more than a host: a path, a
 * query, a fragment, a userinfo, or a percent-encoded octet.
 */
const NON_HOST_CHARACTERS = /[/\\?#@%]/;

/** An optional port after the host: `:` and 1–5 digits. */
const PORT = /^:([0-9]{1,5})$/;

/**
 * One ASCII label: letters, digits, `_` and `-`, not starting or ending with a
 * hyphen. The underscore is there for container service names (`auth_server`),
 * which Docker's DNS resolves and which therefore arrive as a `Host` header.
 */
const LABEL = /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/;

const ipv4Schema = z.ipv4();
const ipv6Schema = z.ipv6();

/**
 * Split an authority into its host and port. A bracketed IPv6 literal keeps its
 * brackets, because that is how it appears in a `Host` header and how it is
 * stored. An IPv6 address without brackets is refused: its last group cannot be
 * told apart from a port.
 */
function splitPort(input: string): { host: string; port: string } {
  if (input.startsWith('[')) {
    const close = input.indexOf(']');
    if (close === -1) {
      throw new InvalidRealmHostError('malformed', `Realm host "${input}" has no closing "]"`);
    }
    return { host: input.slice(0, close + 1), port: input.slice(close + 1) };
  }

  const colon = input.indexOf(':');
  if (colon === -1) return { host: input, port: '' };
  if (input.indexOf(':', colon + 1) !== -1) {
    throw new InvalidRealmHostError(
      'malformed',
      `Realm host "${input}" has more than one ":"; an IPv6 address goes in brackets`
    );
  }
  return { host: input.slice(0, colon), port: input.slice(colon) };
}

/**
 * Normalise a realm host to the form that is stored and matched: lower case,
 * ASCII (punycode for an internationalised name), with no port and no trailing
 * dot. An IPv4 address comes out in dotted-decimal form and an IPv6 address in
 * brackets, compressed, as the URL standard writes them.
 *
 * Refused, with an {@link InvalidRealmHostError}: white space, a wildcard, an
 * empty label, a host over {@link REALM_HOST_MAX_LENGTH} characters once in
 * ASCII, a bad port, and anything that is not a bare host. When `kind` is
 * `'primary'` an IP literal is refused too, because a primary host is the
 * realm's passkey RP ID and an RP ID cannot be an IP address.
 *
 * @param input - a host as configured, or the authority of a request (`Host`
 * header or `:authority`), with or without a port.
 * @param kind - the kind the host will be stored as. Pass it on every write.
 * Omit it to normalise a request authority for a lookup: an IP literal passes
 * then, because an endpoint host may be one.
 * @returns the normalised host.
 * @throws InvalidRealmHostError when the value cannot be a realm host.
 *
 * @example
 * ```typescript
 * normaliseRealmHost('AUTH.Example.com:8443');      // 'auth.example.com'
 * normaliseRealmHost('Bücher.example.');           // 'xn--bcher-kva.example'
 * normaliseRealmHost('[::1]:3000', 'endpoint');    // '[::1]'
 * normaliseRealmHost('127.0.0.1', 'primary');      // throws (ip_literal)
 * normaliseRealmHost('*.example.com');             // throws (wildcard)
 * ```
 */
export function normaliseRealmHost(input: string, kind?: RealmHostKind): string {
  if (typeof input !== 'string' || input.length === 0) {
    throw new InvalidRealmHostError('empty', 'Realm host is empty');
  }
  if (/\s/u.test(input)) {
    throw new InvalidRealmHostError('whitespace', `Realm host "${input}" contains white space`);
  }
  if (input.includes('*')) {
    throw new InvalidRealmHostError(
      'wildcard',
      `Realm host "${input}" is a wildcard; a realm owns exact hosts only`
    );
  }

  if (NON_HOST_CHARACTERS.test(input)) {
    throw new InvalidRealmHostError('malformed', `Realm host "${input}" is not a bare host`);
  }

  const { host: rawHost, port } = splitPort(input);
  if (port !== '') {
    const match = PORT.exec(port);
    if (!match || Number(match[1]) > 65535) {
      throw new InvalidRealmHostError('invalid_port', `Realm host "${input}" has an invalid port`);
    }
  }

  const bracketed = rawHost.startsWith('[');
  if (!bracketed && /[[\]]/.test(rawHost)) {
    throw new InvalidRealmHostError('malformed', `Realm host "${input}" is not a bare host`);
  }
  if (rawHost.length === 0) {
    throw new InvalidRealmHostError('empty', `Realm host "${input}" has no host`);
  }

  let host: string;
  try {
    host = new URL(`http://${rawHost}/`).hostname;
  } catch {
    throw new InvalidRealmHostError('malformed', `Realm host "${input}" is not a valid host`);
  }

  // After the IDNA step, so a trailing ideographic full stop counts as a dot.
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (host.length === 0) {
    throw new InvalidRealmHostError('empty', `Realm host "${input}" has no host`);
  }
  if (host.length > REALM_HOST_MAX_LENGTH) {
    throw new InvalidRealmHostError(
      'too_long',
      `Realm host "${input}" is longer than ${REALM_HOST_MAX_LENGTH} characters`
    );
  }

  const ipLiteral = bracketed
    ? ipv6Schema.safeParse(host.slice(1, -1)).success
    : ipv4Schema.safeParse(host).success;
  if (bracketed && !ipLiteral) {
    throw new InvalidRealmHostError(
      'malformed',
      `Realm host "${input}" is not a valid IPv6 address`
    );
  }

  if (!ipLiteral) {
    for (const label of host.split('.')) {
      if (label.length === 0) {
        throw new InvalidRealmHostError('empty_label', `Realm host "${input}" has an empty label`);
      }
      if (label.length > REALM_HOST_MAX_LABEL_LENGTH || !LABEL.test(label)) {
        throw new InvalidRealmHostError(
          'malformed',
          `Realm host "${input}" has an invalid label "${label}"`
        );
      }
    }
  }

  if (ipLiteral && kind === 'primary') {
    throw new InvalidRealmHostError(
      'ip_literal',
      `Realm host "${input}" is an IP address; a primary host must be a name, because a passkey RP ID cannot be an IP address`
    );
  }

  return host;
}
