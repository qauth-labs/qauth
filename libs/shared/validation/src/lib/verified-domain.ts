/**
 * A client's verified domain (ADR-019 Decision 6, issue #593).
 *
 * Every screen that names a client leads with what the auth server verified
 * about it, never with what the client says about itself. For a client an
 * admin registered, that is the domain the admin set on it:
 * `oauth_clients.verified_domain`. Setting it is an admin operation
 * (`clients.update`, `qauth:admin:security`, ADR-019 Decision 7); until the
 * admin API ships it is the operator's `db:seed-oauth-clients` manifest.
 *
 * The stored form is the one the screens show: a DNS name of at least two
 * labels, lower case, in its ASCII (punycode) form, with no port, no trailing
 * dot and no IP address. {@link VERIFIED_DOMAIN_PATTERN} is that form; the
 * database checks it (`oauth_clients_verified_domain_form`) and the display
 * code checks it again before it shows a stored value, so a value written by
 * hand can never reach a screen in any other form.
 */
import { InvalidRealmHostError, normaliseRealmHost } from './realm-host';

/** Longest DNS name in ASCII, without the trailing dot (RFC 1035 §2.3.4). */
export const VERIFIED_DOMAIN_MAX_LENGTH = 253;

/**
 * The stored form: two or more labels of lower-case letters, digits and
 * inner hyphens, each 1–63 characters, the last one starting with a letter
 * (so an IPv4 address never matches). The same expression is the database's
 * CHECK, which reads it as a POSIX regular expression, so it uses only syntax
 * both read.
 */
export const VERIFIED_DOMAIN_PATTERN =
  '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$';

const VERIFIED_DOMAIN = new RegExp(VERIFIED_DOMAIN_PATTERN);

/**
 * Why {@link normaliseVerifiedDomain} refused a value.
 *
 * - `malformed` — not a bare DNS name: a port, a path, a wildcard, an empty
 *   label, an underscore, a value the IDNA step rejects, or a name that is not
 *   in the stored form once converted.
 * - `ip_literal` — an IPv4 or IPv6 address. A screen shows a domain, and no
 *   one but the address's network vouches for an address.
 * - `single_label` — one label only (`localhost`, `intranet`): no registrable
 *   domain can be shown for it.
 * - `too_long` — over {@link VERIFIED_DOMAIN_MAX_LENGTH} characters in ASCII.
 */
export type InvalidVerifiedDomainReason = 'malformed' | 'ip_literal' | 'single_label' | 'too_long';

/**
 * Thrown by {@link normaliseVerifiedDomain}. The message is fixed text and
 * never repeats the value; the value is on {@link input} for an operator log.
 */
export class InvalidVerifiedDomainError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_VERIFIED_DOMAIN';

  /**
   * @param reason - why the value was refused.
   * @param message - fixed text that names no part of the value.
   * @param input - the refused value, as given.
   */
  constructor(
    public readonly reason: InvalidVerifiedDomainReason,
    message: string,
    public readonly input: string
  ) {
    super(message);
    this.name = 'InvalidVerifiedDomainError';
    Object.setPrototypeOf(this, InvalidVerifiedDomainError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidVerifiedDomainError);
    }
  }
}

/**
 * True when `value` is a verified domain in its stored form. The display code
 * calls this on every stored value, so a row written by hand in another form
 * reads as no verified domain at all.
 */
export function isVerifiedDomain(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= VERIFIED_DOMAIN_MAX_LENGTH &&
    VERIFIED_DOMAIN.test(value)
  );
}

/**
 * Normalise a domain an admin sets on a client to its stored form: lower
 * case, ASCII (an internationalised name becomes its `xn--` labels, as a
 * browser converts it), no trailing dot.
 *
 * @param input - the domain as the admin wrote it, Unicode or ASCII.
 * @returns the stored form.
 * @throws InvalidVerifiedDomainError when the value is not a DNS name of at
 * least two labels.
 *
 * @example
 * ```typescript
 * normaliseVerifiedDomain('App.Example.com');   // 'app.example.com'
 * normaliseVerifiedDomain('bücher.example');    // 'xn--bcher-kva.example'
 * normaliseVerifiedDomain('example.com:443');   // throws (malformed)
 * normaliseVerifiedDomain('192.0.2.1');         // throws (ip_literal)
 * ```
 */
export function normaliseVerifiedDomain(input: string): string {
  if (typeof input !== 'string') {
    throw new InvalidVerifiedDomainError(
      'malformed',
      'Verified domain is not a string',
      String(input)
    );
  }
  // A port and an underscore pass the realm-host rules (an endpoint host may
  // carry either); a verified domain carries neither.
  if (input.includes(':') && !input.startsWith('[')) {
    throw new InvalidVerifiedDomainError('malformed', 'Verified domain has a port', input);
  }
  if (input.includes('_')) {
    throw new InvalidVerifiedDomainError('malformed', 'Verified domain has an underscore', input);
  }

  let host: string;
  try {
    host = normaliseRealmHost(input, 'primary');
  } catch (error) {
    if (error instanceof InvalidRealmHostError) {
      if (error.reason === 'ip_literal') {
        throw new InvalidVerifiedDomainError(
          'ip_literal',
          'Verified domain is an IP address',
          input
        );
      }
      if (error.reason === 'too_long') {
        throw new InvalidVerifiedDomainError('too_long', 'Verified domain is too long', input);
      }
      throw new InvalidVerifiedDomainError('malformed', 'Verified domain is not a host', input);
    }
    throw error;
  }

  if (!host.includes('.')) {
    throw new InvalidVerifiedDomainError(
      'single_label',
      'Verified domain has a single label',
      input
    );
  }
  if (!isVerifiedDomain(host)) {
    throw new InvalidVerifiedDomainError(
      'malformed',
      'Verified domain is not a DNS name in ASCII form',
      input
    );
  }
  return host;
}
