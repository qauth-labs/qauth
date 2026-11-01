import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';

import { isCloudMetadataAddress, isPublicUnicastAddress } from '@qauth-labs/server-egress';
import { normalizeSmtpHost, smtpHostRefusal } from '@qauth-labs/server-realm-policy';

/** The mail rule's own host checks, for the plugin that reads the operator's list. */
export { normalizeSmtpHost, smtpHostRefusal };

/**
 * Where a realm's smtp transport may connect, and how (#529, from the review
 * of #937). A realm admin sets the SMTP host, so the host is checked as any
 * destination a realm admin sets (ADR-019 Decision 8): the transport connects
 * only to a public unicast address unless the operator allows the host, never
 * to a cloud metadata address, and a connection without TLS only when the
 * operator allows it. Both switches are the operator's, from the environment:
 * no realm policy can turn either on.
 */
export interface SmtpConnectionPolicy {
  /**
   * `SMTP_ALLOW_PLAINTEXT`: let a transport with `mail.smtp.secure` off send
   * over a connection the server does not upgrade with STARTTLS. Off, such a
   * transport requires STARTTLS (`requireTLS`), with the certificate checked.
   */
  readonly allowPlaintext: boolean;
  /**
   * `SMTP_ALLOWED_HOSTS`, as `normalizeSmtpHost` writes them: the hosts
   * a transport may reach although they are not public (`localhost`, a
   * private, loopback, link-local or unique-local address, or a name that
   * resolves to one). A cloud metadata address is never reachable.
   */
  readonly allowedHosts: ReadonlySet<string>;
  /** Resolves a host name to its addresses; `dns.lookup` with `all` unless a test passes its own. */
  readonly lookup?: (hostname: string) => Promise<readonly { readonly address: string }[]>;
}

/** The policy with no operator switch on: TLS required, public addresses only. */
export const STRICT_SMTP_CONNECTION_POLICY: SmtpConnectionPolicy = Object.freeze({
  allowPlaintext: false,
  allowedHosts: new Set<string>(),
});

/** A destination the policy refuses. The message names the host, never a credential. */
export class SmtpDestinationRefusedError extends Error {
  override readonly name = 'SmtpDestinationRefusedError';
}

/** The address a transport connects to, and the name its TLS certificate is checked against. */
export interface SmtpDestination {
  /** The IP address the connection dials: the one that was checked. */
  readonly address: string;
  /** The host name for SNI and the certificate check, or `undefined` for an IP literal host. */
  readonly servername: string | undefined;
}

/**
 * The address the smtp transport of `host` connects to: `host` itself when
 * it is an IP literal, or the first address it resolves to that the policy
 * lets it reach. The connection then dials that address, with the host name
 * as its TLS server name, so DNS cannot answer one address to the check and
 * another to the connection.
 *
 * @throws SmtpDestinationRefusedError when the host is refused, or resolves
 *   to no address the policy lets it reach
 */
export async function resolveSmtpDestination(
  host: string,
  policy: SmtpConnectionPolicy
): Promise<SmtpDestination> {
  const normalized = normalizeSmtpHost(host);
  const refusal = smtpHostRefusal(normalized, policy.allowedHosts);
  if (refusal !== undefined) {
    throw new SmtpDestinationRefusedError(`The SMTP host ${normalized} is refused: it ${refusal}`);
  }
  if (isIP(normalized) !== 0) return { address: normalized, servername: undefined };

  const lookup =
    policy.lookup ??
    (async (hostname: string) => dnsLookup(hostname, { all: true, verbatim: true }));
  const addresses = await lookup(normalized);
  const allowed = policy.allowedHosts.has(normalized);
  const usable = addresses.find(
    ({ address }) =>
      !isCloudMetadataAddress(address) && (isPublicUnicastAddress(address) || allowed)
  );
  if (usable === undefined) {
    throw new SmtpDestinationRefusedError(
      `The SMTP host ${normalized} is refused: it resolves to no public address, and SMTP_ALLOWED_HOSTS does not name it`
    );
  }
  return { address: usable.address, servername: normalized };
}
