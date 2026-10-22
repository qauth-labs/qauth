import type { LookupAddress } from 'node:dns';
import { isIP } from 'node:net';

import { addressKind } from './address';
import { EgressFailure } from './errors';

/** A URL that passed the checks that need no network. */
export interface CheckedUrl {
  readonly url: URL;
  /**
   * The host to resolve, to name in SNI and to check the certificate against:
   * lower-case, without IPv6 brackets or a trailing dot.
   */
  readonly hostname: string;
  readonly port: number;
  /** The IP family when the host is an IP literal, else `0`. */
  readonly literalFamily: 0 | 4 | 6;
}

/** Resolves a host name to every A and AAAA address it has. */
export type ResolveHost = (
  hostname: string,
  options: { timeoutMs: number; signal: AbortSignal }
) => Promise<LookupAddress[]>;

/** A URL's host name without IPv6 brackets or a trailing dot, in lower case. */
function normalizeHostname(hostname: string): string {
  return hostname
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '')
    .toLowerCase();
}

/**
 * The host of `url` for errors and logs, or `undefined` when there is none.
 * Never the path, the query string or the user name.
 */
export function hostForLog(url: string | URL): string | undefined {
  try {
    const host = normalizeHostname((typeof url === 'string' ? new URL(url) : url).hostname);
    return host === '' ? undefined : host;
  } catch {
    return undefined;
  }
}

/**
 * The checks of a destination that need no network: an `https` URL, without
 * credentials, whose host — when it is an IP literal — is public. The WHATWG
 * URL parser has already turned the other IPv4 spellings (`0x7f.1`,
 * `2130706433`) into dotted quads.
 */
export function checkUrl(input: string | URL): CheckedUrl {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new EgressFailure('scheme', 'blocked', 'egress refused: not a valid URL');
  }
  if (url.protocol !== 'https:') {
    throw new EgressFailure(
      'scheme',
      'blocked',
      `egress${url.hostname ? ` to ${url.hostname}` : ''} refused: only https is allowed`
    );
  }
  if (url.username !== '' || url.password !== '') {
    throw new EgressFailure(
      'credentials',
      'blocked',
      `egress to ${url.hostname} refused: the URL carries credentials`
    );
  }

  const hostname = normalizeHostname(url.hostname);
  const family = isIP(hostname);
  const literalFamily = family === 4 || family === 6 ? family : 0;
  if (literalFamily !== 0) {
    const kind = addressKind(hostname);
    if (kind !== 'public') {
      throw new EgressFailure(
        'address',
        'blocked',
        `egress to ${hostname} refused: it is a ${kind} address`
      );
    }
  }
  return { url, hostname, port: url.port === '' ? 443 : Number(url.port), literalFamily };
}

/**
 * Every address of the checked URL's host, each of them public. An IP literal
 * is its own address. A name is resolved once, and the whole name is refused
 * when any of its addresses is not public: the client would otherwise dial
 * whichever one the connection happened to pick.
 */
export async function resolveCheckedAddresses(
  target: CheckedUrl,
  resolveHost: ResolveHost,
  options: { timeoutMs: number; signal: AbortSignal }
): Promise<LookupAddress[]> {
  if (target.literalFamily !== 0) {
    return [{ address: target.hostname, family: target.literalFamily }];
  }

  let addresses: LookupAddress[];
  try {
    addresses = await resolveHost(target.hostname, options);
  } catch (err) {
    if (err instanceof EgressFailure) throw err;
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    throw new EgressFailure(
      'network',
      'failed',
      `egress to ${target.hostname} failed: the name did not resolve${code ? ` (${code})` : ''}`
    );
  }
  if (addresses.length === 0) {
    throw new EgressFailure(
      'network',
      'failed',
      `egress to ${target.hostname} failed: the name has no addresses`
    );
  }
  for (const { address } of addresses) {
    const kind = addressKind(address);
    if (kind !== 'public') {
      throw new EgressFailure(
        'address',
        'blocked',
        `egress to ${target.hostname} refused: it resolves to a ${kind} address`
      );
    }
  }
  return addresses;
}
