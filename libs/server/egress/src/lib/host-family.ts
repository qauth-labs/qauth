import { getDomain } from 'tldts';

import { parseIpv6 } from './address';

/**
 * The family a destination host belongs to: the hosts one party can name at
 * no cost, which the pool lets hold only a few fetch processes at once.
 *
 * - A host name counts under its registrable domain, the name below its public
 *   suffix: `a.example.com` and `b.example.com` are one family, `example.com`.
 *   The private section of the Public Suffix List counts too, so
 *   `alice.eu.org` and `bob.eu.org` are two families, as their owners
 *   are two parties. A name that is itself a public suffix is its own family.
 * - An IPv4 literal is its own family.
 * - An IPv6 literal counts under its /64, the smallest network a site is
 *   given, inside which it can use any address.
 *
 * `hostname` is lower-case, without IPv6 brackets or a trailing dot, as
 * `checkUrl` returns it.
 */
export function hostFamily(hostname: string, literalFamily: 0 | 4 | 6): string {
  if (literalFamily === 4) return hostname;
  if (literalFamily === 6) {
    const bytes = parseIpv6(hostname);
    if (bytes === null) return hostname;
    const hextets: string[] = [];
    for (let i = 0; i < 8; i += 2) hextets.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    return `${hextets.join(':')}::/64`;
  }
  return getDomain(hostname, { allowPrivateDomains: true, extractHostname: false }) ?? hostname;
}
