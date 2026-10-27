import type { LookupAddress } from 'node:dns';
import { lookup, Resolver } from 'node:dns/promises';

import type { ResolveHost } from './destination';
import { dialPinned, exchange, type ExchangeJob, type ExchangeOutcome } from './exchange';
import { sharedProcessPool } from './process-pool';

/**
 * Runs one exchange with checked addresses (`exchange.ts`). Never rejects;
 * `signal` aborts it when the call's total time runs out.
 */
export type RunExchange = (job: ExchangeJob, signal: AbortSignal) => Promise<ExchangeOutcome>;

/** What the client needs from the network. Tests replace both. */
export interface EgressTransport {
  readonly resolveHost: ResolveHost;
  readonly exchange: RunExchange;
}

/**
 * Per-query bounds of the c-ares resolver: how long one query waits for an
 * answer, and how often it is sent. The call's deadline cancels what is left.
 */
const DNS_QUERY_TIMEOUT_MS = 2000;
const DNS_QUERY_TRIES = 2;

/**
 * Every A and AAAA record of `hostname`, from c-ares, never from
 * `dns.lookup()`. That one is a blocking getaddrinfo(3) on the libuv thread
 * pool, which the whole process shares, and nothing cancels it: a name server
 * that never answers would hold those threads past every deadline. c-ares
 * queries run on the event loop, each with its own timeout, and the call's
 * signal cancels them. It also reads neither `/etc/hosts` nor any other local
 * source, only DNS. One family failing (a v4-only host has no AAAA) is not an
 * error as long as the other one answered.
 */
export const resolveWithCares: ResolveHost = async (hostname, { timeoutMs, signal }) => {
  const resolver = new Resolver({
    timeout: Math.min(DNS_QUERY_TIMEOUT_MS, timeoutMs),
    tries: DNS_QUERY_TRIES,
  });
  const cancel = (): void => resolver.cancel();
  signal.addEventListener('abort', cancel, { once: true });
  try {
    const [a, aaaa] = await Promise.allSettled([
      resolver.resolve4(hostname),
      resolver.resolve6(hostname),
    ]);
    const addresses: LookupAddress[] = [];
    if (a.status === 'fulfilled') {
      addresses.push(...a.value.map((address) => ({ address, family: 4 })));
    }
    if (aaaa.status === 'fulfilled') {
      addresses.push(...aaaa.value.map((address) => ({ address, family: 6 })));
    }
    if (addresses.length === 0 && a.status === 'rejected') throw a.reason;
    return addresses;
  } finally {
    signal.removeEventListener('abort', cancel);
  }
};

/**
 * The network the client uses outside tests. Names resolve here, with c-ares
 * on the event loop; every exchange runs in the shared pool of fetch processes
 * (`process-pool.ts`), so no TLS handshake with a destination happens in the
 * server's process.
 */
export const NODE_TRANSPORT: EgressTransport = Object.freeze({
  resolveHost: resolveWithCares,
  exchange: (job: ExchangeJob, signal: AbortSignal) => sharedProcessPool().exchange(job, signal),
});

/**
 * TEST SUPPORT — the network of `createTestEgressClient` (`egress-client.ts`),
 * which exists only while `NODE_ENV` is `test`. Names resolve with the
 * operating system's resolver, `/etc/hosts` included, so a fixture server's
 * `localhost` resolves; each exchange runs in the test's process, over a
 * connection to a checked address, as a fetch process would run it.
 *
 * IPv4 addresses come first, so that `localhost` is dialled at `127.0.0.1`,
 * where a fixture listens, before `::1`. Node 26.10 crashes the process when
 * TLS starts on a socket whose first address refused the connection and that
 * moved on to the next one.
 */
export const LOCAL_TEST_TRANSPORT: EgressTransport = Object.freeze({
  resolveHost: async (hostname: string): Promise<LookupAddress[]> =>
    lookup(hostname, { all: true, order: 'ipv4first' }),
  exchange: (job: ExchangeJob, signal: AbortSignal) => exchange(job, dialPinned, signal),
});
