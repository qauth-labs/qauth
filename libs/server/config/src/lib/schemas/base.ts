import { isIP } from 'node:net';

import { z } from 'zod';

/** The named ranges `proxy-addr` (Fastify's `trustProxy`) understands. */
const TRUST_PROXY_NAMED_RANGES = new Set(['loopback', 'linklocal', 'uniquelocal']);

/** One `TRUST_PROXY` list entry: a named range, an IP address, or IP/prefix CIDR. */
function isTrustProxyEntry(entry: string): boolean {
  if (TRUST_PROXY_NAMED_RANGES.has(entry)) return true;
  const [address, prefix, ...rest] = entry.split('/');
  if (rest.length > 0) return false;
  const family = isIP(address);
  if (family === 0) return false;
  if (prefix === undefined) return true;
  if (!/^\d{1,3}$/.test(prefix)) return false;
  return Number(prefix) <= (family === 4 ? 32 : 128);
}

/**
 * Parse `TRUST_PROXY` into a Fastify `trustProxy` value.
 *
 * - unset, empty or `false` (default) → `false`: no proxy is trusted and
 *   `request.ip` is the TCP peer.
 * - a comma-separated list of IP addresses, CIDR ranges and/or the named
 *   ranges `loopback`, `linklocal`, `uniquelocal` → that list: trust exactly
 *   those peers.
 *
 * `true` is REJECTED: it trusts every hop, so any caller could choose its own
 * `request.ip` with an `X-Forwarded-For` header and escape every per-IP limit
 * and lockout. A hop COUNT is rejected too: it cannot tell a proxy from a
 * direct client, so Fastify ignores it (fails closed) — which would leave the
 * operator believing a proxy is trusted when none is.
 */
export function parseTrustProxy(raw: string | undefined, ctx: z.RefinementCtx): false | string[] {
  const value = raw?.trim() ?? '';
  if (value === '' || value === 'false') return false;
  if (value === 'true') {
    ctx.addIssue({
      code: 'custom',
      message:
        'TRUST_PROXY=true would trust every X-Forwarded-For hop, letting any caller pick its own client IP. Set the proxy addresses/CIDRs (e.g. 10.0.0.0/8) instead.',
    });
    return z.NEVER;
  }
  if (/^\d+$/.test(value)) {
    ctx.addIssue({
      code: 'custom',
      message:
        'TRUST_PROXY takes the proxy addresses/CIDRs (e.g. 10.0.0.0/8), not a hop count: a count cannot tell a proxy from a direct client, and Fastify ignores it.',
    });
    return z.NEVER;
  }
  const entries = value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  const invalid = entries.filter((entry) => !isTrustProxyEntry(entry));
  if (invalid.length > 0) {
    ctx.addIssue({
      code: 'custom',
      message: `TRUST_PROXY entries must be IP addresses, CIDR ranges or loopback/linklocal/uniquelocal; invalid: ${invalid.join(', ')}`,
    });
    return z.NEVER;
  }
  return entries;
}

/**
 * Base server environment configuration schema
 * Common settings for all server applications
 */
export const baseEnvSchema = z.object({
  /**
   * Node environment
   */
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  /**
   * Server host address
   */
  HOST: z.string().default('0.0.0.0'),

  /**
   * Server port number
   */
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),

  /**
   * Which reverse proxies' `X-Forwarded-For` hops to trust when deriving the
   * client address (`request.ip`). Every per-IP rate limit and the failed-login
   * lockout key on that address, so behind a proxy with this unset, every
   * caller shares the proxy's address and one bucket. See
   * {@link parseTrustProxy} for the accepted forms; `true` is rejected.
   */
  TRUST_PROXY: z.string().optional().transform(parseTrustProxy),

  /**
   * Logging level
   */
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  /**
   * Vitest test environment flag
   */
  VITEST: z.string().optional(),
});

/**
 * Base environment configuration type
 */
export type BaseEnv = z.infer<typeof baseEnvSchema>;
