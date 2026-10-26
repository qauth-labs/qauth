import type { EgressSource } from '@qauth-labs/fastify-plugin-egress';
import type { FastifyInstance } from 'fastify';

/**
 * A GET of one small JSON document through the egress client
 * (`fastify.egress`, ADR-019 Decision 8, #481), as the CIMD, client JWKS and
 * ID-JAG issuer fetches make it.
 *
 * The egress client checks everything about the destination: `https` only, no
 * credentials, every address of the host public unless the deployment
 * allowlist opens it for an `operator` or `admin` destination of the realm,
 * the connection pinned to the checked addresses. This helper adds the shape
 * these callers share: no redirect is followed (a 3xx with a `Location` is
 * refused as a `redirect`), the whole fetch has one deadline, and the body is
 * capped and read as UTF-8.
 */

export interface EgressGetOptions {
  /** What the fetch is for, such as `cimd`: a fixed label for counts and logs. */
  readonly purpose: string;
  /** Who set the URL; only `operator` and `admin` may use the allowlist. */
  readonly source: EgressSource;
  /** The realm the URL belongs to, by name. */
  readonly realm?: string;
  /** Deadline for the whole fetch, in milliseconds. */
  readonly timeoutMs: number;
  /** Largest response body, in bytes. */
  readonly maxBytes: number;
}

export interface EgressGetResult {
  status: number;
  /** The body, decoded as UTF-8. */
  body: string;
  /** Lower-case names; a repeated header's values joined with `, `. */
  headers: Record<string, string>;
}

/** The connect timeout of the egress client's defaults; a shorter deadline lowers it. */
const CONNECT_TIMEOUT_MS = 5000;

/**
 * GET `url` through the egress client. Resolves with the response whatever its
 * status; rejects with an `EgressError` when a check refuses the fetch
 * (`outcome: 'blocked'`) or the fetch fails (`outcome: 'failed'`).
 */
export async function egressGet(
  fastify: FastifyInstance,
  url: string,
  options: EgressGetOptions
): Promise<EgressGetResult> {
  const response = await fastify.egress.request({
    method: 'GET',
    url,
    headers: { accept: 'application/json' },
    purpose: options.purpose,
    source: options.source,
    ...(options.realm === undefined ? {} : { realm: options.realm }),
    limits: {
      totalTimeoutMs: options.timeoutMs,
      connectTimeoutMs: Math.min(options.timeoutMs, CONNECT_TIMEOUT_MS),
      maxResponseBytes: options.maxBytes,
      maxRedirects: 0,
    },
  });
  return {
    status: response.status,
    body: response.body.toString('utf8'),
    headers: response.headers,
  };
}
