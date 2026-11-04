import { z } from 'zod';

import { isAddressOrCidr } from './base';

/**
 * Parse `CEREMONY_APP_PEERS` (#982): a comma-separated list of IP addresses
 * and CIDR ranges, in the form `TRUST_PROXY` takes them, without its named
 * ranges (`loopback`, `linklocal`, `uniquelocal`), which would list every
 * private address rather than one server's, and without a zone id, which the
 * match could not honour. Unset or empty gives the empty list: no address is
 * a listed peer.
 */
export function parseCeremonyAppPeers(
  raw: string | undefined,
  ctx: z.RefinementCtx
): readonly string[] {
  const entries = (raw ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  const invalid = entries.filter((entry) => entry.includes('%') || !isAddressOrCidr(entry));
  if (invalid.length > 0) {
    ctx.addIssue({
      code: 'custom',
      message: `CEREMONY_APP_PEERS entries must be IP addresses or CIDR ranges without a zone id, such as 10.0.4.12 or 10.0.4.0/28; invalid: ${invalid.join(', ')}`,
    });
    return z.NEVER;
  }
  return Object.freeze(entries);
}

/**
 * Rate limiting environment configuration schema
 * Global rate limiting settings
 */
export const rateLimitEnvSchema = z.object({
  /**
   * Enable or disable rate limiting globally
   * Set to false to disable rate limiting (useful for development/testing)
   */
  RATE_LIMIT_ENABLED: z
    .enum(['true', 'false', '1', '0'])
    .default('true')
    .transform((val) => val === 'true' || val === '1'),

  /**
   * Maximum requests per window
   */
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(100),

  /**
   * Rate limit window in seconds
   */
  RATE_LIMIT_WINDOW: z.coerce.number().int().min(1).default(3600),

  /**
   * Health endpoint maximum requests per window
   * Health checks are typically more frequent, so higher limit
   */
  HEALTH_RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(1000),

  /**
   * Health endpoint rate limit window in seconds
   */
  HEALTH_RATE_LIMIT_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * The ceremony app server's egress addresses (ADR-019 Decision 6, #982).
   *
   * The ceremony app's server reads the current step of the Interaction API
   * (`GET /interaction/v1-rc.0/{interactionId}`) for every browser. A step
   * read whose TCP peer (`request.ip`; no other forwarded header is read for
   * it) is on this list counts per interaction, under
   * `CEREMONY_APP_PEER_RATE_LIMIT`; every other step read counts per realm
   * and address, at the authorization endpoint's budget.
   *
   * Empty by default, so no address is listed. A deployment whose ceremony
   * app reads the step from its server must list that server's addresses
   * here, or every person signing in shares the server's one address bucket.
   * Set together with `CEREMONY_APP_PEER_RATE_LIMIT`
   * ({@link ceremonyAppPeerProblems}).
   */
  CEREMONY_APP_PEERS: z.string().optional().transform(parseCeremonyAppPeers),

  /**
   * The step reads a listed ceremony app peer may make of one interaction per
   * minute (#982). No default: set together with `CEREMONY_APP_PEERS`.
   */
  CEREMONY_APP_PEER_RATE_LIMIT: z.coerce.number().int().min(1).optional(),
});

/**
 * Rate limit environment configuration type
 */
export type RateLimitEnv = z.infer<typeof rateLimitEnvSchema>;

/** The variables {@link ceremonyAppPeerProblems} reads. */
export interface CeremonyAppPeerEnv {
  readonly CEREMONY_APP_PEERS: readonly string[];
  readonly CEREMONY_APP_PEER_RATE_LIMIT?: number | undefined;
}

/** A refusal of the ceremony app peer settings, naming the variable to set. */
export interface CeremonyAppPeerProblem {
  readonly variable: 'CEREMONY_APP_PEERS' | 'CEREMONY_APP_PEER_RATE_LIMIT';
  readonly message: string;
}

/**
 * The refusal of a boot that sets one of `CEREMONY_APP_PEERS` and
 * `CEREMONY_APP_PEER_RATE_LIMIT` without the other (#982), as ADR-017
 * Decision 7 has `FIRST_PARTY_BACKEND_PEERS` and its cap set together. A list
 * without a cap leaves its peers no budget, and a cap without a list applies
 * to no address, while the operator believes the ceremony app's server is
 * listed. An empty list counts as unset.
 */
export function ceremonyAppPeerProblems(env: CeremonyAppPeerEnv): CeremonyAppPeerProblem[] {
  const listed = env.CEREMONY_APP_PEERS.length > 0;
  const capped = env.CEREMONY_APP_PEER_RATE_LIMIT !== undefined;
  if (listed === capped) return [];
  const set = listed ? 'CEREMONY_APP_PEERS' : 'CEREMONY_APP_PEER_RATE_LIMIT';
  const unset = listed ? 'CEREMONY_APP_PEER_RATE_LIMIT' : 'CEREMONY_APP_PEERS';
  return [
    {
      variable: unset,
      message: `CEREMONY_APP_PEERS and CEREMONY_APP_PEER_RATE_LIMIT are set together, and only ${set} is set: CEREMONY_APP_PEERS lists the ceremony app server's addresses, and CEREMONY_APP_PEER_RATE_LIMIT is the step reads each may make of one interaction per minute. Set ${unset} too, or neither.`,
    },
  ];
}
