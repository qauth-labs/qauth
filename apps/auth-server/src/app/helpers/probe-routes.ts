import { SERVICE_ROLE_NAMES } from '@qauth-labs/server-config';
import { TooManyRequestsError } from '@qauth-labs/shared-errors';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { clientAddressKey } from './client-address';
import { createProcessRateLimit } from './process-rate-limit';

/**
 * What `/health` and `/ready` share (issue #500): their rate limit, their
 * headers and the roles they name.
 *
 * Both answer on any host (`config.surface: 'none'`, ADR-019 Decision 1) and
 * carry no realm data: no realm is resolved for them, and what they say is
 * about the process, never about a realm.
 */

/** The service roles a process runs, as `/health` and `/ready` list them. */
export const serviceRolesSchema = z
  .array(z.enum(SERVICE_ROLE_NAMES))
  .describe('The service roles this process runs (`SERVICE_ROLES`).');

/** The rate limit of one probe route: HEALTH_RATE_LIMIT_MAX per HEALTH_RATE_LIMIT_WINDOW seconds. */
export interface ProbeRateLimitSettings {
  readonly max: number;
  readonly windowSeconds: number;
  /** RATE_LIMIT_ENABLED: off, the probe counts nothing, as no other route does. */
  readonly enabled: boolean;
}

/**
 * An `onRequest` hook that limits a probe route per client address, in the
 * process's memory rather than in Redis (`process-rate-limit.ts`): a probe
 * answers while Redis does not. It sets the `x-ratelimit-*` headers the
 * app's other limits set, and refuses a caller over the limit with a 429
 * problem document and `Retry-After`. The route sets `config.rateLimit:
 * false`, so the Redis-backed limiter does not count it too.
 */
export function probeRateLimitHook(
  settings: ProbeRateLimitSettings
): (request: FastifyRequest, reply: FastifyReply) => Promise<void> {
  if (!settings.enabled) return async () => undefined;
  const limit = createProcessRateLimit({
    max: settings.max,
    windowMs: settings.windowSeconds * 1000,
  });
  return async (request, reply) => {
    const decision = limit(clientAddressKey(request));
    reply
      .header('x-ratelimit-limit', decision.limit)
      .header('x-ratelimit-remaining', decision.remaining)
      .header('x-ratelimit-reset', decision.resetSeconds);
    if (!decision.allowed) {
      reply.header('retry-after', decision.resetSeconds);
      throw new TooManyRequestsError(
        `Rate limit exceeded, retry in ${decision.resetSeconds} seconds`
      );
    }
  };
}

/** A probe's answer is about this moment: never stored by a cache. */
export function noStore(reply: FastifyReply): FastifyReply {
  return reply.header('cache-control', 'no-store');
}
