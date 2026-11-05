import {
  createRedisRoundLimits,
  createRoundLimiter,
  type RoundEnvironment,
  type RoundLimitAlertEvent,
  type RoundLimiter,
  roundLimitPolicy,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { parseEnvironment, resolveEnvironmentPolicy } from './environment-policy';
import { createServerDigests } from './password-attempts';
import type { RealmRow } from './request-realm';

/**
 * The sign-in engine's round limits in this process (PRO-13, #636; ADR-017
 * Decision 7): per end-user IP, per IP bucket and, on the FiPA endpoint,
 * per client, around the per-account ladder, counted in Redis.
 */

/**
 * The message of the operator's alert when a round limit's threshold is
 * crossed: an end-user IP blocked, a bucket failing for too many distinct
 * identifiers, or a client over its failure ratio, failure budget or rounds a
 * minute. The log line names the realm, the alert and the key it concerns:
 * an end-user IP or bucket by its keyed HMAC, never the address.
 */
export const ROUND_LIMIT_ALERT = 'a sign-in round limit was crossed';

/** Tell the operator of a round limit's alert, as an `error` log line. */
export function logRoundLimitAlert(log: FastifyBaseLogger, alert: RoundLimitAlertEvent): void {
  log.error({ ...alert }, ROUND_LIMIT_ALERT);
}

/**
 * The round limiter of this process over its Redis, its end-user IPs keyed
 * by the same HMAC as the failure ladder's and the send caps'. The per-IP
 * registration cap is `REGISTRATION_RATE_LIMIT` per
 * `REGISTRATION_RATE_WINDOW`; every other number is ADR-017 Decision 7's.
 *
 * `perClient` turns the client row on: the FiPA endpoint's authenticated
 * client (#646). The Interaction API's client is not authenticated, so its
 * rounds meet the IP rows only.
 */
export function createServerRoundLimiter(
  fastify: FastifyInstance,
  options: { readonly perClient: boolean }
): RoundLimiter {
  const { ipDigest } = createServerDigests(fastify);
  const store = createRedisRoundLimits(fastify.redis, {
    policy: roundLimitPolicy({
      registrationPerIp: {
        limit: env.REGISTRATION_RATE_LIMIT,
        windowMs: env.REGISTRATION_RATE_WINDOW * 1_000,
      },
    }),
  });
  return createRoundLimiter(store, {
    ipDigest,
    perClient: options.perClient,
    onAlert: (alert) => logRoundLimitAlert(fastify.log, alert),
  });
}

/**
 * The environment whose round limits a round of `clientId` meets (ADR-008
 * §5 and §7): the stricter of the client's and the realm's ceiling.
 * `development` relaxes them; `staging` keeps production values.
 *
 * A realm whose ceiling is `production`, every realm's default, reads no
 * client. A client that cannot be read, or none, is `production`: the
 * relaxed limits are never a fallback.
 */
export async function roundEnvironment(
  fastify: FastifyInstance,
  realm: RealmRow,
  clientId: string
): Promise<RoundEnvironment> {
  if (parseEnvironment(realm.maxEnvironmentLaxity) === 'production') return 'production';
  try {
    const client = await fastify.repositories.oauthClients.findByClientId(realm.id, clientId);
    return resolveEnvironmentPolicy(client ?? null, realm).environment;
  } catch (error) {
    fastify.log.warn(
      { err: error, realmId: realm.id },
      'round limits: the client could not be read; its rounds meet production limits'
    );
    return 'production';
  }
}
