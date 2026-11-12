import {
  SIGN_IN_TRANSACTION_CLOCK_SKEW_MS,
  SIGN_IN_TRANSACTION_MAX_AGE_MS,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { REDIS_KEYS } from '../constants/redis-keys';
import { NOT_VALID_BEFORE_MARGIN_MS } from './account-validity';
import { isClientUsable } from './client-status';

/**
 * THE OWNER'S PASSWORD RESET (#642; ADR-017 Decision 8): who may start one,
 * and the session epoch it advances.
 *
 * Reset needs no flag of the client (`hosted-flows.ts`): the hosted pages
 * offer it whenever they are on, to every usable client. A deployment
 * without the Interaction API (`INTERACTION_UI_ENABLED` off) offers none.
 *
 * A reset advances the user's session epoch (`user_session_epochs`, through
 * `fastify.sessionEpochs`): every browser session, and every sign-in in
 * progress, created no later than it belongs to the old password and is
 * treated as absent. The epoch is the app's clock, as a session's
 * `createdAt` is; {@link NOT_VALID_BEFORE_MARGIN_MS} covers the skew between
 * two nodes, as for a disablement (`account-validity.ts`).
 *
 * A password change on the account page (#844) ends the sign-ins in progress
 * too, but not the browser session that made it: it advances no epoch, which
 * would end that session as well. It leaves a cutoff in Redis
 * ({@link recordPasswordChange}) for as long as a sign-in transaction lives,
 * and the engine's `sessionEpochs` port reads the later of the two
 * ({@link signInNotBefore}). The page ends the other sessions itself. The
 * removal of a new factor (#1064) leaves the same cutoff, so no sign-in that
 * proved it, or took a recovery code shown with it, binds a factor after it.
 */

/** What the reset's gate reads of a client: its status. */
export interface ResettingClient {
  readonly enabled: boolean;
  readonly suspended?: boolean | null;
}

/**
 * Whether `client` may start a password reset: the hosted pages are on, and
 * the client is usable (enabled and not suspended, `isClientUsable`).
 * Fail-closed: no client allows nothing.
 */
export function resetAllowed(client: ResettingClient | null | undefined): boolean {
  if (!env.INTERACTION_UI_ENABLED) return false;
  return client !== null && client !== undefined && isClientUsable(client);
}

/**
 * Whether something issued at `issuedAtMs` (epoch ms) predates the user's
 * last reset, `lastReset` (`fastify.sessionEpochs.lastReset`): issued no
 * later than it, with the margin.
 */
export function predatesReset(lastReset: number | null, issuedAtMs: number): boolean {
  if (lastReset === null) return false;
  if (!Number.isFinite(issuedAtMs)) return true;
  return issuedAtMs <= lastReset + NOT_VALID_BEFORE_MARGIN_MS;
}

/**
 * The time at or before which a sign-in of the user belongs to the old
 * password, for the sign-in engine's `sessionEpochs` port: the last reset
 * with the margin, or `null` for a user never reset.
 */
export async function resetNotBefore(
  fastify: FastifyInstance,
  realmId: string,
  userId: string
): Promise<number | null> {
  const lastReset = await fastify.sessionEpochs.lastReset({ realmId, userId });
  return lastReset === null ? null : lastReset + NOT_VALID_BEFORE_MARGIN_MS;
}

/**
 * How long a password change's cutoff is kept, in milliseconds: the longest a
 * sign-in transaction lives, and the skew the engine allows its start. After
 * it, no transaction that began before the change is left.
 */
export const PASSWORD_CHANGE_CUTOFF_TTL_MS =
  SIGN_IN_TRANSACTION_MAX_AGE_MS + SIGN_IN_TRANSACTION_CLOCK_SKEW_MS;

/**
 * Record that the account page changed the user's password at `at` (epoch
 * ms, #844): a sign-in in progress that began no later than it belongs to
 * the old password, and its next round ends it.
 */
export async function recordPasswordChange(
  fastify: Pick<FastifyInstance, 'redis'>,
  realmId: string,
  userId: string,
  at: number
): Promise<void> {
  if (!Number.isSafeInteger(at) || at <= 0) throw new Error('not a password change time');
  await fastify.redis.set(
    REDIS_KEYS.PASSWORD_CHANGED(realmId, userId),
    String(at),
    'PX',
    PASSWORD_CHANGE_CUTOFF_TTL_MS
  );
}

/**
 * When the account page last changed the user's password, while its cutoff
 * is kept; `null` when it did not. A value that is no time throws, so the
 * round that reads it is refused.
 */
export async function passwordChangeNotBefore(
  fastify: Pick<FastifyInstance, 'redis'>,
  realmId: string,
  userId: string
): Promise<number | null> {
  const raw = await fastify.redis.get(REDIS_KEYS.PASSWORD_CHANGED(realmId, userId));
  if (raw === null) return null;
  const at = Number(raw);
  if (!/^[1-9][0-9]{0,15}$/.test(raw) || !Number.isSafeInteger(at)) {
    throw new Error('not a password change time');
  }
  return at;
}

/**
 * The time at or before which a sign-in in progress of the user belongs to
 * an old password, for the sign-in engine's `sessionEpochs` port: the later
 * of its last reset, with the margin, and its last password change on the
 * account page; `null` for neither.
 */
export async function signInNotBefore(
  fastify: FastifyInstance,
  realmId: string,
  userId: string
): Promise<number | null> {
  const [reset, changed] = await Promise.all([
    resetNotBefore(fastify, realmId, userId),
    passwordChangeNotBefore(fastify, realmId, userId),
  ]);
  if (reset === null) return changed;
  if (changed === null) return reset;
  return Math.max(reset, changed);
}
