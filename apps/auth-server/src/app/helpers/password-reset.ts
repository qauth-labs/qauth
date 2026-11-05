import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
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
