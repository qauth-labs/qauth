import { EventValidationError } from '@qauth-labs/shared-events';
import type { FastifyInstance } from 'fastify';

import {
  claimExpiredInteraction,
  eventClientIdOf,
  type ExpiredInteraction,
  expiredInteractionEntries,
  relistExpiredInteraction,
} from '../helpers/interaction-record';
import { defineJob, type JobDefinition } from './job-runner';

/** The job's name: its lock, its log lines and its metric label. */
export const INTERACTION_EXPIRY_JOB_NAME = 'interaction-expiry';

/**
 * How often the sweep runs: every minute. An interaction is refused the
 * moment it expires whatever the sweep does; the sweep only audits the expiry
 * and clears what Redis still holds, so a minute's delay costs nothing.
 */
export const INTERACTION_EXPIRY_INTERVAL_MS = 60_000;

/** The most interactions one pass of a run claims before it reads the index again. */
export const INTERACTION_EXPIRY_BATCH = 200;

/**
 * The role whose nodes run the sweep: `web`, which serves the browser
 * ceremonies the interactions belong to.
 */
export const INTERACTION_EXPIRY_ROLE = 'web';

/** What the sweep uses: the Redis client and the event store. */
export interface InteractionExpiryDependencies {
  readonly redis: FastifyInstance['redis'];
  readonly events: Pick<FastifyInstance['repositories']['events'], 'emitInOwnTransaction'>;
}

/** The `interaction.expired` event of one claimed interaction. */
function expiredEvent(expired: ExpiredInteraction) {
  const { record } = expired;
  const userId = record?.transaction.userId;
  const clientId = record === null ? null : eventClientIdOf(record);
  return {
    type: 'urn:qauth:event:interaction.expired:v1-rc.0' as const,
    realm: expired.realmId,
    actor: { type: 'system' as const },
    ...(userId === undefined ? {} : { subject: { type: 'user' as const, id: userId } }),
    ...(clientId === null ? {} : { client: { id: clientId } }),
    data: {
      interaction: expired.ref,
      ...(record === null ? {} : { step: record.step.name }),
    },
  };
}

/**
 * Whether the event store refused an event for its content. By name as well,
 * since a test's module registry can load a second copy of the class.
 */
function isEventValidationError(error: unknown): error is EventValidationError {
  return (
    error instanceof EventValidationError ||
    (error instanceof Error && error.name === 'EventValidationError' && 'problems' in error)
  );
}

/**
 * Audit and clear the interactions that reached their absolute expiry (#592).
 *
 * An interaction that expires is refused on every read from that moment
 * (`helpers/interaction.ts`); Redis keeps its record a short grace longer.
 * The sweep claims each expired member of the expiry index (`ZREM`, so it is
 * reported once), takes the record that is left, and writes
 * `interaction.expired` with the step the ceremony ended at. An interaction
 * that finished or was cancelled left the index then, and is not reported.
 *
 * When an event cannot be written, the claimed interaction is put back in the
 * index and the run fails, so the next run reports it: no expiry goes
 * unaudited because the event store was briefly down. An event the contract
 * refuses (`EventValidationError`) would be refused on every run, so it is
 * logged and dropped instead, and the sweep goes on: one bad record never
 * holds back the rest. Repeating the sweep reports nothing twice.
 */
export function createInteractionExpiryJob(deps: InteractionExpiryDependencies): JobDefinition {
  return defineJob({
    name: INTERACTION_EXPIRY_JOB_NAME,
    role: INTERACTION_EXPIRY_ROLE,
    intervalMs: INTERACTION_EXPIRY_INTERVAL_MS,
    async run({ signal, now, log }) {
      let expired = 0;
      let dropped = 0;
      for (;;) {
        signal.throwIfAborted();
        const entries = await expiredInteractionEntries(
          deps.redis,
          now(),
          INTERACTION_EXPIRY_BATCH
        );
        for (const entry of entries) {
          signal.throwIfAborted();
          const claimed = await claimExpiredInteraction(deps.redis, log, entry);
          if (claimed === null) continue;
          try {
            await deps.events.emitInOwnTransaction(expiredEvent(claimed));
          } catch (error) {
            if (isEventValidationError(error)) {
              log.warn(
                { interaction: claimed.ref, problems: error.problems },
                'interaction expiry event refused by the event contract; dropped'
              );
              dropped += 1;
              continue;
            }
            await relistExpiredInteraction(deps.redis, claimed);
            throw error;
          }
          expired += 1;
        }
        if (entries.length < INTERACTION_EXPIRY_BATCH) break;
      }
      log.info({ expired, dropped }, 'expired interactions audited');
    },
  });
}
