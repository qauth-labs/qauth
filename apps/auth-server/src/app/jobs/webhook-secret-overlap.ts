import type { WebhookSecrets } from '@qauth-labs/fastify-plugin-signer';
import type { FastifyInstance } from 'fastify';

import { defineJob, type JobDefinition } from './job-runner';

/** The job's name: its lock, its log lines and its metric label. */
export const WEBHOOK_SECRET_OVERLAP_JOB_NAME = 'webhook-secret-overlap';

/**
 * How often the job looks for an overlap that ran out: every minute. A
 * rotation's previous secret signs at most this long past the end the
 * rotation gave it, and a signer node that cached the subscription's keys a
 * minute more; it never stops signing early.
 */
export const WEBHOOK_SECRET_OVERLAP_INTERVAL_MS = 60_000;

/** The most overlaps one pass ends before it looks again. */
export const WEBHOOK_SECRET_OVERLAP_BATCH = 100;

/**
 * The role whose nodes run the job: `signer`, which holds the KEK and the
 * realms' keys, so it alone can switch a subscription's secrets.
 */
export const WEBHOOK_SECRET_OVERLAP_ROLE = 'signer';

/** The repository the job reads and writes beside the signer's key store. */
export const WEBHOOK_SECRET_OVERLAP_REPOSITORIES = ['webhookSubscriptions'] as const;

/** The transaction the job ends each overlap in. */
type Transaction = Parameters<
  FastifyInstance['repositories']['webhookSubscriptions']['endSecretOverlap']
>[3];

/** What the job uses. */
export interface WebhookSecretOverlapJobDependencies {
  /** `fastify.webhookSecrets`: the signer's custody of the subscriptions' secrets. */
  readonly secrets: Pick<WebhookSecrets, 'endOverlap'> | null | undefined;
  readonly subscriptions: Pick<
    FastifyInstance['repositories']['webhookSubscriptions'],
    'listEndedSecretOverlaps' | 'endSecretOverlap'
  >;
  /** Runs `work` in one database transaction. */
  readonly transaction: <T>(work: (tx: Transaction) => Promise<T>) => Promise<T>;
}

/**
 * End the overlaps of webhook secret rotations whose time has come (#537).
 * A rotation with an overlap leaves the replaced secret signing beside the
 * new one until the time it stored on the subscription
 * (`previous_secret_expires_at`); this job then makes the new secret the
 * only one (`webhookSecrets.endOverlap`) and clears the time, in one
 * transaction per subscription.
 *
 * The row is written first, conditional on the time the job read: a
 * rotation that committed meanwhile stored another time (or none), and the
 * job leaves that subscription to its own overlap. Writing the row takes its
 * lock before the realm's key lock, in the order the admin API's rotation
 * takes them, so the two never wait on each other in a cycle. One
 * subscription that fails is logged and left for the next run; the others go
 * on.
 *
 * @throws Error when this process does not hold the signer's webhook
 *   secrets (`fastify.webhookSecrets`), that is, when it loads no signer
 */
export function createWebhookSecretOverlapJob(
  deps: WebhookSecretOverlapJobDependencies
): JobDefinition {
  const { secrets } = deps;
  if (secrets === undefined || secrets === null) {
    throw new Error(
      'The webhook secret overlap job needs `fastify.webhookSecrets`: it runs only where the signer plugin is registered'
    );
  }
  return defineJob({
    name: WEBHOOK_SECRET_OVERLAP_JOB_NAME,
    role: WEBHOOK_SECRET_OVERLAP_ROLE,
    intervalMs: WEBHOOK_SECRET_OVERLAP_INTERVAL_MS,
    async run({ signal, now, log }) {
      let ended = 0;
      let failed = 0;
      const tried = new Set<string>();
      for (;;) {
        signal.throwIfAborted();
        const due = (
          await deps.subscriptions.listEndedSecretOverlaps(now(), WEBHOOK_SECRET_OVERLAP_BATCH)
        ).filter((overlap) => !tried.has(overlap.id));
        if (due.length === 0) break;
        for (const overlap of due) {
          signal.throwIfAborted();
          tried.add(overlap.id);
          try {
            const changed = await deps.transaction(async (tx) => {
              const current = await deps.subscriptions.endSecretOverlap(
                overlap.realmId,
                overlap.id,
                overlap.previousSecretExpiresAt,
                tx
              );
              if (!current) return false;
              await secrets.endOverlap({
                realmId: overlap.realmId,
                subscriptionId: overlap.id,
                tx,
              });
              return true;
            });
            if (changed) ended += 1;
          } catch (err) {
            failed += 1;
            log.warn(
              { err, realmId: overlap.realmId, subscriptionId: overlap.id },
              'a webhook secret overlap could not be ended; the next run tries again'
            );
          }
        }
        if (due.length < WEBHOOK_SECRET_OVERLAP_BATCH) break;
      }
      log.info({ ended, failed }, 'webhook secret overlaps ended');
    },
  });
}
