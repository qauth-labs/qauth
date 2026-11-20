import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { rfc3339 } from '../../api-conventions/time';

/**
 * THE WEBHOOK SUBSCRIPTION REPRESENTATION OF THE ADMIN API (ADR-019
 * Decisions 7 to 9, issue #537): a subscription of a realm
 * (`webhook_subscriptions`) as an admin reads it, and the state its
 * operations render and bind an approval to.
 *
 * It shows where the realm's events are sent, which of them, whether the
 * subscription is enabled, when a rotation's previous secret stops signing,
 * the delivery failures and the row's version, which is its `ETag`. It never
 * shows a signing secret: the answers of `webhooks.create` and
 * `webhooks.rotateSecret` carry the new one, once, beside it.
 *
 * Kept apart from the definitions (`./operations.ts`), which the operation
 * registry imports, and from the routes: it imports no environment.
 */

const isoTime = z.iso.datetime();

/** What `eventTypes` holds for a subscription that receives every type its categories admit. */
export const ALL_EVENT_TYPES = 'all';

/** The reason a subscription an admin disabled carries. */
export const DISABLED_BY_ADMIN = 'disabled_by_admin';

/** The webhook subscription representation. */
export const adminWebhookSubscriptionSchema = z
  .object({
    id: z.uuid().meta({
      description:
        "The id the admin API names the subscription by. Each delivery's webhook-id header is the event's id, not this one.",
    }),
    url: z.string().meta({
      description:
        'The destination, an https URL with no user name or password, which every delivery is POSTed to.',
    }),
    description: z.string().nullable().meta({
      description: 'What the subscription is for, as an admin wrote it; null when none was.',
    }),
    eventTypes: z.union([z.literal(ALL_EVENT_TYPES), z.array(z.string())]).meta({
      description:
        'The event types sent, by their identifier (urn:qauth:event:…), or all: every type of the categories below. webhook.test is sent only by webhooks.test, whatever this says.',
    }),
    categories: z.array(z.enum(['user', 'admin'])).meta({
      description:
        'The event categories sent: user, the events of what people and clients do, and admin, the changes admins make, each diff masked. An event is sent when its category is listed and eventTypes admits its type.',
    }),
    enabled: z.boolean().meta({
      description: 'Whether events are sent. A disabled subscription receives nothing.',
    }),
    disabledReason: z.string().nullable().meta({
      description:
        'Why the subscription is disabled, as a snake_case code: disabled_by_admin, or the sender’s own when it disables one whose deliveries keep failing. null while it is enabled.',
    }),
    previousSecretExpiresAt: isoTime.nullable().meta({
      description:
        'While a rotation’s overlap runs, when the secret it replaced stops signing: until then each delivery carries a signature by each secret, so the receiver can switch without a gap. null when one secret signs.',
    }),
    failures: z
      .object({
        consecutive: z.int().min(0).meta({
          description: 'The deliveries that failed since the last one that succeeded.',
        }),
        total: z.int().min(0).meta({ description: 'Every delivery that failed.' }),
        lastFailureAt: isoTime.nullable().meta({
          description: 'When the last delivery failed; null when none has.',
        }),
      })
      .meta({ description: 'The delivery failures the sender counted.' }),
    createdBy: z.uuid().nullable().meta({
      description:
        'The admin account that created the subscription; null once that account is deleted.',
    }),
    version: z.int().min(1).meta({
      description:
        'Raised by one with every admin change, a rotation included: the subscription’s ETag.',
    }),
    createdAt: isoTime,
    updatedAt: isoTime,
  })
  .meta({ id: 'AdminWebhookSubscription' });

/** A webhook subscription, as the admin API shows it. */
export type AdminWebhookSubscription = z.infer<typeof adminWebhookSubscriptionSchema>;

/** One `webhook_subscriptions` row, as the repository returns it. */
export type WebhookSubscriptionRecord = NonNullable<
  Awaited<ReturnType<FastifyInstance['repositories']['webhookSubscriptions']['findById']>>
>;

/** The representation of a stored subscription: plain copies, never the row's own objects. */
export function adminWebhookSubscriptionOf(
  row: WebhookSubscriptionRecord
): AdminWebhookSubscription {
  return {
    id: row.id,
    url: row.url,
    description: row.description,
    eventTypes: row.eventTypes === null ? ALL_EVENT_TYPES : [...row.eventTypes],
    categories: [...row.categories],
    enabled: row.enabled,
    disabledReason: row.enabled ? null : row.disabledReason,
    previousSecretExpiresAt:
      row.previousSecretExpiresAt === null ? null : rfc3339(row.previousSecretExpiresAt),
    failures: {
      consecutive: row.consecutiveFailures,
      total: row.failureCount,
      lastFailureAt: row.lastFailureAt === null ? null : rfc3339(row.lastFailureAt),
    },
    createdBy: row.createdBy,
    version: row.version,
    createdAt: rfc3339(row.createdAt),
    updatedAt: rfc3339(row.updatedAt),
  };
}

/**
 * The version of a subscription: its row version, raised by one with every
 * admin change, as the opaque value of its `ETag`. An approval approves a
 * request against that version only.
 */
export function adminWebhookSubscriptionVersion(
  subscription: Pick<AdminWebhookSubscription, 'version'>
): string {
  return String(subscription.version);
}

/**
 * A subscription with the secret its call generated: the answer of
 * `webhooks.create` and `webhooks.rotateSecret`, the only ones that carry it.
 */
export const adminWebhookSubscriptionWithSecretSchema = adminWebhookSubscriptionSchema
  .extend({
    secret: z.string().meta({
      description:
        'The new signing secret in the Standard Webhooks form, whsec_ and the base64 of its 32 bytes: answered here once and never again. The receiver verifies each delivery’s webhook-signature with it.',
    }),
  })
  .meta({ id: 'AdminWebhookSubscriptionWithSecret' });
