import { z } from 'zod';

import { defineEventType } from '../definition';

/**
 * The webhook subscriptions of the admin API (issue #537). A subscription is
 * the subject, by its id; the admin that asked is the actor.
 */

export const webhookTest = defineEventType({
  name: 'webhook.test',
  version: 1,
  rc: 0,
  description:
    "An admin asked for a test event on one of the realm's webhook subscriptions (`webhooks.test`). QAuth sends it to that subscription only, signed with the subscription's secrets like every other webhook, so its receiver can check that it gets and verifies QAuth's webhooks. It carries nothing beyond its envelope.",
  category: 'user',
  severity: 'info',
  since: 'v0.2.10',
  subject: 'webhook_subscription',
  data: z.strictObject({}),
});

export const WEBHOOK_EVENT_TYPES = [webhookTest] as const;
