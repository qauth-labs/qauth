import { sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  index,
  integer,
  jsonb,
  pgTable,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { realms, users } from './core';
import { EPOCH_MS_NOW } from './sql-helpers';

/** The event categories a subscription can receive, as `categories` stores them. */
export const WEBHOOK_EVENT_CATEGORIES = ['user', 'admin'] as const;

/** An event category a subscription can receive. */
export type WebhookEventCategory = (typeof WEBHOOK_EVENT_CATEGORIES)[number];

/** The longest URL a subscription takes, in characters. */
export const WEBHOOK_URL_MAX_LENGTH = 2048;

/** The longest description a subscription takes, in characters. */
export const WEBHOOK_DESCRIPTION_MAX_LENGTH = 500;

/**
 * The webhook subscriptions of a realm (ADR-018 §3, ADR-019 Decisions 7 to
 * 9, issue #537): where the realm's events are sent as signed webhooks in the
 * Standard Webhooks form, and which of them.
 *
 * - `url` is the destination: `https` only, no credentials, checked through
 *   the egress client when an admin sets it and again at every delivery.
 * - `event_types` lists the event types sent, or is `NULL` for every type;
 *   `categories` lists the categories sent (`user`, `admin`). An event is
 *   sent when both admit it.
 * - `enabled` is false while the subscription is paused; `disabled_reason`
 *   then says why, as a `snake_case` code (`disabled_by_admin`, or the
 *   sender's own once it disables one that keeps failing). An enabled
 *   subscription has none.
 * - `secret_ref` is the `kid` of the newest signing secret: the realm's
 *   `webhook_signing` key scoped to the subscription (`realm_keys.scope_id`).
 *   The secret itself lives only there, sealed under the KEK; no column here
 *   holds it.
 * - `previous_secret_expires_at` is set while a rotation's overlap runs:
 *   until then the secret the rotation replaced signs beside the new one, so
 *   a receiver can switch without a gap. `NULL` when one secret signs.
 * - `consecutive_failures`, `failure_count` and `last_failure_at` count the
 *   sender's failed deliveries.
 * - `created_by` is the admin account that created it; `NULL` once that
 *   account is deleted.
 * - `version` rises by one with every admin change: the admin API's entity
 *   tag. The sender's counters and the end of an overlap do not raise it.
 *
 * Written by the admin API (`webhooks.*`, security operations); the end of a
 * rotation's overlap is written by the signer role's job. Deleting the realm
 * deletes its rows; deleting a subscription deletes its keys in the same
 * transaction.
 */
export const webhookSubscriptions = pgTable(
  'webhook_subscriptions',
  {
    id: uuid('id').primaryKey(),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** The destination, an absolute `https` URL. */
    url: varchar('url', { length: WEBHOOK_URL_MAX_LENGTH }).notNull(),
    /** What the subscription is for, as the admin wrote it. */
    description: varchar('description', { length: WEBHOOK_DESCRIPTION_MAX_LENGTH }),
    /** The event types sent, or `NULL` for every type. */
    eventTypes: jsonb('event_types').$type<string[]>(),
    /** The event categories sent. */
    categories: jsonb('categories').$type<WebhookEventCategory[]>().notNull(),
    enabled: boolean('enabled').notNull().default(true),
    /** Why the subscription is disabled; `NULL` while it is enabled. */
    disabledReason: varchar('disabled_reason', { length: 64 }),
    /** The `kid` of the newest signing secret. */
    secretRef: varchar('secret_ref', { length: 255 }).notNull(),
    /** Epoch ms. When the secret a rotation replaced stops signing; `NULL` outside an overlap. */
    previousSecretExpiresAt: bigint('previous_secret_expires_at', { mode: 'number' }),
    consecutiveFailures: integer('consecutive_failures').notNull().default(0),
    failureCount: bigint('failure_count', { mode: 'number' }).notNull().default(0),
    lastFailureAt: bigint('last_failure_at', { mode: 'number' }),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    /** Raised by one with every admin change. */
    version: integer('version').notNull().default(1),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    // A realm's list, newest first.
    index('idx_webhook_subscriptions_realm_created').on(t.realmId, t.createdAt, t.id),
    // The overlaps the signer role's job ends.
    index('idx_webhook_subscriptions_overlap')
      .on(t.previousSecretExpiresAt)
      .where(sql`${t.previousSecretExpiresAt} IS NOT NULL`),
    check('webhook_subscriptions_url_https', sql`left(${t.url}, 8) = 'https://'`),
    check(
      'webhook_subscriptions_event_types_list',
      sql`${t.eventTypes} IS NULL OR (jsonb_typeof(${t.eventTypes}) = 'array' AND jsonb_array_length(${t.eventTypes}) > 0)`
    ),
    check(
      'webhook_subscriptions_categories_list',
      sql`jsonb_typeof(${t.categories}) = 'array' AND jsonb_array_length(${t.categories}) > 0 AND ${t.categories} <@ ${sql.raw(`'${JSON.stringify(WEBHOOK_EVENT_CATEGORIES)}'::jsonb`)}`
    ),
    // Disabled with a reason, or enabled without one.
    check(
      'webhook_subscriptions_disabled_reason',
      sql`(${t.enabled} AND ${t.disabledReason} IS NULL) OR (NOT ${t.enabled} AND ${t.disabledReason} IS NOT NULL AND ${t.disabledReason} <> '')`
    ),
    check('webhook_subscriptions_secret_ref', sql`${t.secretRef} <> ''`),
    check(
      'webhook_subscriptions_failures',
      sql`${t.consecutiveFailures} >= 0 AND ${t.failureCount} >= 0`
    ),
    check('webhook_subscriptions_version_positive', sql`${t.version} > 0`),
  ]
);
