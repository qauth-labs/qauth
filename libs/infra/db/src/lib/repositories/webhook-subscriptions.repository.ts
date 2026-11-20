import { and, asc, desc, eq, isNotNull, lt, lte, or, sql } from 'drizzle-orm';

import type { DbClient } from '../../types';
import type { KeysetPage } from '../../types/repository';
import { eventDeliveries } from '../schema/event-deliveries';
import { EPOCH_MS_NOW } from '../schema/sql-helpers';
import { type WebhookEventCategory, webhookSubscriptions } from '../schema/webhook-subscriptions';

/**
 * The webhook subscriptions of a realm (#537): `webhook_subscriptions`. The
 * admin API writes them; the signer role's job ends a secret rotation's
 * overlap; the sender (the delivery role's webhook route) reads them.
 *
 * The repository stores what it is given: the admin API checks the URL
 * through the egress client, the event types against the registry and the
 * texts before it calls it. The table's CHECKs hold the shapes besides. No
 * method reads or writes a secret: the secrets are the realm's
 * `webhook_signing` keys, which only the signer holds.
 */

/** The route kind a webhook delivery is queued under (`event_deliveries.destination_kind`). */
export const WEBHOOK_DELIVERY_KIND = 'webhook';

/** One webhook subscription of a realm. */
export interface WebhookSubscription {
  readonly id: string;
  readonly realmId: string;
  readonly url: string;
  readonly description: string | null;
  /** The event types sent, or `null` for every type. */
  readonly eventTypes: readonly string[] | null;
  readonly categories: readonly WebhookEventCategory[];
  readonly enabled: boolean;
  readonly disabledReason: string | null;
  /** The `kid` of the newest signing secret. */
  readonly secretRef: string;
  /** Epoch ms. When the secret a rotation replaced stops signing; `null` outside an overlap. */
  readonly previousSecretExpiresAt: number | null;
  readonly consecutiveFailures: number;
  readonly failureCount: number;
  readonly lastFailureAt: number | null;
  readonly createdBy: string | null;
  /** Raised by one with every admin change. */
  readonly version: number;
  readonly createdAt: number;
  readonly updatedAt: number;
}

/** What an admin sets on a subscription. */
export interface WebhookSubscriptionSettings {
  readonly url: string;
  readonly description: string | null;
  /** `null` for every type; otherwise one or more types. */
  readonly eventTypes: readonly string[] | null;
  /** One or more categories. */
  readonly categories: readonly WebhookEventCategory[];
  readonly enabled: boolean;
  /** Required while disabled, `null` while enabled. */
  readonly disabledReason: string | null;
}

/** Input of {@link WebhookSubscriptionsRepository.create}. */
export interface NewWebhookSubscription extends WebhookSubscriptionSettings {
  /** The subscription's id, a UUID: its signing secret is scoped to it before the row is written. */
  readonly id: string;
  /** The `kid` of its first signing secret. */
  readonly secretRef: string;
  /** The admin account that creates it. */
  readonly createdBy: string | null;
}

/** A rotation's overlap that has run out, as the signer role's job reads it. */
export interface EndedWebhookSecretOverlap {
  readonly realmId: string;
  readonly id: string;
  readonly previousSecretExpiresAt: number;
}

/** The webhook subscription repository (#537). Every id-keyed method takes the realm first. */
export interface WebhookSubscriptionsRepository {
  /** One page of the realm's subscriptions, newest first by `created_at` and then `id`. */
  pageByRealm(realmId: string, page: KeysetPage, tx?: DbClient): Promise<WebhookSubscription[]>;
  /** The subscription `id` of the realm, or `undefined`. */
  findById(realmId: string, id: string, tx?: DbClient): Promise<WebhookSubscription | undefined>;
  /**
   * The subscription `id` of the realm, locked `FOR NO KEY UPDATE` in `tx`
   * until it commits, or `undefined`.
   */
  findByIdForUpdate(
    realmId: string,
    id: string,
    tx: DbClient
  ): Promise<WebhookSubscription | undefined>;
  /**
   * A new subscription id, a UUIDv7 from Postgres (`uuidv7()`), as every
   * primary key of the schema is. A subscription's signing secret is scoped
   * to its id, so the id is reserved, in `tx`, before either is written.
   */
  newId(tx: DbClient): Promise<string>;
  /** Store a new subscription at version 1. */
  create(
    realmId: string,
    input: NewWebhookSubscription,
    tx?: DbClient
  ): Promise<WebhookSubscription>;
  /**
   * Replace the settings of the subscription `id` while it is at
   * `expectedVersion`, raising its version by one. With `resetFailures`, its
   * consecutive failure count starts again at zero (an admin enabled it
   * again). Answers the written row, or `undefined` when it is gone or at
   * another version.
   */
  update(
    realmId: string,
    id: string,
    settings: WebhookSubscriptionSettings,
    options: { readonly expectedVersion: number; readonly resetFailures: boolean },
    tx?: DbClient
  ): Promise<WebhookSubscription | undefined>;
  /**
   * Record a rotation of the subscription's secret while it is at
   * `expectedVersion`, raising its version by one: `secretRef` is the new
   * secret's `kid`, and `previousSecretExpiresAt` when the secret it replaced
   * stops signing (`null` when it stopped at once). Answers the written row,
   * or `undefined`.
   */
  recordSecretRotation(
    realmId: string,
    id: string,
    rotation: { readonly secretRef: string; readonly previousSecretExpiresAt: number | null },
    expectedVersion: number,
    tx?: DbClient
  ): Promise<WebhookSubscription | undefined>;
  /**
   * Remove the subscription `id` while it is at `expectedVersion`. Answers
   * whether a row was removed. Its keys are the caller's to delete, in the
   * same transaction.
   */
  delete(realmId: string, id: string, expectedVersion: number, tx?: DbClient): Promise<boolean>;
  /**
   * The rotations, of every realm, whose overlap ran out at or before `now`
   * (epoch ms), oldest first, at most `limit`.
   */
  listEndedSecretOverlaps(
    now: number,
    limit: number,
    tx?: DbClient
  ): Promise<EndedWebhookSecretOverlap[]>;
  /**
   * Mark the overlap of the subscription `id` ended, while it still ends at
   * `expiresAt`: one secret signs from now on. The version stays: no admin
   * changed anything. Answers whether the row changed.
   */
  endSecretOverlap(realmId: string, id: string, expiresAt: number, tx: DbClient): Promise<boolean>;
  /**
   * Queue the event `eventId`, written in `tx`, for the subscription alone
   * (`webhooks.test`): one `event_deliveries` row of the `webhook` route.
   * Answers whether it was queued; `false` when the subscription is not of
   * the event's realm.
   */
  enqueueForEvent(
    tx: DbClient,
    request: { readonly subscriptionId: string; readonly eventId: string; readonly now: number }
  ): Promise<boolean>;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Refuse an id Postgres would refuse with an error (22P02) before it reaches it. */
const isUuid = (value: unknown): value is string =>
  typeof value === 'string' && UUID_PATTERN.test(value);

const isVersion = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 1;

/** The stored columns of `settings`: plain copies, so no caller object is stored by reference. */
function columnsOf(settings: WebhookSubscriptionSettings) {
  return {
    url: settings.url,
    description: settings.description,
    eventTypes: settings.eventTypes === null ? null : [...settings.eventTypes],
    categories: [...settings.categories],
    enabled: settings.enabled === true,
    disabledReason: settings.enabled === true ? null : settings.disabledReason,
  };
}

/**
 * Factory for the webhook subscription repository (#537).
 *
 * @param defaultDb - The database a call without a transaction runs on.
 */
export function createWebhookSubscriptionsRepository(
  defaultDb: DbClient
): WebhookSubscriptionsRepository {
  const ofRealm = (realmId: string, id: string) =>
    and(eq(webhookSubscriptions.realmId, realmId), eq(webhookSubscriptions.id, id));

  return {
    async pageByRealm(realmId, page, tx) {
      if (!isUuid(realmId)) return [];
      const after = page.after;
      return (tx ?? defaultDb)
        .select()
        .from(webhookSubscriptions)
        .where(
          and(
            eq(webhookSubscriptions.realmId, realmId),
            after === undefined
              ? undefined
              : or(
                  lt(webhookSubscriptions.createdAt, after.at),
                  and(
                    eq(webhookSubscriptions.createdAt, after.at),
                    lt(webhookSubscriptions.id, after.id)
                  )
                )
          )
        )
        .orderBy(desc(webhookSubscriptions.createdAt), desc(webhookSubscriptions.id))
        .limit(page.limit);
    },

    async findById(realmId, id, tx) {
      if (!isUuid(realmId) || !isUuid(id)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .select()
        .from(webhookSubscriptions)
        .where(ofRealm(realmId, id))
        .limit(1);
      return row;
    },

    async findByIdForUpdate(realmId, id, tx) {
      if (!isUuid(realmId) || !isUuid(id)) return undefined;
      const [row] = await tx
        .select()
        .from(webhookSubscriptions)
        .where(ofRealm(realmId, id))
        .limit(1)
        .for('no key update');
      return row;
    },

    async newId(tx) {
      const { rows } = await tx.execute<{ id: string }>(sql`select uuidv7()::text as "id"`);
      const id = rows[0]?.id;
      if (id === undefined) throw new Error('webhookSubscriptions.newId: uuidv7() returned no row');
      return id;
    },

    async create(realmId, input, tx) {
      if (!isUuid(realmId) || !isUuid(input.id)) {
        throw new TypeError(
          'webhookSubscriptions.create: the realm and subscription ids must be UUIDs'
        );
      }
      const [row] = await (tx ?? defaultDb)
        .insert(webhookSubscriptions)
        .values({
          id: input.id,
          realmId,
          ...columnsOf(input),
          secretRef: input.secretRef,
          createdBy: input.createdBy,
        })
        .returning();
      if (row === undefined) throw new Error('webhookSubscriptions.create: no row was written');
      return row;
    },

    async update(realmId, id, settings, options, tx) {
      if (!isUuid(realmId) || !isUuid(id) || !isVersion(options.expectedVersion)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .update(webhookSubscriptions)
        .set({
          ...columnsOf(settings),
          ...(options.resetFailures ? { consecutiveFailures: 0 } : {}),
          version: sql`${webhookSubscriptions.version} + 1`,
          updatedAt: EPOCH_MS_NOW,
        })
        .where(and(ofRealm(realmId, id), eq(webhookSubscriptions.version, options.expectedVersion)))
        .returning();
      return row;
    },

    async recordSecretRotation(realmId, id, rotation, expectedVersion, tx) {
      if (!isUuid(realmId) || !isUuid(id) || !isVersion(expectedVersion)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .update(webhookSubscriptions)
        .set({
          secretRef: rotation.secretRef,
          previousSecretExpiresAt: rotation.previousSecretExpiresAt,
          version: sql`${webhookSubscriptions.version} + 1`,
          updatedAt: EPOCH_MS_NOW,
        })
        .where(and(ofRealm(realmId, id), eq(webhookSubscriptions.version, expectedVersion)))
        .returning();
      return row;
    },

    async delete(realmId, id, expectedVersion, tx) {
      if (!isUuid(realmId) || !isUuid(id) || !isVersion(expectedVersion)) return false;
      const removed = await (tx ?? defaultDb)
        .delete(webhookSubscriptions)
        .where(and(ofRealm(realmId, id), eq(webhookSubscriptions.version, expectedVersion)))
        .returning({ id: webhookSubscriptions.id });
      return removed.length > 0;
    },

    async listEndedSecretOverlaps(now, limit, tx) {
      if (!Number.isSafeInteger(now) || !Number.isSafeInteger(limit) || limit < 1) return [];
      const rows = await (tx ?? defaultDb)
        .select({
          realmId: webhookSubscriptions.realmId,
          id: webhookSubscriptions.id,
          previousSecretExpiresAt: webhookSubscriptions.previousSecretExpiresAt,
        })
        .from(webhookSubscriptions)
        .where(
          and(
            isNotNull(webhookSubscriptions.previousSecretExpiresAt),
            lte(webhookSubscriptions.previousSecretExpiresAt, now)
          )
        )
        .orderBy(asc(webhookSubscriptions.previousSecretExpiresAt), asc(webhookSubscriptions.id))
        .limit(limit);
      return rows.map((row) => ({
        realmId: row.realmId,
        id: row.id,
        previousSecretExpiresAt: row.previousSecretExpiresAt as number,
      }));
    },

    async endSecretOverlap(realmId, id, expiresAt, tx) {
      if (!isUuid(realmId) || !isUuid(id) || !Number.isSafeInteger(expiresAt)) return false;
      const ended = await tx
        .update(webhookSubscriptions)
        .set({ previousSecretExpiresAt: null })
        .where(
          and(ofRealm(realmId, id), eq(webhookSubscriptions.previousSecretExpiresAt, expiresAt))
        )
        .returning({ id: webhookSubscriptions.id });
      return ended.length > 0;
    },

    async enqueueForEvent(tx, request) {
      if (!isUuid(request.subscriptionId) || !isUuid(request.eventId)) {
        throw new TypeError(
          'webhookSubscriptions.enqueueForEvent: the subscription and event ids must be UUIDs'
        );
      }
      // `events_own_row` returns the event only to the transaction that wrote
      // it (migration 0033), so a subscription cannot be handed another
      // event, and only a subscription of the event's own realm gets the row.
      // The destination is the stored id, as Postgres prints it, whatever
      // spelling the caller passed: one subscription is one destination.
      const result = await tx.execute(sql`
        insert into ${eventDeliveries} (destination_kind, destination_id, event_id, realm_id,
          event_xid, event_seq, event_time, next_attempt_at, created_at, updated_at)
        select ${WEBHOOK_DELIVERY_KIND}, ${webhookSubscriptions.id}::text, "own"."id",
          "own"."realm_id", "own"."xid", "own"."seq", "own"."time", ${request.now},
          ${request.now}, ${request.now}
        from events_own_row(${request.eventId}::uuid) as "own"
        join ${webhookSubscriptions}
          on ${webhookSubscriptions.id} = ${request.subscriptionId}
          and ${webhookSubscriptions.realmId} = "own"."realm_id"
        on conflict on constraint event_deliveries_event_destination_unique do nothing
      `);
      return (result.rowCount ?? 0) > 0;
    },
  };
}
