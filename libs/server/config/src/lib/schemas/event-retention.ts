import {
  ADMIN_EVENT_RETENTION_DEFAULT_DAYS,
  ADMIN_EVENT_RETENTION_MIN_DAYS,
  EVENT_RETENTION_MAX_DAYS,
  USER_EVENT_RETENTION_DEFAULT_DAYS,
  USER_EVENT_RETENTION_MIN_DAYS,
} from '@qauth-labs/shared-validation';
import { z } from 'zod';

/**
 * Event retention (ADR-020 §3, ADR-019 Decision 10, issue #536): the days a
 * new realm keeps its events, a realm policy. The keys seed
 * `realms.user_event_retention_days` and `realms.admin_event_retention_days`
 * when a realm is created; the realm row owns the values from then on, and a
 * later change of a key leaves existing realms as they are.
 *
 * The admin key refuses fewer than 90 days, as the realm row does. Neither
 * key stops an event from being stored: the retention job deletes only
 * events older than the realm's retention, and only once every enabled
 * delivery destination has finished them.
 *
 * A plain `z.object`, so the auth server can spread its `.shape`.
 */
export const eventRetentionEnvSchema = z.object({
  /** Days a new realm keeps its user events. */
  EVENT_RETENTION_USER_DAYS: z.coerce
    .number()
    .int()
    .min(USER_EVENT_RETENTION_MIN_DAYS)
    .max(EVENT_RETENTION_MAX_DAYS)
    .default(USER_EVENT_RETENTION_DEFAULT_DAYS),

  /** Days a new realm keeps its admin events; at least 90. */
  EVENT_RETENTION_ADMIN_DAYS: z.coerce
    .number()
    .int()
    .min(ADMIN_EVENT_RETENTION_MIN_DAYS)
    .max(EVENT_RETENTION_MAX_DAYS)
    .default(ADMIN_EVENT_RETENTION_DEFAULT_DAYS),
});

/** The event retention a new realm is seeded with. */
export type EventRetentionEnv = z.infer<typeof eventRetentionEnvSchema>;
