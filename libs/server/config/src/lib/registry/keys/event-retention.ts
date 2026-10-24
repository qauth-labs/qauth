import { defineKeys } from '../types';

/**
 * Event retention (ADR-020 §3, ADR-019 Decision 10, issue #536): the keys of
 * `eventRetentionEnvSchema`. Both are realm policies that already live on the
 * realm row: they only seed a new realm's values.
 */
export const EVENT_RETENTION_KEYS = defineKeys([
  {
    name: 'EVENT_RETENTION_USER_DAYS',
    tier: 'stable',
    role: 'realm-seed',
    seeds: 'retention.userEventDays',
    owner: 'events',
    default: '90',
    since: '0.2.0',
    docs: "The days a new realm keeps its user events before the retention job deletes them, once every enabled delivery destination has finished them; it seeds the realm row, so a later change leaves existing realms' retention as it is.",
  },
  {
    name: 'EVENT_RETENTION_ADMIN_DAYS',
    tier: 'stable',
    role: 'realm-seed',
    seeds: 'retention.adminEventDays',
    owner: 'events',
    default: '365',
    since: '0.2.0',
    docs: "The days a new realm keeps its admin events, at least 90, before the retention job deletes the oldest of them; it seeds the realm row, so a later change leaves existing realms' retention as it is.",
  },
]);
