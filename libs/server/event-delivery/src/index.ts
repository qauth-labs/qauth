// The delivery role: at-least-once delivery of events to their routes
// (ADR-019 Decision 8, issue #460). It holds no key and imports no library
// that loads one (ADR-019 Decision 9).
export {
  DEFAULT_DELIVERY_SETTINGS,
  DELIVERY_ERROR_CLASSES,
  DELIVERY_HOLD_INTERVAL_MS,
  DeliveryAttemptTimeoutError,
  type DeliveryRole,
  type DeliveryRoleOptions,
  DeliveryRoleStoppedError,
  type DeliverySettings,
  type DeliverySettingsInput,
  resolveDeliverySettings,
  SIGNER_HOLD_WARN_INTERVAL_MS,
  type SignerHeldDeliveries,
  startDeliveryRole,
} from './lib/delivery-role';
export {
  checkRetrySchedule,
  DEFAULT_RETRY_SCHEDULE,
  MAX_RETRY_DELAY_MS,
  retryDelayMs,
  type RetrySchedule,
} from './lib/retry';
export {
  type ClaimedDelivery,
  type Delivery,
  type DeliveryAttemptRecord,
  type DeliveryAttemptResult,
  type DeliveryClock,
  type DeliveryContext,
  type DeliveryDestination,
  type DeliveryLogger,
  type DeliveryMetrics,
  type DeliveryOutcome,
  type DeliveryRoute,
  type DeliverySigner,
  type DeliveryStore,
  type DestinationTypeRule,
  type EventSubjectRef,
  ROUTE_BACKFILL_MAX_MS,
  type RouteDestination,
} from './lib/types';
