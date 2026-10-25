// The delivery role: at-least-once delivery of events to their routes
// (ADR-019 Decision 8, issue #460). It holds no key and imports no library
// that loads one (ADR-019 Decision 9).
export {
  DEFAULT_DELIVERY_SETTINGS,
  DELIVERY_ERROR_CLASSES,
  DeliveryAttemptTimeoutError,
  type DeliveryRole,
  type DeliveryRoleOptions,
  DeliveryRoleStoppedError,
  type DeliverySettings,
  type DeliverySettingsInput,
  resolveDeliverySettings,
  startDeliveryRole,
} from './lib/delivery-role';
export {
  checkRetrySchedule,
  DEFAULT_RETRY_SCHEDULE,
  MAX_RETRY_DELAY_MS,
  retryDelayMs,
  type RetrySchedule,
} from './lib/retry';
export type {
  ClaimedDelivery,
  Delivery,
  DeliveryAttemptRecord,
  DeliveryAttemptResult,
  DeliveryClock,
  DeliveryContext,
  DeliveryDestination,
  DeliveryLogger,
  DeliveryMetrics,
  DeliveryOutcome,
  DeliveryRoute,
  DeliverySigner,
  DeliveryStore,
  EventSubjectRef,
  RouteDestination,
} from './lib/types';
