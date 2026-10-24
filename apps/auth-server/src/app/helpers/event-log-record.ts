import { type Context, isSpanContextValid, trace } from '@opentelemetry/api';
import { type LogAttributes, type LogRecord, SeverityNumber } from '@opentelemetry/api-logs';
import { type EventSeverity, getEventType, parseEvent } from '@qauth-labs/shared-events';

/**
 * How an event becomes an OpenTelemetry log record (ADR-018 §3, issue #541).
 * The attribute names below are the route's contract with an operator's
 * collector queries.
 */

/** The attributes every record carries, and the two it carries when the event has them. */
export const EVENT_LOG_ATTRIBUTES = {
  id: 'qauth.event.id',
  type: 'qauth.event.type',
  category: 'qauth.event.category',
  realm: 'qauth.realm',
  subjectId: 'qauth.subject.id',
  clientId: 'qauth.client.id',
  /** The request id, carried only when no span is active to give the trace id. */
  requestId: 'qauth.request.id',
} as const;

/**
 * The OpenTelemetry severity of each registry severity. `critical`, a
 * security incident or an operator's emergency action, takes ERROR2: the
 * number the OpenTelemetry log data model gives syslog's Critical.
 */
export const EVENT_SEVERITY_NUMBERS: Readonly<Record<EventSeverity, SeverityNumber>> = {
  info: SeverityNumber.INFO,
  warning: SeverityNumber.WARN,
  critical: SeverityNumber.ERROR2,
};

/**
 * The log record of one event.
 *
 * - The body is the envelope as JSON, exactly as the event store holds it.
 * - `eventName` is the event type, which makes the record an OpenTelemetry
 *   event.
 * - The severity is the type's, from the registry; `severityText` keeps the
 *   registry's word (`info`, `warning`, `critical`).
 * - The timestamp is the event's `time`.
 * - When `context` holds a valid span, the SDK takes the record's trace id
 *   and span id from it. Otherwise the record carries the request id as
 *   `qauth.request.id`, when the event names its request.
 *
 * The event is checked against the contract first (`parseEvent`), so a value
 * shaped like a secret is refused here, before anything is exported, even if
 * it did not come through the event store. The event store's own check means
 * that never happens for an event it wrote; the sink adds no masking of its
 * own.
 *
 * @throws {EventValidationError} when the event fails the contract
 */
export function eventLogRecord(input: unknown, context: Context): LogRecord {
  const event = parseEvent(input);
  // parseEvent refuses an unregistered type, so the definition is there.
  const severity = getEventType(event.type)?.severity ?? 'info';

  const attributes: LogAttributes = {
    [EVENT_LOG_ATTRIBUTES.id]: event.id,
    [EVENT_LOG_ATTRIBUTES.type]: event.type,
    [EVENT_LOG_ATTRIBUTES.category]: event.category,
    [EVENT_LOG_ATTRIBUTES.realm]: event.realm,
  };
  if (event.subject !== undefined) attributes[EVENT_LOG_ATTRIBUTES.subjectId] = event.subject.id;
  if (event.client !== undefined) attributes[EVENT_LOG_ATTRIBUTES.clientId] = event.client.id;
  const span = trace.getSpanContext(context);
  const spanActive = span !== undefined && isSpanContextValid(span);
  if (!spanActive && event.request?.traceId !== undefined) {
    attributes[EVENT_LOG_ATTRIBUTES.requestId] = event.request.traceId;
  }

  return {
    eventName: event.type,
    timestamp: new Date(event.time),
    severityNumber: EVENT_SEVERITY_NUMBERS[severity],
    severityText: severity,
    body: JSON.stringify(event),
    attributes,
    context,
  };
}
