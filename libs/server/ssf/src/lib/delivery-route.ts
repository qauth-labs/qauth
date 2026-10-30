import { type EgressClient, type EgressLimits, isEgressError } from '@qauth-labs/server-egress';
import type {
  DeliveryOutcome,
  DeliveryRoute,
  DestinationTypeRule,
  RouteDestination,
} from '@qauth-labs/server-event-delivery';
import {
  EVENT_TYPES,
  type EventEnvelope,
  type EventTypeDefinition,
  type SsfEventMapping,
  ssfEventMembers,
  ssfMappingOf,
  ssfStreamVerificationRequested,
} from '@qauth-labs/shared-events';

import {
  authorizationHeaderContext,
  SECEVENT_MEDIA_TYPE,
  SECEVENT_TYP,
  SSF_DELIVERY_KIND,
  SSF_EGRESS_PURPOSE,
} from './constants';
import { eventTypesFor } from './event-types';
import { type SetClaims, setClaims, verificationSetClaims } from './set';
import { ssfSubjectOf, type SubjectIdentifier } from './subjects';

/** A stream as the route lists it for the fan-out. */
export interface SsfRouteStream {
  readonly id: string;
  readonly realmId: string;
  /** The receiver's `client_id`: the SETs' `aud`. */
  readonly audience: string;
  readonly eventsRequested: readonly string[];
  /** The event store subjects of the subjects its receiver added. */
  readonly subjects: ReadonlyArray<{ readonly type: string; readonly id: string }>;
}

/** A stream as one delivery attempt reads it. */
export interface SsfDeliveryStream {
  readonly id: string;
  readonly realmId: string;
  /** The SETs' `aud`. */
  readonly audience: string;
  readonly endpointUrl: string;
  /** The receiver's `Authorization` header, encrypted with the realm's `data_at_rest` key. */
  readonly authorizationHeader: string | null;
  readonly status: 'enabled' | 'paused' | 'disabled';
  /** Its realm's switch is on, and its receiver is enabled and not suspended. */
  readonly active: boolean;
  /** The realm's issuer: the `iss` of a user's `iss_sub`; `null` when the realm has none. */
  readonly issuer: string | null;
}

/** Where the route reads its streams: the `ssfStreams` repository of `@qauth-labs/infra-db`. */
export interface SsfStreamSource {
  /** The streams the route serves: enabled and paused ones of active receivers. */
  listDestinations(): Promise<readonly SsfRouteStream[]>;
  /** One stream, whatever its status, or `undefined` when it no longer exists. */
  findForDelivery(streamId: string): Promise<SsfDeliveryStream | undefined>;
}

/** Options of {@link createSsfDeliveryRoute}. */
export interface SsfDeliveryRouteOptions {
  readonly streams: SsfStreamSource;
  /** The SSRF-safe egress client: every push goes through it, and it checks the address again. */
  readonly egress: Pick<EgressClient, 'request'>;
  /** Caps of a push, over the route's own (no redirect, a 64 KiB answer). */
  readonly limits?: Partial<EgressLimits>;
  /** The event registry; the registry of `@qauth-labs/shared-events` unless a test sets one. */
  readonly eventTypes?: readonly EventTypeDefinition[];
}

/**
 * The error codes a receiver answers a pushed SET with (RFC 8935 §2.4, SSF
 * 1.0 §8.1.4.1). Each becomes the error class `set_<code>`. A `400` without
 * one of them, such as a proxy's error page, says nothing about the SET: it
 * is `http_status`, retried like any other status.
 */
const SET_ERROR_CODES = new Set([
  'invalid_request',
  'invalid_key',
  'invalid_issuer',
  'invalid_audience',
  'authentication_failed',
  'access_denied',
  'invalid_state',
]);

/**
 * The codes a receiver may stop giving without the SET changing: a key it had
 * not fetched yet, or credentials it had not set up. Those are retried; any
 * other refusal of the SET is final.
 */
const RETRIED_SET_ERRORS = new Set(['invalid_key', 'authentication_failed', 'access_denied']);

const DEFAULT_PUSH_LIMITS: Partial<EgressLimits> = {
  maxRedirects: 0,
  maxResponseBytes: 64 * 1024,
};

/** The error classes a receiver reads as `destination_unreachable`: see {@link receiverErrorClass}. */
const UNREACHABLE_ERROR_CLASSES = new Set(['destination_blocked', 'network']);

/**
 * The error class a receiver reads on its stream status (`GET /ssf/status`).
 * An endpoint QAuth refused to reach (`destination_blocked`) and one it could
 * not reach (`network`) both read `destination_unreachable`: told apart, they
 * would show a receiver which names resolve to private addresses from QAuth,
 * which the check at registration does not tell either. The delivery history,
 * the logs and the metrics keep the class as recorded.
 */
export function receiverErrorClass(errorClass: string): string {
  return UNREACHABLE_ERROR_CLASSES.has(errorClass) ? 'destination_unreachable' : errorClass;
}

/**
 * How the fan-out reads a mapped type for one stream: an event about a key
 * passes the subject filter whatever subjects the receiver added; a client's
 * credential event is matched on its client; a type sent only to its own
 * client reaches only the stream whose receiver that client is.
 */
function typeRuleOf(mapping: SsfEventMapping, audience: string): DestinationTypeRule | undefined {
  const rule: { subjectFrom?: 'client' | 'none'; clientId?: string } = {};
  if (mapping.subject === 'client') rule.subjectFrom = 'client';
  if (mapping.subject === 'key') rule.subjectFrom = 'none';
  if (mapping.clientOnly) rule.clientId = audience;
  return Object.keys(rule).length > 0 ? rule : undefined;
}

/**
 * The SET subject of a mapped event, by the mapping's `subject` (RFC 9493, SSF
 * 1.0 §3), or `undefined` when the event does not carry what it names.
 */
function subjectOf(
  mapping: SsfEventMapping,
  event: EventEnvelope,
  issuer: string | null
): SubjectIdentifier | undefined {
  switch (mapping.subject ?? 'subject') {
    case 'client':
      return event.client === undefined
        ? undefined
        : ssfSubjectOf({ type: 'client', id: event.client.id }, issuer ?? '');
    case 'key': {
      const keyId = event.data['keyId'];
      return typeof keyId === 'string' ? { format: 'opaque', id: keyId } : undefined;
    }
    default:
      if (event.subject === undefined) return undefined;
      // A user is named under the realm's issuer; a realm with none names no user.
      if (event.subject.type === 'user' && issuer === null) return undefined;
      return ssfSubjectOf(event.subject, issuer ?? '');
  }
}

/** A refusal no retry changes: the delivery ends `failed` at once. */
const refused = (errorClass: string): DeliveryOutcome => ({ ok: false, errorClass, retry: false });

/** The `err` code of a receiver's `400` answer (RFC 8935 §2.3), if it is a known one. */
function setErrorCode(body: Buffer): string | undefined {
  try {
    const parsed: unknown = JSON.parse(body.toString('utf8'));
    const code =
      parsed !== null && typeof parsed === 'object' ? (parsed as { err?: unknown }).err : undefined;
    return typeof code === 'string' && SET_ERROR_CODES.has(code) ? code : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The Shared Signals Framework delivery route (SSF 1.0 §6.1.1, RFC 8935,
 * issue #410): push delivery of Security Event Tokens to receivers' streams,
 * run by the delivery role (ADR-019 Decision 8).
 *
 * - **Destinations.** Every stream of an active receiver in a realm whose
 *   switch is on, `enabled` or `paused`. A stream receives the QAuth event
 *   types whose SSF events it requested, and only about the subjects its
 *   receiver added (`default_subjects: NONE`). Its verification events do
 *   not come through the fan-out: the verification endpoint writes their
 *   delivery row for that stream alone. A type's mapping can change that per
 *   type (#540): an event about a key reaches every stream that requested
 *   it, a client's credential event is matched on the client, and a type
 *   sent to its own client reaches only that client's stream.
 * - **The SET of a mapped type** (#540). The event the type's mapping names,
 *   with its members, `event_timestamp` and `initiating_entity`; `sub_id` is
 *   the subject the mapping names, a user as `iss_sub` under the realm's
 *   issuer. An event that cannot fill it, such as one without a subject, is
 *   not sent (`event_not_offered`).
 * - **The SET.** `jti` is the event id and `iat` the event's time, so every
 *   retry sends the same claims; `aud` is the receiver's `client_id`. The
 *   signer signs it with the realm's `event_signing` key and adds `iss`; the
 *   route holds no key.
 * - **The push.** A `POST` of the SET as `application/secevent+jwt` through
 *   the egress client, which checks the endpoint's addresses again at every
 *   attempt, with the receiver's `Authorization` header when it gave one,
 *   decrypted for the attempt. No redirect is followed.
 * - **Outcomes.** A `2xx` delivers. A `400` with a known RFC 8935 `err` is
 *   the receiver refusing the SET: final, unless the `err` says something
 *   the receiver may fix (`invalid_key`, `authentication_failed`,
 *   `access_denied`). Any other status, a `400` without a known `err`
 *   included, a timeout or a network failure is retried on the delivery role's
 *   schedule. A paused stream's events are held: the delivery role asks
 *   again every 30 seconds without spending an attempt, and sends them once
 *   the stream is enabled. A disabled, deleted or inactive stream's
 *   deliveries end at once.
 */
export function createSsfDeliveryRoute(options: SsfDeliveryRouteOptions): DeliveryRoute {
  const definitions = options.eventTypes ?? EVENT_TYPES;
  const limits = { ...DEFAULT_PUSH_LIMITS, ...options.limits };
  const mappings = new Map<string, SsfEventMapping>();
  for (const definition of definitions) {
    const mapping = ssfMappingOf(definition);
    if (mapping !== undefined) mappings.set(definition.type, mapping);
  }

  /** The SET claims for `event` on `stream`, or `undefined` when the stream cannot get it. */
  function claimsFor(event: EventEnvelope, stream: SsfDeliveryStream): SetClaims | undefined {
    if (event.type === ssfStreamVerificationRequested.type) {
      // Only the stream the event names: the verification endpoint wrote this
      // row for it, and a stream never gets another stream's verification.
      if (event.subject?.type !== 'ssf_stream' || event.subject.id !== stream.id) return undefined;
      const state = typeof event.data['state'] === 'string' ? event.data['state'] : undefined;
      return verificationSetClaims(event, stream.audience, stream.id, state);
    }
    const mapping = mappings.get(event.type);
    if (mapping === undefined) return undefined;
    // The fan-out wrote this row only for the event's own client; checked
    // again, so a row written under other rules never reaches another one.
    if (mapping.clientOnly && event.client?.id !== stream.audience) return undefined;
    const subject = subjectOf(mapping, event, stream.issuer);
    const members = ssfEventMembers(mapping, event);
    if (subject === undefined || members === undefined) return undefined;
    return setClaims(event, stream.audience, subject, { [mapping.event]: members });
  }

  return {
    kind: SSF_DELIVERY_KIND,

    async destinations(): Promise<RouteDestination[]> {
      const streams = await options.streams.listDestinations();
      return streams.map((stream) => {
        const types = eventTypesFor(stream.eventsRequested, definitions);
        const typeRules: Record<string, DestinationTypeRule> = {};
        for (const type of types) {
          const mapping = mappings.get(type);
          const rule = mapping === undefined ? undefined : typeRuleOf(mapping, stream.audience);
          if (rule !== undefined) typeRules[type] = rule;
        }
        return {
          id: stream.id,
          realmId: stream.realmId,
          types,
          subjects: stream.subjects.map((subject) => ({ type: subject.type, id: subject.id })),
          ...(Object.keys(typeRules).length > 0 ? { typeRules } : {}),
        };
      });
    },

    async deliver(delivery, event, context): Promise<DeliveryOutcome> {
      const stream = await options.streams.findForDelivery(delivery.destinationId);
      if (stream === undefined) return refused('stream_deleted');
      if (stream.realmId !== delivery.realmId || event.realm !== stream.realmId) {
        return refused('realm_mismatch');
      }
      if (!stream.active) return refused('stream_inactive');
      if (stream.status === 'disabled') return refused('stream_disabled');
      // SSF 1.0 §8.1.2: a paused stream's events are held, not sent, and go
      // out once it is enabled. A hold spends no attempt, however long.
      if (stream.status === 'paused') return { ok: false, hold: true };

      const claims = claimsFor(event, stream);
      if (claims === undefined) return refused('event_not_offered');

      const headers: Record<string, string> = {
        'content-type': SECEVENT_MEDIA_TYPE,
        accept: 'application/json',
      };
      if (stream.authorizationHeader !== null) {
        const plaintext = await context.signer.decrypt({
          realmId: stream.realmId,
          ciphertext: stream.authorizationHeader,
          context: authorizationHeaderContext(stream.id),
        });
        headers['authorization'] = new TextDecoder().decode(plaintext);
      }
      const token = await context.signer.signEventToken({
        realmId: stream.realmId,
        typ: SECEVENT_TYP,
        claims,
      });

      let status: number;
      let body: Buffer;
      try {
        const response = await options.egress.request({
          method: 'POST',
          url: stream.endpointUrl,
          headers,
          body: token,
          purpose: SSF_EGRESS_PURPOSE,
          // A receiver registers its own push endpoint: never an allowlist
          // destination (ADR-019 Decision 8).
          source: 'client',
          limits,
        });
        status = response.status;
        body = response.body;
      } catch (error) {
        if (!isEgressError(error)) throw error;
        if (error.outcome === 'blocked') {
          // An address may resolve elsewhere later; a URL's form never changes.
          return {
            ok: false,
            errorClass: 'destination_blocked',
            retry: error.reason === 'address',
          };
        }
        return { ok: false, errorClass: error.reason };
      }

      if (status >= 200 && status < 300) return { ok: true, statusCode: status };
      const code = status === 400 ? setErrorCode(body) : undefined;
      if (code !== undefined) {
        return {
          ok: false,
          statusCode: status,
          errorClass: `set_${code}`,
          retry: RETRIED_SET_ERRORS.has(code),
        };
      }
      return { ok: false, statusCode: status, errorClass: 'http_status' };
    },
  };
}
