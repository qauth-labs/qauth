import { SSF_VERIFICATION_STATE_MAX } from '@qauth-labs/shared-events';
import { z } from 'zod';

import {
  SSF_AUTHORIZATION_HEADER_MAX,
  SSF_DESCRIPTION_MAX,
  SSF_ENDPOINT_URL_MAX,
  SSF_EVENTS_REQUESTED_MAX,
  SSF_MIN_VERIFICATION_INTERVAL,
  SSF_POLL_METHOD,
  SSF_PUSH_METHOD,
  SSF_STATUS_REASON_MAX,
} from './constants';
import { subjectIdentifierSchema } from './subjects';

/**
 * The stream management API's requests and responses (SSF 1.0 §8.1, issue
 * #410).
 *
 * A request member a receiver supplies is checked here; a member the
 * transmitter supplies may be present in an update only when it equals what
 * QAuth holds (§8.1.1.3, §8.1.1.4), and is otherwise refused.
 */

/** A request QAuth refuses with `400`; the message says why, without echoing values. */
export class SsfRequestError extends Error {
  override readonly name = 'SsfRequestError';
}

const streamIdSchema = z.string().min(1).max(255).describe('The `stream_id`.');

/** The `delivery` member a receiver sends (§8.1.1, §6.1.1). */
export const deliveryRequestSchema = z
  .object({
    method: z
      .string()
      .min(1)
      .max(255)
      .describe('The delivery method URI: `urn:ietf:rfc:8935` (push).'),
    endpoint_url: z
      .string()
      .min(1)
      .max(SSF_ENDPOINT_URL_MAX)
      .optional()
      .describe('Where QAuth POSTs each SET: an `https` URL on a public address.'),
    authorization_header: z
      .string()
      .min(1)
      .max(SSF_AUTHORIZATION_HEADER_MAX)
      .optional()
      .describe(
        'The `Authorization` header QAuth sends with every push. Stored encrypted and never returned.'
      ),
  })
  .describe('How QAuth delivers the stream: push only.');

/**
 * The body of create (POST), update (PATCH) and replace (PUT). The members a
 * transmitter supplies are typed loosely: they are compared, never stored.
 */
export const streamConfigRequestSchema = z
  .object({
    stream_id: streamIdSchema.optional(),
    events_requested: z
      .array(z.string().min(1).max(255))
      .max(SSF_EVENTS_REQUESTED_MAX)
      .optional()
      .describe('The event type URIs the receiver wants.'),
    delivery: deliveryRequestSchema.optional(),
    description: z
      .string()
      .max(16 * SSF_DESCRIPTION_MAX)
      .optional()
      .describe('The receiver’s description, cut to 1024 characters.'),
    iss: z.unknown().optional(),
    aud: z.unknown().optional(),
    events_supported: z.unknown().optional(),
    events_delivered: z.unknown().optional(),
    min_verification_interval: z.unknown().optional(),
    inactivity_timeout: z.unknown().optional(),
  })
  .describe('A stream configuration, as a receiver sends it (SSF 1.0 §8.1.1).');

export type StreamConfigRequest = z.infer<typeof streamConfigRequestSchema>;

/** The `delivery` member QAuth returns: the method and the URL, never the authorization header. */
export const deliveryResponseSchema = z.object({
  method: z.string(),
  endpoint_url: z.string(),
});

/** A stream configuration, as QAuth returns it. */
export const streamConfigurationSchema = z
  .object({
    stream_id: z.string(),
    iss: z.string(),
    aud: z.string(),
    events_supported: z.array(z.string()),
    events_requested: z.array(z.string()),
    events_delivered: z.array(z.string()),
    delivery: deliveryResponseSchema,
    min_verification_interval: z.number().int(),
    description: z.string().optional(),
  })
  .describe('A stream configuration (SSF 1.0 §8.1.1).');

export type StreamConfiguration = z.infer<typeof streamConfigurationSchema>;

/** A stored stream, as {@link streamConfiguration} reads it. */
export interface StoredStream {
  readonly id: string;
  readonly audience: string;
  readonly eventsRequested: readonly string[];
  readonly deliveryMethod: string;
  readonly endpointUrl: string;
  readonly description: string | null;
}

/** The members of a stream that only the transmitter supplies (§8.1.1). */
const TRANSMITTER_MEMBERS = [
  'iss',
  'aud',
  'events_supported',
  'events_delivered',
  'min_verification_interval',
] as const;

/**
 * The configuration QAuth returns for a stream.
 *
 * `events_delivered` is what the transmitter sends: the requested events it
 * supports. The verification event is not listed: it is sent on request,
 * whatever the stream requested.
 *
 * @param issuer - The realm's issuer, the SETs' `iss`.
 * @param eventsSupported - `events_supported`.
 */
export function streamConfiguration(
  stream: StoredStream,
  issuer: string,
  eventsSupported: readonly string[]
): StreamConfiguration {
  const supported = new Set(eventsSupported);
  return {
    stream_id: stream.id,
    iss: issuer,
    aud: stream.audience,
    events_supported: [...eventsSupported],
    events_requested: [...stream.eventsRequested],
    events_delivered: stream.eventsRequested.filter((uri) => supported.has(uri)),
    delivery: { method: stream.deliveryMethod, endpoint_url: stream.endpointUrl },
    min_verification_interval: SSF_MIN_VERIFICATION_INTERVAL,
    ...(stream.description === null ? {} : { description: stream.description }),
  };
}

/** JSON with sorted members, to compare two values regardless of member order. */
function canonical(value: unknown): string {
  const sort = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(sort);
    if (item !== null && typeof item === 'object') {
      return Object.fromEntries(
        Object.keys(item)
          .sort()
          .map((key) => [key, sort((item as Record<string, unknown>)[key])])
      );
    }
    return item;
  };
  return JSON.stringify(sort(value));
}

/**
 * Refuse an update whose transmitter-supplied members differ from what QAuth
 * holds (§8.1.1.3, §8.1.1.4). A member left out is fine.
 *
 * @param current - The stream's configuration before the update.
 * @throws SsfRequestError naming the first member that differs
 */
export function assertTransmitterMembers(
  request: StreamConfigRequest,
  current: StreamConfiguration
): void {
  for (const name of TRANSMITTER_MEMBERS) {
    const sent = request[name];
    if (sent === undefined) continue;
    const held = current[name];
    // `events_supported` and `events_delivered` are sets: order is not a change.
    const same =
      Array.isArray(sent) && Array.isArray(held)
        ? canonical([...sent].map(String).sort()) === canonical([...held].sort())
        : canonical(sent) === canonical(held);
    if (!same) {
      throw new SsfRequestError(`${name} is supplied by the transmitter and does not match`);
    }
  }
  if (request.inactivity_timeout !== undefined) {
    throw new SsfRequestError(
      'inactivity_timeout is supplied by the transmitter and does not match'
    );
  }
}

/** The delivery a stream uses, checked: push, with an endpoint URL. */
export interface CheckedDelivery {
  readonly method: typeof SSF_PUSH_METHOD;
  readonly endpointUrl: string;
  readonly authorizationHeader: string | null;
}

/**
 * Check a requested `delivery`. Push only: SSF assumes poll when `delivery`
 * is absent (§8.1.1), and QAuth does not offer poll, so a stream without one
 * is refused too. Only the URL's form is checked here; the egress client
 * checks its addresses.
 *
 * @throws SsfRequestError when the method is not push, or the URL is missing
 *   or not an absolute `https` URL
 */
export function checkDelivery(delivery: StreamConfigRequest['delivery']): CheckedDelivery {
  if (delivery === undefined || delivery.method === SSF_POLL_METHOD) {
    throw new SsfRequestError('poll delivery is not offered: use push (urn:ietf:rfc:8935)');
  }
  if (delivery.method !== SSF_PUSH_METHOD) {
    throw new SsfRequestError('the delivery method is not supported: use push (urn:ietf:rfc:8935)');
  }
  if (delivery.endpoint_url === undefined) {
    throw new SsfRequestError('push delivery needs an endpoint_url');
  }
  if (!URL.canParse(delivery.endpoint_url)) {
    throw new SsfRequestError('endpoint_url is not a URL');
  }
  const url = new URL(delivery.endpoint_url);
  if (url.protocol !== 'https:') {
    throw new SsfRequestError('endpoint_url must be an https URL');
  }
  if (url.username !== '' || url.password !== '') {
    throw new SsfRequestError('endpoint_url must not carry credentials');
  }
  if (url.hash !== '') {
    throw new SsfRequestError('endpoint_url must not carry a fragment');
  }
  const header = delivery.authorization_header;
  if (header !== undefined && !/^[\x21-\x7e]([\x20-\x7e]*[\x21-\x7e])?$/.test(header)) {
    throw new SsfRequestError('authorization_header must be printable ASCII');
  }
  return {
    method: SSF_PUSH_METHOD,
    endpointUrl: delivery.endpoint_url,
    authorizationHeader: header ?? null,
  };
}

/** A description cut to what QAuth keeps (§8.1.1 lets the transmitter cut it). */
export function keptDescription(description: string | undefined): string | null {
  if (description === undefined) return null;
  const cut = description.slice(0, SSF_DESCRIPTION_MAX);
  // Never end on half a surrogate pair.
  return /[\uD800-\uDBFF]$/.test(cut) ? cut.slice(0, -1) : cut;
}

/** The status members (§8.1.2). */
export const STREAM_STATUSES = ['enabled', 'paused', 'disabled'] as const;

/** The body of a status update (§8.1.2.2). */
export const statusUpdateRequestSchema = z.object({
  stream_id: streamIdSchema,
  status: z.enum(STREAM_STATUSES).describe('`enabled`, `paused` or `disabled`.'),
  reason: z.string().min(1).max(SSF_STATUS_REASON_MAX).optional(),
});

/** A stream's status (§8.1.2.1), with QAuth's delivery status of the stream beside it. */
export const streamStatusSchema = z.object({
  stream_id: z.string(),
  status: z.enum(STREAM_STATUSES),
  reason: z.string().optional(),
  delivery_status: z
    .object({
      pending: z.number().int().describe('Deliveries waiting for an attempt or a retry.'),
      last_failure: z
        .object({
          event_id: z.string().describe('The `jti` of the SET whose delivery failed.'),
          attempts: z.number().int(),
          status_code: z.number().int().optional(),
          error: z.string().describe('Why it failed, such as `http_status` or `timeout`.'),
          time: z.string().describe('When the attempt was recorded (RFC 3339).'),
          state: z.enum(['retrying', 'failed']),
          next_attempt_at: z.string().optional(),
        })
        .optional()
        .describe('The latest failed attempt of a delivery to this stream.'),
    })
    .describe('QAuth’s extension: how deliveries to this stream go, from the delivery history.'),
});

/** The body of add subject (§8.1.3.2). */
export const addSubjectRequestSchema = z.object({
  stream_id: streamIdSchema,
  subject: subjectIdentifierSchema,
  verified: z.boolean().optional(),
});

/** The body of remove subject (§8.1.3.3). */
export const removeSubjectRequestSchema = z.object({
  stream_id: streamIdSchema,
  subject: subjectIdentifierSchema,
});

/** The body of a verification request (§8.1.4.2). */
export const verificationRequestSchema = z.object({
  stream_id: streamIdSchema,
  state: z.string().min(1).max(SSF_VERIFICATION_STATE_MAX).optional(),
});
