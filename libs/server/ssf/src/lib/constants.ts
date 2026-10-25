/**
 * The identifiers of the Shared Signals Framework transmitter (OpenID Shared
 * Signals Framework 1.0, issue #410).
 */

/** The SSF version the transmitter conforms to: its metadata's `spec_version`. */
export const SSF_SPEC_VERSION = '1_0';

/** Push delivery (RFC 8935): the only delivery method the transmitter offers. */
export const SSF_PUSH_METHOD = 'urn:ietf:rfc:8935';

/** Poll delivery (RFC 8936): named so a request for it is refused by name. Not offered. */
export const SSF_POLL_METHOD = 'urn:ietf:rfc:8936';

/** The verification event (SSF 1.0 §8.1.4.1). */
export const SSF_VERIFICATION_EVENT =
  'https://schemas.openid.net/secevent/ssf/event-type/verification';

/** The explicit type of every Security Event Token (RFC 8417 §2.3, SSF 1.0 §4.1.8). */
export const SECEVENT_TYP = 'secevent+jwt';

/** The media type of a pushed SET (RFC 8935 §2). */
export const SECEVENT_MEDIA_TYPE = 'application/secevent+jwt';

/**
 * The scope a receiver's access token carries to manage its streams. A
 * receiver is an OAuth client that the operator gave this scope.
 */
export const SSF_STREAM_SCOPE = 'ssf:stream';

/** The delivery route's kind: `event_deliveries.destination_kind` of its rows. */
export const SSF_DELIVERY_KIND = 'ssf';

/** The `purpose` of the transmitter's outbound calls through the egress client. */
export const SSF_EGRESS_PURPOSE = 'ssf_push';

/**
 * The transmitter's endpoints, relative to the realm's issuer. SSF 1.0 names
 * them only through the metadata, so the paths are QAuth's.
 */
export const SSF_PATHS = Object.freeze({
  configuration: '/.well-known/ssf-configuration',
  stream: '/ssf/stream',
  status: '/ssf/status',
  addSubject: '/ssf/subjects/add',
  removeSubject: '/ssf/subjects/remove',
  verify: '/ssf/verify',
});

/** The most subjects one stream may hold. */
export const SSF_STREAM_SUBJECTS_MAX = 1000;

/**
 * The shortest time between two verification requests of one stream, in
 * seconds: the stream's `min_verification_interval`. A request sooner is
 * answered `429`.
 */
export const SSF_MIN_VERIFICATION_INTERVAL = 10;

/** The longest `description` kept; a longer one is cut (SSF 1.0 §8.1.1). */
export const SSF_DESCRIPTION_MAX = 1024;

/** The most entries of `events_requested`. */
export const SSF_EVENTS_REQUESTED_MAX = 64;

/** The longest `endpoint_url`, in characters. */
export const SSF_ENDPOINT_URL_MAX = 2048;

/** The longest `authorization_header`, in characters. */
export const SSF_AUTHORIZATION_HEADER_MAX = 4096;

/** The longest status `reason`, in characters. */
export const SSF_STATUS_REASON_MAX = 255;

/**
 * The `context` the receiver's `authorization_header` is encrypted under with
 * the realm's `data_at_rest` key: it names the stream, so a ciphertext copied
 * to another stream's row does not decrypt.
 */
export function authorizationHeaderContext(streamId: string): string {
  return `ssf_streams.authorization_header:${streamId}`;
}
