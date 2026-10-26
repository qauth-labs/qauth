import { SSF_VERIFICATION_EVENT } from './constants';
import type { SubjectIdentifier } from './subjects';

/**
 * Security Event Token claims (RFC 8417 §2.2, SSF 1.0 §4, issue #410).
 *
 * The signer adds `iss`, the realm's issuer, and the header (`alg`, `kid`,
 * `typ: secevent+jwt`). What the claims never carry: `sub` and `exp`, which
 * SSF 1.0 §4.1.2 and §4.1.6 forbid in a SET.
 */
// A type, not an interface: the signer takes a plain record of claims.
export type SetClaims = {
  /** The event's id: one event keeps it on every route and every retry. */
  readonly jti: string;
  /** When the event happened, in whole seconds, so a retry sends the same claims. */
  readonly iat: number;
  /** The receiver's `client_id`: the stream's `aud`. */
  readonly aud: string;
  /** The subject (SSF 1.0 §4.1.1). */
  readonly sub_id: SubjectIdentifier;
  /** One event type URI and its members. */
  readonly events: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
};

/** An event, as a SET is built from it: its envelope's `id` and `time`. */
export interface SetSource {
  readonly id: string;
  /** An RFC 3339 time. */
  readonly time: string;
}

/** The claims of a SET for `event`. `iat` is the event's time, so retries repeat it. */
export function setClaims(
  event: SetSource,
  audience: string,
  subject: SubjectIdentifier,
  events: SetClaims['events']
): SetClaims {
  const time = Date.parse(event.time);
  if (!Number.isFinite(time)) throw new TypeError('setClaims: the event time is not a time');
  return {
    jti: event.id,
    iat: Math.floor(time / 1000),
    aud: audience,
    sub_id: subject,
    events,
  };
}

/**
 * The claims of a verification SET (SSF 1.0 §8.1.4.1): its subject is the
 * stream, as an `opaque` identifier, and `state` comes back as the receiver
 * sent it.
 */
export function verificationSetClaims(
  event: SetSource,
  audience: string,
  streamId: string,
  state: string | undefined
): SetClaims {
  return setClaims(
    event,
    audience,
    { format: 'opaque', id: streamId },
    { [SSF_VERIFICATION_EVENT]: state === undefined ? {} : { state } }
  );
}
