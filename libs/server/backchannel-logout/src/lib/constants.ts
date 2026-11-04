/**
 * The fixed names of back-channel logout (OpenID Connect Back-Channel Logout
 * 1.0, issue #624).
 */

/** The delivery route's kind: a destination is a client with a `backchannel_logout_uri`. */
export const BACKCHANNEL_LOGOUT_DELIVERY_KIND = 'backchannel_logout';

/** The egress client's purpose label for a logout token's POST and its address check. */
export const BACKCHANNEL_LOGOUT_EGRESS_PURPOSE = 'backchannel-logout';

/**
 * The `typ` header of a logout token (Back-Channel Logout 1.0 §2.4): the
 * explicit type the spec recommends, which tells it from an ID token. The
 * signer's policy lets the delivery role sign it with `event_signing` only.
 */
export const LOGOUT_TOKEN_TYP = 'logout+jwt';

/** The member of a logout token's `events` claim (Back-Channel Logout 1.0 §2.4). */
export const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

/**
 * How long a logout token is valid, in seconds: two minutes, the most Back-
 * Channel Logout 1.0 §4 suggests. Each attempt signs a new token, so a retry
 * hours later still arrives within it.
 */
export const LOGOUT_TOKEN_LIFETIME_SECONDS = 120;

/**
 * How far back the delivery role starts a realm it fans out for this route
 * for the first time, or again after the realm had no client with a URI: one
 * day. A notice is written only for a client with a URI, so one committed
 * before the role first listed the realm (the role was down, or had not
 * polled yet) is meant for delivery and is sent late rather than lost.
 */
export const BACKCHANNEL_LOGOUT_BACKFILL_MS = 24 * 60 * 60 * 1000;

/**
 * The event a session revocation writes for each client to notify, in its
 * own transaction: `user.client_session_ended` of `@qauth-labs/shared-events`.
 */
export const CLIENT_SESSION_ENDED_EVENT = 'urn:qauth:event:user.client_session_ended:v1-rc.0';

/** The media type of the POST body (Back-Channel Logout 1.0 §2.5). */
export const LOGOUT_REQUEST_MEDIA_TYPE = 'application/x-www-form-urlencoded';
