import { BACKCHANNEL_LOGOUT_EVENT, LOGOUT_TOKEN_LIFETIME_SECONDS } from './constants';

/**
 * The claims of a logout token, without `iss`: the signer adds the realm's
 * issuer (OpenID Connect Back-Channel Logout 1.0 §2.4).
 */
// A type alias, not an interface: the signer takes a `Record<string, unknown>`.
export type LogoutTokenClaims = {
  /** The client's `client_id`. */
  readonly aud: string;
  readonly iat: number;
  readonly exp: number;
  readonly jti: string;
  readonly events: { readonly [BACKCHANNEL_LOGOUT_EVENT]: Record<string, never> };
  /** The user the session was of: the `sub` of its ID tokens. */
  readonly sub?: string;
  /** The session that ended: the `sid` of its ID tokens. */
  readonly sid?: string;
};

/** What {@link logoutTokenClaims} builds a token from. */
export interface LogoutTokenInput {
  /** The client's `client_id`. */
  readonly audience: string;
  /** The user's id, the `sub` QAuth puts in ID tokens; absent sends `sid` alone. */
  readonly subject?: string;
  /** The session's id, the `sid` QAuth puts in ID tokens; absent sends `sub` alone. */
  readonly sid?: string;
  /**
   * The token's unique identifier. The delivery route gives the delivery's
   * id: unique per client and session, and the same on every retry of it, so
   * a receiver that keeps the `jti` it saw treats a retry it already acted on
   * as the same notice.
   */
  readonly jti: string;
  /** Now, in epoch milliseconds. */
  readonly now: number;
}

/**
 * The claims of one logout token (Back-Channel Logout 1.0 §2.4): `aud`, `iat`,
 * a short `exp` ({@link LOGOUT_TOKEN_LIFETIME_SECONDS}), `jti`, the `events`
 * claim with the back-channel logout member and an empty object, and `sub`,
 * `sid` or both. Never a `nonce`, which the spec prohibits.
 *
 * @throws {TypeError} when neither `subject` nor `sid` is given: a logout
 *   token must name one of them
 */
export function logoutTokenClaims(input: LogoutTokenInput): LogoutTokenClaims {
  if (input.subject === undefined && input.sid === undefined) {
    throw new TypeError('A logout token must carry a sub or a sid claim');
  }
  const iat = Math.floor(input.now / 1000);
  return {
    aud: input.audience,
    iat,
    exp: iat + LOGOUT_TOKEN_LIFETIME_SECONDS,
    jti: input.jti,
    events: { [BACKCHANNEL_LOGOUT_EVENT]: {} },
    ...(input.subject === undefined ? {} : { sub: input.subject }),
    ...(input.sid === undefined ? {} : { sid: input.sid }),
  };
}

/** The POST body of a back-channel logout request (Back-Channel Logout 1.0 §2.5). */
export function logoutRequestBody(logoutToken: string): string {
  return new URLSearchParams({ logout_token: logoutToken }).toString();
}
