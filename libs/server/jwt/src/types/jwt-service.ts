/**
 * RFC 8693 §4.1 `act` (actor) claim.
 *
 * Identifies the party acting on behalf of the subject. A delegation chain is
 * expressed by nesting: the outermost `act` is the current (most recent)
 * actor, and each nested `act` is a prior actor. The only claim REQUIRED by
 * RFC 8693 is `sub`; additional identity claims MAY be present.
 *
 * @example
 * ```jsonc
 * // user delegated to agentA, which further delegated to agentB:
 * { "sub": "user-uuid", "act": { "sub": "agentB", "act": { "sub": "agentA" } } }
 * ```
 */
export interface ActClaim {
  /** Identifier of the actor (for QAuth, the agent client's `client_id`). */
  sub: string;
  /** Nested prior actor in the delegation chain (RFC 8693 §4.1). */
  act?: ActClaim;
}

/**
 * Payload for signing access tokens
 *
 * When `email` / `email_verified` are omitted, the token is a client-only
 * credential (OAuth 2.1 client_credentials grant) and `sub` equals `clientId`.
 */
export interface SignAccessTokenPayload {
  /** Subject (user ID, or client_id for client_credentials grants) */
  sub: string;
  /** User email (omitted for client_credentials grants) */
  email?: string;
  /** Email verification status (omitted for client_credentials grants) */
  email_verified?: boolean;
  /** OAuth client identifier */
  clientId: string;
  /**
   * Space-separated OAuth scopes (RFC 8693 `scope` claim).
   * Omitted when no scopes were granted.
   */
  scope?: string;
  /**
   * Audience for the JWT (OAuth 2.1 / RFC 8707 light-mode).
   * String or array of strings; falls back to `clientId` when absent.
   */
  aud?: string | string[];
  /**
   * RFC 8693 §4.1 `act` (actor) claim — present only on delegated tokens
   * minted via the token-exchange grant. `sub` stays the end-user; `act`
   * identifies the acting agent (nested for chained delegation). Omitted for
   * all non-delegated tokens.
   */
  act?: ActClaim;
}

/**
 * JWT payload structure, including standard claims
 */
export interface JWTPayload extends SignAccessTokenPayload {
  /** Issued at (timestamp) */
  iat?: number;
  /** Expiration time (timestamp) */
  exp?: number;
  /** Issuer */
  iss?: string;
}
