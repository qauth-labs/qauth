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
 * Payload for signing an OIDC ID token (OpenID Connect Core 1.0 §2).
 *
 * An ID token is a security token asserting the authentication of an end-user
 * to a Relying Party (the OAuth client). It is distinct from an access token:
 * its audience (`aud`) is the client itself, and it carries identity claims
 * about the authenticated subject — not authorization scopes.
 *
 * Issued only when the granted scope includes `openid` (OIDC Core §3.1.3.3).
 * Signed with the same EdDSA key as access tokens; `iss`, `aud`, `exp`, `iat`
 * are set by `signIdToken`.
 */
export interface SignIdTokenPayload {
  /** Subject — the stable user identifier (OIDC Core §2, `sub`). */
  sub: string;
  /**
   * Audience — the OAuth client identifier the token is issued for
   * (OIDC Core §2, `aud` = `client_id`).
   */
  audience: string;
  /** End-user email, when available. Mapped to the `email` claim. */
  email?: string;
  /** Whether the email is verified. Mapped to the `email_verified` claim. */
  email_verified?: boolean;
  /** End-user display name, when available. Mapped to the `name` claim. */
  name?: string;
  /**
   * The `nonce` value from the original authorization request, echoed verbatim
   * (OIDC Core §3.1.3.6). Present only when the client supplied one; binds the
   * ID token to the client's authorization request to defend against replay.
   */
  nonce?: string;
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
  /**
   * Token-use marker. `signAccessToken` always stamps `'access'` so consumers
   * can distinguish a genuine access token from any other JWT signed with the
   * same key (token-confusion defence — e.g. an ID token must not be accepted
   * as a `subject_token` at the token-exchange endpoint). Absent on legacy
   * tokens minted before this marker existed.
   */
  token_use?: string;
}
