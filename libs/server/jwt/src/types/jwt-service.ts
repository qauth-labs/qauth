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
 * RFC 7800 `cnf` (confirmation) claim of a sender-constrained access token.
 *
 * QAuth sets only the RFC 9449 §6.1 `jkt` member: the base64url RFC 7638
 * SHA-256 thumbprint of the DPoP key the token is bound to. A resource server
 * accepts such a token only with a DPoP proof signed by that key, and never
 * as a Bearer token (RFC 9449 §7.2).
 */
export interface ConfirmationClaim {
  /** RFC 9449 §6.1 JWK SHA-256 thumbprint of the DPoP key. */
  jkt: string;
}

/**
 * Payload for signing access tokens
 *
 * `email` / `email_verified` are optional. QAuth's auth-server passes them
 * only when the grant includes the `email` scope and the user has a verified
 * address, so their absence says nothing about whether `sub` is a user. A
 * client_credentials token has no end user and `sub` equals `clientId`.
 */
export interface SignAccessTokenPayload {
  /** Subject (user ID, or client_id for client_credentials grants) */
  sub: string;
  /** User email (only under the `email` scope; never on client_credentials) */
  email?: string;
  /** Email verification status (present exactly when `email` is) */
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
  /**
   * RFC 9449 §6.1 `cnf` claim — present only on a DPoP-bound token, which the
   * token endpoint issues with `token_type: DPoP`. Omitted for a Bearer token.
   */
  cnf?: ConfirmationClaim;
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
  /**
   * Time of the end-user authentication, in epoch MILLISECONDS. Mapped to the
   * OIDC `auth_time` claim (epoch SECONDS, floored) by {@link buildIdTokenClaims}.
   * OIDC Core §2 requires `auth_time` when the authorization request included
   * `max_age`; QAuth tracks it for every code-flow issuance and emits it whenever
   * available. Omitted (claim absent) when unknown — e.g. in-flight codes minted
   * before the auth-time column existed.
   */
  authTime?: number;
  /**
   * OIDC Core §2 `acr` — Authentication Context Class Reference, the assurance
   * level of the authentication event this token asserts (#237, ADR-004,
   * ADR-010).
   *
   * Passed as the FINAL claim value (e.g. `http://eidas.europa.eu/LoA/high`),
   * already mapped from the internal `AssuranceLevel` by the federation layer's
   * `resolveAcrValue`. This module deliberately does no mapping: the eIDAS LoA →
   * `acr` vocabulary is a deployment choice and belongs where that configuration
   * is read, not in the signer.
   *
   * **Omitted — claim absent — for every authentication that established no
   * higher assurance,** which today means every password login (ADR-003:
   * `assuranceLevel: 'low'` carries no `acr`). OIDC Core treats `acr` as an
   * optional higher-assurance indicator, so its ABSENCE is meaningful: a Relying
   * Party may gate on presence. Emitting a "low" value for ordinary logins would
   * destroy that signal.
   */
  acr?: string;
  /**
   * OIDC `sid` — the browser session the end-user authenticated in (ADR-019
   * Decisions 3 and 4, #549): the `sessions` row id the authorization code
   * recorded, which back-channel logout names (Back-Channel Logout 1.0 §2.1).
   *
   * Only the authorization code exchange passes it, and only for a code a
   * browser session backs. Omitted (claim absent) otherwise: a code from the
   * legacy Bearer path has no session. Never the Authority Tree's id, which is
   * `tree_id` on agent access tokens (ADR-014).
   */
  sid?: string;
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
   * JWT ID (RFC 7519 §4.1.7). `signAccessToken` stamps a unique value on every
   * access token so a specific token can be revoked (RFC 7009) by adding its
   * `jti` to the auth-server's denylist. Absent on legacy tokens minted before
   * this claim existed.
   */
  jti?: string;
  /**
   * Token-use marker. `signAccessToken` always stamps `'access'` so consumers
   * can distinguish a genuine access token from any other JWT signed with the
   * same key (token-confusion defence — e.g. an ID token must not be accepted
   * as a `subject_token` at the token-exchange endpoint). Absent on legacy
   * tokens minted before this marker existed.
   */
  token_use?: string;
}
