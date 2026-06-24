/**
 * Public types for `@qauth-labs/mcp-guard`.
 *
 * `mcp-guard` is the resource-server (RS) side of the QAuth OAuth 2.1 stack.
 * An MCP-server author drops it in to obtain spec-correct OAuth from a
 * self-hosted QAuth authorization server (AS), per the MCP Authorization
 * profile revision 2025-11-25 and the RFCs it references:
 *
 * - RFC 9728 — OAuth 2.0 Protected Resource Metadata (PRM)
 * - RFC 8707 — Resource Indicators (audience binding; no token passthrough)
 * - RFC 7662 — OAuth 2.0 Token Introspection
 * - RFC 6750 §3 — Bearer token `WWW-Authenticate` challenges
 */

/**
 * Token-validation strategy.
 *
 * - `jwt` — verify the bearer locally against the AS JWKS (offline, fast,
 *   the recommended path). Checks signature, `iss`, `exp`, and that `aud`
 *   contains this resource's identifier.
 * - `introspection` — call the AS RFC 7662 endpoint for every request. Use
 *   when tokens are opaque or when the RS must honour near-real-time
 *   revocation. Requires confidential introspection-client credentials.
 */
export type ValidationMode = 'jwt' | 'introspection';

/**
 * Result of a successful token validation. Claims are normalised to the
 * shapes QAuth emits (see auth-server `signAccessToken` / introspect route).
 */
export interface ValidatedToken {
  /** Subject — user UUID (authorization_code) or client id (client_credentials). */
  sub?: string;
  /** OAuth client that the token was issued to (`client_id` claim). */
  clientId?: string;
  /** Granted scopes, already split on whitespace (RFC 8693 `scope`). */
  scopes: string[];
  /** Audience — always the resource identifier(s) this token is bound to. */
  audience: string[];
  /** Issuer (`iss`). */
  issuer?: string;
  /** Expiry, seconds since epoch. */
  expiresAt?: number;
  /** Issued-at, seconds since epoch. */
  issuedAt?: number;
  /**
   * Raw claims as received (JWT payload, or introspection response body).
   * Provided for advanced callers; prefer the normalised fields above.
   */
  raw: Record<string, unknown>;
}

/**
 * Confidential client credentials used to authenticate to the AS
 * introspection endpoint (RFC 7662 requires client authentication).
 */
export interface IntrospectionClientCredentials {
  clientId: string;
  clientSecret: string;
}

/**
 * Minimal `fetch` shape used by the JWKS and introspection clients. Defaults
 * to the global `fetch`; injectable so tests need no network and deployments
 * can wrap it with an SSRF-guarded / instrumented implementation.
 */
export type FetchLike = (
  input: string | URL,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  }
) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}>;

/**
 * Configuration shared by the framework-agnostic core and the Fastify plugin.
 */
export interface McpGuardConfig {
  /**
   * Identifier of THIS protected resource — the canonical URL clients use to
   * reach it (RFC 9728 `resource`, RFC 8707 resource indicator). Every
   * accepted token MUST carry this value in `aud`; tokens minted for a
   * different audience are rejected (no token passthrough).
   *
   * @example 'https://memory.mcp.example.com'
   */
  resource: string;

  /**
   * Issuer identifier of the QAuth authorization server. Advertised in PRM
   * as `authorization_servers[]` and used to validate the JWT `iss` claim.
   * Trailing slashes are normalised away.
   *
   * @example 'https://auth.example.com'
   */
  authorizationServer: string;

  /**
   * Scopes a caller must hold to access the resource by default. An empty
   * array means "any valid, audience-bound token is accepted". Per-operation
   * step-up requirements are expressed at the call site (see `requireScopes`).
   */
  requiredScopes?: string[];

  /** Token-validation strategy. Defaults to `'jwt'`. */
  validationMode?: ValidationMode;

  /**
   * JWKS URL of the AS. Defaults to `${authorizationServer}/.well-known/jwks.json`,
   * matching the QAuth AS contract. Only used in `jwt` mode.
   */
  jwksUri?: string;

  /**
   * How long (ms) a fetched JWKS may be reused before the next refresh is
   * allowed. Maps to the jose remote-JWKS cooldown. Defaults to 300_000 (5m).
   * Only used in `jwt` mode.
   */
  jwksCacheTtlMs?: number;

  /**
   * Introspection endpoint URL. Defaults to `${authorizationServer}/oauth/introspect`,
   * matching the QAuth AS contract. Only used in `introspection` mode.
   */
  introspectionEndpoint?: string;

  /**
   * Confidential credentials for the introspection endpoint. REQUIRED in
   * `introspection` mode (RFC 7662 mandates client authentication).
   */
  introspectionClient?: IntrospectionClientCredentials;

  /**
   * Accepted JWT signature algorithms. Defaults to `['EdDSA']` — the only
   * algorithm QAuth signs with (Ed25519). Constrained to defend against
   * algorithm-confusion attacks. Only used in `jwt` mode.
   */
  allowedAlgorithms?: string[];

  /**
   * Injectable `fetch`. Defaults to the global `fetch`. Override for tests or
   * to apply an SSRF-guarded / instrumented HTTP client.
   */
  fetch?: FetchLike;
}
