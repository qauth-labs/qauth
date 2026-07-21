/**
 * Helpers for building OAuth 2.0 / OIDC discovery metadata documents.
 *
 * - `/.well-known/oauth-authorization-server` — RFC 8414.
 * - `/.well-known/openid-configuration` — OIDC Discovery 1.0.
 *
 * We intentionally keep the builder pure (no Fastify / env dependency) so
 * the route layer controls caching and the tests can exercise shape directly.
 */

/**
 * Default scopes advertised when a realm-specific list is not configured.
 *
 * Covers the canonical OIDC scopes (`openid`, `profile`, `email`) plus
 * `offline_access` — useful once the refresh_token grant lands on main, and
 * harmless to advertise in the meantime since unknown scopes are ignored
 * per the authorize route's deny-by-default allowlist.
 */
export const DEFAULT_SCOPES_SUPPORTED: readonly string[] = [
  'openid',
  'profile',
  'email',
  'offline_access',
] as const;

/**
 * Input to {@link buildAuthorizationServerMetadata} — pre-resolved issuer
 * and any optional overrides. The caller is responsible for ensuring
 * `issuer` has no trailing slash (RFC 8414 §2 recommends this).
 */
export interface DiscoveryMetadataInput {
  /** `iss` value; also used as the base URL for well-known endpoints. */
  issuer: string;
  /** Supported scopes list; defaults to {@link DEFAULT_SCOPES_SUPPORTED}. */
  scopesSupported?: readonly string[];
  /**
   * Whether the server accepts Client ID Metadata Documents (CIMD) —
   * draft-ietf-oauth-client-id-metadata-document-00 / MCP 2025-11-25.
   * When true, `client_id_metadata_document_supported: true` is advertised
   * so MCP clients know they can present an https-URL `client_id`. Defaults
   * to false here; the route layer passes the env-gated value.
   */
  clientIdMetadataDocumentSupported?: boolean;
  /**
   * `id_token_signing_alg_values_supported` to advertise (OIDC Discovery 1.0 /
   * RFC 8414). Defaults to {@link DEFAULT_ID_TOKEN_SIGNING_ALG_VALUES} (`EdDSA`).
   * The route passes the plugin's live value: `['RS256','EdDSA']` when an RS256
   * signing key is configured (#309, needed for OIDC Basic/Config certification,
   * #286), otherwise `['EdDSA']`. MUST reflect the keys actually published in the
   * JWKS — advertising an algorithm with no matching key is a conformance failure.
   */
  idTokenSigningAlgValuesSupported?: readonly string[];
}

/**
 * Default `id_token_signing_alg_values_supported`. EdDSA is always available;
 * RS256 is added by the route only when an RS256 key is configured (#309).
 */
export const DEFAULT_ID_TOKEN_SIGNING_ALG_VALUES: readonly string[] = ['EdDSA'] as const;

/**
 * OAuth 2.0 Authorization Server Metadata (RFC 8414).
 *
 * We keep the return type permissive (`Record<string, unknown>`) so the
 * OIDC variant can spread this and add OIDC-only fields without type
 * gymnastics. The well-known route schemas pin the exact wire shape.
 */
export function buildAuthorizationServerMetadata(
  input: DiscoveryMetadataInput
): Record<string, unknown> {
  const base = resolveIssuerIdentifier(input.issuer);

  return {
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    introspection_endpoint: `${base}/oauth/introspect`,
    revocation_endpoint: `${base}/oauth/revoke`,
    userinfo_endpoint: `${base}/oauth/userinfo`,
    // DCR (#149) lives on a sibling branch; advertise the URL so discovery
    // stays stable and clients can retry once the endpoint ships.
    registration_endpoint: `${base}/oauth/register`,
    jwks_uri: `${base}/.well-known/jwks.json`,

    response_types_supported: ['code'],
    // refresh_token is advertised eagerly: a sibling branch is implementing
    // the grant handler. Token endpoint still rejects unsupported grants.
    // The token-exchange grant (RFC 8693, ADR-007 §2) powers agent
    // on-behalf-of delegation; only agent clients may use it (handler-gated).
    grant_types_supported: [
      'authorization_code',
      'client_credentials',
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:token-exchange',
    ],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    introspection_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    revocation_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    scopes_supported: Array.from(input.scopesSupported ?? DEFAULT_SCOPES_SUPPORTED),
    // Public subject identifiers — no pairwise salts today.
    subject_types_supported: ['public'],
    // #309: reflects the keys actually configured/published. `['EdDSA']` by
    // default; `['RS256','EdDSA']` when an RS256 key is present (RS256 is the
    // default ID-token signature then). MUST match the JWKS.
    id_token_signing_alg_values_supported: Array.from(
      input.idTokenSigningAlgValuesSupported ?? DEFAULT_ID_TOKEN_SIGNING_ALG_VALUES
    ),
    // RFC 8707 §3: advertise Resource Indicator support. Clients that want
    // audience-scoped tokens can rely on this metadata flag.
    resource_indicators_supported: true,
    // RFC 9207 §3 (#282): an AS that emits `iss` in authorization responses
    // MUST advertise it, so clients know they can (and should) validate the
    // parameter instead of ignoring an unrecognised one. Hard-coded true
    // rather than configurable: /oauth/authorize emits `iss` unconditionally
    // — a deployment cannot turn it off, so the flag cannot go stale. Set on
    // the AS metadata so `buildOpenIdConfiguration` inherits it too. The
    // upcoming MCP authorization revision requires this validation, and
    // RFC 9207 signals a future SHOULD→MUST upgrade.
    authorization_response_iss_parameter_supported: true,
    // CIMD (draft-ietf-oauth-client-id-metadata-document-00 / MCP
    // 2025-11-25): advertise that an https-URL `client_id` resolves to a
    // metadata document fetched on demand. Only emitted when enabled so a
    // deployment that turns CIMD off does not over-advertise.
    ...(input.clientIdMetadataDocumentSupported
      ? { client_id_metadata_document_supported: true }
      : {}),
  };
}

/**
 * OIDC Discovery 1.0 document. Superset of the AS metadata with a handful
 * of OIDC-specific fields. Reuses the same base to avoid drift between
 * the two endpoints.
 */
export function buildOpenIdConfiguration(input: DiscoveryMetadataInput): Record<string, unknown> {
  const asMetadata = buildAuthorizationServerMetadata(input);

  return {
    ...asMetadata,
    // OIDC Core §5.1 — `sub` is always emitted. `nonce` is echoed in the ID
    // token when the client supplies it (OIDC Core §3.1.3.6). `name` is emitted
    // when the user has a display name set. This list MUST stay consistent with
    // the ID token (token endpoint) and the userinfo response.
    // Discovery §3 lists claims the OP "MAY be able to supply" — conditional
    // emission is compliant. Since #229, email/email_verified are released
    // only when a VERIFIED email attribute exists (omitted entirely
    // otherwise), so they stay listed here unchanged.
    claims_supported: [
      'sub',
      'iss',
      'aud',
      'exp',
      'iat',
      'nonce',
      'email',
      'email_verified',
      'name',
    ],
    // We only issue compact-serialized JWT access tokens; IdP-signed userinfo
    // JWTs are not yet supported, so userinfo_signing_alg_values_supported
    // is intentionally omitted rather than emitted as `['none']`.
  };
}

/**
 * Canonicalise a configured issuer URL into THE authorization server's issuer
 * identifier — the exact string published as `issuer` in discovery metadata.
 *
 * The only transformation is dropping a trailing slash (RFC 8414 §2). It is
 * deliberately NOT a URL normalisation: the value is never round-tripped
 * through `new URL(...)`, which would case-fold the authority, elide default
 * ports and rewrite percent-encoding.
 *
 * This is the shared choke point for #282: `/oauth/authorize` derives the
 * RFC 9207 `iss` response parameter from the SAME function over the SAME
 * source (`fastify.jwtUtils.getIssuer()`), so the redirect value is
 * byte-identical to the advertised `issuer`. Clients compare the two by simple
 * string comparison (RFC 9207 §2.4, RFC 3986 §6.2.1) and MUST NOT normalise
 * before comparing — a one-character divergence is a failed authorization, so
 * this must stay the only place the issuer string is shaped.
 */
export function resolveIssuerIdentifier(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}
