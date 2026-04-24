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
}

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
  const base = stripTrailingSlash(input.issuer);

  return {
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    introspection_endpoint: `${base}/oauth/introspect`,
    userinfo_endpoint: `${base}/oauth/userinfo`,
    // DCR (#149) lives on a sibling branch; advertise the URL so discovery
    // stays stable and clients can retry once the endpoint ships.
    registration_endpoint: `${base}/oauth/register`,
    jwks_uri: `${base}/.well-known/jwks.json`,

    response_types_supported: ['code'],
    // refresh_token is advertised eagerly: a sibling branch is implementing
    // the grant handler. Token endpoint still rejects unsupported grants.
    grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    introspection_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    scopes_supported: Array.from(input.scopesSupported ?? DEFAULT_SCOPES_SUPPORTED),
    // Public subject identifiers — no pairwise salts today.
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['EdDSA'],
    // RFC 8707 §3: advertise Resource Indicator support. Clients that want
    // audience-scoped tokens can rely on this metadata flag.
    resource_indicators_supported: true,
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
    // OIDC Core §5.1 — `sub` is always emitted.
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'email_verified'],
    // We only issue compact-serialized JWT access tokens; IdP-signed userinfo
    // JWTs are not yet supported, so userinfo_signing_alg_values_supported
    // is intentionally omitted rather than emitted as `['none']`.
  };
}

function stripTrailingSlash(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}
