/**
 * RFC 9728 — OAuth 2.0 Protected Resource Metadata (PRM).
 *
 * The RS publishes a JSON document describing itself and the authorization
 * server(s) that protect it. MCP clients fetch it (advertised via the
 * `WWW-Authenticate: ... resource_metadata="…"` challenge, or discovered at
 * the well-known location as a fallback) to learn which AS to authenticate
 * with — the entry point of the MCP authorization handshake.
 */

/** Well-known suffix for Protected Resource Metadata (RFC 9728 §3.1). */
export const PRM_WELL_KNOWN_PREFIX = '/.well-known/oauth-protected-resource';

/** Strip a single trailing slash; leaves the root path `/` untouched-ish. */
function stripTrailingSlash(value: string): string {
  return value.length > 1 && value.endsWith('/') ? value.slice(0, -1) : value;
}

/**
 * RFC 9728 Protected Resource Metadata document. Permissive extra keys are
 * allowed; the fields below are what QAuth-backed MCP clients consume.
 */
export interface ProtectedResourceMetadata {
  /** This resource's identifier (RFC 9728 §3.2 `resource`). */
  resource: string;
  /** Issuer identifier(s) of the AS(es) that can authorize this resource. */
  authorization_servers: string[];
  /** Scopes the resource understands (advertised for client convenience). */
  scopes_supported?: string[];
  /** Supported ways to present the token; QAuth resources use the header. */
  bearer_methods_supported: string[];
  /** RFC 9728 §3.2 — where to learn more (docs link). */
  resource_documentation?: string;
}

export interface BuildMetadataInput {
  /** Resource identifier (`aud` value tokens must carry). */
  resource: string;
  /** AS issuer identifier. */
  authorizationServer: string;
  /** Scopes to advertise as `scopes_supported`. */
  scopesSupported?: string[];
  /** Optional documentation URL. */
  resourceDocumentation?: string;
}

/**
 * Build the RFC 9728 PRM document. Pure (no I/O) so route handlers control
 * caching and tests can assert the wire shape directly.
 */
export function buildProtectedResourceMetadata(
  input: BuildMetadataInput
): ProtectedResourceMetadata {
  const metadata: ProtectedResourceMetadata = {
    resource: stripTrailingSlash(input.resource),
    authorization_servers: [stripTrailingSlash(input.authorizationServer)],
    bearer_methods_supported: ['header'],
  };
  if (input.scopesSupported && input.scopesSupported.length > 0) {
    metadata.scopes_supported = [...input.scopesSupported];
  }
  if (input.resourceDocumentation) {
    metadata.resource_documentation = input.resourceDocumentation;
  }
  return metadata;
}

/**
 * Compute the well-known PRM **path** for a resource, per RFC 9728 §3.1.
 *
 * For a resource with no path component the document lives at
 * `/.well-known/oauth-protected-resource`. For a resource that has a path
 * (e.g. `https://host/mcp/memory`), the path is inserted **after** the
 * well-known prefix: `/.well-known/oauth-protected-resource/mcp/memory`. This
 * lets a single host expose distinct metadata per protected resource.
 *
 * @returns the path (always starting with the well-known prefix).
 */
export function metadataPathForResource(resource: string): string {
  let pathname: string;
  try {
    pathname = new URL(resource).pathname;
  } catch {
    // Not parseable as a URL — treat as opaque, root path.
    pathname = '/';
  }
  // Only hierarchical (http/https) URLs have a `/`-rooted path we can insert
  // after the well-known prefix. Opaque URIs (e.g. `urn:example:resource`)
  // expose a non-rooted `pathname`; for those we serve the bare prefix.
  if (!pathname.startsWith('/')) {
    return PRM_WELL_KNOWN_PREFIX;
  }
  const normalized = stripTrailingSlash(pathname);
  if (normalized === '' || normalized === '/') {
    return PRM_WELL_KNOWN_PREFIX;
  }
  return `${PRM_WELL_KNOWN_PREFIX}${normalized}`;
}

/**
 * Absolute URL where this resource's PRM document is served — the value
 * advertised in the `resource_metadata` challenge parameter (RFC 9728 §5.1).
 */
export function metadataUrlForResource(resource: string): string {
  const path = metadataPathForResource(resource);
  try {
    const url = new URL(resource);
    return `${url.origin}${path}`;
  } catch {
    return path;
  }
}
