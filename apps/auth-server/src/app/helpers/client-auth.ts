import { BadRequestError, InvalidCredentialsError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';

/**
 * Minimal OAuth client view used by helper functions in this file.
 * Mirrors the shape returned by `fastify.repositories.oauthClients.findByClientId`
 * without forcing a direct dependency on `@qauth-labs/infra-db`.
 */
export type OAuthClientLike = {
  id: string;
  clientId: string;
  clientSecretHash: string;
  enabled: boolean;
  grantTypes: string[];
  scopes: string[];
  audience: string[] | null;
};

/**
 * Credentials extracted from an OAuth client authentication request.
 * RFC 6749 2.3.1 — either `client_secret_post` (body) or
 * `client_secret_basic` (HTTP Basic Authorization header).
 */
export interface ExtractedClientCredentials {
  clientId: string;
  clientSecret: string;
  method: 'client_secret_post' | 'client_secret_basic';
}

/**
 * Parse `Authorization: Basic <b64>` header per RFC 6749 2.3.1.
 * Values are `application/x-www-form-urlencoded`-decoded after base64 decoding
 * — in that encoding, spaces are represented as `+` (not `%20`), so we
 * translate `+` → ` ` before calling decodeURIComponent.
 *
 * Returns null if the header is missing or not Basic-scheme.
 */
function parseBasicAuthHeader(
  authHeader: string | undefined
): { clientId: string; clientSecret: string } | null {
  if (!authHeader) return null;
  const match = authHeader.match(/^Basic\s+([A-Za-z0-9+/=_-]+)$/);
  if (!match) return null;
  let decoded: string;
  try {
    decoded = Buffer.from(match[1], 'base64').toString('utf8');
  } catch {
    return null;
  }
  const sep = decoded.indexOf(':');
  if (sep === -1) return null;
  const clientId = decodeURIComponent(decoded.slice(0, sep).replace(/\+/g, ' '));
  const clientSecret = decodeURIComponent(decoded.slice(sep + 1).replace(/\+/g, ' '));
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret };
}

/**
 * Extract client credentials from an OAuth token/introspection request.
 *
 * RFC 6749 Section 2.3 is explicit: "The authorization server MUST NOT accept
 * more than one mechanism of client authentication in any given request."
 * So when the Authorization header carries Basic credentials, the body MUST
 * NOT also carry a `client_secret`, and any `client_id` in the body must
 * match the one decoded from the header.
 */
export function extractClientCredentials(
  request: FastifyRequest,
  bodyClientId: string | undefined,
  bodyClientSecret: string | undefined
): ExtractedClientCredentials {
  const basic = parseBasicAuthHeader(request.headers.authorization);

  if (basic) {
    // Reject any additional body-based auth material — RFC 6749 2.3.
    if (bodyClientSecret || (bodyClientId && bodyClientId !== basic.clientId)) {
      throw new InvalidCredentialsError('Client authentication failed');
    }
    return {
      clientId: basic.clientId,
      clientSecret: basic.clientSecret,
      method: 'client_secret_basic',
    };
  }

  if (bodyClientId && bodyClientSecret) {
    return {
      clientId: bodyClientId,
      clientSecret: bodyClientSecret,
      method: 'client_secret_post',
    };
  }

  throw new InvalidCredentialsError('Client authentication failed');
}

/**
 * Look up and authenticate a confidential OAuth client.
 * Throws `InvalidCredentialsError` with the generic RFC 6749 5.2 message
 * regardless of which check failed (timing-safe handled upstream).
 */
export async function authenticateClient(
  fastify: FastifyInstance,
  realmId: string,
  creds: ExtractedClientCredentials
): Promise<OAuthClientLike> {
  const client = await fastify.repositories.oauthClients.findByClientId(realmId, creds.clientId);
  if (!client || !client.enabled) {
    throw new InvalidCredentialsError('Client authentication failed');
  }
  const valid = await fastify.passwordHasher.verifyPassword(
    client.clientSecretHash,
    creds.clientSecret
  );
  if (!valid) {
    throw new InvalidCredentialsError('Client authentication failed');
  }
  return client;
}

/**
 * Validate that every requested scope is in the client's allowed list.
 * Empty allowed-list means "no custom scopes configured" — we accept nothing
 * (safer default for machine grants).
 *
 * Returns the validated list (may be empty). Throws `BadRequestError` with
 * OAuth's `invalid_scope` code (RFC 6749 5.2 → HTTP 400) when any requested
 * scope is outside the client's allowlist.
 */
export function validateScopes(
  requestedScopeString: string | undefined,
  allowedScopes: string[]
): string[] {
  if (!requestedScopeString || requestedScopeString.trim().length === 0) {
    return [];
  }
  const requested = requestedScopeString.split(/\s+/).filter((s) => s.length > 0);
  const disallowed = requested.filter((s) => !allowedScopes.includes(s));
  if (disallowed.length > 0) {
    throw new BadRequestError(
      `invalid_scope: ${disallowed.join(' ')} not permitted for this client`
    );
  }
  return requested;
}

/**
 * Resolve the `aud` JWT claim for a client.
 * Returns the client's configured audience (string[] from DB) when set,
 * otherwise falls back to the client_id per RFC 8707 light-mode.
 */
export function resolveAudience(client: OAuthClientLike): string | string[] {
  if (client.audience && Array.isArray(client.audience) && client.audience.length > 0) {
    // Collapse single-item arrays to string for compact JWTs.
    return client.audience.length === 1 ? client.audience[0] : client.audience;
  }
  return client.clientId;
}
