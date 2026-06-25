import { InvalidClientError, InvalidScopeError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { isAgentClient, resolveClient } from './client-resolution';
import { type AgentMode, findExceedingAgentScopes, parseAgentMode } from './scope-modes';

/** Maximum length of a single audience URI (defensive cap, RFC 8707 leaves this open). */
const AUDIENCE_ENTRY_MAX_LENGTH = 256;
/** Maximum number of audience entries per client (defensive cap to bound JWT size). */
const AUDIENCE_MAX_ENTRIES = 20;

const audienceSchema = z
  .array(z.string().min(1).max(AUDIENCE_ENTRY_MAX_LENGTH))
  .max(AUDIENCE_MAX_ENTRIES);

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
  /**
   * Token endpoint auth method (RFC 7591). `'none'` identifies public
   * clients (PKCE, native/SPA) that present only `client_id` at /token.
   * When absent we conservatively treat the client as confidential.
   */
  tokenEndpointAuthMethod?: string;
  /**
   * ADR-007 §2 (#182) self-asserted agent classification. Optional here so
   * the structural type stays a superset of older callers; absent ⇒ NOT an
   * agent (fail-closed via {@link isAgentClient}).
   */
  isAgent?: boolean;
  /**
   * ADR-007 §2 (#184) server-side maximum agent scope mode. NULL/absent ⇒ no
   * agent-mode scope is permitted (default-deny). This is operator-set
   * server state, NOT client input — it is the independent server-side
   * criterion that, together with `isAgent`, gates agent-mode scopes.
   */
  maxAgentMode?: AgentMode | null;
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
  const match = authHeader.match(/^Basic\s+([A-Za-z0-9+/]+={0,2})$/);
  if (!match) return null;
  try {
    const decoded = Buffer.from(match[1], 'base64').toString('utf8');
    const sep = decoded.indexOf(':');
    if (sep === -1) return null;
    const clientId = decodeURIComponent(decoded.slice(0, sep).replace(/\+/g, ' '));
    const clientSecret = decodeURIComponent(decoded.slice(sep + 1).replace(/\+/g, ' '));
    if (!clientId || !clientSecret) return null;
    return { clientId, clientSecret };
  } catch {
    return null;
  }
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
      throw new InvalidClientError();
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

  throw new InvalidClientError();
}

/**
 * Look up and authenticate a confidential OAuth client.
 * Throws `InvalidClientError` (RFC 6749 5.2 `invalid_client`) regardless of
 * which check failed — timing-safe padding handled upstream.
 */
export async function authenticateClient(
  fastify: FastifyInstance,
  realmId: string,
  creds: ExtractedClientCredentials
): Promise<OAuthClientLike> {
  const client = await fastify.repositories.oauthClients.findByClientId(realmId, creds.clientId);
  if (!client || !client.enabled) {
    throw new InvalidClientError();
  }
  const valid = await fastify.passwordHasher.verifyPassword(
    client.clientSecretHash,
    creds.clientSecret
  );
  if (!valid) {
    throw new InvalidClientError();
  }
  return client;
}

/**
 * Authenticate a client for grant types that permit public clients:
 * `authorization_code` (PKCE-bound) and `refresh_token` (ownership-bound).
 *
 * OAuth 2.1 §4.1.3 / §4.3.1 / RFC 6749 §6: confidential clients present
 * full credentials (same rules as `authenticateClient`); public clients
 * (`token_endpoint_auth_method: 'none'`) present only `client_id`.
 *
 * Returns the client row regardless of confidential-vs-public
 * classification. The caller MUST still enforce the grant-specific
 * binding — PKCE `code_verifier` for authorization_code, refresh-token
 * ownership + rotation for refresh_token.
 */
export async function authenticateClientPublicOrConfidential(
  fastify: FastifyInstance,
  realmId: string,
  request: FastifyRequest,
  bodyClientId: string | undefined,
  bodyClientSecret: string | undefined
): Promise<OAuthClientLike> {
  // Determine whether the request carries any secret material (Basic
  // header or body client_secret). If it does, run the confidential
  // authentication path — mixing auth modes must remain rejected.
  const hasBasic = /^Basic\s/i.test(request.headers.authorization ?? '');
  if (hasBasic || bodyClientSecret) {
    const creds = extractClientCredentials(request, bodyClientId, bodyClientSecret);
    return authenticateClient(fastify, realmId, creds);
  }

  // Public-client path: only `client_id` supplied. Resolve via the shared
  // pre-registered → CIMD chain. A CIMD client (https-URL client_id) is
  // materialised here too, so a direct token call whose authorize-time row
  // was never created (or whose document cache expired) still resolves.
  // CIMD clients are public by construction (token_endpoint_auth_method:
  // 'none'), so they satisfy the public-client requirement below.
  if (!bodyClientId) {
    throw new InvalidClientError();
  }
  const { client } = await resolveClient(fastify, realmId, bodyClientId);
  if (!client || !client.enabled) {
    throw new InvalidClientError();
  }
  if (client.tokenEndpointAuthMethod !== 'none') {
    // Confidential client missing its secret.
    throw new InvalidClientError();
  }
  return client as unknown as OAuthClientLike;
}

/**
 * Agent context consumed by the scope-mode cap (ADR-007 §2, #184). Carries
 * exactly the two server-side inputs the cap needs:
 *   - `isAgent` — the fail-closed classification (pass `isAgentClient(client)`).
 *   - `maxAgentMode` — the operator-set ceiling (NULL ⇒ no agent mode).
 */
export interface AgentScopeContext {
  isAgent: boolean;
  maxAgentMode: AgentMode | null;
}

/**
 * Build the {@link AgentScopeContext} for a resolved client, applying the
 * fail-closed accessor and parsing the stored cap. A non-agent client, or a
 * client whose stored `maxAgentMode` is null / unknown, yields a context that
 * denies every reserved agent-mode scope.
 *
 * `maxAgentMode` may arrive as a string from the DB column; {@link parseAgentMode}
 * fails closed to `null` for any unrecognised value.
 */
export function toAgentScopeContext(
  client: { isAgent?: boolean; maxAgentMode?: string | AgentMode | null } | null | undefined
): AgentScopeContext {
  return {
    isAgent: isAgentClient(client),
    maxAgentMode: parseAgentMode(client?.maxAgentMode ?? null),
  };
}

/**
 * Reject any reserved agent-mode scope (`agent:readonly|admin|exec`) that the
 * client may not hold (ADR-007 §2, #184). Runs as a deny-by-default gate in
 * front of the ordinary allowlist: a reserved-mode scope is permitted ONLY
 * when the client is a verified agent AND the mode is within its server-side
 * cap. See `scope-modes.ts` for the full trust-boundary rationale.
 *
 * Throws `InvalidScopeError` (RFC 6749 §5.2 `invalid_scope`) — the same error
 * shape `validateScopes` raises — so callers need no new error handling.
 */
export function enforceAgentScopeCap(
  requestedScopes: readonly string[],
  agent: AgentScopeContext
): void {
  const exceeding = findExceedingAgentScopes(requestedScopes, agent.isAgent, agent.maxAgentMode);
  if (exceeding.length > 0) {
    throw new InvalidScopeError(`${exceeding.join(' ')} exceeds the client's agent scope mode`);
  }
}

/**
 * Validate that every requested scope is in the client's allowed list.
 * Empty allowed-list means "no custom scopes configured" — we accept nothing
 * (safer default for machine grants).
 *
 * When an {@link AgentScopeContext} is supplied, the reserved agent-mode
 * scopes are additionally gated by {@link enforceAgentScopeCap} BEFORE the
 * allowlist check, so a capped agent can never obtain a higher mode and a
 * non-agent client can never obtain any agent-mode scope (default-deny). The
 * parameter is optional so existing two-argument callers compile unchanged;
 * callers that resolve a full client SHOULD pass `toAgentScopeContext(client)`.
 *
 * Returns the validated list (may be empty). Throws `InvalidScopeError`
 * (RFC 6749 5.2 `invalid_scope`, HTTP 400) when any requested scope is
 * outside the client's allowlist or exceeds its agent scope mode.
 */
export function validateScopes(
  requestedScopeString: string | undefined,
  allowedScopes: string[],
  agent?: AgentScopeContext
): string[] {
  if (!requestedScopeString || requestedScopeString.trim().length === 0) {
    return [];
  }
  const requested = requestedScopeString.split(/\s+/).filter((s) => s.length > 0);
  // Deny-by-default agent-mode cap first: an agent-mode scope that the client
  // may not hold is rejected even if it also appears in the raw allowlist.
  if (agent) {
    enforceAgentScopeCap(requested, agent);
  }
  const disallowed = requested.filter((s) => !allowedScopes.includes(s));
  if (disallowed.length > 0) {
    throw new InvalidScopeError(`${disallowed.join(' ')} not permitted for this client`);
  }
  return requested;
}

/**
 * Resolve the `aud` JWT claim for a client.
 *
 * Precedence (RFC 8707 §2 then RFC 8707 light-mode fallback):
 *   1. `resource` — resource indicators bound to the grant (auth code /
 *      refresh token) or sent with a client_credentials request. When
 *      present, overrides the pre-configured client audience so tokens
 *      are always scoped to the caller-requested resource.
 *   2. `client.audience` — configured per-client in the DB (machine
 *      clients that don't send `resource`).
 *   3. `client.clientId` — last-resort light-mode default.
 *
 * Validates the stored JSONB shape at read time for (2); falls back to
 * (3) when the stored value is malformed (belt-and-braces beside the DB
 * CHECK constraint).
 */
export function resolveAudience(client: OAuthClientLike, resource?: string[]): string | string[] {
  if (resource && resource.length > 0) {
    return resource.length === 1 ? resource[0] : resource;
  }
  const parsed = audienceSchema.safeParse(client.audience);
  if (!parsed.success || parsed.data.length === 0) {
    return client.clientId;
  }
  return parsed.data.length === 1 ? parsed.data[0] : parsed.data;
}
