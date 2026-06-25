import { randomBytes } from 'node:crypto';

import { InvalidClientError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

import { fetchAndValidateCimdDocument, isCimdClientId, toCimdClientInsert } from './cimd';

/**
 * Unified OAuth client resolution implementing the MCP 2025-11-25 client
 * priority order: **pre-registered (DB) → CIMD → DCR/manual**.
 *
 * - A pre-registered client_id (opaque string OR a URL already stored as a
 *   persisted client) always wins — an operator-provisioned record takes
 *   precedence over an on-demand metadata fetch. A previously-resolved CIMD
 *   client is itself a persisted row, so the second authorize for the same
 *   client_id short-circuits here without re-fetching unless its document
 *   cache has expired (`upsertCimdClient` then refreshes it).
 * - Otherwise, a URL-formatted client_id (https + path) is resolved as a
 *   CIMD client: fetched + validated (SSRF-guarded) then idempotently
 *   materialised into a row so the auth-code / refresh-token / audit foreign
 *   keys are satisfied.
 * - Anything else is an unknown client → `invalid_client`.
 *
 * RFC 7591 Dynamic Client Registration remains the documented fallback: a
 * DCR-registered client is simply a pre-registered record by the time it
 * reaches this resolver, so it is handled by the first branch.
 *
 * The returned object is the persisted `OAuthClient` row (structural
 * superset of `OAuthClientLike`), so the authorize / token / consent code
 * paths treat CIMD and pre-registered clients identically.
 */
export interface ResolvedClient {
  id: string;
  clientId: string;
  clientSecretHash: string;
  enabled: boolean;
  grantTypes: string[];
  responseTypes: string[];
  scopes: string[];
  audience: string[] | null;
  redirectUris: string[];
  tokenEndpointAuthMethod?: string;
  name: string;
  dynamicRegisteredAt: number | null;
  /**
   * ADR-007 §2 first-class agent classification. Surfaced here so the
   * authorize / token / consent handlers that already consume the resolved
   * client can gate agent-native behaviour (delegation, scope modes,
   * step-up) in later issues. Nothing is gated on it yet.
   */
  isAgent: boolean;
  metadata: Record<string, unknown> | null;
}

/** True iff the resolved client originated from a CIMD metadata document. */
export function isCimdClient(client: { metadata: Record<string, unknown> | null }): boolean {
  return client.metadata?.registrationType === 'cimd';
}

/**
 * True iff the client is classified as an autonomous AI agent (ADR-007 §2).
 * A thin, intention-revealing accessor for the `is_agent` column so later
 * agent-native gating reads `isAgentClient(client)` rather than poking the
 * raw field. Nothing gates on it yet.
 */
export function isAgentClient(client: { isAgent: boolean }): boolean {
  return client.isAgent === true;
}

/**
 * Build a non-verifiable sentinel for the NOT-NULL `client_secret_hash`
 * column of a CIMD (public) client, WITHOUT running Argon2id.
 *
 * CIMD clients are public (`token_endpoint_auth_method=none`, PKCE-only) and
 * have no shared secret, but the column is NOT NULL. The previous code ran
 * the CPU/memory-intensive Argon2id KDF here — on the *unauthenticated*,
 * on-demand `resolveClient` path — which is a denial-of-service / CPU- and
 * memory-exhaustion amplifier (OWASP API4 Unrestricted Resource Consumption):
 * an attacker drives any number of distinct CIMD `client_id`s through
 * authorize and forces one ~64MB Argon2id computation per resolution.
 *
 * We instead synthesise a well-formed argon2id PHC string from random bytes.
 * It is structurally a hash but corresponds to no known password, so
 * `verifyPassword` returns `false` for every input (it does not throw — see
 * @qauth-labs/server-password), i.e. any `client_secret` attempt fails
 * closed. Cost is a few `randomBytes` calls instead of a full KDF.
 */
export function cimdSentinelSecretHash(): string {
  const salt = randomBytes(16).toString('base64').replace(/=+$/, '');
  const digest = randomBytes(32).toString('base64').replace(/=+$/, '');
  // Mirrors the @node-rs/argon2 default params (m=65536,t=3,p=4) so the value
  // is shaped like a genuine hash; the salt/digest are random and unverifiable.
  return `$argon2id$v=19$m=65536,t=3,p=4$${salt}$${digest}`;
}

/**
 * Resolve a client_id to a client record, honouring the pre-registered →
 * CIMD priority. Returns `{ client: null, reason }` when no client can be
 * resolved so the caller controls the audit-log shape and error mapping.
 * CIMD-specific validation/SSRF/trust failures surface as
 * {@link InvalidClientError} from {@link fetchAndValidateCimdDocument}; they
 * are caught here and converted to a null + reason.
 */
export async function resolveClient(
  fastify: FastifyInstance,
  realmId: string,
  clientId: string
): Promise<{ client: ResolvedClient | null; reason?: string }> {
  // 1. Pre-registered (DB) — highest priority. A previously-materialised
  //    CIMD client also lives here once its first authorize succeeded.
  const persisted = await fastify.repositories.oauthClients.findByClientId(realmId, clientId);
  if (persisted) {
    return { client: persisted as unknown as ResolvedClient };
  }

  // 2. CIMD — URL-formatted client_id resolved + materialised on demand.
  if (isCimdClientId(clientId)) {
    try {
      const doc = await fetchAndValidateCimdDocument(fastify, clientId);

      // Public client → no usable secret. Store a non-verifiable sentinel
      // shaped like a real argon2id hash so the NOT-NULL column is satisfied
      // and any client_secret attempt fails closed. Built synchronously
      // (no Argon2id) — see cimdSentinelSecretHash for the DoS rationale.
      const sentinelSecretHash = cimdSentinelSecretHash();

      const insert = toCimdClientInsert(realmId, clientId, doc, sentinelSecretHash);
      const row = await fastify.repositories.oauthClients.upsertCimdClient(insert);
      return { client: row as unknown as ResolvedClient };
    } catch (err) {
      const reason = err instanceof InvalidClientError ? err.message : 'cimd_resolution_failed';
      return { client: null, reason };
    }
  }

  // 3. Unknown.
  return { client: null, reason: 'invalid_client' };
}
