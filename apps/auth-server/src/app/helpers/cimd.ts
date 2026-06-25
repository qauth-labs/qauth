import { createHash } from 'node:crypto';

import { InvalidClientError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { env } from '../../config/env';
import { SsrfBlockedError, ssrfSafeGet } from './ssrf-safe-fetch';

/**
 * Client ID Metadata Documents (CIMD) resolver.
 *
 * draft-ietf-oauth-client-id-metadata-document-00 + MCP Authorization rev
 * 2025-11-25. A CIMD `client_id` is itself an HTTPS URL; the authorization
 * server fetches the JSON document at that URL on demand instead of looking
 * up a persisted registration record. Client-resolution priority is
 * therefore: pre-registered (DB) → CIMD (URL client_id) → RFC 7591 DCR
 * (fallback) → manual.
 *
 * Security-critical invariants enforced here:
 *   - The document is fetched through {@link ssrfSafeGet} (SSRF guards,
 *     https-only, no redirects, DNS-pinned IP validation) — CIMD §6.
 *   - `client_id` inside the document MUST equal the URL it was fetched
 *     from, byte-for-byte. This binds the document to its own URL and
 *     prevents a document hosted at URL A from claiming to be client B.
 *   - The authorization request's `redirect_uri` MUST be one of the
 *     document's `redirect_uris` (exact match — no wildcards).
 *   - An optional deployment-configured domain trust policy gates which
 *     hosts may act as CIMD clients at all.
 *
 * CIMD clients are deliberately NOT persisted: there is no registration
 * record to spam, which is what neutralizes the open-DCR abuse surface
 * (ADR-007 §1 / spec tracking).
 */

/** Cache key namespace for stored CIMD documents in Redis. */
const CIMD_CACHE_PREFIX = 'cimd:doc:';

/**
 * CIMD metadata document shape. Mirrors the RFC 7591 client-metadata
 * vocabulary; the draft requires `client_id` and reuses 7591 field names.
 * We require the three fields the issue calls out (`client_id`,
 * `client_name`, `redirect_uris`) and accept the common optional subset.
 * Unknown fields are stripped (Zod default), per RFC 7591 §3.2 "servers
 * MUST ignore unrecognized metadata".
 */
export const cimdDocumentSchema = z.object({
  client_id: z.string().min(1).max(2048),
  client_name: z.string().min(1).max(255),
  redirect_uris: z.array(z.string().min(1).max(2048)).min(1).max(20),
  scope: z.string().max(2048).optional(),
  grant_types: z
    .array(z.enum(['authorization_code', 'refresh_token', 'client_credentials']))
    .max(8)
    .optional(),
  response_types: z
    .array(z.enum(['code']))
    .max(4)
    .optional(),
  token_endpoint_auth_method: z
    .enum(['none', 'client_secret_basic', 'client_secret_post'])
    .optional(),
  client_uri: z.string().max(2048).optional(),
  logo_uri: z.string().max(2048).optional(),
  tos_uri: z.string().max(2048).optional(),
  policy_uri: z.string().max(2048).optional(),
  /**
   * QAuth extension metadata (ADR-007 §2): the document declares itself an
   * autonomous AI-agent client. Unknown metadata fields are normally stripped
   * (RFC 7591 §3.2), so we accept this one explicitly to recognise the
   * indicator. Defaults to a standard (non-agent) client when absent.
   * Persisted to `oauth_clients.is_agent`; nothing is gated on it yet.
   *
   * TRUST: this is self-asserted, unverified client input — it comes from the
   * client's own externally-fetched metadata document, not anything the AS
   * established. The CIMD url==client_id binding authenticates *which* URL the
   * document belongs to, NOT the truthfulness of `is_agent`. Later gating must
   * treat it as untrusted (verify, don't trust) and default-deny, since a
   * client can also *omit* it to dodge agent-specific controls.
   */
  is_agent: z.boolean().optional(),
});

export type CimdDocument = z.infer<typeof cimdDocumentSchema>;

/**
 * Insert payload for a materialised CIMD client. The auth-code,
 * refresh-token, and audit-log tables all carry a NOT-NULL foreign key to
 * `oauth_clients.id`, so a CIMD client must be backed by a real row before a
 * code/token can be issued for it. We therefore idempotently upsert a row
 * keyed by (realm_id, client_id) — see `upsertCimdClient`. This is NOT open
 * registration: the row is keyed by the (validated, SSRF-checked) URL, so
 * re-resolving the same client_id updates one row instead of creating new
 * ones; there is no record to spam.
 */
export type CimdGrantType = 'authorization_code' | 'refresh_token' | 'client_credentials';

export interface CimdClientInsert {
  realmId: string;
  clientId: string;
  clientSecretHash: string;
  name: string;
  description: string;
  redirectUris: string[];
  grantTypes: CimdGrantType[];
  responseTypes: 'code'[];
  tokenEndpointAuthMethod: 'none';
  requirePkce: true;
  enabled: true;
  developerId: null;
  scopes: string[];
  /** ADR-007 §2 agent classification, mirrored from the metadata document. */
  isAgent: boolean;
  // NOTE (#184): no `maxAgentMode` here, by design. The agent scope-mode cap
  // is operator-set server state and MUST NOT be self-asserted via a CIMD
  // document. A CIMD client therefore defaults to a NULL cap (the DB column
  // default) — deny-by-default — so it can hold no `agent:*` scope until an
  // operator provisions a cap out of band. This is the epic #181 requirement:
  // never trust the client's own document for an escalation control.
  metadata: Record<string, unknown>;
}

/**
 * Whether a `client_id` is CIMD-formatted: an absolute https URL with a
 * non-root path component (the draft requires a path so a bare origin like
 * `https://example.com` is not mistaken for a metadata URL). Anything that
 * is not a parseable https URL with a path is treated as an opaque,
 * pre-registered client_id.
 */
export function isCimdClientId(clientId: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(clientId);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:') return false;
  // Require a path component beyond "/". A metadata document lives at a
  // specific path, not a bare origin.
  if (parsed.pathname === '' || parsed.pathname === '/') return false;
  // Fragments are meaningless for a fetch target and a sign of a malformed id.
  if (parsed.hash) return false;
  return true;
}

/**
 * Apply the configured domain trust policy to a CIMD client_id URL host.
 * Throws {@link InvalidClientError} when the host is not trusted. Runs
 * AFTER the SSRF / structural checks; it is a coarse-grained, operator-set
 * gate, not a security boundary on its own.
 */
function enforceTrustPolicy(host: string): void {
  if (env.CIMD_TRUST_POLICY === 'accept-any-https') return;

  // allowlist policy
  const h = host.toLowerCase();
  const trusted = env.CIMD_TRUSTED_DOMAINS.some((entry) => {
    if (entry.startsWith('*.')) {
      const suffix = entry.slice(1); // ".example.com"
      return h.endsWith(suffix) && h.length > suffix.length;
    }
    return h === entry;
  });
  if (!trusted) {
    throw new InvalidClientError('client_id host is not in the CIMD trust allowlist');
  }
}

/**
 * Parse `Cache-Control: max-age` / `Expires` from a response header map and
 * clamp to the configured min(default)/max bounds. Returns a TTL in
 * seconds. `no-store` / `no-cache` → 0 (do not cache).
 */
export function resolveCacheTtlSeconds(headers: Record<string, string>): number {
  const cacheControl = headers['cache-control'];
  if (cacheControl) {
    const cc = cacheControl.toLowerCase();
    if (cc.includes('no-store') || cc.includes('no-cache')) return 0;
    const maxAge = cc.match(/max-age\s*=\s*(\d+)/);
    if (maxAge) {
      const seconds = Number.parseInt(maxAge[1], 10);
      if (Number.isFinite(seconds)) {
        return Math.min(Math.max(seconds, 0), env.CIMD_CACHE_MAX_TTL);
      }
    }
  }

  const expires = headers['expires'];
  if (expires) {
    const expMs = Date.parse(expires);
    if (Number.isFinite(expMs)) {
      const ttl = Math.floor((expMs - Date.now()) / 1000);
      return Math.min(Math.max(ttl, 0), env.CIMD_CACHE_MAX_TTL);
    }
  }

  return Math.min(env.CIMD_CACHE_DEFAULT_TTL, env.CIMD_CACHE_MAX_TTL);
}

function cacheKey(clientId: string): string {
  // Hash the URL so the Redis key is bounded and free of reserved chars.
  return CIMD_CACHE_PREFIX + createHash('sha256').update(clientId).digest('hex');
}

/**
 * Map a validated CIMD document to the persistence insert payload. CIMD
 * clients are always public (PKCE) — the AS has no shared secret with a
 * client it never registered, so `token_endpoint_auth_method=none` and
 * `requirePkce=true`. Scopes are intentionally left empty: the authorize
 * route's deny-by-default `filterRequestedScopes` then grants only what the
 * realm/consent layer permits, exactly as for an unknown-scope DCR client.
 *
 * `clientSecretHash` is a non-verifiable sentinel (the column is NOT NULL).
 * Because the client is public, no `client_secret_post`/`basic` attempt can
 * ever succeed against it.
 */
export function toCimdClientInsert(
  realmId: string,
  clientId: string,
  doc: CimdDocument,
  sentinelSecretHash: string
): CimdClientInsert {
  const grantTypes: CimdGrantType[] =
    doc.grant_types && doc.grant_types.length > 0
      ? doc.grant_types
      : ['authorization_code', 'refresh_token'];
  const responseTypes: 'code'[] =
    doc.response_types && doc.response_types.length > 0 ? doc.response_types : ['code'];

  return {
    realmId,
    clientId,
    clientSecretHash: sentinelSecretHash,
    name: doc.client_name,
    description: 'CIMD client (client_id metadata document)',
    redirectUris: doc.redirect_uris,
    grantTypes,
    responseTypes,
    tokenEndpointAuthMethod: 'none',
    requirePkce: true,
    enabled: true,
    developerId: null,
    scopes: [],
    // ADR-007 §2: carry the agent classification from the metadata document.
    isAgent: doc.is_agent ?? false,
    metadata: {
      registrationType: 'cimd',
      client_id_metadata_url: clientId,
      ...(doc.client_uri ? { client_uri: doc.client_uri } : {}),
      ...(doc.logo_uri ? { logo_uri: doc.logo_uri } : {}),
      ...(doc.tos_uri ? { tos_uri: doc.tos_uri } : {}),
      ...(doc.policy_uri ? { policy_uri: doc.policy_uri } : {}),
    },
  };
}

/**
 * Read a cached, already-validated CIMD document from Redis. Returns null on
 * a miss or any cache error (cache is best-effort; a miss just re-fetches).
 */
async function readCache(fastify: FastifyInstance, clientId: string): Promise<CimdDocument | null> {
  try {
    const raw = await fastify.redis.get(cacheKey(clientId));
    if (!raw) return null;
    const parsed = cimdDocumentSchema.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

async function writeCache(
  fastify: FastifyInstance,
  clientId: string,
  doc: CimdDocument,
  ttlSeconds: number
): Promise<void> {
  if (ttlSeconds <= 0) return;
  try {
    await fastify.redis.set(cacheKey(clientId), JSON.stringify(doc), 'EX', ttlSeconds);
  } catch {
    // Best-effort cache; ignore write failures.
  }
}

/**
 * Fetch + validate a CIMD `client_id` URL into a parsed metadata document.
 *
 * Steps (all of which can reject):
 *   1. CIMD enabled + structural client_id check.
 *   2. Domain trust policy (operator-set allowlist / accept-any-https).
 *   3. Document cache hit → return cached doc (HTTP cache-header behaviour).
 *   4. SSRF-guarded https GET (no redirects, DNS-pinned, size/time-bounded).
 *   5. 200 + valid JSON + required fields.
 *   6. **client_id == document URL** (exact) — the core CIMD binding.
 *   7. Cache the validated doc per the response cache headers.
 *
 * Throws {@link InvalidClientError} (RFC 6749 §5.2 `invalid_client`) for any
 * failure so the caller surfaces a uniform error and never leaks why the
 * document was rejected; the message carries detail for the caller's audit
 * log only.
 *
 * Returns the validated document; persistence into a client row is the
 * caller's responsibility (see client-resolution.ts).
 */
export async function fetchAndValidateCimdDocument(
  fastify: FastifyInstance,
  clientId: string
): Promise<CimdDocument> {
  if (!env.CIMD_ENABLED) {
    throw new InvalidClientError();
  }
  if (!isCimdClientId(clientId)) {
    throw new InvalidClientError();
  }

  const host = new URL(clientId).hostname;
  enforceTrustPolicy(host);

  // Cache hit: serve without re-fetching (HTTP cache-header behaviour).
  const cached = await readCache(fastify, clientId);
  if (cached) {
    return cached;
  }

  let result;
  try {
    result = await ssrfSafeGet(clientId, {
      timeoutMs: env.CIMD_FETCH_TIMEOUT_MS,
      maxBytes: env.CIMD_MAX_DOCUMENT_BYTES,
      allowPrivateAddresses: env.CIMD_ALLOW_PRIVATE_ADDRESSES,
    });
  } catch (err) {
    if (err instanceof SsrfBlockedError) {
      // Distinguish in the error chain for the caller's audit log, but still
      // present invalid_client to the client.
      throw new InvalidClientError(`CIMD fetch blocked: ${err.message}`);
    }
    throw new InvalidClientError('CIMD document fetch failed');
  }

  if (result.status !== 200) {
    throw new InvalidClientError(`CIMD document fetch returned ${result.status}`);
  }

  let json: unknown;
  try {
    json = JSON.parse(result.body);
  } catch {
    throw new InvalidClientError('CIMD document is not valid JSON');
  }

  const parsed = cimdDocumentSchema.safeParse(json);
  if (!parsed.success) {
    throw new InvalidClientError('CIMD document is missing required fields');
  }

  // Core CIMD binding: the document's own client_id MUST equal the URL it
  // was fetched from, exactly. This stops a document hosted at URL A from
  // impersonating client B.
  if (parsed.data.client_id !== clientId) {
    throw new InvalidClientError('CIMD client_id does not match the document URL');
  }

  const ttl = resolveCacheTtlSeconds(result.headers);
  await writeCache(fastify, clientId, parsed.data, ttl);

  return parsed.data;
}
