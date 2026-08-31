import { createHash } from 'node:crypto';

import { InvalidClientError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { env } from '../../config/env';
import { TOKEN_EXCHANGE_GRANT_TYPE } from '../schemas/oauth';
import {
  assertJwksMutuallyExclusive,
  CLIENT_JWKS_URI_MAX_LENGTH,
  clientJwkSetSchema,
} from './client-jwks';
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
  /**
   * RFC 7591 §2 tolerance: `grant_types` / `response_types` /
   * `token_endpoint_auth_method` accept ANY string values, not just the ones
   * QAuth implements. A CIMD document describes the client's capabilities
   * across every AS it talks to (e.g. claude.ai declares
   * `urn:ietf:params:oauth:grant-type:jwt-bearer`), so an unknown value is
   * not an error — rejecting the whole document over it breaks interop.
   * Materialisation (`toCimdClientInsert`) intersects with what QAuth
   * supports and fails only when nothing usable remains.
   */
  grant_types: z.array(z.string().min(1).max(128)).max(16).optional(),
  response_types: z.array(z.string().min(1).max(64)).max(8).optional(),
  token_endpoint_auth_method: z.string().min(1).max(64).optional(),
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
  /**
   * RFC 7591 §2 inline JWK Set (CIMD §6.2, #384). A CIMD client has no shared
   * secret with the AS — there was never a registration in which to issue one —
   * so publishing PUBLIC signature-verification keys in the metadata document
   * is the only way it can be a CONFIDENTIAL client. Together with
   * `token_endpoint_auth_method: 'private_key_jwt'` it upgrades the
   * materialised row from public to assertion-authenticated.
   *
   * TRUST: like every other field here this is self-asserted. What makes it
   * usable is the CIMD binding, not the field: the document was fetched from
   * the client_id URL over the SSRF-guarded https path and its own `client_id`
   * had to equal that URL byte-for-byte, so "the party controlling this URL
   * holds these keys" is exactly what it establishes — and that is precisely
   * the claim `private_key_jwt` needs. It confers no privilege beyond
   * authenticating as that URL: scopes stay empty, `is_agent` stays untrusted,
   * and `max_agent_mode` / `environment` remain operator-set.
   */
  jwks: clientJwkSetSchema.optional(),
  /**
   * RFC 7591 §2 `jwks_uri` — the by-reference alternative to {@link jwks},
   * dereferenced only through the SSRF-guarded fetcher and only for an
   * already-resolved client. Mutually exclusive with `jwks`; a document
   * carrying both is rejected at materialisation.
   */
  jwks_uri: z.string().min(1).max(CLIENT_JWKS_URI_MAX_LENGTH).optional(),
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
export type CimdGrantType =
  'authorization_code' | 'refresh_token' | 'client_credentials' | typeof TOKEN_EXCHANGE_GRANT_TYPE;

/**
 * RFC 8693 token exchange (#381) is admitted here for the same reason it is
 * admitted on DCR: the grant records only that the client MAY attempt an
 * exchange, and the exchange itself requires a valid subject token the client
 * already holds, preserves-or-narrows its scope and audience, and clamps any
 * reserved `agent:*` scope to the OPERATOR-set `max_agent_mode` — which CIMD
 * materialisation deliberately never sets. CIMD is the primary
 * client-registration path for MCP clients, so leaving the grant off it left
 * ADR-007 §2's whole delegation surface unreachable through the path the
 * project positions first.
 *
 * `urn:ietf:params:oauth:grant-type:jwt-bearer` stays OUT, matching DCR: its
 * capability depends on an operator-set issuer allowlist a CIMD document
 * cannot reach, so accepting it would advertise something the client can never
 * use.
 */
const SUPPORTED_CIMD_GRANT_TYPES: readonly CimdGrantType[] = [
  'authorization_code',
  'refresh_token',
  'client_credentials',
  TOKEN_EXCHANGE_GRANT_TYPE,
];

function isSupportedCimdGrantType(value: string): value is CimdGrantType {
  return (SUPPORTED_CIMD_GRANT_TYPES as readonly string[]).includes(value);
}

export interface CimdClientInsert {
  realmId: string;
  clientId: string;
  clientSecretHash: string;
  name: string;
  description: string;
  redirectUris: string[];
  grantTypes: CimdGrantType[];
  responseTypes: 'code'[];
  /**
   * `'none'` (public, PKCE-only) for every CIMD client that publishes no key
   * set — which is the overwhelming majority and the historical behaviour.
   * `'private_key_jwt'` only when the document BOTH declares that method and
   * publishes exactly one of `jwks` / `jwks_uri` (#384).
   */
  tokenEndpointAuthMethod: 'none' | 'private_key_jwt';
  /**
   * The client's PUBLIC assertion-signing keys, carried over from the metadata
   * document. NULL unless {@link tokenEndpointAuthMethod} resolved to
   * `private_key_jwt` — a key set is persisted only when it is actually the
   * client's authentication mechanism, so a stray `jwks` on a public client is
   * dropped rather than lying dormant in the row.
   */
  jwks: { keys: Record<string, unknown>[] } | null;
  /** By-reference form of the above; at most one of the two is ever non-null. */
  jwksUri: string | null;
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
  //
  // NOTE (ADR-008 §4, #196): likewise NO `environment` here, by design. The
  // environment policy profile is OPERATOR-SET and MUST NOT be self-asserted via
  // a CIMD document. `cimdDocumentSchema` defines no `environment` field (and
  // strips unknowns per RFC 7591 §3.2), so a document cannot declare itself
  // `development`. A CIMD client therefore takes the DB column's `production`
  // default — the strictest profile — until an operator widens it out of band.
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
 * Map a validated CIMD document to the persistence insert payload.
 *
 * A CIMD client has no SHARED SECRET — the AS never registered it, so there was
 * no exchange in which to issue one — and it therefore defaults to public
 * (`token_endpoint_auth_method=none`, `requirePkce=true`). Since #384 it has a
 * second option: a document that publishes PUBLIC keys and asks for
 * `private_key_jwt` (CIMD §6.2 / RFC 7591 §2) materialises as a CONFIDENTIAL
 * client that authenticates by assertion. PKCE stays required either way.
 *
 * Scopes are intentionally left empty: the authorize route's deny-by-default
 * `filterRequestedScopes` then grants only what the realm/consent layer
 * permits, exactly as for an unknown-scope DCR client.
 *
 * `clientSecretHash` is a non-verifiable sentinel (the column is NOT NULL) in
 * BOTH cases. No `client_secret_post`/`basic` attempt can ever succeed against
 * a CIMD client: the public row is rejected for its `'none'` method and the
 * assertion row for its `'private_key_jwt'` method, before the sentinel is even
 * reached.
 */
export function toCimdClientInsert(
  realmId: string,
  clientId: string,
  doc: CimdDocument,
  sentinelSecretHash: string
): CimdClientInsert {
  // The schema tolerates unknown grant/response types (RFC 7591 §2 — the
  // document describes the client's capabilities across every AS it talks
  // to); here we keep only what QAuth implements. A document that declares
  // values but none QAuth supports is unusable — invalid_client, so the
  // audit log says why instead of a code/token failing later.
  const declaredGrants = doc.grant_types ?? [];
  const supportedGrants = declaredGrants.filter(isSupportedCimdGrantType);
  if (declaredGrants.length > 0 && supportedGrants.length === 0) {
    throw new InvalidClientError('CIMD document declares no supported grant types');
  }
  const defaultedGrants: CimdGrantType[] =
    supportedGrants.length > 0 ? supportedGrants : ['authorization_code', 'refresh_token'];

  const declaredResponses = doc.response_types ?? [];
  const supportedResponses = declaredResponses.filter((value): value is 'code' => value === 'code');
  if (declaredResponses.length > 0 && supportedResponses.length === 0) {
    throw new InvalidClientError('CIMD document declares no supported response types');
  }
  const responseTypes: 'code'[] = supportedResponses.length > 0 ? supportedResponses : ['code'];

  // CIMD §6.2 / RFC 7591 §2 (#384). A document may register PUBLIC keys so the
  // client can authenticate with `private_key_jwt` instead of being restricted
  // to the public, PKCE-only posture it has had until now.
  //
  // Both forms at once is an RFC 7591 §2 violation and leaves it ambiguous which
  // key set is authoritative, so the document is rejected outright rather than
  // materialised with a guess.
  assertJwksMutuallyExclusive(doc.jwks, doc.jwks_uri, 'CIMD document');

  const hasKeySet = doc.jwks !== undefined || doc.jwks_uri !== undefined;
  // Fail SAFE, not merely closed: a document that asks for `private_key_jwt`
  // without publishing keys, or publishes keys without asking for the method,
  // falls back to the public posture it would have had before #384. Neither
  // half-configuration can authenticate an assertion (the verifier requires the
  // registered method AND a key set), so the fallback grants nothing — it just
  // avoids breaking a client over metadata it never needed us to act on.
  const usesPrivateKeyJwt = doc.token_endpoint_auth_method === 'private_key_jwt' && hasKeySet;

  // RFC 8693 token exchange requires a CONFIDENTIAL client: `POST /oauth/token`
  // authenticates the agent through the confidential client-auth path and
  // rejects a public client with `invalid_client` before any exchange logic
  // runs. A CIMD client is public unless it registered a key set for
  // `private_key_jwt` above, so materialising the grant on a public one would
  // record a capability it can never use (#381).
  //
  // DROPPED rather than rejected, matching how this function already treats a
  // grant QAuth does not implement — a CIMD document describes the client
  // across every AS it talks to, so an unusable-here grant is not an error.
  // The one exception is a document that has NOTHING left afterwards, which is
  // unusable for the same reason a document declaring no supported grant is,
  // and gets the same error.
  const grantTypes: CimdGrantType[] = usesPrivateKeyJwt
    ? defaultedGrants
    : defaultedGrants.filter((grant) => grant !== TOKEN_EXCHANGE_GRANT_TYPE);
  if (grantTypes.length === 0) {
    throw new InvalidClientError(
      'CIMD document declares only the token-exchange grant, which requires a confidential client'
    );
  }

  return {
    realmId,
    clientId,
    clientSecretHash: sentinelSecretHash,
    name: doc.client_name,
    description: 'CIMD client (client_id metadata document)',
    redirectUris: doc.redirect_uris,
    grantTypes,
    responseTypes,
    tokenEndpointAuthMethod: usesPrivateKeyJwt ? 'private_key_jwt' : 'none',
    jwks: usesPrivateKeyJwt && doc.jwks !== undefined ? doc.jwks : null,
    jwksUri: usesPrivateKeyJwt && doc.jwks_uri !== undefined ? doc.jwks_uri : null,
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
