import { randomBytes } from 'node:crypto';

import { InvalidClientError, InvalidRequestError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

import { fetchAndValidateCimdDocument, isCimdClientId, toCimdClientInsert } from './cimd';
import { cimdPolicyOf } from './cimd-policy';
import type { RealmRow } from './request-realm';
import type { AgentMode } from './scope-modes';

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
  /** The owner's on/off switch (`PATCH /api/clients/:id`). */
  enabled: boolean;
  /**
   * Operator-only suspension (ANT-2026-DR5XI3LV). Never written by any route
   * and never by CIMD re-resolution. Read through `isClientUsable` (`helpers/client-status.ts`).
   */
  suspended: boolean;
  grantTypes: string[];
  responseTypes: string[];
  scopes: string[];
  audience: string[] | null;
  /**
   * ADR-011 (#434) ID-JAG mint targets and redeemable resources. Operator-set
   * through the seed manifest only; `[]` for every DCR, developer-API and CIMD
   * row, which denies both ID-JAG paths.
   */
  idJagTargets: string[];
  /**
   * RFC 9449 §5.2 `dpop_bound_access_tokens` (#480): refuse a token request
   * without a DPoP proof while `DPOP_ENABLED` is on. Operator-set through the
   * seed manifest only; `false` for every DCR, developer-API and CIMD row.
   */
  dpopBoundAccessTokens: boolean;
  redirectUris: string[];
  tokenEndpointAuthMethod?: string;
  /**
   * RFC 7591 §2 key set of a `private_key_jwt` client (#384), inline or by
   * reference. Surfaced here so the assertion verifier authenticates against
   * the row this resolver returned rather than a separate, un-resolved read.
   */
  jwks?: { keys: Record<string, unknown>[] } | null;
  jwksUri?: string | null;
  name: string;
  dynamicRegisteredAt: number | null;
  /**
   * ADR-007 §2 first-class agent classification. Surfaced here so the
   * authorize / token / consent handlers that already consume the resolved
   * client can gate agent-native behaviour (delegation, scope modes,
   * step-up). Self-asserted, untrusted (see schema column note) — agent-mode
   * gating uses it via the fail-closed {@link isAgentClient} accessor AND the
   * server-side `maxAgentMode` cap below, never on its own.
   */
  isAgent: boolean;
  /**
   * ADR-007 §2 (#184) server-side maximum agent scope mode. NULL ⇒ no agent
   * mode permitted (deny-by-default). Operator-set server state, not client
   * input. Consumed by `toAgentScopeContext` / `findExceedingAgentScopes` to
   * bound the reserved `agent:*` scopes the client may request.
   */
  maxAgentMode: AgentMode | null;
  /**
   * ADR-008 §2 (#196/#197) the client's declared environment / policy profile.
   * Surfaced here so the authorize / token / consent handlers that already
   * consume the resolved client can resolve the effective environment policy
   * via `resolveEnvironmentPolicy(client, realm)` without a second DB read.
   * OPERATOR-SET, never self-asserted; the resolver fails safe to `production`
   * for any absent / unknown value. Persisted rows and CIMD-materialised rows
   * both carry the NOT NULL `production`-default column.
   */
  environment: string;
  /**
   * `oauth_clients.provisioned_by_operator` (ANT-2026-O8U3P920): true only for
   * a client an operator provisioned, the one kind whose redirect URI receives
   * authorization error responses by automatic redirect
   * (`helpers/authorization-error.ts`). Always false for a CIMD row.
   */
  provisionedByOperator: boolean;
  /**
   * `oauth_clients.verified_domain` (#593): the domain an admin set on the
   * client, which the screens show first while `provisionedByOperator` holds
   * (`helpers/client-display.ts`). Optional so a partially shaped object
   * type-checks; absent reads as none.
   */
  verifiedDomain?: string | null;
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
 *
 * Fail-closed by design: returns true ONLY for a strict `isAgent === true`,
 * so a missing / null / undefined field (e.g. a partially-shaped object that
 * omits the flag) reads as NOT an agent rather than throwing. This is the safe default for a
 * classification gate. It does NOT make `is_agent` trustworthy — the value is
 * self-asserted client input (see the schema column note); downstream gating
 * must still verify rather than trust, and the escalation risk is a client
 * *omitting* the flag, which this accessor treats as non-agent.
 */
export function isAgentClient(client: { isAgent?: boolean } | null | undefined): boolean {
  return client?.isAgent === true;
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

/** The document-derived columns `upsertCimdClient` refreshes on conflict. */
const CIMD_REFRESHED_FIELDS = [
  'name',
  'description',
  'redirectUris',
  'grantTypes',
  'responseTypes',
  'tokenEndpointAuthMethod',
  'jwks',
  'jwksUri',
  'isAgent',
  'metadata',
  'enabled',
] as const;

/**
 * JSON with object keys sorted at every level, so jsonb key order cannot matter.
 *
 * Keys are compared by UTF-16 code unit, never collated. The order only has to
 * be deterministic, and some keys are a document author's (JWK member names,
 * and whatever a stored row kept from an earlier document): `localeCompare`
 * is quadratic in a run of out-of-order combining marks, once per comparison
 * (ANT-2026-AF8IKIPI), and it calls canonically equivalent names equal, which
 * leaves their order to the input.
 */
function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v as Record<string, unknown>).sort(([a], [b]) =>
            a < b ? -1 : a > b ? 1 : 0
          )
        )
      : v
  );
}

/**
 * True when a materialised CIMD row already holds every document-derived value
 * a fresh resolution would write — so re-resolution costs no write when the
 * document has not changed.
 */
function cimdRowMatchesInsert(row: object, insert: object): boolean {
  const current = row as Record<string, unknown>;
  const next = insert as Record<string, unknown>;
  return CIMD_REFRESHED_FIELDS.every(
    (field) => canonicalJson(current[field] ?? null) === canonicalJson(next[field] ?? null)
  );
}

/**
 * The refusal of a `client_id` {@link resolveClient} resolves to no client, at
 * the authorization and consent endpoints (#513). RFC 6749 §4.1.2.1 forbids
 * redirecting it, so it is answered in place, as `invalid_request`: the
 * parameter names no client this realm can use. Why (unknown, a CIMD document
 * refused) goes to the event, never to the wire.
 */
export function unresolvedClientError(): InvalidRequestError {
  return new InvalidRequestError('client_id does not name a client of this realm');
}

/**
 * Resolve a client_id to a client record of `realm`, the realm the request
 * resolved to (ADR-019 Decision 1), honouring the pre-registered → CIMD
 * priority. Returns `{ client: null, reason }` when no client can be
 * resolved so the caller controls the audit-log shape and error mapping.
 * CIMD-specific validation/SSRF/trust failures surface as
 * {@link InvalidClientError} from {@link fetchAndValidateCimdDocument}; they
 * are caught here and converted to a null + reason.
 *
 * The CIMD branch follows the realm's CIMD policy (`cimdPolicyOf`, #534),
 * read off the row the caller holds: a realm that switched CIMD off resolves
 * a URL `client_id` as it does any unknown one.
 *
 * @throws PolicyValidationError when the CIMD branch runs and the realm's
 *   stored policies are not a valid policy document: a server error, as for
 *   the token lifetimes (#527), not an unknown client
 */
export async function resolveClient(
  fastify: FastifyInstance,
  realm: RealmRow,
  clientId: string
): Promise<{ client: ResolvedClient | null; reason?: string }> {
  const realmId = realm.id;
  // 1. Pre-registered (DB) — highest priority.
  const persisted = await fastify.repositories.oauthClients.findByClientId(realmId, clientId);
  if (persisted && !isCimdClient(persisted)) {
    return { client: persisted };
  }

  // 2. CIMD — URL-formatted client_id resolved + materialised on demand, and
  //    RE-resolved on every use once materialised (ADR-012 §3: the metadata
  //    document is the management surface). A materialised row is only a
  //    cache of the document. Serving it without re-resolving would freeze the
  //    client at its first authorize: document edits, key rotation, a host
  //    removed from the realm's trust allowlist and CIMD switched off in the
  //    realm would never take effect, because all of those live in
  //    `fetchAndValidateCimdDocument`. That call is cheap within the cache
  //    TTL: the switch and trust policy run first, then a cache read.
  if (isCimdClientId(clientId) || persisted) {
    // The realm's switch and trust policy (#534), read outside the `try`: a
    // stored policy document the schema refuses is the server's error, not
    // a reason to call the client unknown.
    const policy = cimdPolicyOf(fastify, realm);
    try {
      const doc = await fetchAndValidateCimdDocument(fastify, clientId, policy);

      // Public client → no usable secret. Store a non-verifiable sentinel
      // shaped like a real argon2id hash so the NOT-NULL column is satisfied
      // and any client_secret attempt fails closed. Built synchronously
      // (no Argon2id) — see cimdSentinelSecretHash for the DoS rationale.
      // (Ignored on conflict: the upsert never rewrites an existing secret.)
      const sentinelSecretHash = cimdSentinelSecretHash();

      const insert = toCimdClientInsert(realmId, clientId, doc, sentinelSecretHash);
      // An operator's `enabled = false` survives re-resolution; the document
      // can never re-enable a client the server disabled. This snapshot
      // predates the fetch above, so the upsert ANDs it with the live row
      // rather than writing it back (ANT-2026-SSI34ODQ). `suspended` is not
      // part of the insert at all and the upsert never names it, so a
      // re-resolution can neither set nor clear an operator's suspension
      // (ANT-2026-DR5XI3LV); `.returning()` hands back the live value.
      const data = persisted ? { ...insert, enabled: persisted.enabled } : insert;
      // Unchanged document (the common, cache-served case) → no write.
      if (persisted && cimdRowMatchesInsert(persisted, data)) {
        return { client: persisted };
      }
      const row = await fastify.repositories.oauthClients.upsertCimdClient(data);
      return { client: row };
    } catch (err) {
      // `errorDescription` before `message` (#365): since `InvalidClientError`
      // carries the registered RFC 6749 §5.2 token as its message, reading
      // `message` here would collapse every distinct CIMD failure into the
      // string `invalid_client`. This `reason` is server-side diagnostic text —
      // it reaches the audit log and the operator's log, never a client — so it
      // wants the detail, and falls back to the token when the throw carried
      // none (which is what `helpers/client-auth.ts` throws deliberately).
      const reason =
        err instanceof InvalidClientError
          ? (err.errorDescription ?? err.message)
          : 'cimd_resolution_failed';
      return { client: null, reason };
    }
  }

  // 3. Unknown.
  return { client: null, reason: 'invalid_client' };
}
