/**
 * PostgreSQL Enum Types
 *
 * Centralized enum definitions for type safety and database constraints
 */

import { FIRST_PARTY_PROFILES, REALM_HOST_KINDS } from '@qauth-labs/shared-validation';
import { pgEnum } from 'drizzle-orm/pg-core';

/**
 * OAuth 2.1 Token Endpoint Authentication Methods
 * RFC 7591: OAuth 2.0 Dynamic Client Registration Protocol
 */
export const tokenEndpointAuthMethodEnum = pgEnum('token_endpoint_auth_method', [
  'client_secret_post', // Client credentials in POST body (default)
  'client_secret_basic', // Client credentials in HTTP Basic Auth header
  'private_key_jwt', // JWT signed with private key
  'none', // Public client (no authentication)
]);

/**
 * SSL Requirement Levels
 * Controls when SSL/TLS is required
 */
export const sslRequiredEnum = pgEnum('ssl_required', [
  'none', // SSL never required
  'external', // SSL required for external requests only
  'all', // SSL required for all requests
]);

/**
 * PKCE Code Challenge Methods
 * RFC 7636: Proof Key for Code Exchange by OAuth Public Clients
 *
 * Note: Only S256 is supported. Plain text method is insecure and not supported.
 */
export const codeChallengeMethodEnum = pgEnum('code_challenge_method', [
  'S256', // SHA256 (only supported method)
]);

/**
 * OAuth 2.1 Grant Types
 * RFC 8252: OAuth 2.0 for Native Apps
 *
 * Supported grant types:
 * - authorization_code: Authorization Code Flow (with PKCE)
 * - refresh_token: Refresh Token Flow
 * - client_credentials: Client Credentials Flow (for service-to-service)
 * - urn:ietf:params:oauth:grant-type:jwt-bearer: RFC 7523 JWT assertion grant,
 *   used by QAuth to CONSUME an Identity Assertion Authorization Grant
 *   (ID-JAG) minted by a trusted enterprise IdP (ADR-011). Registering it on a
 *   client only records that the client MAY present an assertion — the grant
 *   itself is inert unless `ID_JAG_ENABLED=true` AND the assertion's issuer is
 *   on `ID_JAG_TRUSTED_ISSUERS`. Both gates are fail-closed.
 * - urn:ietf:params:oauth:grant-type:token-exchange: RFC 8693 on-behalf-of
 *   delegation (ADR-007 §2, #183). Registering it records only that the client
 *   MAY attempt an exchange; it confers no authority. Every consequence is
 *   still decided by the handler's gates — `isAgentClient(client)`, a
 *   cryptographically valid subject token, preserve-or-narrow on scope and
 *   audience, a bounded `act` chain, and the OPERATOR-set `max_agent_mode`
 *   ceiling that self-registration deliberately never sets.
 *
 *   This value was previously absent, with a note here claiming eligibility was
 *   "decided by the agent classification + `max_agent_mode` gates in the
 *   handler, not by a per-client registered grant type". That was not what
 *   shipped: `handleTokenExchange` gates on
 *   `client.grantTypes.includes(TOKEN_EXCHANGE_GRANT_TYPE)` as GATE 1's second
 *   half, so the registered grant type is load-bearing. With the value missing
 *   from every provisioning path, the grant was advertised in
 *   `grant_types_supported` and enforced at the token endpoint while being
 *   reachable only by writing the JSONB column out of band (#381).
 *
 * Note: OAuth 2.1 removed deprecated grant types (password, implicit).
 */
const GRANT_TYPES = [
  'authorization_code', // Authorization Code Flow (with PKCE)
  'refresh_token', // Refresh Token Flow
  'client_credentials', // Client Credentials Flow
  'urn:ietf:params:oauth:grant-type:jwt-bearer', // RFC 7523 assertion grant (ID-JAG, ADR-011)
  'urn:ietf:params:oauth:grant-type:token-exchange', // RFC 8693 delegation (ADR-007 §2, #381)
] as const;

export const grantTypeEnum = pgEnum('grant_type', GRANT_TYPES);

export type GrantType = (typeof GRANT_TYPES)[number];

/**
 * OAuth 2.1 Response Types
 * Controls what type of response is returned from authorization endpoint
 */
const RESPONSE_TYPES = [
  'code', // Authorization Code (only supported in OAuth 2.1)
] as const;

export const responseTypeEnum = pgEnum('response_type', RESPONSE_TYPES);

export type ResponseType = (typeof RESPONSE_TYPES)[number];

/**
 * Agent scope modes (ADR-007 §2, issue #184).
 *
 * The coarse capability ceiling an agent client may be granted, ordered
 * lowest → highest privilege: ReadOnly ⊂ Admin ⊂ Exec (for cap purposes).
 * Persisted on `oauth_clients.max_agent_mode` as the server-side MAXIMUM mode
 * a client may request via the reserved `agent:*` scopes. NULL ⇒ no agent
 * mode permitted (default-deny). This is operator-set server state, NOT
 * client input — it is the independent server-side criterion that gates the
 * self-asserted `is_agent` flag.
 */
const AGENT_MODES = [
  'readonly', // read-only access
  'admin', // administrative (ranks above readonly for the cap only)
  'exec', // action-taking (most privileged)
] as const;

export const agentModeEnum = pgEnum('agent_mode', AGENT_MODES);

export type AgentMode = (typeof AGENT_MODES)[number];

/**
 * First-party client profiles (ADR-017 Decision 2, issue #631), persisted on
 * `oauth_clients.first_party_profile`. The list is `FIRST_PARTY_PROFILES` from
 * `@qauth-labs/shared-validation`, the same list `resolveFirstPartyProfile()`
 * and the seed manifest read, so the three cannot drift. ADR-017 phase F4 adds
 * `native_attested`. Operator-set server state, never client input.
 */
export const firstPartyProfileEnum = pgEnum('first_party_profile', FIRST_PARTY_PROFILES);

/**
 * Deployment environment / policy profile (ADR-008, issue #196).
 *
 * Selects an environment-aware **policy profile** — a coordinated bundle of
 * security and operational defaults — rather than N independent knobs. Ordered
 * here laxest → strictest (`development` < `staging` < `production`); the
 * effective profile for a client is always the STRICTER of the client's own
 * value and its realm ceiling (see `resolveEnvironmentPolicy`).
 *
 * - `development` — relaxes security-relevant conveniences (static API keys,
 *   localhost redirects, long token lifespans, lenient rate limits, open DCR,
 *   relaxed agent step-up / T3 headers). Local work only.
 * - `staging` — keeps PRODUCTION-GRADE security; relaxes only operational
 *   conveniences (e.g. lenient rate limits for load testing). Promoting
 *   dev→staging surfaces security posture before production.
 * - `production` — the strict baseline and the T3 hardening bundle. This is the
 *   FAIL-SAFE default everywhere: an unset client or realm value resolves to
 *   `production`, so misconfiguration fails closed.
 *
 * The relaxation direction is OPERATOR-SET only — never self-asserted via DCR
 * (`POST /oauth/register`) or a CIMD metadata document — mirroring how
 * `max_agent_mode` and `dynamic_registration_allowed_scopes` are handled.
 */
const ENVIRONMENTS = [
  'development', // laxest — local convenience, security relaxations apply here only
  'staging', // production-grade security; operational conveniences relaxed
  'production', // strictest — fail-safe default; the T3 hardening bundle
] as const;

export const environmentEnum = pgEnum('environment', ENVIRONMENTS);

export type Environment = (typeof ENVIRONMENTS)[number];

/**
 * Lifecycle status of a realm key (ADR-019 Decision 9, issue #461).
 *
 * Shared by `realm_keys` and its public mirror `realm_public_keys`:
 *
 * - `next` — generated and (for a published purpose) pre-published in the
 *   JWKS, but not yet used to sign or encrypt.
 * - `active` — the key that signs or encrypts for its realm, purpose, scope
 *   and algorithm. At most one per that tuple (a partial unique index).
 * - `retired` — no longer signs or encrypts; still verifies or decrypts until
 *   it is unpublished.
 * - `compromised` — retired in an emergency: leaves the JWKS at once and its
 *   `kid` is denylisted. Always carries `compromised_at` (a CHECK).
 */
const REALM_KEY_STATUSES = ['next', 'active', 'retired', 'compromised'] as const;

export const realmKeyStatusEnum = pgEnum('realm_key_status', REALM_KEY_STATUSES);

export type RealmKeyStatus = (typeof REALM_KEY_STATUSES)[number];

/**
 * Kind of a `realm_hosts` row (ADR-019 Decision 1, issue #470): `primary` is
 * the realm's issuer host, `endpoint` an extra name for server-to-server
 * callers. The list is `REALM_HOST_KINDS` from `@qauth-labs/shared-validation`,
 * the same list `normaliseRealmHost()` checks a host against, so the two
 * cannot drift.
 */
export const realmHostKindEnum = pgEnum('realm_host_kind', REALM_HOST_KINDS);

/**
 * Who performed an admin operation recorded in `admin_audit_log` (ADR-019
 * Decision 7, issue #448):
 *
 * - `human_admin` — an admin account, signed in with a passkey.
 * - `service_account` — an operator-realm service account (`client_credentials`).
 * - `break_glass_operator` — the break-glass CLI, run on a host that holds the
 *   database credentials and the KEK. The actor id is the operating-system user.
 * - `host_operator` — a host-side tool that is not break-glass, such as the
 *   seed script. The actor id is the operating-system user.
 */
const ADMIN_ACTOR_KINDS = [
  'human_admin',
  'service_account',
  'break_glass_operator',
  'host_operator',
] as const;

export const adminActorKindEnum = pgEnum('admin_actor_kind', ADMIN_ACTOR_KINDS);

export type AdminActorKind = (typeof ADMIN_ACTOR_KINDS)[number];

/**
 * Class of an admin operation, from the permission catalog (ADR-019 Decision
 * 7): each class is reached by its own scope, `qauth:admin:read`,
 * `qauth:admin:write` or `qauth:admin:security`.
 */
const ADMIN_OPERATION_CLASSES = ['read', 'write', 'security'] as const;

export const adminOperationClassEnum = pgEnum('admin_operation_class', ADMIN_OPERATION_CLASSES);

export type AdminOperationClass = (typeof ADMIN_OPERATION_CLASSES)[number];

/**
 * How an admin operation ended. A `succeeded` row commits in the transaction
 * of the change it records; `failed` and `denied` rows record an operation
 * whose change did not happen.
 */
const ADMIN_AUDIT_OUTCOMES = ['succeeded', 'failed', 'denied'] as const;

export const adminAuditOutcomeEnum = pgEnum('admin_audit_outcome', ADMIN_AUDIT_OUTCOMES);

export type AdminAuditOutcome = (typeof ADMIN_AUDIT_OUTCOMES)[number];

/**
 * Audit Log Event Types
 * Categorizes audit events for filtering and analysis
 */
export const auditEventTypeEnum = pgEnum('audit_event_type', [
  'auth', // Authentication events (login, logout, register)
  'token', // Token events (issued, refreshed, revoked)
  'client', // Client events (created, updated, deleted)
  'security', // Security events (failed login, suspicious activity)
  'user', // User management events
  'realm', // Realm management events
  // Reserved (ADR-007 §2, #186) for a future DEDICATED agent-action event type.
  // The current agent-native emit sites (token-exchange, step-up elevation,
  // client_credentials) keep their existing `token`/`auth` category and carry
  // agent attribution via the `actor_client_id` / `delegation_chain` /
  // `scope_mode` COLUMNS — not by changing `event_type` — so existing queries
  // filtering on those categories stay unaffected. This value lets a
  // purpose-built agent event be added later without a second enum migration.
  'agent',
]);
