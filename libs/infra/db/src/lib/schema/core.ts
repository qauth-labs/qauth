import { relations, sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  index,
  jsonb,
  pgTable,
  text,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import {
  agentModeEnum,
  environmentEnum,
  GrantType,
  ResponseType,
  sslRequiredEnum,
  tokenEndpointAuthMethodEnum,
} from './enums';
import { EPOCH_MS_NOW, JSONB_EMPTY_ARRAY } from './sql-helpers';

/**
 * Password Policy Configuration
 * Defines password requirements for a realm
 */
export interface PasswordPolicy {
  minLength?: number; // Minimum password length (default: 8)
  requireUppercase?: boolean; // Require at least one uppercase letter
  requireLowercase?: boolean; // Require at least one lowercase letter
  requireDigits?: number; // Minimum number of digits required
  requireSpecialChars?: boolean; // Require at least one special character
  forbiddenPasswords?: string[]; // List of forbidden passwords (e.g., "password", "12345678")
  maxLength?: number; // Maximum password length
  preventReuse?: number; // Number of previous passwords to prevent reuse
}

/**
 * A JSON Web Key Set as persisted on an OAuth client (RFC 7517 §5) — the
 * `oauth_clients.jwks` column's shape.
 *
 * Deliberately structural (`Record<string, unknown>` members) rather than a
 * pinned JWK union: the DB layer stores whatever the operator registered and
 * MUST NOT be the component that decides which key types / algorithms are
 * acceptable. That decision belongs to the verifier at the auth layer, which
 * validates each key before use and rejects anything outside its allowlist.
 *
 * The column below repeats this shape inline rather than referencing the alias.
 * That is not an oversight: naming it inside `$type<>` puts the alias into the
 * inferred type of every downstream helper that returns a client row, and
 * `tsc --emitDeclarationOnly` then cannot write a portable import for it across
 * the workspace's nested-symlink package layout (TS2883). Keep the two in sync.
 */
export type ClientJwkSet = { keys: Record<string, unknown>[] };

export const realms = pgTable(
  'realms',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    name: varchar('name', { length: 255 }).notNull().unique(),
    enabled: boolean('enabled').notNull().default(true),
    accessTokenLifespan: bigint('access_token_lifespan', { mode: 'number' }).default(900),
    refreshTokenLifespan: bigint('refresh_token_lifespan', { mode: 'number' }).default(604800),
    sslRequired: sslRequiredEnum('ssl_required').default('external'),
    verifyEmail: boolean('verify_email').notNull().default(true),
    registrationAllowed: boolean('registration_allowed').notNull().default(false),
    loginWithEmailAllowed: boolean('login_with_email_allowed').notNull().default(true),
    duplicateEmailsAllowed: boolean('duplicate_emails_allowed').notNull().default(false),
    passwordPolicy: jsonb('password_policy').$type<PasswordPolicy | null>(),
    ssoIdleTimeout: bigint('sso_idle_timeout', { mode: 'number' }),
    ssoMaxLifespan: bigint('sso_max_lifespan', { mode: 'number' }),
    revokeRefreshToken: boolean('revoke_refresh_token').notNull().default(false),
    refreshTokenMaxReuse: bigint('refresh_token_max_reuse', { mode: 'number' }).default(0),
    defaultLocale: varchar('default_locale', { length: 10 }),
    supportedLocales: jsonb('supported_locales').default(JSONB_EMPTY_ARRAY).$type<unknown[]>(),
    /**
     * Scopes that may be requested by clients created via Dynamic Client
     * Registration (RFC 7591). This is the hard cap enforced by the
     * `/oauth/register` endpoint: any scope outside this list is rejected
     * with `invalid_client_metadata`. Admin-level scopes (e.g. `memory:admin`)
     * and tenant-scoped grants (e.g. `akinon:*`) MUST NOT appear here.
     */
    dynamicRegistrationAllowedScopes: jsonb('dynamic_registration_allowed_scopes')
      .notNull()
      .default(JSONB_EMPTY_ARRAY)
      .$type<string[]>(),
    /**
     * Realm-level CEILING on how lax any client in this realm may be
     * (ADR-008 §2, issue #196). A client's effective environment is the
     * STRICTER of its own `oauth_clients.environment` and this ceiling, so a
     * realm set to `production` forces every client to the production profile
     * regardless of the client's own field — the ceiling can never be exceeded.
     * This mirrors `dynamic_registration_allowed_scopes` as a realm-level hard
     * cap on what a client may obtain.
     *
     * FAIL-SAFE DEFAULT: `production`. A fresh realm caps everything at the
     * strictest profile until an operator deliberately widens it, so an
     * unconfigured deployment is hardened and misconfiguration fails closed.
     *
     * OPERATOR-SET ONLY: the relaxation direction is set via seed/manifest,
     * admin API, or realm config — never self-asserted by a client. The single
     * resolver `resolveEnvironmentPolicy(client, realm)` consumes this value;
     * policy checkpoints (#197/#97/#98) consult the resolver, not this column
     * directly. Defaulting NOT NULL keeps the migration backward-compatible:
     * every existing realm becomes `production` (the prior, strict behaviour).
     */
    maxEnvironmentLaxity: environmentEnum('max_environment_laxity').notNull().default('production'),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    index('idx_realms_enabled')
      .on(t.enabled)
      .where(sql`${t.enabled} = true`),
  ]
);

export const users = pgTable(
  'users',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    enabled: boolean('enabled').notNull().default(true),
    firstName: varchar('first_name', { length: 255 }),
    lastName: varchar('last_name', { length: 255 }),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    lastLoginAt: bigint('last_login_at', { mode: 'number' }),
  },
  (t) => [
    index('idx_users_realm_id').on(t.realmId),
    index('idx_users_enabled')
      .on(t.enabled)
      .where(sql`${t.enabled} = true`),
  ]
);

export const oauthClients = pgTable(
  'oauth_clients',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    clientId: varchar('client_id', { length: 255 }).notNull(),
    clientSecretHash: text('client_secret_hash').notNull(),
    name: varchar('name', { length: 255 }).notNull(),
    description: text('description'),
    redirectUris: jsonb('redirect_uris').notNull().$type<string[]>(),
    scopes: jsonb('scopes').notNull().default(JSONB_EMPTY_ARRAY).$type<string[]>(),
    audience: jsonb('audience').$type<string[] | null>(),
    enabled: boolean('enabled').notNull().default(true),
    requirePkce: boolean('require_pkce').notNull().default(true),
    tokenEndpointAuthMethod: tokenEndpointAuthMethodEnum('token_endpoint_auth_method')
      .notNull()
      .default('client_secret_post'),
    /**
     * Inline JWK Set holding the client's PUBLIC signature-verification keys,
     * used to verify an RFC 7523 §2.2 `private_key_jwt` client assertion
     * (issue #384). NULL for every client that authenticates with a shared
     * secret or is public — which is every pre-existing row, so this column is
     * backward-compatible by construction.
     *
     * MUTUALLY EXCLUSIVE with {@link oauthClients.jwksUri}. RFC 7591 §2 permits
     * either form but forbids both ("The `jwks_uri` and `jwks` parameters MUST
     * NOT both be present in the same request or response"). That rule is
     * enforced at the VALIDATION layer, not by a DB CHECK, so the server can
     * return a structured OAuth error naming the offending parameter instead
     * of surfacing a constraint violation.
     *
     * PUBLIC KEYS ONLY. A key set containing a private component (`d`, or any
     * other private JWK member) MUST be rejected before it ever reaches this
     * column — the AS never needs a client's private key, so accepting one is
     * pure liability. The verifier must also re-check on read (defence in
     * depth) rather than trusting what was persisted.
     */
    jwks: jsonb('jwks').$type<{ keys: Record<string, unknown>[] } | null>(),
    /**
     * HTTPS URL of the client's JWK Set (RFC 7591 §2), the by-reference
     * alternative to {@link oauthClients.jwks}. Mutually exclusive with it
     * (see above). NULL for every existing client.
     *
     * SECURITY: this is an operator/registration-supplied URL that the AS will
     * dereference, so every fetch MUST go through `ssrfSafeGet` with the same
     * guards the CIMD path uses — https-only, no redirect following, DNS-pinned
     * IP validation, byte cap, timeout, non-200 rejection — and the result MUST
     * be cached with a bounded TTL. It is NEVER read from a token request; only
     * from the persisted client record resolved by an authenticated client_id.
     */
    jwksUri: text('jwks_uri'),
    grantTypes: jsonb('grant_types')
      .notNull()
      .default(sql`'["authorization_code","refresh_token"]'::jsonb`)
      .$type<GrantType[]>(),
    responseTypes: jsonb('response_types')
      .notNull()
      .default(sql`'["code"]'::jsonb`)
      .$type<ResponseType[]>(),
    developerId: uuid('developer_id').references(() => users.id, { onDelete: 'set null' }),
    /**
     * First-class classification flag for autonomous AI-agent clients
     * (ADR-007 §2 agent-native authorization). When true, the auth server
     * may later treat the client differently for delegation eligibility,
     * scope modes, step-up policy, and per-agent audit — all gated by
     * separate, later issues. This issue only persists + plumbs the flag;
     * nothing is gated on it yet.
     *
     * Orthogonal to confidential/public: an agent client can be either.
     * Defaults to false so every existing row stays a standard client and
     * the migration is backward-compatible.
     *
     * TRUST BOUNDARY — this value is SELF-ASSERTED, UNVERIFIED client input.
     * It is set by the client itself: in its own DCR request body, or in its
     * own externally-fetched CIMD metadata document. It is NOT an
     * authenticated property the AS established. Downstream agent gating
     * (token exchange #183, scope modes #184, step-up #185) MUST treat it as
     * untrusted (verify, don't trust). Note the real escalation direction is
     * a client *omitting* the flag to dodge agent-specific controls, so any
     * such gating must default-deny / fail-closed and must not assume the
     * flag is truthful or present.
     */
    isAgent: boolean('is_agent').notNull().default(false),
    /**
     * Server-side MAXIMUM agent scope mode (ADR-007 §2, issue #184). Bounds
     * the reserved `agent:*` scopes a client may request: ReadOnly ⊂ Admin ⊂
     * Exec. NULL (the default) means NO agent mode is permitted — deny by
     * default — so every existing row, and any client that never had a cap
     * provisioned, can hold no `agent:*` scope.
     *
     * Unlike `is_agent` (self-asserted client input), this is OPERATOR-SET
     * SERVER STATE — set via seed/admin provisioning, not by the client's own
     * DCR/CIMD document. It is the independent server-side criterion the epic
     * #181 security requirement calls for: agent-mode scopes require BOTH the
     * agent classification AND this cap, never the client's self-declaration
     * alone. A client omitting `is_agent` to dodge controls simply fails the
     * classification and gets no agent scope; a client cannot raise its own
     * cap because this column is not part of the registration request.
     */
    maxAgentMode: agentModeEnum('max_agent_mode'),
    /**
     * The client's declared deployment environment / policy profile
     * (ADR-008 §2, issue #196). Selects a coordinated bundle of security and
     * operational defaults (static API keys, localhost redirects, PKCE, token
     * lifespans, refresh rotation, rate limits, open DCR, agent step-up, T3
     * headers — see ADR-008 §5) instead of a dozen independent switches.
     *
     * This is only the client's REQUESTED laxity; the effective profile is the
     * STRICTER of this value and the realm's `max_environment_laxity` ceiling,
     * computed by `resolveEnvironmentPolicy(client, realm)`. A realm pinned to
     * `production` overrides a client that asks for `development`.
     *
     * FAIL-SAFE DEFAULT: `production`. An unconfigured client gets the strictest
     * profile, never the laxest — the relaxed posture is opt-in and bounded, the
     * default everywhere is the hardened one. NOT NULL keeps the migration
     * backward-compatible: every existing row becomes `production`.
     *
     * OPERATOR-SET, NOT SELF-ASSERTED. Unlike `is_agent` (self-asserted client
     * input), the relaxation direction here is set ONLY by an operator —
     * seed/manifest, admin API, or realm config. It is NOT accepted from
     * `POST /oauth/register` (DCR) or a CIMD metadata document: a client cannot
     * declare itself `development` to escape production gates, exactly as a
     * client cannot self-grant `max_agent_mode`. New clients created via
     * DCR/CIMD therefore always get this column's `production` default. Mirror
     * this guarantee at every future write path that persists a client.
     */
    environment: environmentEnum('environment').notNull().default('production'),
    /**
     * Set when the client was created via dynamic client registration (RFC 7591).
     * Null for hand-provisioned / first-party clients. Consumed by the consent
     * screen to show a "newly registered" phishing-defense badge — callers
     * MUST treat null as "not dynamic" and therefore not new.
     */
    dynamicRegisteredAt: bigint('dynamic_registered_at', { mode: 'number' }),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    lastUsedAt: bigint('last_used_at', { mode: 'number' }),
  },
  (t) => [
    uniqueIndex('idx_oauth_clients_realm_client_id_unique').on(t.realmId, t.clientId),
    index('idx_oauth_clients_client_id').on(t.clientId),
    index('idx_oauth_clients_realm_id').on(t.realmId),
    index('idx_oauth_clients_developer_id').on(t.developerId),
    index('idx_oauth_clients_enabled')
      .on(t.enabled)
      .where(sql`${t.enabled} = true`),
    index('idx_oauth_clients_realm_client_id_enabled').on(t.realmId, t.clientId, t.enabled),
    check(
      'oauth_clients_audience_is_array',
      sql`${t.audience} IS NULL OR jsonb_typeof(${t.audience}) = 'array'`
    ),
  ]
);

/**
 * Static developer API keys (ADR-008 §6, issue #97).
 *
 * An API key is the **DX half** of ADR-008's environment-aware posture — an
 * environment-gated developer convenience, NOT a parallel to OAuth
 * `client_credentials` (which remains the production machine-to-machine path).
 * A key is only ever issuable for a `development` (optionally `staging`) client;
 * in `production` the API-key path is OFF. The gate is enforced at the route
 * layer through `resolveEnvironmentPolicy(client, realm).staticApiKeysAllowed`
 * (fail-safe: an unset / `production` client cannot mint a key) — this table
 * only persists the issued material.
 *
 * SECRET HANDLING (mirrors `oauth_clients.client_secret_hash`):
 *   - Only the argon2id `key_hash` is ever stored — never the plaintext.
 *   - The plaintext key is returned exactly once, at creation.
 *   - `prefix` is the public, indexed lookup handle embedded in the plaintext
 *     (`qauth_<keyId>`); it is NOT secret and is safe to display/list. It lets
 *     authentication resolve the single candidate row by an indexed equality
 *     lookup, then verify the full presented key against the salted `key_hash`
 *     with argon2's constant-time comparison (a salted hash is not itself
 *     searchable, so a non-secret lookup handle is required).
 *   - `last4` is the trailing 4 chars of the secret, for "•••• abcd" display.
 *
 * A key NEVER authenticates once `revoked_at` is set (soft delete: the row is
 * retained for audit) or once its client is no longer `staticApiKeysAllowed`.
 */
export const apiKeys = pgTable(
  'api_keys',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /**
     * The OAuth client this key is scoped to. The environment gate
     * (`staticApiKeysAllowed`) is resolved from THIS client's `environment` and
     * its realm ceiling, so the key inherits the client's environment posture.
     * `cascade` so deleting the client removes its keys.
     */
    clientId: uuid('client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    /**
     * The developer who created the key (`users.id`). Nullable + `set null` so
     * a deleted developer does not orphan the historical key row (matches
     * `oauth_clients.developer_id`).
     */
    developerId: uuid('developer_id').references(() => users.id, { onDelete: 'set null' }),
    /** Human-readable label chosen by the developer (e.g. "local laptop"). */
    name: varchar('name', { length: 255 }).notNull(),
    /**
     * argon2id hash of the FULL plaintext key. Hash only — the plaintext is
     * never stored and is unrecoverable after creation (same contract as
     * `oauth_clients.client_secret_hash`).
     */
    keyHash: text('key_hash').notNull(),
    /**
     * Public, NON-SECRET lookup handle embedded in the plaintext key
     * (`qauth_<keyId>`). Unique so authentication resolves exactly one
     * candidate row by an indexed equality lookup before the constant-time hash
     * verification. Safe to display and to list.
     */
    prefix: varchar('prefix', { length: 64 }).notNull(),
    /** Trailing 4 chars of the secret portion, for masked display only. */
    last4: varchar('last4', { length: 4 }).notNull(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    /** Last time this key successfully authenticated a request (best-effort). */
    lastUsedAt: bigint('last_used_at', { mode: 'number' }),
    /**
     * Soft-delete / revocation marker. When set, the key MUST NOT authenticate.
     * Retained (rather than hard-deleted) so the audit trail and `last_used_at`
     * survive revocation.
     */
    revokedAt: bigint('revoked_at', { mode: 'number' }),
  },
  (t) => [
    // Authentication resolves the candidate row by this handle, so it must be
    // unique and indexed. The unique index doubles as the lookup index.
    uniqueIndex('idx_api_keys_prefix_unique').on(t.prefix),
    // "List this client's keys" (newest first) and "this developer's keys".
    index('idx_api_keys_client_id').on(t.clientId),
    index('idx_api_keys_developer_id').on(t.developerId),
    index('idx_api_keys_realm_id').on(t.realmId),
    // Partial index over live (non-revoked) keys — the hot path for both
    // listing active keys and the authentication lookup.
    index('idx_api_keys_active')
      .on(t.clientId)
      .where(sql`${t.revokedAt} IS NULL`),
  ]
);

export const realmsRelations = relations(realms, ({ many }) => ({
  users: many(users),
  oauthClients: many(oauthClients),
  apiKeys: many(apiKeys),
}));

export const usersRelations = relations(users, ({ one, many }) => ({
  realm: one(realms, { fields: [users.realmId], references: [realms.id] }),
  oauthClientsAsDeveloper: many(oauthClients),
}));

export const oauthClientsRelations = relations(oauthClients, ({ one, many }) => ({
  realm: one(realms, { fields: [oauthClients.realmId], references: [realms.id] }),
  developer: one(users, { fields: [oauthClients.developerId], references: [users.id] }),
  apiKeys: many(apiKeys),
}));

export const apiKeysRelations = relations(apiKeys, ({ one }) => ({
  realm: one(realms, { fields: [apiKeys.realmId], references: [realms.id] }),
  client: one(oauthClients, { fields: [apiKeys.clientId], references: [oauthClients.id] }),
  developer: one(users, { fields: [apiKeys.developerId], references: [users.id] }),
}));
