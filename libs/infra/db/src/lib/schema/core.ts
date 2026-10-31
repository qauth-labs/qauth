import {
  ADMIN_EVENT_RETENTION_DEFAULT_DAYS,
  ADMIN_EVENT_RETENTION_MIN_DAYS,
  EVENT_RETENTION_MAX_DAYS,
  USER_EVENT_RETENTION_DEFAULT_DAYS,
  USER_EVENT_RETENTION_MIN_DAYS,
  VERIFIED_DOMAIN_PATTERN,
} from '@qauth-labs/shared-validation';
import { relations, sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  unique,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import {
  agentModeEnum,
  environmentEnum,
  firstPartyProfileEnum,
  GrantType,
  realmHostKindEnum,
  ResponseType,
  sslRequiredEnum,
  tokenEndpointAuthMethodEnum,
} from './enums';
import { EPOCH_MS_NOW, JSONB_EMPTY_ARRAY, JSONB_EMPTY_OBJECT } from './sql-helpers';

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
    /**
     * The realm's issuer identifier (RFC 8414 §2; ADR-019 Decision 1, issue
     * #470): the `iss` of every token the realm signs and the base of its
     * discovery document. Its host is the realm's primary host in
     * {@link realmHosts}. Stored without a trailing slash (a CHECK).
     *
     * PERMANENT once set: the trigger `realms_issuer_permanent` refuses every
     * UPDATE that changes a non-NULL issuer, so the only change allowed is from
     * NULL to a value. A new issuer would break issued tokens, registered
     * clients, enrolled passkeys and federation partners.
     *
     * NULL only on a realm that predates migration 0025. Such a realm is
     * unroutable until the boot step fills it from `JWT_ISSUER` (#484). Unique,
     * because a token's `iss` must name one realm.
     */
    issuer: text('issuer').unique(),
    /**
     * Marks the operator realm (ADR-019 Decisions 1 and 7): the realm whose
     * admins administer the deployment. In simple mode it is the default realm.
     * The partial unique index `idx_realms_one_operator` allows at most one.
     */
    isOperator: boolean('is_operator').notNull().default(false),
    /**
     * The realm's passkey RP ID (ADR-019 Decision 2, issues #467 and #553):
     * NULL means the realm's primary host, the default. A value is a parent
     * domain of it that the operator opted in to (`allowParentDomainRpId`);
     * `resolveRpId` in `@qauth-labs/shared-validation` reads the two.
     *
     * Changeable until the realm's first passkey is enrolled, then locked with
     * {@link realms.webauthnRpIdLockedAt}: the trigger
     * `realms_webauthn_rp_id_locked` refuses every change once that is set,
     * because another RP ID would orphan every enrolled passkey. Stored in the
     * realm host form (`normaliseRealmHost`), never an IP literal (CHECKs
     * below). Only `setWebAuthnRpId` writes it; `UpdateRealm` leaves it out.
     */
    webauthnRpId: varchar('webauthn_rp_id', { length: 253 }),
    /**
     * When the realm's first passkey enrolment locked its RP ID, in epoch ms
     * (#553); NULL while the realm has none. Written once, by
     * `lockRpIdForEnrolment` in the transaction that stores that passkey, and
     * permanent: the trigger `realms_webauthn_rp_id_locked` refuses clearing
     * or changing it, and every change of {@link realms.webauthnRpId} after it.
     */
    webauthnRpIdLockedAt: bigint('webauthn_rp_id_locked_at', { mode: 'number' }),
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
     * `/oauth/register` endpoint: any scope outside this list is dropped from
     * the registration. Admin-level scopes (e.g. `example:admin`) and
     * tenant-scoped grants (e.g. `tenant-a:*`) MUST NOT appear here, and a
     * scope in QAuth's reserved `qauth:` namespace cannot: the CHECK
     * `realms_dynamic_registration_scopes_not_qauth` refuses it (#507).
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
    /**
     * Days the realm keeps its user events (ADR-020 §3, issue #536), 1 to
     * 36500. The retention job deletes a user event once it is older than
     * this and every enabled delivery destination has finished it.
     *
     * A realm policy (ADR-019 Decision 10): `EVENT_RETENTION_USER_DAYS`
     * seeds it when the realm is created (`createRealmsRepository`'s seeds),
     * and the realm row owns it from then on. The column default, 90, is
     * what a realm created before migration 0036 got.
     */
    userEventRetentionDays: integer('user_event_retention_days')
      .notNull()
      .default(USER_EVENT_RETENTION_DEFAULT_DAYS),
    /**
     * Days the realm keeps its admin events (ADR-020 §3, issue #536), never
     * fewer than 90: the CHECK below refuses a lower value for every writer.
     * The retention job deletes only the oldest admin events, in chain
     * order, and stores the last one it deleted as the realm's chain anchor
     * (`event_chain_anchors`). Seeded by `EVENT_RETENTION_ADMIN_DAYS`; the
     * column default is 365.
     */
    adminEventRetentionDays: integer('admin_event_retention_days')
      .notNull()
      .default(ADMIN_EVENT_RETENTION_DEFAULT_DAYS),
    /**
     * Whether the realm runs the Shared Signals Framework transmitter (issue
     * #410): its `/.well-known/ssf-configuration`, its stream management and
     * the deliveries to its streams. It counts only while the deployment's
     * SSF_TRANSMITTER_ENABLED is on. Off by default: an operator turns it on
     * for each realm that has receivers.
     */
    ssfTransmitterEnabled: boolean('ssf_transmitter_enabled').notNull().default(false),
    /**
     * The realm's policies (ADR-019 Decision 10, issue #516): one document of
     * the realm policy schema (`@qauth-labs/server-realm-policy`), stored in
     * two forms. Four fields keep the columns that held them before this
     * column existed ({@link REALM_POLICY_COLUMNS}): the token lifetimes,
     * the dynamic registration allowlist and the environment ceiling. Every
     * other field is a member of this document. A secret field is never
     * here: the realm's secret store holds it.
     *
     * Only the policy store writes it, and it writes whole documents, so a
     * field missing here was added to the schema after the realm got its
     * policies (the boot step fills it once from the environment).
     */
    policies: jsonb('policies')
      .notNull()
      .default(JSONB_EMPTY_OBJECT)
      .$type<Record<string, unknown>>(),
    /**
     * The policy schema version the stored policies follow (`1-rc.0` before
     * QAuth 1.0.0, ADR-018 §5); NULL while the realm has no policies.
     */
    policySchemaVersion: varchar('policy_schema_version', { length: 32 }),
    /**
     * A counter of the realm's policy writes, the admin API's `ETag` and the
     * `If-Match` a policy update compares (#516). 0 means the realm has no
     * policies yet: it was created before migration 0046, or by a release
     * that predates it, and the boot step fills it from the environment,
     * with `UPDATE ... WHERE policies_version = 0` so the first node wins.
     *
     * Every change of the policies raises it, whoever writes them: the
     * trigger `realms_policies_version` raises it on an UPDATE that changes
     * the document or one of the four policy columns and leaves the counter
     * as it was, and refuses an UPDATE that lowers it, so an `ETag` never
     * names two documents. 0 is no `ETag`: a realm without policies reads
     * as its fill, which depends on the environment of the node reading it.
     */
    policiesVersion: integer('policies_version').notNull().default(0),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    index('idx_realms_enabled')
      .on(t.enabled)
      .where(sql`${t.enabled} = true`),
    // Every indexed row has the same key, `true`, so the index admits one.
    uniqueIndex('idx_realms_one_operator')
      .on(t.isOperator)
      .where(sql`${t.isOperator} = true`),
    check('realms_issuer_not_empty', sql`${t.issuer} <> ''`),
    check('realms_issuer_no_trailing_slash', sql`right(${t.issuer}, 1) <> '/'`),
    // RFC 8414 §2 issuers are https. Plain http only on localhost or a name
    // under it (RFC 6761 §6.3), for development.
    check(
      'realms_issuer_scheme',
      sql`${t.issuer} ~* '^(https://|http://([^/?#@:]+\\.)?localhost(:[0-9]+)?(/|$))'`
    ),
    // The URL parser drops white space and control characters and reads `\`
    // as `/`, so such an issuer is not the string a parser compares.
    check('realms_issuer_no_space_or_control', sql`${t.issuer} !~ '[[:space:][:cntrl:]\\\\]'`),
    // The host form of `realm_hosts.host`, without the IP literal branch: an RP
    // ID is a domain name (ADR-019 Decision 2).
    check(
      'realms_webauthn_rp_id_normalised',
      sql`${t.webauthnRpId} ~ '^[a-z0-9_-]+(\\.[a-z0-9_-]+)*$' and ${t.webauthnRpId} !~ '^[0-9.]+$'`
    ),
    // The limits of `eventRetentionProblems` (shared-validation), so a row
    // written by hand cannot keep admin events fewer than 90 days (#536).
    check(
      'realms_user_event_retention_days_range',
      sql`${t.userEventRetentionDays} between ${sql.raw(String(USER_EVENT_RETENTION_MIN_DAYS))} and ${sql.raw(String(EVENT_RETENTION_MAX_DAYS))}`
    ),
    check(
      'realms_admin_event_retention_days_range',
      sql`${t.adminEventRetentionDays} between ${sql.raw(String(ADMIN_EVENT_RETENTION_MIN_DAYS))} and ${sql.raw(String(EVENT_RETENTION_MAX_DAYS))}`
    ),
    // A maximum session length of zero or less would end every session and
    // every refresh-token family at its start (#552): none or a positive
    // number of seconds. The realms repository refuses the same before the
    // row is written.
    check(
      'realms_sso_max_lifespan_positive',
      sql`${t.ssoMaxLifespan} IS NULL OR ${t.ssoMaxLifespan} > 0`
    ),
    // The same for the idle timeout: zero or less would end every session at
    // its first request after sign-in.
    check(
      'realms_sso_idle_timeout_positive',
      sql`${t.ssoIdleTimeout} IS NULL OR ${t.ssoIdleTimeout} > 0`
    ),
    // The `qauth:` scope namespace is QAuth's own, the admin API's scopes
    // among them (#507, ADR-019 Decision 7), whatever the case of its ASCII
    // letters, so the dynamic registration allowlist cannot hold one, whoever
    // writes the row. The class spells the case out instead of a
    // case-insensitive flag, so the match does not depend on the database's
    // locale. `isReservedQauthScope` (shared-validation) is the same rule, and
    // the realms repository refuses the same before the row is written.
    check(
      'realms_dynamic_registration_scopes_not_qauth',
      sql`NOT jsonb_path_exists(${t.dynamicRegistrationAllowedScopes}, '$[*] ? (@ like_regex "^[qQ][aA][uU][tT][hH]:")')`
    ),
    // The realm's policies (#516): a JSON object, a counter that starts at 0,
    // and a schema version written as `1-rc.<M>` or `<N>` once the realm has
    // policies. The token lifetimes are policy fields from then on, so they
    // are set, whoever writes the row.
    check('realms_policies_object', sql`jsonb_typeof(${t.policies}) = 'object'`),
    check('realms_policies_version_not_negative', sql`${t.policiesVersion} >= 0`),
    check(
      'realms_policy_schema_version_format',
      sql`${t.policySchemaVersion} ~ '^[1-9][0-9]*(-rc\\.(0|[1-9][0-9]*))?$'`
    ),
    check(
      'realms_policies_complete',
      sql`${t.policiesVersion} = 0 OR (${t.policySchemaVersion} IS NOT NULL AND ${t.accessTokenLifespan} IS NOT NULL AND ${t.refreshTokenLifespan} IS NOT NULL)`
    ),
  ]
);

/**
 * The hosts a realm answers on (ADR-019 Decision 1, issue #470).
 *
 * A request belongs to the realm whose host equals the request's authority:
 * exact and case-insensitive, on the port-less ASCII form. Every `host` here is
 * in that form, written by `normaliseRealmHost()` from
 * `@qauth-labs/shared-validation`, so the lookup is a plain equality on the
 * primary key. The CHECK `realm_hosts_host_normalised` refuses anything else
 * (upper case, a port, a trailing dot, a wildcard, an empty label, non-ASCII),
 * so a row written by hand cannot dodge the uniqueness below.
 *
 * - `primary` — the realm's issuer host and default passkey RP ID. At most one
 *   per realm (`idx_realm_hosts_one_primary`) and never an IP literal
 *   (`realm_hosts_primary_not_ip_literal`). PERMANENT once set: the trigger
 *   `realm_hosts_primary_permanent` refuses an UPDATE that changes a primary
 *   row and a DELETE of one while its realm exists. Only the realm's own
 *   deletion removes it.
 * - `endpoint` — an extra name a server-to-server caller addresses the realm
 *   by, such as the Compose service name in `AUTH_SERVER_URL`. It answers API
 *   routes only. May be an IP literal; added and removed freely.
 *
 * Both kinds share one table on purpose: `host` is the primary key, so a host
 * exists once across every realm and both kinds, sandbox twins included. A
 * host cannot be one realm's primary host and another's endpoint host.
 */
export const realmHosts = pgTable(
  'realm_hosts',
  {
    host: varchar('host', { length: 253 }).primaryKey(),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    kind: realmHostKindEnum('kind').notNull(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    uniqueIndex('idx_realm_hosts_one_primary')
      .on(t.realmId)
      .where(sql`${t.kind} = 'primary'`),
    // The partial index above covers primary rows only; listing a realm's
    // endpoint hosts and the cascade from `realms` need the full column.
    index('idx_realm_hosts_realm_id').on(t.realmId),
    // A bracketed IPv6 literal, or dot-separated non-empty ASCII labels. The
    // finer rules (hyphens, label length, IDNA) are `normaliseRealmHost()`'s.
    check(
      'realm_hosts_host_normalised',
      sql`${t.host} ~ '^(\\[[0-9a-f:.]+\\]|[a-z0-9_-]+(\\.[a-z0-9_-]+)*)$'`
    ),
    // A passkey RP ID cannot be an IP address (ADR-019 Decision 2).
    check(
      'realm_hosts_primary_not_ip_literal',
      sql`${t.kind} = 'endpoint' or (${t.host} !~ '^\\[' and ${t.host} !~ '^[0-9.]+$')`
    ),
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
    /**
     * When the account was last disabled, in epoch ms (#748): every browser
     * session and token of the user issued before it is refused, even after
     * the account is enabled again. NULL for an account never disabled.
     *
     * The trigger `users_not_valid_before` (migration 0044) sets it whenever
     * `enabled` turns from true to false, from the database's clock, however
     * the account is disabled (the `db:disable-user` script or an `UPDATE` by
     * hand), and refuses an update that moves it back or clears it. So
     * enabling the account again leaves it as it is. The deferred trigger
     * `users_not_valid_before_at_commit` moves it once more, to the commit of
     * the disabling transaction, before which other transactions still read
     * the account as enabled. Migration 0044 gave every account disabled
     * when it ran the time it ran.
     */
    notValidBefore: bigint('not_valid_before', { mode: 'number' }),
    firstName: varchar('first_name', { length: 255 }),
    lastName: varchar('last_name', { length: 255 }),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    lastLoginAt: bigint('last_login_at', { mode: 'number' }),
  },
  (t) => [
    // The target of `sessions_user_realm_fk` (issue #468). Already unique
    // through `id`; it exists so a row that names a user can also name the
    // user's realm, and the database refuses a pair that disagrees. A
    // constraint rather than an index because drizzle-kit adds foreign keys
    // before it creates indexes.
    unique('users_id_realm_id_unique').on(t.id, t.realmId),
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
    /**
     * The foreign parties this client may name in an Identity Assertion
     * Authorization Grant (ID-JAG, ADR-011, #434): on the MINT side the target
     * authorization server's issuer (`audience`) and the MCP server
     * (`resource`), on the CONSUME side the `resource` an assertion may be
     * redeemed for. An empty list (the default) denies both sides; there is no
     * fallback.
     *
     * Kept apart from {@link oauthClients.audience}, which bounds the tokens
     * QAuth itself issues (`client_credentials`), so listing a foreign
     * authorization server here never lets the client obtain a QAuth access
     * token that names it, and listing a value only in `audience` never lets
     * the client mint or redeem an ID-JAG for it.
     *
     * OPERATOR-SET, NOT SELF-ASSERTED, exactly like `max_agent_mode`: only the
     * `db:seed-oauth-clients` manifest writes it. Dynamic registration,
     * `POST /api/clients` and CIMD materialisation pin it to `[]`, no request
     * body or metadata document can reach it, and `UpdateOAuthClient` excludes
     * it so no route can change it.
     */
    idJagTargets: jsonb('id_jag_targets').notNull().default(JSONB_EMPTY_ARRAY).$type<string[]>(),
    /**
     * The OWNER's on/off switch: `PATCH /api/clients/:id` may set it either
     * way. An operator's cut-off is {@link oauthClients.suspended}, a separate
     * column, so the owner can never undo it (ANT-2026-DR5XI3LV).
     */
    enabled: boolean('enabled').notNull().default(true),
    /**
     * OPERATOR-ONLY suspension (ANT-2026-DR5XI3LV). A suspended client is
     * refused everywhere a disabled one is (authorize, consent, every client
     * authentication path and therefore token, introspection, revocation and
     * token exchange, API keys), with the same error. Only an operator path
     * sets or clears it: the `db:suspend-oauth-client` script (or the same
     * `UPDATE` by hand). No route writes it, `UpdateOAuthClient` excludes it so
     * application code cannot, and `upsertCimdClient` never names it, so a
     * CIMD re-resolution cannot clear it.
     */
    suspended: boolean('suspended').notNull().default(false),
    /** When the current suspension began (epoch ms); NULL when not suspended. */
    suspendedAt: bigint('suspended_at', { mode: 'number' }),
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
     * dereference, so every fetch MUST go through the egress client as a
     * `client` destination (ADR-019 Decision 8), with the same guards the CIMD
     * path uses — https-only, no redirect following, DNS-pinned IP validation,
     * byte cap, timeout, non-200 rejection — and the result MUST be cached with
     * a bounded TTL. It is NEVER read from a token request; only
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
    /**
     * True only for a client an OPERATOR provisioned: the system client and
     * the clients of the `db:seed-oauth-clients` manifest / `db:seed` fixture.
     * RFC 9700 §4.11.2 lets the AS redirect automatically only to a redirect
     * URI it trusts, and this is that trust: only such a client receives
     * authorization error responses (`login_required` for `prompt=none`, …) by
     * an automatic 302 before the user has seen a QAuth page. Every other
     * client gets the error on an issuer page instead
     * (`helpers/authorization-error.ts`, ANT-2026-O8U3P920).
     *
     * A POSITIVE marker, so the safe answer is the default: `false` for every
     * row no operator path wrote. Dynamic registration, `POST /api/clients`
     * and CIMD materialisation always write `false` and no request body can
     * reach it. The marker vouches for the redirect URIs as the operator
     * wrote them, so a change by anyone else clears it: an owner's
     * `PATCH /api/clients/:id` that changes `redirectUris`, and every
     * `upsertCimdClient` conflict update. Mirror that at every future write
     * path that persists a client.
     */
    provisionedByOperator: boolean('provisioned_by_operator').notNull().default(false),
    /**
     * OPERATOR-SET passkey origins of a native app (ADR-017 Decision 14, issue
     * #467): extra `clientDataJSON.origin` values a WebAuthn ceremony started
     * for this client accepts beside the realm's own origin. An Android app's
     * is `android:apk-key-hash:<base64url SHA-256 of its signing certificate>`;
     * a first-party web front-end under a parent-domain RP ID has its `https`
     * origin. An iOS app needs none: it sends the RP ID's own origin.
     *
     * Only the operator sets it, through the `db:seed-oauth-clients` manifest,
     * where each entry is checked with `normaliseWebAuthnOrigin`. No route
     * writes it: DCR, CIMD and `/api/clients` cannot, and `UpdateOAuthClient`
     * excludes it. A client cannot widen where its own passkeys may be used.
     */
    webauthnAllowedOrigins: jsonb('webauthn_allowed_origins')
      .notNull()
      .default(JSONB_EMPTY_ARRAY)
      .$type<string[]>(),
    /**
     * RFC 9449 §5.2 `dpop_bound_access_tokens` (ADR-014 §3, ADR-017 phase F3,
     * issue #480): the client always uses DPoP at the token endpoint. While
     * `DPOP_ENABLED` is on, a token request from such a client without a
     * `DPoP` proof is refused with `invalid_dpop_proof`, whatever the grant.
     * While it is off, no client is DPoP-bound and the column is not read.
     *
     * OPERATOR-SET, NOT SELF-ASSERTED, like `max_agent_mode`: only the
     * `db:seed-oauth-clients` manifest writes it. Dynamic registration, CIMD
     * materialisation and `/api/clients` never name it, so their clients keep
     * the `false` default, and `UpdateOAuthClient` excludes it. A client that
     * could clear it could ask for bearer tokens its operator meant to refuse.
     */
    dpopBoundAccessTokens: boolean('dpop_bound_access_tokens').notNull().default(false),
    /**
     * The domain an admin verified for this client (ADR-019 Decision 6, issue
     * #593): what consent, device-code entry, logout and the account console
     * show FIRST for a client an admin registered, above the name the client
     * declared. Stored as a DNS name of two or more labels in its ASCII
     * (punycode) form, lower case, no port and no IP address
     * (`VERIFIED_DOMAIN_PATTERN` in shared-validation, checked below). NULL
     * (every row until an admin sets one) means nothing is verified: the
     * screen says the app is unverified and shows where the code goes.
     *
     * Read only for an operator-provisioned client (`provisioned_by_operator`),
     * so an owner who changes the redirect URIs, which clears that marker, also
     * stops the domain from showing. A CIMD client's verified domain is the
     * host of its client id URL, never this column.
     *
     * ADMIN-SET, NOT SELF-ASSERTED. Setting it is a security operation of
     * `clients.update` (`qauth:admin:security`, ADR-019 Decision 7); until the
     * admin API ships, only the `db:seed-oauth-clients` manifest writes it.
     * Dynamic registration, CIMD materialisation and `/api/clients` never name
     * it, and `UpdateOAuthClient` excludes it, so no client can verify itself.
     */
    verifiedDomain: varchar('verified_domain', { length: 253 }),
    /**
     * The client's first-party profile (ADR-017 Decision 2, issue #631):
     * `web_redirect` for a web front-end on the redirect flow, such as the
     * developer portal's system client, or `native_backend` for the backend
     * of a native app. NULL (every row no operator flagged) means the client
     * is not first party. Read only through `resolveFirstPartyProfile()` in
     * shared-validation, which also fails closed on a policy that does not
     * parse.
     *
     * OPERATOR-SET, NEVER SELF-ASSERTED, and held by the four CHECKs below: a
     * profile only on a `private_key_jwt` client that no developer owns, that
     * is not an agent and that neither dynamic registration nor a CIMD
     * document created; a policy exactly on `native_backend`; and
     * `native_backend` only with the `authorization_code` grant. The
     * `db:seed-oauth-clients` manifest and the system-client provisioner write
     * it, and later a `qauth:admin:security` operation (ADR-019 Decision 7).
     * The repository's `create` and `upsertCimdClient` write NULL whatever
     * they are given, and `UpdateOAuthClient` excludes it, so no route can set
     * it. Removing a profile revokes every refresh family of the client.
     */
    firstPartyProfile: firstPartyProfileEnum('first_party_profile'),
    /**
     * A `native_backend` client's policy (ADR-017 Decision 2): the strict
     * object `{ flows, email_code_after_password, pkce_required }` of
     * `firstPartyPolicySchema` in shared-validation, stored with every member
     * filled in. NULL on every other row. A stored value that does not parse
     * makes the client not first party; one that is not a JSON object is
     * refused (CHECK `oauth_clients_first_party_policy_object`).
     */
    firstPartyPolicy: jsonb('first_party_policy').$type<Record<string, unknown> | null>(),
    /**
     * The operator's written reason for the profile (ADR-017 Decision 2):
     * why the entity that operates this server controls the app and users see
     * it under that entity's brand. Set exactly with a profile, not blank and
     * at most 1000 characters (CHECK `oauth_clients_first_party_reason`), and
     * recorded in the `client.first_party_changed` event.
     */
    firstPartyReason: text('first_party_reason'),
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
    check('oauth_clients_id_jag_targets_is_array', sql`jsonb_typeof(${t.idJagTargets}) = 'array'`),
    check(
      'oauth_clients_webauthn_allowed_origins_is_array',
      sql`jsonb_typeof(${t.webauthnAllowedOrigins}) = 'array'`
    ),
    // #593: the stored form of a verified domain, so a value written by hand
    // can never reach a screen in any other form. The same expression as
    // `VERIFIED_DOMAIN_PATTERN` in shared-validation.
    check(
      'oauth_clients_verified_domain_form',
      sql`${t.verifiedDomain} IS NULL OR ${t.verifiedDomain} ~ ${sql.raw(`'${VERIFIED_DOMAIN_PATTERN}'`)}`
    ),
    // ADR-017 Decision 2 (#631): first-partyness is operator-set. These four
    // hold on every write path, the admin API's included.
    //
    // 1. No profile on a client someone other than the operator wrote: a
    //    developer-owned one, an agent, a dynamic registration or a CIMD
    //    client.
    check(
      'oauth_clients_first_party_operator_only',
      sql`${t.firstPartyProfile} IS NULL OR (${t.dynamicRegisteredAt} IS NULL AND ${t.developerId} IS NULL AND ${t.isAgent} = false AND coalesce(${t.metadata}->>'registrationType', '') NOT IN ('dynamic', 'cimd'))`
    ),
    // 2. A profile only on a client that authenticates with a private key.
    check(
      'oauth_clients_first_party_private_key_jwt',
      sql`${t.firstPartyProfile} IS NULL OR ${t.tokenEndpointAuthMethod} = 'private_key_jwt'`
    ),
    // 3. A policy exactly on `native_backend`. Null-safe, so a policy on a row
    //    with no profile is refused too.
    check(
      'oauth_clients_first_party_policy_native',
      sql`(${t.firstPartyProfile} IS NOT DISTINCT FROM 'native_backend') = (${t.firstPartyPolicy} IS NOT NULL)`
    ),
    // 4. `native_backend` only with the `authorization_code` grant.
    check(
      'oauth_clients_first_party_native_authorization_code',
      sql`${t.firstPartyProfile} IS DISTINCT FROM 'native_backend' OR ${t.grantTypes} ? 'authorization_code'`
    ),
    // And the stored forms the decision implies: a written reason exactly
    // with a profile, not blank and no longer than the event that records it
    // carries (1000 characters); a policy that is a JSON object.
    check(
      'oauth_clients_first_party_reason',
      sql`(${t.firstPartyProfile} IS NULL) = (${t.firstPartyReason} IS NULL) AND (${t.firstPartyReason} IS NULL OR (char_length(${t.firstPartyReason}) <= 1000 AND ${t.firstPartyReason} ~ '\\S'))`
    ),
    check(
      'oauth_clients_first_party_policy_object',
      sql`${t.firstPartyPolicy} IS NULL OR jsonb_typeof(${t.firstPartyPolicy}) = 'object'`
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
  hosts: many(realmHosts),
  users: many(users),
  oauthClients: many(oauthClients),
  apiKeys: many(apiKeys),
}));

export const realmHostsRelations = relations(realmHosts, ({ one }) => ({
  realm: one(realms, { fields: [realmHosts.realmId], references: [realms.id] }),
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
