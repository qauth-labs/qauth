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

import { oauthClients, users } from './core';
import { codeChallengeMethodEnum } from './enums';
import { userCredentials } from './identity';
import { EPOCH_MS_NOW, JSONB_EMPTY_ARRAY } from './sql-helpers';

export const emailVerificationTokens = pgTable(
  'email_verification_tokens',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /** SHA-256 hash of the verification token (64 hex characters) */
    tokenHash: varchar('token_hash', { length: 64 }).notNull().unique(),
    /**
     * Password credential this verification targets (ADR-002: email
     * verification is a property of the password authentication method, not
     * of the abstract identity). NOT NULL since #230 — the token's identity
     * link is the credential; user resolution goes through
     * `user_credentials.user_id`. Cascade covers both levels
     * (user → credential → token).
     */
    credentialId: uuid('credential_id')
      .notNull()
      .references(() => userCredentials.id, { onDelete: 'cascade' }),
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    used: boolean('used').notNull().default(false),
    usedAt: bigint('used_at', { mode: 'number' }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    index('idx_email_verification_tokens_credential_id').on(t.credentialId),
    index('idx_email_verification_tokens_active')
      .on(t.tokenHash, t.expiresAt)
      .where(sql`${t.used} = false`),
    index('idx_email_verification_tokens_expires_at').on(t.expiresAt),
  ]
);

export const authorizationCodes = pgTable(
  'authorization_codes',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    code: varchar('code', { length: 255 }).notNull().unique(),
    oauthClientId: uuid('oauth_client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    redirectUri: text('redirect_uri').notNull(),
    codeChallenge: text('code_challenge').notNull(),
    codeChallengeMethod: codeChallengeMethodEnum('code_challenge_method').notNull().default('S256'),
    /**
     * OIDC Core §3.1.2.1 `nonce` — opaque, client-owned, and replayed verbatim
     * into the ID token. `text` rather than a bounded varchar because neither
     * OIDC Core nor RFC 6749 places ANY length limit on it: the storage layer
     * must never be the thing that truncates or rejects a value the client is
     * entitled to choose. The DoS bound lives in the app layer
     * (`OAUTH_OPAQUE_PARAM_MAX_LENGTH`), which is the single place it belongs.
     * See qauth-labs/qauth#316.
     */
    nonce: text('nonce'),
    /**
     * OIDC Core §2 `auth_time` (epoch MILLISECONDS): when the end-user
     * authentication that backs this code actually occurred — the browser
     * session's establishment time, captured at code-mint time so /oauth/token
     * can assert `auth_time` (epoch seconds) in the ID token. Deliberately
     * DISTINCT from `createdAt` (when THIS code row was minted): a code minted
     * from a long-lived session MUST report when the user authenticated, not
     * "now" — otherwise a stale session would silently pass a `max_age` check it
     * should fail. Nullable for backward-compat with in-flight codes minted
     * before this column existed (those simply omit the claim).
     */
    authTime: bigint('auth_time', { mode: 'number' }),
    /**
     * eIDAS Level of Assurance of the authentication that backs this code
     * (ADR-004, ADR-010, issue #237). `'substantial'` or `'high'`; NULL means no
     * assurance above `low` was established — which is every password login, and
     * every wallet login whose issuer the realm assures nothing about.
     *
     * Captured at code-mint time from the browser session, exactly as
     * {@link authTime} is, because /oauth/token has no other view of HOW the
     * user authenticated: the ID token is minted from this row long after the
     * session that produced it stopped being in scope.
     *
     * The internal LEVEL is stored, never the rendered `acr` string. The eIDAS
     * LoA → `acr` vocabulary is deployment configuration (`ACR_VALUE_STYLE`), so
     * storing the rendered value would freeze in-flight codes into whichever
     * vocabulary was configured when they were minted and make a config change
     * observable as two different `acr` values for the same level.
     *
     * NULL — not `'low'` — for the unassured case, so "no assurance was
     * established" is one value everywhere and no code path has to remember that
     * `'low'` means "omit the claim".
     */
    assuranceLevel: text('assurance_level'),
    /**
     * The absolute end, in epoch ms, of the browser session that backs this
     * code, as the session service gave it when the code was minted (ADR-019
     * Decision 3, issue #552). The refresh-token family the exchange starts
     * copies it, so no token of that family outlives the session's maximum
     * lifespan, even when the code came from a silent re-authorization just
     * before the session's end.
     *
     * NULL when no browser session backs the code (the legacy Bearer path), and
     * for a code minted by a release before migration 0038.
     */
    sessionExpiresAt: bigint('session_expires_at', { mode: 'number' }),
    scopes: jsonb('scopes').notNull().default(JSONB_EMPTY_ARRAY).$type<string[]>(),
    /**
     * RFC 8707 `resource` parameter(s) from /oauth/authorize. Absolute URIs
     * identifying the protected resource(s) the issued access token is
     * intended for. Becomes the token's `aud` claim at /oauth/token time.
     * Empty array means "no resource indicated; fall back to
     * client.audience / light-mode default" (backward-compatible path).
     */
    resource: jsonb('resource').notNull().default(JSONB_EMPTY_ARRAY).$type<string[]>(),
    /**
     * RFC 6749 §4.1.1 `state` — opaque, client-owned, and round-tripped to the
     * client verbatim on the authorization response. `text` for the same reason
     * as `nonce`: the spec sets no length limit and real clients pack context
     * in (Cursor's MCP client base64url-encodes ~275 chars of workspace state),
     * so a varchar(255) here rejected the code-mint AFTER both schema layers
     * had already accepted the request. See qauth-labs/qauth#316.
     */
    state: text('state'),
    /**
     * RFC 9449 §10 `dpop_jkt` (issue #480): the RFC 7638 SHA-256 thumbprint
     * of the DPoP key the authorization request bound this code to. The code
     * is redeemed only with a DPoP proof under that key. NULL for a code not
     * bound to a key, which is every code minted while `DPOP_ENABLED` is off.
     */
    dpopJkt: varchar('dpop_jkt', { length: 43 }),
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    used: boolean('used').notNull().default(false),
    usedAt: bigint('used_at', { mode: 'number' }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    index('idx_authorization_codes_active')
      .on(t.code, t.expiresAt)
      .where(sql`${t.used} = false`),
    index('idx_authorization_codes_expires_at').on(t.expiresAt),
    index('idx_authorization_codes_user_id').on(t.userId),
    index('idx_authorization_codes_oauth_client_id').on(t.oauthClientId),
    /**
     * Only the two levels that BEAR an `acr` claim may be stored. `'low'` is
     * excluded deliberately: NULL is the single representation of "no assurance
     * established", so a row can never carry a level the claim builder would
     * have to remember to drop. A corrupt or hand-edited value is refused by the
     * database rather than reaching the ID token.
     */
    check(
      'authorization_codes_assurance_level_valid',
      sql`${t.assuranceLevel} IS NULL OR ${t.assuranceLevel} IN ('substantial', 'high')`
    ),
    /** A SHA-256 thumbprint in base64url is 43 characters of its alphabet, nothing else. */
    check(
      'authorization_codes_dpop_jkt_format',
      sql`${t.dpopJkt} IS NULL OR ${t.dpopJkt} ~ '^[A-Za-z0-9_-]{43}$'`
    ),
  ]
);

export const refreshTokens = pgTable(
  'refresh_tokens',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /** SHA-256 hash of the refresh token (64 hex characters) */
    tokenHash: varchar('token_hash', { length: 64 }).notNull().unique(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    oauthClientId: uuid('oauth_client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    /**
     * Refresh token family identifier (OAuth 2.1 §4.3.1 / RFC 9700 §2.2.2).
     *
     * Every rotation MUST preserve this value so that a single "family"
     * can be revoked atomically when replay of a revoked token is detected.
     * Tokens created at initial issuance (authorization_code, password login)
     * generate a new UUID; rotations inherit the predecessor's family_id.
     */
    familyId: uuid('family_id')
      .notNull()
      .default(sql`uuidv7()`),
    /**
     * When the family started, in epoch ms (ADR-019 Decision 3, issue #552):
     * the moment the code exchange or sign-in issued its first token. Every
     * rotation copies it, and a realm's `sso_max_lifespan` counts from it, so
     * no token of the family lives past that limit. Migration 0038 filled it
     * from each family's earliest `created_at`.
     *
     * No default on purpose: a default would restart the family's clock for an
     * insert that forgot to copy it. Instead the trigger
     * `refresh_tokens_family_created_at_fill` (migration 0038) gives an insert
     * without a value the start of the family it joins, or now for a new
     * family, for the previous release during a rolling upgrade.
     */
    familyCreatedAt: bigint('family_created_at', { mode: 'number' }).notNull(),
    /**
     * The absolute end, in epoch ms, of the browser session that started the
     * family (ADR-019 Decision 3, issue #552): the authorization code's
     * `session_expires_at`. Every rotation copies it. When the realm sets
     * `sso_max_lifespan`, the family ends at the earlier of its start plus the
     * limit and this, so no token outlives the SSO session that granted it.
     *
     * NULL when no browser session started the family (`/auth/login`, the
     * legacy Bearer authorize path) or the family predates migration 0038; the
     * family's start plus the limit then applies alone. The repository's insert
     * type requires the key, so a rotation cannot forget to copy it; the 0038
     * trigger copies it for the previous release during a rolling upgrade.
     */
    familySessionExpiresAt: bigint('family_session_expires_at', { mode: 'number' }),
    scopes: jsonb('scopes').notNull().default(JSONB_EMPTY_ARRAY).$type<string[]>(),
    /**
     * RFC 8707 resource indicator(s) carried from the originating
     * authorization code. All access tokens minted from this refresh
     * token MUST have `aud` equal to (or a subset of) this list. Empty
     * array means "no resource bound; use light-mode default".
     */
    resource: jsonb('resource').notNull().default(JSONB_EMPTY_ARRAY).$type<string[]>(),
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    revoked: boolean('revoked').notNull().default(false),
    revokedAt: bigint('revoked_at', { mode: 'number' }),
    revokedReason: varchar('revoked_reason', { length: 255 }),
    /** SHA-256 hash of the previous token for rotation tracking (64 hex characters) */
    previousTokenHash: varchar('previous_token_hash', { length: 64 }),
    /**
     * The RFC 7638 SHA-256 thumbprint of the DPoP key this refresh token is
     * bound to (RFC 9449 §5, issue #480). Set for a PUBLIC client that sent a
     * DPoP proof when the token was issued; each use then needs a proof under
     * the same key, and every rotation keeps it. NULL for a confidential
     * client, whose refresh tokens client authentication already binds
     * (RFC 9449 §5), and for every token issued without a proof.
     */
    cnfJkt: varchar('cnf_jkt', { length: 43 }),
    /**
     * The authorization code whose redemption issued this token (ADR-017
     * Decision 10, issue #627). Set only on the first token of a family the
     * code exchange starts; rotations leave it NULL and share the family's
     * `family_id`, and the purge job deletes a family only whole, so the first
     * token, and with it the link, stays while any token of the family lives.
     * A second redemption of the code finds the family through it and revokes
     * it (OAuth 2.1 §4.1.3).
     *
     * NULL for every other token, for a family that predates migration 0039,
     * and once the code row is purged (`ON DELETE SET NULL`): a code that is
     * gone can no longer be replayed, since the token endpoint finds no row.
     */
    authorizationCodeId: uuid('authorization_code_id').references(() => authorizationCodes.id, {
      onDelete: 'set null',
    }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    lastUsedAt: bigint('last_used_at', { mode: 'number' }),
  },
  (t) => [
    index('idx_refresh_tokens_active')
      .on(t.tokenHash, t.expiresAt)
      .where(sql`${t.revoked} = false`),
    index('idx_refresh_tokens_expires_at').on(t.expiresAt),
    index('idx_refresh_tokens_user_id').on(t.userId),
    index('idx_refresh_tokens_oauth_client_id').on(t.oauthClientId),
    index('idx_refresh_tokens_user_active')
      .on(t.userId, t.expiresAt)
      .where(sql`${t.revoked} = false`),
    // Fast family-wide revocation lookups for replay detection.
    index('idx_refresh_tokens_family_id').on(t.familyId),
    // One family per code, and the index the code purge's `ON DELETE SET NULL`
    // reads: without it every deleted code would scan the table.
    uniqueIndex('idx_refresh_tokens_authorization_code_id')
      .on(t.authorizationCodeId)
      .where(sql`${t.authorizationCodeId} IS NOT NULL`),
    check(
      'refresh_tokens_cnf_jkt_format',
      sql`${t.cnfJkt} IS NULL OR ${t.cnfJkt} ~ '^[A-Za-z0-9_-]{43}$'`
    ),
  ]
);

export const emailVerificationTokensRelations = relations(emailVerificationTokens, ({ one }) => ({
  credential: one(userCredentials, {
    fields: [emailVerificationTokens.credentialId],
    references: [userCredentials.id],
  }),
}));

export const authorizationCodesRelations = relations(authorizationCodes, ({ one }) => ({
  user: one(users, { fields: [authorizationCodes.userId], references: [users.id] }),
  oauthClient: one(oauthClients, {
    fields: [authorizationCodes.oauthClientId],
    references: [oauthClients.id],
  }),
}));

export const refreshTokensRelations = relations(refreshTokens, ({ one }) => ({
  user: one(users, { fields: [refreshTokens.userId], references: [users.id] }),
  oauthClient: one(oauthClients, {
    fields: [refreshTokens.oauthClientId],
    references: [oauthClients.id],
  }),
}));
