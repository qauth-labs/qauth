import { relations, sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  index,
  jsonb,
  pgTable,
  text,
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
