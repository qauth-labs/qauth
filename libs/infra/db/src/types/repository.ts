import type { InferInsertModel, InferSelectModel } from 'drizzle-orm';

import type { oauthConsents } from '../lib/schema/consents';
import type { apiKeys, oauthClients } from '../lib/schema/core';
import type { userAttributes, userCredentials } from '../lib/schema/identity';
import type {
  authorizationCodes,
  emailVerificationTokens,
  refreshTokens,
} from '../lib/schema/tokens';
import type { DbClient } from './database';

/**
 * OAuth client types
 */
export type OAuthClient = InferSelectModel<typeof oauthClients>;
export type NewOAuthClient = InferInsertModel<typeof oauthClients>;
export type UpdateOAuthClient = Partial<Omit<NewOAuthClient, 'id' | 'createdAt' | 'realmId'>> & {
  updatedAt?: number;
};

/**
 * Static developer API key types (ADR-008 §6, issue #97).
 */
export type ApiKey = InferSelectModel<typeof apiKeys>;
export type NewApiKey = InferInsertModel<typeof apiKeys>;

/**
 * Email verification token types
 */
export type EmailVerificationToken = InferSelectModel<typeof emailVerificationTokens>;
export type NewEmailVerificationToken = InferInsertModel<typeof emailVerificationTokens>;

/**
 * Identity-model types (ADR-002, #228). The attribute row types carry a `Row`
 * suffix to avoid colliding with the federation lib's `UserAttribute`
 * interface (the provider-facing shape) at shared import sites.
 */
export type UserCredential = InferSelectModel<typeof userCredentials>;
export type NewUserCredential = InferInsertModel<typeof userCredentials>;
export type UserAttributeRow = InferSelectModel<typeof userAttributes>;
export type NewUserAttributeRow = InferInsertModel<typeof userAttributes>;

/**
 * Input shape for {@link UserAttributesRepository.upsertMany} — mirrors the
 * federation `UserAttribute` interface but speaks DB units (`expiresAt` as
 * epoch-ms) and lives here so infra-db never imports from server libs.
 */
export interface UpsertUserAttributeInput {
  source: string;
  attrKey: string;
  attrValue: string;
  verified: boolean;
  expiresAt?: number | null;
}

/**
 * Repository for `user_credentials` (one row per authentication method per
 * user; ADR-002 §Decision.2).
 */
export interface UserCredentialsRepository {
  create(data: NewUserCredential, tx?: DbClient): Promise<UserCredential>;
  findById(id: string, tx?: DbClient): Promise<UserCredential | undefined>;
  findByRealmProviderSub(
    realmId: string,
    providerType: string,
    externalSub: string,
    tx?: DbClient
  ): Promise<UserCredential | undefined>;
  findByUserIdAndType(
    userId: string,
    providerType: string,
    tx?: DbClient
  ): Promise<UserCredential | undefined>;
  setEmailVerified(id: string, tx?: DbClient): Promise<UserCredential>;
}

/**
 * Repository for `user_attributes` (claims as data; ADR-002 §Decision.3).
 */
export interface UserAttributesRepository {
  upsertMany(
    userId: string,
    attrs: readonly UpsertUserAttributeInput[],
    tx?: DbClient
  ): Promise<UserAttributeRow[]>;
  findVerifiedByUserIdAndKey(
    userId: string,
    attrKey: string,
    tx?: DbClient
  ): Promise<UserAttributeRow[]>;
  setVerified(
    userId: string,
    source: string,
    attrKey: string,
    verified: boolean,
    tx?: DbClient
  ): Promise<UserAttributeRow | undefined>;
}

/**
 * Refresh token types inferred from schema
 */
export type RefreshToken = InferSelectModel<typeof refreshTokens>;
export type NewRefreshToken = InferInsertModel<typeof refreshTokens>;

/**
 * Authorization code types inferred from schema
 */
export type AuthorizationCode = InferSelectModel<typeof authorizationCodes>;
export type NewAuthorizationCode = InferInsertModel<typeof authorizationCodes>;

/**
 * Base repository interface for common CRUD operations
 * This provides a consistent interface for all repositories
 * Implementations should follow this pattern to reduce code duplication
 */
export interface BaseRepository<TSelect, TInsert, TUpdate> {
  /** Create a new entity */
  create(data: TInsert, tx?: DbClient): Promise<TSelect>;
  /** Find an entity by ID @returns Entity if found, undefined otherwise */
  findById(id: string, tx?: DbClient): Promise<TSelect | undefined>;
  /** Find an entity by ID, throwing an error if not found @throws NotFoundError if entity is not found */
  findByIdOrThrow(id: string, tx?: DbClient): Promise<TSelect>;
  /** Update an entity by ID @throws NotFoundError if entity is not found */
  update(id: string, data: TUpdate, tx?: DbClient): Promise<TSelect>;
  /** Delete an entity by ID @returns True if deleted, false if not found */
  delete(id: string, tx?: DbClient): Promise<boolean>;
}

/**
 * OAuth clients repository interface extending BaseRepository with additional methods
 */
export interface OAuthClientsRepository extends BaseRepository<
  OAuthClient,
  NewOAuthClient,
  UpdateOAuthClient
> {
  /**
   * Find an OAuth client by client ID within a realm
   */
  findByClientId(
    realmId: string,
    clientId: string,
    tx?: DbClient
  ): Promise<OAuthClient | undefined>;
  /**
   * List the OAuth clients owned by a developer, newest first.
   *
   * Ownership is scoped by `oauth_clients.developer_id`. Clients created via
   * open dynamic registration (RFC 7591) have a null `developer_id` and are
   * therefore never returned here.
   */
  listByDeveloper(developerId: string, tx?: DbClient): Promise<OAuthClient[]>;

  /**
   * Idempotently materialise a Client ID Metadata Document (CIMD) client.
   *
   * CIMD clients are keyed by their (realm_id, client_id) URL. On conflict
   * the mutable, document-derived fields are refreshed from the latest
   * validated metadata document; the row is otherwise left untouched. This
   * is NOT open registration: the row is keyed by the URL itself, so
   * re-resolving the same client_id updates one row rather than creating
   * new ones — there is no record to spam. The row exists only to satisfy
   * the auth-code / refresh-token / audit foreign keys.
   */
  upsertCimdClient(data: NewOAuthClient, tx?: DbClient): Promise<OAuthClient>;
}

/**
 * Email verification tokens repository interface
 */
export interface EmailVerificationTokensRepository {
  /**
   * Create a new email verification token
   */
  create(data: NewEmailVerificationToken, tx?: DbClient): Promise<EmailVerificationToken>;
  /**
   * Find a token by its token hash
   */
  findByTokenHash(tokenHash: string, tx?: DbClient): Promise<EmailVerificationToken | undefined>;
  /**
   * Mark a token as used
   */
  markUsed(id: string, tx?: DbClient): Promise<EmailVerificationToken>;
  /**
   * Invalidate all active tokens for a credential (#230: credential-keyed)
   */
  invalidateCredentialTokens(credentialId: string, tx?: DbClient): Promise<number>;
  /**
   * Delete expired tokens
   */
  deleteExpired(tx?: DbClient): Promise<EmailVerificationToken[]>;
}

/**
 * Refresh tokens repository interface
 */
export interface RefreshTokensRepository {
  /**
   * Create a new refresh token
   */
  create(data: NewRefreshToken, tx?: DbClient): Promise<RefreshToken>;
  /**
   * Find a token by its token hash
   * Only returns tokens that are not revoked and not expired
   */
  findByTokenHash(tokenHash: string, tx?: DbClient): Promise<RefreshToken | undefined>;
  /**
   * Find a token by its token hash regardless of `revoked`/`expiresAt`.
   *
   * Used by the refresh-token rotation flow to detect replay of an
   * already-revoked token (OAuth 2.1 §4.3.1 / RFC 9700 §2.2.2). Callers
   * MUST apply their own liveness and freshness checks.
   */
  findByTokenHashIncludingRevoked(
    tokenHash: string,
    tx?: DbClient
  ): Promise<RefreshToken | undefined>;
  /**
   * Find all active tokens for a user
   * Returns tokens that are not revoked and not expired
   */
  findByUserId(userId: string, tx?: DbClient): Promise<RefreshToken[]>;
  /**
   * Revoke a token by ID
   * Sets revoked=true, revokedAt=now, and optional revocation reason
   */
  revoke(id: string, reason?: string, tx?: DbClient): Promise<RefreshToken>;
  /**
   * Revoke all tokens in a refresh-token family.
   *
   * Triggered when a revoked token is replayed: the whole family (every
   * rotation descended from the initial token) is revoked in a single
   * statement. Already-revoked rows are left untouched so the original
   * `revokedReason` is preserved for audit.
   *
   * @returns Count of rows whose state was changed by this call.
   */
  revokeFamily(familyId: string, reason?: string, tx?: DbClient): Promise<number>;
  /**
   * Revoke all active tokens for a user
   * Useful for "logout all sessions" functionality
   */
  revokeAllForUser(userId: string, reason?: string, tx?: DbClient): Promise<void>;
  /**
   * Delete expired tokens
   * Returns count of deleted tokens
   */
  deleteExpired(tx?: DbClient): Promise<number>;
}

/**
 * OAuth consent types
 */
export type OAuthConsent = InferSelectModel<typeof oauthConsents>;
export type NewOAuthConsent = InferInsertModel<typeof oauthConsents>;

/**
 * OAuth consents repository interface.
 *
 * Consents are scoped to (userId, oauthClientId). A single active
 * (not revoked) row exists per pair; re-consent merges scopes into the same
 * row. Revocation sets `revokedAt` rather than deleting, so history is kept.
 */
export interface OAuthConsentsRepository {
  /** Create a consent row (insert). Caller is responsible for uniqueness. */
  create(data: NewOAuthConsent, tx?: DbClient): Promise<OAuthConsent>;
  /** Fetch the active (non-revoked) consent for a (user, client) pair. */
  findActive(
    userId: string,
    oauthClientId: string,
    tx?: DbClient
  ): Promise<OAuthConsent | undefined>;
  /** List all active consents for a user, joined to client metadata (revocation UI). */
  listActiveForUser(userId: string, tx?: DbClient): Promise<OAuthConsent[]>;
  /**
   * List all active consents for a user *with* their client metadata joined
   * in a single query. Used by the revocation UI to render client name and
   * client_id without a per-row findById fan-out.
   */
  listActiveForUserWithClient(
    userId: string,
    tx?: DbClient
  ): Promise<
    Array<
      OAuthConsent & {
        clientClientId: string;
        clientName: string;
      }
    >
  >;
  /**
   * Grant/update consent for (user, client).
   *
   * If an active row exists, its `scopes` array is replaced with the union
   * of old ∪ new and `grantedAt` is refreshed. Otherwise a new row is
   * inserted.
   */
  upsertGrant(
    userId: string,
    oauthClientId: string,
    realmId: string,
    scopes: string[],
    tx?: DbClient
  ): Promise<OAuthConsent>;
  /** Revoke a consent row by id (owner must be checked by caller). */
  revoke(id: string, tx?: DbClient): Promise<OAuthConsent>;
}

/**
 * Authorization codes repository interface
 */
export interface AuthorizationCodesRepository {
  /**
   * Create a new authorization code
   */
  create(data: NewAuthorizationCode, tx?: DbClient): Promise<AuthorizationCode>;
  /**
   * Find an authorization code by its code value
   * Only returns codes that are not used and not expired
   */
  findByCode(code: string, tx?: DbClient): Promise<AuthorizationCode | undefined>;
  /**
   * Mark a code as used
   * Sets used=true and usedAt=now
   */
  markUsed(id: string, tx?: DbClient): Promise<AuthorizationCode>;
  /**
   * Invalidate all active codes for a user
   * Useful for security events (password change, account compromise)
   */
  invalidateForUser(userId: string, tx?: DbClient): Promise<number>;
  /**
   * Delete expired codes
   * Returns count of deleted codes
   */
  deleteExpired(tx?: DbClient): Promise<number>;
}

/**
 * Static developer API keys repository (ADR-008 §6, issue #97).
 *
 * Persists environment-gated developer API keys. The environment GATE itself
 * (`resolveEnvironmentPolicy(...).staticApiKeysAllowed`) lives at the route
 * layer — this repository is unconditional storage. The plaintext key is never
 * persisted: callers pass a pre-computed argon2id `keyHash` plus the non-secret
 * `prefix` / `last4` display handles, exactly as client secrets are stored.
 */
export interface ApiKeysRepository {
  /**
   * Create a new API key row. `keyHash` MUST be pre-hashed (argon2id); the
   * plaintext is never handed to the repository.
   *
   * @throws UniqueConstraintError if `prefix` collides (astronomically unlikely)
   */
  create(data: NewApiKey, tx?: DbClient): Promise<ApiKey>;
  /**
   * Find an API key by its public lookup `prefix`. Returns the row regardless
   * of revocation state — the caller checks `revokedAt` after the constant-time
   * hash verification so a revoked vs unknown prefix are indistinguishable by
   * timing. Returns undefined when no row matches.
   */
  findByPrefix(prefix: string, tx?: DbClient): Promise<ApiKey | undefined>;
  /**
   * List the API keys scoped to a client, newest first. Includes revoked keys
   * (callers mask them); the route projects to non-secret fields only.
   */
  listByClient(clientId: string, tx?: DbClient): Promise<ApiKey[]>;
  /**
   * Find a single API key by id, or undefined.
   */
  findById(id: string, tx?: DbClient): Promise<ApiKey | undefined>;
  /**
   * Revoke a key by id (idempotent soft-delete): sets `revokedAt` if not
   * already set. Returns the updated row, or undefined when no row matches.
   */
  revoke(id: string, tx?: DbClient): Promise<ApiKey | undefined>;
  /**
   * Best-effort touch of `lastUsedAt` after a successful authentication. Never
   * throws on a missing row.
   */
  touchLastUsed(id: string, tx?: DbClient): Promise<void>;
}
