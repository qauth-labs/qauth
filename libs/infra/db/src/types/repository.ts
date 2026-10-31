import type {
  AdminApproval,
  EventCategory,
  EventDataOf,
  EventEnvelope,
  JsonObject,
  RegisteredEventType,
} from '@qauth-labs/shared-events';
import type { InferInsertModel, InferSelectModel } from 'drizzle-orm';

import type {
  AdminAuditActChain,
  AdminAuditApproval,
  AdminAuditDiff,
  FieldAnnotations,
} from '../lib/admin-audit/types';
import type { EventPosition } from '../lib/events/position';
import type { adminAuditLog } from '../lib/schema/admin-audit';
import type { oauthConsents } from '../lib/schema/consents';
import type { apiKeys, oauthClients } from '../lib/schema/core';
import type {
  AdminActorKind,
  AdminAuditOutcome,
  AdminOperationClass,
  RealmKeyStatus,
} from '../lib/schema/enums';
import type { userAttributes, userCredentials } from '../lib/schema/identity';
import type { realmKeys, realmPublicKeys } from '../lib/schema/keys';
import type { oid4vpRequestStates } from '../lib/schema/oid4vp';
import type { sessionClients, SessionRevokedReason, sessions } from '../lib/schema/sessions';
import type {
  authorizationCodes,
  emailVerificationTokens,
  refreshTokens,
} from '../lib/schema/tokens';
import type { DbClient, DbTransaction } from './database';

/**
 * OAuth client types
 */
export type OAuthClient = InferSelectModel<typeof oauthClients>;
export type NewOAuthClient = InferInsertModel<typeof oauthClients>;
/**
 * Fields an application write may change. `suspended` / `suspendedAt` are left
 * out on purpose (ANT-2026-DR5XI3LV): a suspension is operator state, set and
 * lifted only by the operator tooling (`scripts/client-suspension.ts`), so no
 * route can write it through `update`, not even by mistake. `idJagTargets` is
 * left out for the same reason (#434): only the `db:seed-oauth-clients`
 * manifest writes a client's ID-JAG targets. `webauthnAllowedOrigins` is left
 * out too (#467): the operator sets a client's passkey origins through the
 * same manifest. So is `dpopBoundAccessTokens` (#480): a client that could
 * clear it could obtain the bearer tokens its operator meant to refuse.
 */
export type UpdateOAuthClient = Partial<
  Omit<
    NewOAuthClient,
    | 'id'
    | 'createdAt'
    | 'realmId'
    | 'suspended'
    | 'suspendedAt'
    | 'idJagTargets'
    | 'webauthnAllowedOrigins'
    | 'dpopBoundAccessTokens'
  >
> & {
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
  /**
   * What the attribute rests on (`user_attributes.provenance`). Written as
   * given on insert AND on conflict, so a re-presented credential replaces the
   * provenance of the rows it rewrites. Absent means NULL.
   */
  provenance?: Record<string, unknown> | null;
}

/**
 * Repository for `user_credentials` (one row per authentication method per
 * user; ADR-002 §Decision.2).
 */
export interface UserCredentialsRepository {
  create(data: NewUserCredential, tx?: DbClient): Promise<UserCredential>;
  /** A credential of the realm by id; another realm's is answered as unknown (#489). */
  findById(realmId: string, id: string, tx?: DbClient): Promise<UserCredential | undefined>;
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
  /**
   * Every credential in a realm carrying this `external_sub`, ACROSS provider
   * types (#235/#238).
   *
   * The account-store read behind `SubjectAccountLookup.byAssertedIdentifier`
   * (ADR-009 / #300). Deliberately not restricted to one provider type: an
   * account may hold a password credential and a wallet credential under the
   * same identifier, and returning only the wallet ones would hide ADR-009's
   * second bootstrap case — an existing password account with no wallet
   * binding — turning a takeover attempt into a "no account found" the caller
   * might register over.
   */
  findAllByRealmAndExternalSub(
    realmId: string,
    externalSub: string,
    tx?: DbClient
  ): Promise<UserCredential[]>;
  /** Every credential a user holds for one provider type (#238). */
  findAllByUserIdAndType(
    userId: string,
    providerType: string,
    tx?: DbClient
  ): Promise<UserCredential[]>;
  /**
   * Replace a credential's `credential_data` wholesale (#238).
   *
   * Used by account linking to RE-bind an existing wallet credential row when
   * the same account links a re-issued credential. A whole-object replace rather
   * than a targeted `jsonb_set` because the wallet shape is written as a unit by
   * `buildWalletCredentialData`, and a partial update could leave a binding and
   * an issuer that came from two different credentials.
   *
   * @throws NotFoundError if the credential does not exist.
   */
  updateCredentialData(
    id: string,
    credentialData: Record<string, unknown>,
    tx?: DbClient
  ): Promise<UserCredential>;
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
  /** Every row one source holds for a user, verified or not. */
  findByUserIdAndSource(userId: string, source: string, tx?: DbClient): Promise<UserAttributeRow[]>;
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
/**
 * A new refresh token. `familySessionExpiresAt` is required (null when no
 * browser session started the family), so a rotation that forgets to copy the
 * family's session end fails to compile rather than dropping the session's cap
 * (#552).
 */
export type NewRefreshToken = InferInsertModel<typeof refreshTokens> & {
  familySessionExpiresAt: number | null;
};

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
 * {@link BaseRepository} for a table whose rows each belong to one realm
 * (ADR-019 Decision 1, #489).
 *
 * Every method that takes an id takes the realm first, as a required argument:
 * an id read from a request, a token, a code or a cookie names a row only in
 * the realm the request was resolved to. A row of another realm is answered as
 * no row (`undefined`, `false` or `NotFoundError`), from the same single query
 * an unknown id gets, so neither the answer nor its timing tells the caller
 * that the id exists elsewhere.
 */
export interface RealmScopedRepository<TSelect, TInsert, TUpdate> {
  /** Create a new entity; its realm is in `data` */
  create(data: TInsert, tx?: DbClient): Promise<TSelect>;
  /** Find an entity of the realm by ID @returns Entity if found, undefined otherwise */
  findById(realmId: string, id: string, tx?: DbClient): Promise<TSelect | undefined>;
  /** Find an entity of the realm by ID @throws NotFoundError if the realm has no such entity */
  findByIdOrThrow(realmId: string, id: string, tx?: DbClient): Promise<TSelect>;
  /** Update an entity of the realm by ID @throws NotFoundError if the realm has no such entity */
  update(realmId: string, id: string, data: TUpdate, tx?: DbClient): Promise<TSelect>;
  /** Delete an entity of the realm by ID @returns True if deleted, false if not found */
  delete(realmId: string, id: string, tx?: DbClient): Promise<boolean>;
}

/**
 * OAuth clients repository interface: realm-scoped CRUD plus lookups by the
 * public `client_id` and by owning developer
 */
export interface OAuthClientsRepository extends RealmScopedRepository<
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
  listByDeveloper(realmId: string, developerId: string, tx?: DbClient): Promise<OAuthClient[]>;

  /**
   * Count the OAuth clients owned by a developer: the rows
   * {@link listByDeveloper} would return, without loading them. Used to
   * enforce the per-developer client ceiling before a create.
   */
  countByDeveloper(realmId: string, developerId: string, tx?: DbClient): Promise<number>;

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
   * Find an unused, unexpired token by its token hash, among the tokens of the
   * realm's credentials (#489): the table has no realm column, its credential
   * has one. A token of another realm is answered as an unknown one.
   */
  findByTokenHash(
    realmId: string,
    tokenHash: string,
    tx?: DbClient
  ): Promise<EmailVerificationToken | undefined>;
  /**
   * Mark a token as used
   */
  /** CAS single-use (#258): undefined when the token was already used. */
  markUsed(id: string, tx?: DbClient): Promise<EmailVerificationToken | undefined>;
  /**
   * Invalidate all active tokens for a credential (#230: credential-keyed)
   */
  invalidateCredentialTokens(credentialId: string, tx?: DbClient): Promise<number>;
  /**
   * Delete expired tokens
   */
  deleteExpired(tx?: DbClient): Promise<EmailVerificationToken[]>;
}

/** What revoking the refresh family an authorization code started found and did. */
export interface RefreshFamilyRevocation {
  /** The family the code's redemption started; `null` when it started none. */
  readonly familyId: string | null;
  /** How many of the family's tokens this call revoked. */
  readonly revokedCount: number;
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
   *
   * Only a token issued to a client of `realmId` is found (#489). The table
   * has no realm column: the client pins the realm, so a token of another
   * realm's client is answered as an unknown one.
   */
  findByTokenHash(
    realmId: string,
    tokenHash: string,
    tx?: DbClient
  ): Promise<RefreshToken | undefined>;
  /**
   * Find a token by its token hash regardless of `revoked`/`expiresAt`.
   *
   * Used by the refresh-token rotation flow to detect replay of an
   * already-revoked token (OAuth 2.1 §4.3.1 / RFC 9700 §2.2.2). Callers
   * MUST apply their own liveness and freshness checks.
   *
   * Realm-scoped through the token's client, as {@link findByTokenHash} is: a
   * token of another realm never reaches the replay logic, so presenting it
   * cannot revoke that realm's family.
   */
  findByTokenHashIncludingRevoked(
    realmId: string,
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
   * Revoke a token by ID only if it is still live: a compare-and-set on
   * `revoked = false`.
   *
   * Refresh-token rotation uses this instead of `revoke`. Two concurrent
   * presentations of one token serialise on the row lock; Postgres then
   * re-evaluates the predicate for the second, finds `revoked = true`, and
   * updates nothing. The caller treats that as a replay.
   *
   * @returns The revoked row, or `undefined` when the token was already
   *   revoked (or does not exist).
   */
  revokeIfActive(id: string, reason: string, tx?: DbClient): Promise<RefreshToken | undefined>;
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
   * Revoke the family an authorization code's redemption started, found
   * through the first token's `authorizationCodeId`.
   *
   * Triggered when a spent code is redeemed again (OAuth 2.1 §4.1.3).
   * Already-revoked rows keep their original `revokedReason`.
   *
   * @returns The family the code started (`null` when none) and the count of
   *   rows whose state was changed by this call.
   */
  revokeFamilyByAuthorizationCode(
    authorizationCodeId: string,
    reason: string,
    tx?: DbClient
  ): Promise<RefreshFamilyRevocation>;
  /**
   * Revoke all active tokens for a user
   * Useful for "logout all sessions" functionality
   */
  revokeAllForUser(userId: string, reason?: string, tx?: DbClient): Promise<void>;
  /**
   * Revoke every active refresh token one user holds for one client.
   *
   * Consent revocation calls this: withdrawing a grant must also end the
   * refresh tokens minted under it, or the client keeps refreshing on a grant
   * that no longer exists.
   *
   * @returns Count of rows revoked by this call.
   */
  revokeAllForUserAndClient(
    userId: string,
    oauthClientId: string,
    reason: string,
    tx?: DbClient
  ): Promise<number>;
  /**
   * Delete the families whose every token has expired, whole. A rotated token
   * is kept while its family has a live token, so replay detection lasts as
   * long as the family. Returns count of deleted tokens.
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
  /** Fetch the active (non-revoked) consent for a (user, client) pair of the realm. */
  findActive(
    realmId: string,
    userId: string,
    oauthClientId: string,
    tx?: DbClient
  ): Promise<OAuthConsent | undefined>;
  /**
   * `findActive`, holding a shared lock on the row until `tx` ends.
   *
   * `findActive` is a snapshot: a revocation can commit between it and
   * whatever the caller writes on the strength of the consent. A caller that
   * issues something under the consent re-reads it with this and writes in
   * the same `tx`. `revoke` updates the row, so it either waits for `tx` to
   * end, or has already committed and no row is returned.
   */
  findActiveForShare(
    realmId: string,
    userId: string,
    oauthClientId: string,
    tx: DbClient
  ): Promise<OAuthConsent | undefined>;
  /** List all active consents a user of the realm holds. */
  listActiveForUser(realmId: string, userId: string, tx?: DbClient): Promise<OAuthConsent[]>;
  /**
   * List all active consents for a user *with* their client metadata joined
   * in a single query. Used by the revocation UI to render client name and
   * client_id without a per-row findById fan-out.
   */
  listActiveForUserWithClient(
    realmId: string,
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
   * inserted. `scopes` are merged the same way into the `resourceScopes`
   * entry of each of `resources`, the RFC 8707 resources they were approved
   * for.
   */
  upsertGrant(
    realmId: string,
    userId: string,
    oauthClientId: string,
    scopes: string[],
    resources?: readonly string[],
    tx?: DbClient
  ): Promise<OAuthConsent>;
  /**
   * Revoke an active consent row of the realm by id (owner must be checked by
   * caller). @throws NotFoundError when the realm has no such active row.
   */
  revoke(realmId: string, id: string, tx?: DbClient): Promise<OAuthConsent>;
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
   *
   * Only a code issued to a client of `realmId` is found (#489): the client
   * pins the realm, so a code of another realm is answered as an unknown one
   * (`invalid_grant`).
   */
  findByCode(realmId: string, code: string, tx?: DbClient): Promise<AuthorizationCode | undefined>;
  /**
   * Find an authorization code by its code value regardless of `used` and
   * `expiresAt`.
   *
   * The token endpoint uses this to recognise a second redemption of a spent
   * code (OAuth 2.1 §4.1.3). Callers MUST apply their own single-use and
   * expiry checks. Realm-scoped as {@link findByCode} is (#489): a code of
   * another realm, spent or not, is not found.
   */
  findByCodeIncludingUsed(
    realmId: string,
    code: string,
    tx?: DbClient
  ): Promise<AuthorizationCode | undefined>;
  /**
   * Mark a code as used
   * Sets used=true and usedAt=now
   */
  markUsed(id: string, tx?: DbClient): Promise<AuthorizationCode>;
  /**
   * Invalidate all unredeemed codes for a user
   * Useful for security events (logout, password change, account compromise)
   */
  invalidateForUser(userId: string, tx?: DbClient): Promise<number>;
  /**
   * Invalidate all unredeemed codes a user holds for one client
   * (consent revocation). Returns count of invalidated codes.
   */
  invalidateForUserAndClient(userId: string, oauthClientId: string, tx?: DbClient): Promise<number>;
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
  findByPrefix(realmId: string, prefix: string, tx?: DbClient): Promise<ApiKey | undefined>;
  /**
   * List the API keys scoped to a client, newest first. Includes revoked keys
   * (callers mask them); the route projects to non-secret fields only.
   */
  listByClient(realmId: string, clientId: string, tx?: DbClient): Promise<ApiKey[]>;
  /**
   * Find a single API key of the realm by id, or undefined.
   */
  findById(realmId: string, id: string, tx?: DbClient): Promise<ApiKey | undefined>;
  /**
   * Revoke a key of the realm by id (idempotent soft-delete): sets `revokedAt`
   * if not already set. Returns the updated row, or undefined when no row
   * matches.
   */
  revoke(realmId: string, id: string, tx?: DbClient): Promise<ApiKey | undefined>;
  /**
   * Best-effort touch of `lastUsedAt` after a successful authentication. Never
   * throws on a missing row.
   */
  touchLastUsed(id: string, tx?: DbClient): Promise<void>;
}

/**
 * Outbound OID4VP presentation-request state types (ADR-004, issue #233).
 */
export type Oid4vpRequestState = InferSelectModel<typeof oid4vpRequestStates>;
export type NewOid4vpRequestState = InferInsertModel<typeof oid4vpRequestStates>;

/**
 * The Response Code (#405, OID4VP 1.0 §8.2 / §14.2) as the repository is
 * allowed to see it: its SHA-256 digest and its own deadline, handed to the
 * redemption so both are written by the statement that consumes the row.
 *
 * The code itself never reaches the repository, for the reason the raw
 * `state` never does — `codeHash` MUST be `hashOid4vpResponseCode(code)` from
 * `@qauth-labs/server-federation`, and the repository stores nothing else.
 * `codeExpiresAt` is epoch ms, deliberately not derived from the row's
 * `expiresAt` (see `responseCodeExpiresAt` in the schema for why).
 */
export interface NewOid4vpResponseCode {
  /** SHA-256 hex digest of the Response Code that goes into the `redirect_uri`. */
  codeHash: string;
  /** The code's own expiry, epoch ms — the return leg's deadline. */
  codeExpiresAt: number;
}

/**
 * Repository for `oid4vp_request_states` — the single-use, expiring correlator
 * behind the OID4VP `direct_post` response endpoint (ADR-004, issue #233).
 *
 * Deliberately NARROW. There is no `findByStateHash`, and adding one would be a
 * regression: a read-then-write caller ("look it up, check it, then mark it
 * used") is precisely the race this repository exists to make impossible, and an
 * innocent-looking finder is how that pattern gets reintroduced. The only way to
 * observe a row is to CONSUME it — see {@link Oid4vpRequestStatesRepository.redeem}.
 * The same holds of the Response Code (#405): there is no `findByResponseCode`;
 * {@link Oid4vpRequestStatesRepository.redeemResponseCode} consumes the code,
 * and that is the only way to learn which row it named.
 */
export interface Oid4vpRequestStatesRepository {
  /**
   * Persist a presentation request that is about to be sent to a wallet.
   *
   * `stateHash` MUST be the SHA-256 digest of the `state` that goes on the wire
   * (`hashOid4vpState` in `@qauth-labs/server-federation`); the raw `state` is
   * never handed to the repository. `nonce` IS stored in the clear — #234 has to
   * compare it against the Key Binding JWT byte-for-byte.
   */
  create(data: NewOid4vpRequestState, tx?: DbClient): Promise<Oid4vpRequestState>;
  /**
   * ATOMICALLY consume a request state, exactly once.
   *
   * One guarded `UPDATE ... WHERE state_hash = $1 AND redeemed_at IS NULL AND
   * expires_at > $now RETURNING *`. The guard lives in the statement, so two
   * concurrent posts carrying the same `state` are serialized by the row lock
   * and exactly one of them sees a returned row — no transaction, no advisory
   * lock, and no window between a check and a write.
   *
   * The same statement writes the Response Code's digest and deadline (#405):
   * `responseCode` is minted by the caller BEFORE redemption and lands on the
   * row in the one write that consumes it, so a code exists exactly when a
   * redemption happened and there is no second statement that could fail
   * between the two. It is written for EVERY redeemed row — one shape, no
   * branch — and whether the code is then EMITTED is the caller's decision,
   * read off the returned row's `sameDevice`; for a cross-device row the
   * digest names a secret nobody holds.
   *
   * @returns the redeemed row, or `undefined` when the state is unknown,
   * expired, or already consumed. Those three are DELIBERATELY indistinguishable
   * to the caller so the endpoint's rejection cannot be used to enumerate
   * request states. A state of another realm than `realmId`, the request's, is
   * unknown too (#489): it is neither matched nor consumed.
   */
  redeem(
    realmId: string,
    stateHash: string,
    responseCode: NewOid4vpResponseCode,
    tx?: DbClient
  ): Promise<Oid4vpRequestState | undefined>;
  /**
   * ATOMICALLY consume a request state by its encryption `kid` (#377 Phase C)
   * — the SECOND correlator, for a `direct_post.jwt` response that carries no
   * cleartext `state`.
   *
   * The same single guarded `UPDATE` as {@link redeem}, on
   * `response_encryption_kid` instead of `state_hash`, with the same
   * consequences: exactly one caller sees a row, and unknown, expired and
   * already-consumed are one indistinguishable `undefined`. The row is consumed
   * BEFORE the ciphertext is decrypted, on purpose — a decrypt that failed
   * against a still-live row would let a caller retry until something opened.
   *
   * The `kid` is attacker-controlled (OID4VP 1.0 §14.5) and is an OPAQUE lookup
   * index here: a match proves only that a row with that `kid` was live. The
   * binding that is trusted is the `state` inside the decrypted payload,
   * checked against the returned row's `stateHash` by the caller.
   *
   * The returned row is the row AS CONSUMED, and this is the ONE hand-off of
   * the private key: the same statement that sets `redeemed_at` NULLs
   * `response_encryption_kid`, `response_encryption_private_jwk` and
   * `response_encryption_key_protection` in the table, and projects their
   * pre-update values into the result. The key's only job ends when the row is
   * consumed, and a key that outlives its response is pure exposure — a later
   * database dump plus retained POST bodies would decrypt historical
   * presentations. The caller must decrypt from the returned value; no second
   * read can ever produce it. {@link redeem} clears the same three columns
   * (a consumed row keeps no key whichever correlator consumed it) but returns
   * them NULL, because the cleartext path has no use for a key.
   *
   * There is deliberately no `findByEncryptionKid`, for the reason the module
   * JSDoc gives: the only way to observe a row is to consume it.
   *
   * Writes the Response Code exactly as {@link redeem} does (#405), in the same
   * statement as the erasure: `responseCode` is on the row the instant it is
   * consumed, whichever correlator consumed it.
   */
  redeemByEncryptionKid(
    realmId: string,
    kid: string,
    responseCode: NewOid4vpResponseCode,
    tx?: DbClient
  ): Promise<Oid4vpRequestState | undefined>;
  /**
   * ATOMICALLY consume a Response Code (#405) — the THIRD correlator, presented
   * back by the BROWSER on the same-device return leg rather than by the
   * wallet — and learn which request it named.
   *
   * One guarded `UPDATE ... WHERE response_code_hash = $1 AND
   * response_code_redeemed_at IS NULL AND response_code_expires_at > $now AND
   * redeemed_at IS NOT NULL AND same_device = true SET response_code_redeemed_at
   * = $now RETURNING state_hash`. Five predicates, each load-bearing: the digest
   * finds the row; the marker makes the code single-use under concurrency
   * (row lock, as with {@link redeem}); the code's OWN deadline bounds the
   * return leg, independently of the request's `expires_at`; `redeemed_at IS
   * NOT NULL` says a code is only good on a row a wallet actually answered;
   * and `same_device = true` says a code that was never emitted — every
   * cross-device row carries a digest it never sent anywhere — can never be
   * presented, whatever a caller manages to guess.
   *
   * Returns ONLY `stateHash`, never the row: the return route needs the one
   * value that joins the code to a browser flow, and the encrypted-response
   * columns must never be projected on a path the browser drives. Unknown,
   * expired, replayed, cross-device and never-answered are ONE `undefined`, so
   * the landing page cannot be used to enumerate codes.
   *
   * Consuming, not finding — the code is SPENT by this call whatever the
   * caller does next, which is what lets a foreign-session landing burn it
   * (HAIP 1.0 §5.1) and guarantees the initiating flow can then never
   * complete. There is deliberately no `findByResponseCode`.
   */
  redeemResponseCode(
    realmId: string,
    codeHash: string,
    tx?: DbClient
  ): Promise<{ stateHash: string } | undefined>;
  /**
   * Delete expired rows. Cleanup only — expiry is already enforced by
   * {@link Oid4vpRequestStatesRepository.redeem}'s guard, so this never affects
   * whether a state is accepted.
   *
   * A row is expired only when BOTH its deadlines have passed: `expires_at`
   * (the request's) and, where one was written, `response_code_expires_at`
   * (the code's, #405). A request answered at its last second carries a code
   * that outlives it, and sweeping the row would turn a wallet's on-time
   * answer into a return leg that finds nothing.
   *
   * @returns count of deleted rows.
   */
  deleteExpired(tx?: DbClient): Promise<number>;
}

/**
 * Realm key types (ADR-019 Decision 9, issue #461).
 */
export type NewRealmKey = InferInsertModel<typeof realmKeys>;
export type RealmPublicKey = InferSelectModel<typeof realmPublicKeys>;

/**
 * The three `realm_keys` columns that hold wrapped key material. Only
 * {@link RealmKeysRepository.getWrappedForSigner} returns them.
 */
export type RealmKeyWrappedColumn = 'ciphertext' | 'iv' | 'wrappedDek';

/**
 * A full `realm_keys` row, wrapped material included. Returned only by
 * {@link RealmKeysRepository.getWrappedForSigner}.
 */
export type WrappedRealmKey = InferSelectModel<typeof realmKeys>;

/**
 * A `realm_keys` row without its wrapped material: what every list and find
 * method returns. `kekRef` and `aadVersion` stay: they name how the key was
 * wrapped, not what it is.
 */
export type RealmKey = Omit<WrappedRealmKey, RealmKeyWrappedColumn>;

/**
 * Input of {@link RealmKeysRepository.create}: the key row, plus the public
 * JWK when the purpose is published.
 *
 * The public row's `realmId`, `kid`, `purpose`, `algorithm`, `status`,
 * `publishAt` and `unpublishAt` are copied from `key`, so the two rows cannot
 * disagree at creation. A published key therefore needs `publishAt`.
 * Symmetric purposes (cookie HMAC, data at rest, webhook secrets) pass no
 * `publicJwk` and get no public row.
 */
export type NewRealmKeyInput =
  | { key: NewRealmKey & { publishAt: number }; publicJwk: Record<string, unknown> }
  | { key: NewRealmKey; publicJwk?: undefined };

/**
 * Filter for {@link RealmKeysRepository.listByRealm}. An omitted field does not
 * filter; `scopeId: null` selects unscoped keys only.
 */
export interface RealmKeyFilter {
  purpose?: string;
  scopeId?: string | null;
  status?: RealmKeyStatus;
}

/**
 * One rotation step for {@link RealmKeysRepository.updateStatus} (#547):
 *
 * - `active` — a `next` key starts to sign at `activateAt`;
 * - `retired` — an `active` key stops signing at `retireAt`. A published key
 *   leaves its JWKS at `unpublishAt`; an unpublished one passes `null`.
 */
export type RealmKeyStatusChange =
  | { status: 'active'; activateAt: number }
  | { status: 'retired'; retireAt: number; unpublishAt: number | null };

/**
 * The published keys of each realm (`realm_public_keys`): public material that
 * every service role reads (#491, #495), unlike `realm_keys`.
 */
export interface RealmPublicKeysRepository {
  /**
   * Every published key of a realm, whatever its status or publication
   * window, ordered by purpose, `publish_at` and `kid`.
   */
  listByRealm(realmId: string, tx?: DbClient): Promise<RealmPublicKey[]>;
}

/**
 * Realm keys repository (ADR-019 Decision 9, issue #461).
 *
 * The signer's view of `realm_keys` and `realm_public_keys`. Only the signer's
 * database user may read `realm_keys` (#498), and in code the same rule holds
 * one level up: {@link RealmKeysRepository.getWrappedForSigner} is the only
 * method that selects `ciphertext`, `iv` or `wrapped_dek`. Every other method
 * returns {@link RealmKey}, which has no wrapped columns, and a unit test fails
 * when a new method selects one.
 */
export interface RealmKeysRepository {
  /**
   * Store a key, and its public row when `publicJwk` is given, in ONE
   * transaction (a savepoint when `tx` is an outer transaction): either both
   * rows exist afterwards or neither does.
   *
   * @throws UniqueConstraintError on a `kid` already used in the realm
   * (`realm_keys_realm_id_kid_unique`) or a second `active` key for the same
   * realm, purpose, scope and algorithm (`idx_realm_keys_one_active`)
   */
  create(input: NewRealmKeyInput, tx?: DbClient): Promise<RealmKey>;
  /** Find a key by `kid` within a realm, without its wrapped material. */
  findByKid(realmId: string, kid: string, tx?: DbClient): Promise<RealmKey | undefined>;
  /**
   * List a realm's keys, oldest first, without their wrapped material.
   * Optionally narrowed by purpose, scope and status.
   */
  listByRealm(realmId: string, filter?: RealmKeyFilter, tx?: DbClient): Promise<RealmKey[]>;
  /**
   * Every `realm_public_keys` row of a realm, whatever its status or
   * publication window, ordered by purpose, `publish_at` and `kid`. The signer
   * builds the realm's JWKS and verification keys from them (#464). Public
   * material only: the table's CHECKs refuse a private JWK member.
   */
  listPublicByRealm(realmId: string, tx?: DbClient): Promise<RealmPublicKey[]>;
  /**
   * Whether a realm other than `realmId` publishes a key whose public JWK has
   * every member of `identity` (its key type and public value, such as
   * `{ kty, crv, x }`), whatever its status or window: two realms never share a
   * key (#491).
   */
  anotherRealmPublishes(
    realmId: string,
    identity: Readonly<Record<string, string>>,
    tx?: DbClient
  ): Promise<boolean>;
  /**
   * The ONE method that returns wrapped key material: the full row, for the
   * signer to unwrap. Takes the realm id as well as the `kid`, so a `kid` from
   * one realm never opens another realm's key.
   */
  getWrappedForSigner(
    realmId: string,
    kid: string,
    tx?: DbClient
  ): Promise<WrappedRealmKey | undefined>;
  /**
   * Move one key a step through its rotation (#547): `next` → `active`, or
   * `active` → `retired`. A key in any other status is left as it is, so two
   * rotations that race cannot both move it. The status reaches the key's
   * public row through its foreign key; a retirement also writes the public
   * row's `unpublish_at`. Both rows change in ONE transaction (a savepoint
   * inside `tx`).
   *
   * @returns the updated key, or `undefined` when the realm holds no key with
   *   `kid` in the status the step starts from.
   */
  updateStatus(
    realmId: string,
    kid: string,
    change: RealmKeyStatusChange,
    tx?: DbClient
  ): Promise<RealmKey | undefined>;
  /**
   * Delete every key of one scope: a webhook subscription's secrets or an
   * upstream provider's client-assertion keys (#547). Their public rows go
   * with them (foreign key, `ON DELETE CASCADE`). An unscoped key never
   * matches, since its `scope_id` is NULL.
   *
   * @returns the `kid`s of the deleted keys.
   */
  deleteByScope(
    realmId: string,
    purpose: string,
    scopeId: string,
    tx?: DbClient
  ): Promise<string[]>;
  /**
   * Take the realm's key lock for the rest of the transaction `tx`: a
   * transaction-level advisory lock, released at commit or rollback. The key
   * boot step (#485) holds it while it imports and creates a realm's keys, so
   * nodes that boot together do that one at a time.
   */
  lockRealm(realmId: string, tx: DbClient): Promise<void>;
}

/**
 * Browser session types (ADR-019 Decision 3, issue #468).
 */
export type Session = InferSelectModel<typeof sessions>;
export type SessionClient = InferSelectModel<typeof sessionClients>;

/**
 * A `session_clients` row with the public identity of its client (issue
 * #550): what a session list shows and what a revocation returns, so a caller
 * names the client without reading `oauth_clients` again.
 */
export interface SessionClientDetail extends SessionClient {
  /** The client's public `client_id`. */
  clientId: string;
  /** The client's display name (`oauth_clients.name`). */
  clientName: string;
}

/**
 * What the revocations of {@link SessionsRepository} return for each session
 * they end: the ended row and the `session_clients` rows deleted with it
 * (issue #549), the clients the session served, which back-channel logout
 * notifies. A registry row whose client is gone by the time it is read is
 * left out: there is no client to notify.
 */
export interface RevokedSession {
  session: Session;
  clients: SessionClientDetail[];
}

/**
 * A session as a list shows it (issue #550): the row, whatever its state, and
 * the clients its registry holds, oldest first. An ended session holds none:
 * its revocation deleted them.
 */
export interface ListedSession {
  session: Session;
  clients: SessionClientDetail[];
}

/**
 * A place in a newest-first session list: the `created_at` and `id` of the
 * last row a page showed. The next page starts after it.
 */
export interface SessionListPosition {
  createdAt: number;
  id: string;
}

/** One page of a session list. */
export interface SessionListPage {
  /** The most rows to return. */
  limit: number;
  /** Start after this row; from the newest when absent. */
  after?: SessionListPosition;
}

/** Which of a user's sessions {@link SessionsRepository.revokeForUser} ends. */
export interface RevokeUserSessionsFilter {
  /** Keep this session: the one the request that signs out everywhere else came from. */
  exceptId?: string;
  /**
   * End only the sessions created before this time, in epoch milliseconds: a
   * password reset ends the sessions older than the new password.
   */
  createdBefore?: number;
}

/** One batch of {@link SessionsRepository.revokeRealmBatch}. */
export interface RevokeRealmSessionsBatch {
  /** Start after this session id; from the first when absent. */
  after?: string;
  /**
   * End only sessions created at or before this time, in epoch milliseconds:
   * the time the whole run started, so a sign-in during the run survives it.
   */
  createdThrough: number;
  /**
   * End only sessions used at or after this time (`last_seen_at`), in epoch
   * milliseconds. Every live session when absent.
   */
  activeSince?: number;
  /** The most sessions to end. */
  limit: number;
}

/** One batch of {@link SessionsRepository.revokeLapsedBatch}. */
export interface RevokeLapsedSessionsBatch {
  /** The time to judge the ends at, in epoch milliseconds. */
  now: number;
  /**
   * `SESSION_COOKIE_TTL` in milliseconds: the maximum lifespan of a session
   * in a realm that sets no `sso_max_lifespan`, as the session service
   * applies it.
   */
  defaultMaxLifespanMs: number;
  /** Start after this session id; from the first when absent. */
  after?: string;
  /** The most sessions to end. */
  limit: number;
}

/** What one batch of a bulk revocation did. */
export interface RevokedSessionsBatch {
  /** The sessions this batch ended, in id order. */
  ended: RevokedSession[];
  /**
   * The id the next batch starts after: the last session this batch
   * selected. `null` when it selected none, which ends the run.
   */
  last: string | null;
  /** How many sessions the batch selected: fewer than its limit ends the run. */
  selected: number;
}

/** One batch of {@link SessionsRepository.deleteEnded}. */
export interface DeleteEndedSessionsBatch {
  /**
   * Delete the rows revoked, or past `expires_at`, before this time, in epoch
   * milliseconds.
   */
  before: number;
  /** Start after this session id; from the first when absent. */
  after?: string;
  /** The most rows to delete. */
  limit: number;
}

/** What one batch of {@link SessionsRepository.deleteEnded} did. */
export interface DeletedSessionsBatch {
  deleted: number;
  /** The id the next batch starts after; `null` when the batch selected no row. */
  last: string | null;
  /** How many rows the batch selected: fewer than its limit ends the run. */
  selected: number;
}

/**
 * Input of {@link SessionsRepository.create}. The id is not accepted: the
 * database makes it (`uuidv7()`), and it becomes the session's `sid`. Nor are
 * the revocation columns: a session starts live.
 */
export type NewSession = Omit<
  InferInsertModel<typeof sessions>,
  'id' | 'revokedAt' | 'revokedReason'
>;

/** Options of {@link SessionsRepository.updateLastSeen}. */
export interface UpdateSessionLastSeenOptions {
  /**
   * Write only when the stored `last_seen_at` is at least this many
   * milliseconds old. Defaults to 0, which always writes.
   */
  minIntervalMs?: number;
}

/**
 * Browser sessions repository (ADR-019 Decision 3, issue #468).
 *
 * Storage only. Whether a session counts as signed in (the realm's idle limit,
 * the cache in front of Postgres) is the session service's call (#469).
 *
 * Every method that names a session or a user also takes the realm id, and
 * its statement filters on it (ADR-019 Decision 1). A session of another realm
 * is never found, touched, ended or listed; to the caller it does not exist.
 */
export interface SessionsRepository {
  /**
   * Store a new, live session. The realm comes from `data.realmId`; the
   * database refuses a user of another realm (`sessions_user_realm_fk`).
   *
   * @returns the stored row; its `id` is the session's `sid`
   */
  create(data: NewSession, tx?: DbClient): Promise<Session>;
  /**
   * Find a session by id within a realm, whatever its state: a revoked or
   * expired row is returned as stored, for the caller to judge.
   *
   * @returns the row, or `undefined` when the realm holds no session with that id
   */
  findById(realmId: string, id: string, tx?: DbClient): Promise<Session | undefined>;
  /**
   * Set `last_seen_at` to now on a live session: one conditional `UPDATE` that
   * skips a revoked or expired row, and a row seen less than
   * `options.minIntervalMs` ago. Of several nodes touching one session within
   * the interval, only the first writes.
   *
   * @returns `true` when this call wrote the row
   */
  updateLastSeen(
    realmId: string,
    id: string,
    options?: UpdateSessionLastSeenOptions,
    tx?: DbClient
  ): Promise<boolean>;
  /**
   * End a session: one guarded `UPDATE` that sets `revoked_at` and
   * `revoked_reason` on a row not yet revoked. An expired row may still be
   * revoked, with `expired` or any other reason.
   *
   * In the same transaction it deletes the session's `session_clients` rows
   * (issue #549), an ended session holding no client, and returns them: the
   * one complete list of the clients it served, which back-channel logout
   * reads. A list read before the call could miss a code being minted
   * meanwhile, whose row {@link recordClient} commits before this `UPDATE`
   * proceeds; the `DELETE` that follows sees it. It also spends the
   * session's unredeemed authorization codes, so none is redeemed into an ID
   * token whose `sid` names the ended session.
   *
   * Runs READ COMMITTED; a `tx` passed in must be READ COMMITTED too, or the
   * `DELETE` reads the snapshot from before the `UPDATE` waited. A `tx` at
   * another level is refused with an error before anything is written.
   *
   * @returns the ended row and the clients it served, or `undefined` when the
   * realm holds no such session or it was already revoked. A second call
   * changes nothing and keeps the first reason.
   */
  revoke(
    realmId: string,
    id: string,
    reason: SessionRevokedReason,
    tx?: DbClient
  ): Promise<RevokedSession | undefined>;
  /**
   * A user's live sessions in a realm, newest first: not revoked and before
   * `expires_at`. Served by the partial index `idx_sessions_realm_user_active`.
   */
  listActiveForUser(realmId: string, userId: string, tx?: DbClient): Promise<Session[]>;
  /**
   * Record that a live session served a client (issue #549): the
   * `session_clients` row back-channel logout reads, written in the
   * transaction that mints the authorization code. A session that served the
   * client before keeps its one row and its first time.
   *
   * The session row is locked `FOR SHARE` until `tx` ends, so a concurrent
   * {@link revoke} either waits and then deletes (and returns) the row
   * written here, or committed first and this call finds no live session.
   * Hence `tx` is required, a transaction (not the root client), and READ
   * COMMITTED: outside a transaction the lock would end with the statement.
   *
   * @returns `true` when the realm holds the session live (not revoked, before
   * `expires_at`), the client is one of the same realm, and the row is stored;
   * `false`, writing nothing, otherwise. The caller then issues no code, so
   * every code minted from a session is among the clients its revocation
   * returns.
   */
  recordClient(
    realmId: string,
    sessionId: string,
    oauthClientId: string,
    tx: DbTransaction
  ): Promise<boolean>;
  /**
   * The clients one live session of the realm served, oldest first. Empty for
   * a session of another realm, and for one revoked or past `expires_at`. The
   * idle limit is the session service's call and is not judged here.
   */
  listClientsForSession(
    realmId: string,
    sessionId: string,
    tx?: DbClient
  ): Promise<SessionClient[]>;
  /**
   * The registry rows of every live session of one user in the realm (not
   * revoked, before `expires_at`), oldest first.
   */
  listClientsForUser(realmId: string, userId: string, tx?: DbClient): Promise<SessionClient[]>;
  /**
   * The registry rows of one client (its `oauth_clients.id`) across the
   * realm's live sessions, oldest first. A session past `expires_at` keeps its
   * rows until it is revoked or its row deleted, but is not listed.
   */
  listSessionsForClient(
    realmId: string,
    oauthClientId: string,
    tx?: DbClient
  ): Promise<SessionClient[]>;
  /**
   * One page of a user's sessions in the realm, newest first (`created_at`,
   * then `id`), whatever their state: live, past an end, or revoked, until
   * {@link deleteEnded} removes them. Each comes with the clients its
   * registry holds; a revoked one with none. Empty for a user of another
   * realm.
   */
  listForUser(
    realmId: string,
    userId: string,
    page: SessionListPage,
    tx?: DbClient
  ): Promise<ListedSession[]>;
  /**
   * One page of the realm's sessions that served a client (its
   * `oauth_clients.id`), newest first, each with all the clients its
   * registry holds. Only sessions not yet revoked are listed: a revocation
   * deletes the registry rows, and one a previous release made during a
   * rolling upgrade, which left them, does not count. Empty for a client of
   * another realm.
   */
  listForClient(
    realmId: string,
    oauthClientId: string,
    page: SessionListPage,
    tx?: DbClient
  ): Promise<ListedSession[]>;
  /**
   * End a user's sessions in the realm that are not yet revoked, with one
   * reason, as {@link revoke} ends one: the rows are locked in id order,
   * revoked, their registry rows deleted and returned, their unredeemed codes
   * spent, all in one READ COMMITTED transaction. A session past an end that
   * {@link revokeLapsedBatch} has not marked yet is ended with this reason
   * too.
   *
   * A `tx` passed in must be READ COMMITTED, as for {@link revoke}.
   *
   * @returns the sessions this call ended, in id order; one another call
   * ended first is not among them
   */
  revokeForUser(
    realmId: string,
    userId: string,
    reason: SessionRevokedReason,
    filter?: RevokeUserSessionsFilter,
    tx?: DbClient
  ): Promise<RevokedSession[]>;
  /**
   * End one batch of the realm's sessions not yet revoked, in id order after
   * `batch.after`: one short READ COMMITTED transaction, as {@link revoke}
   * ends one session. A caller ends a whole realm batch after batch, so no
   * transaction holds more than `batch.limit` rows.
   */
  revokeRealmBatch(
    realmId: string,
    reason: SessionRevokedReason,
    batch: RevokeRealmSessionsBatch
  ): Promise<RevokedSessionsBatch>;
  /**
   * Mark one batch of sessions, of every realm, that are past an end but not
   * yet revoked: past the absolute end (`expires_at`, or the realm's current
   * `sso_max_lifespan` from creation, `SESSION_COOKIE_TTL` without one) as
   * `expired`, past the realm's idle limit (`sso_idle_timeout` from
   * `last_seen_at`) as `idle`, whichever came first. The rules are the
   * session service's, so the rows marked are sessions it already treats as
   * absent. `revoked_at` is `batch.now`, the time of the mark, so the
   * retention of {@link deleteEnded} counts from it. Otherwise as
   * {@link revokeRealmBatch}.
   */
  revokeLapsedBatch(batch: RevokeLapsedSessionsBatch): Promise<RevokedSessionsBatch>;
  /**
   * Delete one batch of rows, of every realm, that were revoked or passed
   * `expires_at` before `batch.before`, in id order after `batch.after`. A
   * live session is never deleted. The rows' registry rows go with them
   * (cascade), and their codes lose the session (`ON DELETE SET NULL`).
   */
  deleteEnded(batch: DeleteEndedSessionsBatch): Promise<DeletedSessionsBatch>;
}

/** A stored `admin_audit_log` row (ADR-019 Decision 7, issue #448). */
export type AdminAuditRecord = InferSelectModel<typeof adminAuditLog>;

/**
 * One admin operation, as its caller records it with
 * {@link AdminAuditLogRepository.appendAdminAudit}. The repository adds the
 * chain columns (`seq`, `prev_hash`, `row_hash`) and the time.
 */
export interface AdminAuditEntry {
  /** The realm the operation targeted. Its chain receives the row. */
  realmId: string;
  actorKind: AdminActorKind;
  /**
   * An account id for a human admin, a `client_id` for a service account, the
   * operating-system user for the break-glass CLI or a host tool.
   */
  actorId: string;
  /**
   * The realm the actor's account lives in. Required for a human admin or a
   * service account, and `null` for the host-side kinds.
   */
  actorRealmId: string | null;
  /**
   * The full act chain, when the actor acted for a user: every link, each with
   * the claims {@link AdminAuditActClaim} names. Other members are not stored.
   */
  actChain?: AdminAuditActChain | null;
  /** The permission catalog id of the operation, such as `realms.policies.write`. */
  operationId: string;
  operationClass: AdminOperationClass;
  /** Ids of the effects that make the operation what it is (ADR-019 Decision 7). */
  effects?: readonly string[];
  outcome: AdminAuditOutcome;
  /**
   * The change, with the annotations that name the resource's secret fields.
   * It is stored only through `maskSecrets`, never as given.
   */
  diff?: { change: AdminAuditDiff; annotations: FieldAnnotations } | null;
  /** The approvals the operation ran on, with the members their type names only. */
  approvals?: readonly AdminAuditApproval[];
  /** SHA-256 (32 bytes) of the canonical request an approval is bound to. */
  requestDigest?: Buffer | null;
  /** The id under which QAuth logged the request, at most 128 characters. */
  traceId?: string | null;
}

/** Why {@link AdminAuditLogRepository.verifyAdminAuditChain} stopped at a row. */
export type AdminAuditChainBreakReason =
  /** The row's `seq` is not the one after the row (or the checkpoint) before it. */
  | 'sequence_mismatch'
  /** The row's `prev_hash` is not the `row_hash` of the row (or checkpoint) before it. */
  | 'prev_hash_mismatch'
  /** The row's content does not hash to its `row_hash`: the row was changed. */
  | 'row_hash_mismatch'
  /** The row's JSON columns hold a value that cannot be hashed. */
  | 'unhashable_row';

/**
 * The result of {@link AdminAuditLogRepository.verifyAdminAuditChain}. Hashes
 * are lowercase hex.
 */
export type AdminAuditChainReport =
  | {
      ok: true;
      realmId: string;
      /** How many rows were checked. */
      rowsChecked: number;
      /** The checkpoint the chain was checked from, or `null` from the first row. */
      checkpoint: { seq: number; rowHash: string } | null;
      /** The newest row, or `null` when the realm has no retained row. */
      head: { seq: number; rowHash: string } | null;
    }
  | {
      ok: false;
      realmId: string;
      /** How many rows verified before the break. */
      rowsChecked: number;
      checkpoint: { seq: number; rowHash: string } | null;
      /** The first row that does not verify. */
      break: {
        seq: number;
        reason: AdminAuditChainBreakReason;
        /** The `seq` the row should have had, for a `sequence_mismatch`. */
        expectedSeq?: number;
      };
    };

/**
 * Called inside the transaction right after a row is inserted. The event
 * outbox writer plugs in here (ADR-019 Decision 8): it writes the event that
 * mirrors the row in the same transaction, and an error it throws rolls back
 * the row and the change with it.
 */
export type AdminAuditAfterAppend = (tx: DbTransaction, record: AdminAuditRecord) => Promise<void>;

/** Options of `createAdminAuditLogRepository`. */
export interface AdminAuditLogOptions {
  /** See {@link AdminAuditAfterAppend}. */
  afterAppend?: AdminAuditAfterAppend;
  /** The clock for `created_at`, in epoch milliseconds. Defaults to `Date.now`. */
  now?: () => number;
  /** Rows read per query while verifying, a positive integer. Defaults to 500. */
  verifyBatchSize?: number;
}

/**
 * The admin audit log (ADR-019 Decision 7, issue #448): append-only, one hash
 * chain per target realm.
 */
export interface AdminAuditLogRepository {
  /**
   * Append one row to the target realm's chain, in the caller's transaction,
   * so the row commits or rolls back with the change it records.
   *
   * Takes the realm's chain lock (`pg_advisory_xact_lock`) until the
   * transaction ends, so appends to one realm form one linear chain. Under
   * REPEATABLE READ or SERIALIZABLE, an append that raced another fails on the
   * primary key instead; retry the transaction. Because the lock lasts to the
   * end of the transaction, append last; a transaction that appends to
   * several realms appends in a fixed order (by realm id), or two such
   * transactions can deadlock.
   *
   * After the insert it hashes the row as Postgres returned it and throws if
   * that differs from the hash it wrote, so a row the chain would reject later
   * never commits.
   *
   * @throws TypeError on an entry that cannot be stored: an id that is not a
   *   UUID, a missing or extra `actorRealmId`, a digest that is not 32 bytes,
   *   a text longer than its column, an act chain without a `sub`, or a JSON
   *   value outside the I-JSON model.
   */
  appendAdminAudit(tx: DbTransaction, entry: AdminAuditEntry): Promise<AdminAuditRecord>;

  /**
   * Check a realm's chain from its oldest retained row to its newest, and
   * report the first row that breaks it.
   *
   * The chain starts at `seq` 1 and the genesis hash, or, after a prune, at
   * the newest checkpoint. Every row must follow the one before it in `seq`,
   * carry its hash as `prev_hash`, and hash to its own `row_hash`. Reads run
   * in one REPEATABLE READ transaction, so a concurrent append or prune
   * cannot produce a false break.
   */
  verifyAdminAuditChain(realmId: string): Promise<AdminAuditChainReport>;
}

/**
 * One event as its emitter hands it to {@link EventsRepository.emit}: the
 * envelope of the event contract (`@qauth-labs/shared-events`) without `id`,
 * `time` and `category`. The repository makes the id (a UUIDv7) and the time,
 * and takes the category from the type's registry entry.
 */
export interface EmitEvent<Type extends RegisteredEventType = RegisteredEventType> {
  /** A registered event type. */
  type: Type;
  /** The id of the realm the event happened in. */
  realm: string;
  actor?: EventEnvelope['actor'];
  subject?: EventEnvelope['subject'];
  client?: EventEnvelope['client'];
  request?: EventEnvelope['request'];
  /** The type's own payload, as its schema in the registry describes it. */
  data: EventDataOf<Type>;
}

/** An event read back from the store, with its place in the realm's stream. */
export interface StoredEvent {
  /** The position of this event: reading on from it returns the events after it. */
  position: EventPosition;
  /** The envelope, as it was emitted. */
  event: EventEnvelope;
}

/**
 * Narrowing of {@link EventsRepository.readAfter}. Every member is optional
 * and they combine with AND. A position does not depend on them: a reader may
 * change its filters and read on from the same position.
 */
export interface EventReadFilters {
  /** Only events of these types. An empty list matches no event. */
  types?: readonly string[];
  category?: EventCategory;
  /** Only events about this subject (`subject.id`). */
  subjectId?: string;
  /** Only events whose request came through this client (`client.id`). */
  clientId?: string;
  /** Only events whose `time` is at or after this, in epoch milliseconds. */
  fromTime?: number;
}

/** One read of a realm's stream. */
export interface EventPage {
  /** The events after the position read from, oldest first, at most the limit. */
  events: StoredEvent[];
  /**
   * Where to read on from: the last event's position when the page is full,
   * else the read's horizon. Never before the position read from.
   */
  next: EventPosition;
}

/**
 * Where the event store hands each event once its transaction has committed
 * (ADR-019 Decision 8, issue #541): the auth server's OpenTelemetry log
 * export. Telemetry, not delivery: it has no delivery guarantee, and an event
 * the process loses between the commit and the hand-over is not sent again.
 * The event API and webhooks read the store and carry the guarantee.
 */
export interface EventTelemetrySink {
  /**
   * Take one committed event, the envelope as it was stored. Called after the
   * COMMIT, never inside the transaction. It must return at once (it queues)
   * and never throw; an error it throws anyway is ignored.
   */
  record(event: EventEnvelope): void;
}

/** Options of `createEventsRepository`. */
export interface EventsRepositoryOptions {
  /** The clock for an event's `time` and id, in epoch milliseconds. Defaults to `Date.now`. */
  now?: () => number;
  /** Admin rows read per query while verifying the chain, a positive integer. Defaults to 500. */
  verifyBatchSize?: number;
  /**
   * Hand each committed event to this sink. With it, the repository makes
   * the root database report its commits (see {@link EventsRepository}).
   * Without it, nothing leaves the store but through its reads.
   */
  telemetry?: EventTelemetrySink;
}

/**
 * One admin change, as an admin operation records it with
 * {@link EventsRepository.emitAdminEvent} (ADR-020 §3, issue #459). The
 * repository builds the masked diff from `before` and `after` and writes one
 * `admin.change_applied` event.
 */
export interface AdminEventInput {
  /** The realm the operation changed: the chain the event joins. */
  realm: string;
  /**
   * Who made the change: an admin (`user`), a service account (`client`), or
   * an operator on the server host (`operator_cli`, with the operating-system
   * user; see `operatorCliActor`). Required: an admin change always has one.
   */
  actor: NonNullable<EventEnvelope['actor']>;
  /** The operation's id in the permission catalog, such as `realms.policies.write`. */
  operation: string;
  /** What the operation changed, such as `{ type: 'client', id: clientId }`. */
  target: { type: string; id: string };
  /** The target before the operation, or `null` when the operation created it. */
  before: JsonObject | null;
  /** The target after the operation, or `null` when the operation deleted it. */
  after: JsonObject | null;
  /**
   * Fields the operation marks secret, by path inside the target (`smtp.password`,
   * `webhooks.*.secret`). A field whose name looks like a secret is masked
   * without a mark.
   */
  secretFields?: readonly string[];
  /** The approvals the operation ran on, both of a two-admin operation. */
  approvals?: readonly AdminApproval[];
  /** The OAuth client the request came through, when there was one. */
  client?: EventEnvelope['client'];
  /** The HTTP request, when there was one. */
  request?: EventEnvelope['request'];
}

/**
 * A point of a realm's admin chain: an admin row's `seq` and its `hash`, in
 * lowercase hex. {@link EventsRepository.verifyChain} starts after one.
 */
export interface EventChainPoint {
  seq: bigint;
  hash: string;
}

/** Why {@link EventsRepository.verifyChain} stopped at a row. */
export type EventChainBreakReason =
  /**
   * The row's `prev_hash` is not the `hash` of the admin row before it (or of
   * the point verified from): a row before it was removed, or changed and
   * given a new hash.
   */
  | 'prev_hash_mismatch'
  /** The row's envelope does not hash to its `hash`: the row was changed. */
  | 'hash_mismatch'
  /** The row cannot be read back into an envelope that hashes. */
  | 'unreadable_row'
  /**
   * No admin row of the realm is at the point verified from: it was removed
   * by something other than retention, which keeps the point it deletes as
   * the realm's anchor.
   */
  | 'anchor_missing'
  /**
   * The row at the point verified from no longer carries the point's hash,
   * or no longer hashes to it: it, or the chain up to it, was rewritten.
   */
  | 'anchor_mismatch';

/** The result of {@link EventsRepository.verifyChain}. */
export type EventChainReport =
  | {
      ok: true;
      realmId: string;
      /** The point the chain was verified from. */
      from: EventChainPoint;
      /** How many admin rows were checked. */
      rowsChecked: number;
      /**
       * The newest admin row, with its event id, or `null` when no admin row
       * follows `from`. Kept outside the database, it is the point a later
       * verification starts from: that run fails when the chain up to it was
       * cut or rewritten. It reads no row before the point, so a single row
       * changed there shows only in a run from the start. Rows cut after it
       * leave no break; the next head is then older than expected.
       */
      head: (EventChainPoint & { id: string }) | null;
    }
  | {
      ok: false;
      realmId: string;
      from: EventChainPoint;
      /** How many admin rows verified before the break. */
      rowsChecked: number;
      /**
       * The first admin row that does not verify. `id` is `null` when the row
       * at the point verified from is missing.
       */
      break: { id: string | null; seq: bigint; reason: EventChainBreakReason };
    };

/**
 * The event store (ADR-019 Decision 8, ADR-018 §3, issue #457): the
 * transactional outbox and the event log in one append-only table.
 *
 * ## The write rule
 *
 * An event is written in the transaction of the change it records, so both
 * commit or neither does. A caller that has a transaction passes it to
 * {@link emit}. A caller without one (a change that is a single statement, or
 * an event that records no change, such as a refused sign-in) calls
 * {@link emitInOwnTransaction}, which writes the event in a short transaction
 * of its own. Never open a transaction only to emit after it commits: the
 * change could commit and the event be lost.
 *
 * ## The read rule and its lag
 *
 * Every read takes a realm id; there is no read across realms.
 * {@link readAfter} returns only events whose writing transaction is older
 * than every transaction still open, so a reader never skips an event that
 * commits late. The price is lag: one long-open transaction that has written
 * anything, on any database of the Postgres server, holds back every event
 * written after it began until it ends. {@link oldestUnreadEventAge} measures
 * that wait; the auth server publishes it as the gauge
 * `qauth_events_oldest_unread_age_seconds`.
 *
 * ## Telemetry
 *
 * With a telemetry sink in its options, the repository hands every event it
 * wrote to the sink once the event's transaction has committed: right after
 * the insert for {@link emitInOwnTransaction}, and after the outermost COMMIT
 * for {@link emit}. An event whose transaction or savepoint rolls back is
 * never handed over. The sink never reads the store. Only a transaction
 * opened on the root database the repository was made with can report its
 * commit; an event emitted in any other is stored but not handed over.
 */
export interface EventsRepository {
  /**
   * Write one event in the caller's transaction (a `DbTransaction`, never the
   * root database), so it commits or rolls back with the change it records.
   *
   * The event is checked against the registry first (`parseEvent`): its type
   * must be registered, its `data` must match the type's schema and the
   * payload rules, and its subject the type's. Nothing is written when it
   * fails.
   *
   * The insert returns nothing, so a role granted only `INSERT` on `events`
   * can write a user event.
   *
   * An event of an `admin` type joins the realm's admin chain: the call takes
   * the realm's chain lock (`pg_advisory_xact_lock`) until the transaction
   * ends, reads the chain head, and stores `prev_hash` and `hash` with the
   * row, then reads the row back and throws if it does not hash as written,
   * so a row the chain would reject never commits. It reads the head and the
   * row through the functions `events_admin_chain_head` and `events_own_row`
   * (migration 0033), so a writer needs `EXECUTE` on them besides `INSERT`,
   * and no `SELECT` on `events`. Because the lock lasts to the end of the transaction,
   * emit an admin event last; a transaction that writes admin events to
   * several realms writes them in a fixed order (by realm id), or two such
   * transactions can deadlock. Under REPEATABLE READ or SERIALIZABLE, an
   * admin event that raced another fails instead of forking the chain, on
   * `idx_events_chain_link` (23505) or with a serialization failure (40001);
   * retry the transaction. {@link emitInOwnTransaction} runs an admin event
   * under READ COMMITTED.
   *
   * @returns the event id, a UUIDv7
   * @throws {EventValidationError} on an unknown type, a payload that fails
   *   its schema or the payload rules, or a text Postgres cannot store (a NUL
   *   character)
   */
  emit<Type extends RegisteredEventType>(
    tx: DbTransaction,
    event: EmitEvent<Type>
  ): Promise<string>;

  /**
   * Write one event in a transaction of its own: the write rule's path for a
   * caller without a transaction. Checked like {@link emit}.
   *
   * @returns the event id, a UUIDv7
   * @throws {EventValidationError} as {@link emit} does
   */
  emitInOwnTransaction<Type extends RegisteredEventType>(event: EmitEvent<Type>): Promise<string>;

  /**
   * Record one admin change as an `admin.change_applied` event (ADR-020 §3,
   * issue #459), in the caller's transaction, so it commits or rolls back with
   * the change. Every admin operation calls it, the command-line tools on the
   * server host included; nothing turns it off.
   *
   * It builds the diff from `before` and `after` (`buildAdminDiff`): changed
   * fields only, nested objects diffed, arrays whole, every secret field
   * `***`. The event then joins the realm's admin chain as {@link emit}
   * writes any admin event.
   *
   * @returns the event id, a UUIDv7
   * @throws {TypeError} on a target that is not plain JSON, or a secret field
   *   mark with an empty segment
   * @throws {EventValidationError} as {@link emit} does
   */
  emitAdminEvent(tx: DbTransaction, input: AdminEventInput): Promise<string>;

  /**
   * Check a realm's admin chain after a point, oldest row first, and report
   * the first admin row that breaks it.
   *
   * Every admin row after `from`, in `seq` order, must carry the `hash` of the
   * row before it (the point's hash, for the first) as `prev_hash`, and its
   * envelope must hash to its own `hash`. A changed row breaks the chain at
   * that row; a removed one at the row after it. A point after the start must
   * still be an admin row of the realm with that hash and an envelope that
   * hashes to it (`anchor_missing`, `anchor_mismatch`). No row before the
   * point is read: a run from a kept head shows a chain cut back or rewritten
   * up to it, but a single row changed before it shows only in a run from the
   * start. Reads run in one REPEATABLE READ transaction, so a concurrent write
   * cannot produce a false break. They read the table, so run it as a role
   * that may: a writing role holds no `SELECT` on `events` (#827).
   *
   * The retention job (#536) deletes the oldest admin rows and keeps the
   * last one it deleted as the realm's anchor (`event_chain_anchors`), in the
   * same transaction. A run starts from the anchor when it is given no point,
   * or a point at or before the anchor, which retention has deleted: the
   * report's `from` is then the anchor, and the oldest row left must carry
   * the anchor's hash as its `prev_hash`, so a changed anchor breaks the
   * chain there. A point at the anchor's `seq` with another hash is an
   * `anchor_mismatch`. The anchor's own row is gone, so it is not read; one
   * still there must match it. The reading role needs `SELECT` on
   * `event_chain_anchors` too.
   *
   * @param realmId - the realm whose chain to check
   * @param from - where to start: the head an earlier verification returned.
   *   Defaults to the realm's anchor, or, before retention has deleted any
   *   admin row, the chain's start, `seq` 0 and 32 zero bytes.
   * @throws {TypeError} on a realm id that is not a UUID, or a point whose
   *   hash is not 64 hex digits
   */
  verifyChain(realmId: string, from?: EventChainPoint): Promise<EventChainReport>;

  /**
   * Read a realm's events after a position, oldest first, in `(xid, seq)`
   * order.
   *
   * Only events whose `xid` is older than the read's snapshot xmin
   * (`pg_snapshot_xmin(pg_current_snapshot())`) are returned. Every
   * transaction below it has ended, so no event can appear before the last
   * one returned later on, and reading on from `next` never skips or repeats
   * one. The horizon and the rows come from one statement, one snapshot.
   *
   * @param realmId - the realm to read; required, there is no read across realms
   * @param position - where to read on from: `eventStreamStart(realmId)`, or
   *   a `position` or `next` this realm's reads returned
   * @param limit - the most events to return, from 1 to 1000
   * @throws {EventPositionError} on a position that does not parse or belongs
   *   to another realm
   * @throws {TypeError} on a realm id that is not a UUID, or a limit out of range
   */
  readAfter(
    realmId: string,
    position: EventPosition,
    limit: number,
    filters?: EventReadFilters
  ): Promise<EventPage>;

  /**
   * How long, in seconds, the oldest committed event that readers cannot take
   * yet has waited: an event held back because a transaction older than it
   * is still open. 0 when no event is held back.
   *
   * Not an event read: it returns one number for the whole store and no
   * event, so it takes no realm.
   */
  oldestUnreadEventAge(): Promise<number>;
}
