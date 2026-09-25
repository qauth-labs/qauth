import type { InferInsertModel, InferSelectModel } from 'drizzle-orm';

import type { oauthConsents } from '../lib/schema/consents';
import type { apiKeys, oauthClients } from '../lib/schema/core';
import type { userAttributes, userCredentials } from '../lib/schema/identity';
import type { oid4vpRequestStates } from '../lib/schema/oid4vp';
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
   * request states.
   */
  redeem(
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
  redeemResponseCode(codeHash: string, tx?: DbClient): Promise<{ stateHash: string } | undefined>;
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
