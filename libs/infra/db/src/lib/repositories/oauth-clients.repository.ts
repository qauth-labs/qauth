import {
  extractConstraintName,
  isUniqueConstraintError,
  NotFoundError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { and, asc, count, desc, eq, gt, lt, or, sql } from 'drizzle-orm';

import type {
  AdminUpdateOAuthClient,
  KeysetPage,
  NewOAuthClient,
  OAuthClient,
  OAuthClientsRepository,
  RealmClientFilter,
  UnshowableRedirectUriScan,
  UnshowableRedirectUriScanOptions,
  UpdateOAuthClient,
} from '../../types/repository';
import { DbClient } from '../db';
import { oauthClients, realms } from '../schema/core';
import { scanUnshowableRedirectUris } from './unshowable-redirect-uris';

/** The client row `id` names in `realmId`: a client of another realm matches nothing (#489). */
function clientOfRealm(realmId: string, id: string) {
  return and(eq(oauthClients.realmId, realmId), eq(oauthClients.id, id));
}

/** The clients of `realmId` a developer owns. */
function ownedBy(realmId: string, developerId: string) {
  return and(eq(oauthClients.realmId, realmId), eq(oauthClients.developerId, developerId));
}

/**
 * The operator-set columns as every application write leaves them: empty.
 * The first-party profile, its policy and its reason (ADR-017 Decision 2,
 * #631), the hosted flows (ADR-017 Decision 8, #640), so no registration
 * path lets a client allow its own sign-up, and the registration's bot
 * challenge (ADR-017 Decision 7, #643), so none sets or lifts its own.
 * Spread last, so no caller's value survives.
 */
const NOT_FIRST_PARTY = {
  firstPartyProfile: null,
  firstPartyPolicy: null,
  firstPartyReason: null,
  hostedFlows: null,
  registrationChallenge: null,
} as const;

/**
 * `data` without the operator-set columns of {@link NOT_FIRST_PARTY}, which
 * `update` never writes (ADR-017 Decisions 2 and 8, #631, #640).
 * `UpdateOAuthClient` already leaves them out, but only at compile time: a
 * caller that spreads a wider object, or casts, would otherwise set or clear
 * a profile or a hosted flow through an ordinary update. Removed, not nulled,
 * so an update leaves the operator's values as they are.
 */
function withoutFirstPartyColumns<T extends object>(data: T): T {
  const copy = { ...data } as Record<string, unknown>;
  for (const column of Object.keys(NOT_FIRST_PARTY)) delete copy[column];
  return copy as T;
}

/** The columns {@link AdminUpdateOAuthClient} names, which `updateByAdmin` writes and no other. */
const ADMIN_UPDATE_COLUMNS: ReadonlySet<string> = new Set<keyof AdminUpdateOAuthClient>([
  'name',
  'description',
  'redirectUris',
  'postLogoutRedirectUris',
  'backchannelLogoutUri',
  'backchannelLogoutUriSource',
  'backchannelLogoutSessionRequired',
  'scopes',
  'clientCredentialsScopes',
  'grantTypes',
  'responseTypes',
  'tokenEndpointAuthMethod',
  'jwks',
  'jwksUri',
  'requirePkce',
  'dpopBoundAccessTokens',
  'environment',
  'isAgent',
  'maxAgentMode',
  'verifiedDomain',
  'firstPartyProfile',
  'firstPartyPolicy',
  'firstPartyReason',
  'accessTokenLifespanSeconds',
  'refreshTokenLifespanSeconds',
  'enabled',
  'suspended',
  'suspendedAt',
]);

/**
 * `data` with only the columns of {@link ADMIN_UPDATE_COLUMNS}: the type
 * leaves the others out at compile time only, and a caller that spreads a
 * wider object would otherwise rewrite a client's secret or owner.
 */
function adminColumnsOf(data: AdminUpdateOAuthClient): AdminUpdateOAuthClient {
  return Object.fromEntries(
    Object.entries(data).filter(([key]) => ADMIN_UPDATE_COLUMNS.has(key))
  ) as AdminUpdateOAuthClient;
}

/** `text` as a `LIKE` pattern that matches it literally, anywhere. */
function containsPattern(text: string): string {
  return `%${text.replace(/[\\%_]/g, (character) => `\\${character}`)}%`;
}

/**
 * The back-channel logout columns of a CIMD client (#624): the document's URI
 * with `client` as its source, whatever the caller passed, or none of it.
 */
function cimdBackchannelLogout(data: NewOAuthClient) {
  const uri = data.backchannelLogoutUri ?? null;
  return {
    backchannelLogoutUri: uri,
    backchannelLogoutUriSource: uri === null ? null : ('client' as const),
    backchannelLogoutSessionRequired: data.backchannelLogoutSessionRequired ?? false,
  };
}

/**
 * Factory function that creates an OAuth clients repository with CRUD operations
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository object with realm-scoped CRUD methods (#489)
 */
export function createOAuthClientsRepository(defaultDb: DbClient): OAuthClientsRepository {
  return {
    /**
     * Create a new OAuth client
     * Note: Client secret should be pre-hashed before calling this method
     *
     * @param data - OAuth client data to create
     * @param tx - Optional transaction client
     * @returns Created OAuth client
     * @throws UniqueConstraintError if client with same client_id in realm already exists
     */
    async create(data: NewOAuthClient, tx?: DbClient): Promise<OAuthClient> {
      const invoker = tx ?? defaultDb;
      try {
        const [client] = await invoker
          .insert(oauthClients)
          // Never first party (ADR-017 Decision 2, #631): dynamic registration,
          // the developer API and the server's own system client create rows
          // here, and first-partyness is the operator's to set, through the
          // seed manifest or the system-client provisioner, whatever the
          // caller passed.
          .values({ ...data, ...NOT_FIRST_PARTY })
          .returning();
        return client;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint =
            extractConstraintName(error) || 'idx_oauth_clients_realm_client_id_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    /**
     * Find an OAuth client of the realm by ID
     *
     * @param realmId - Realm the request was resolved to
     * @param id - OAuth client ID
     * @param tx - Optional transaction client
     * @returns OAuth client if found, undefined otherwise — including for a
     * client of another realm
     */
    async findById(realmId: string, id: string, tx?: DbClient): Promise<OAuthClient | undefined> {
      const invoker = tx ?? defaultDb;
      const [client] = await invoker
        .select()
        .from(oauthClients)
        .where(clientOfRealm(realmId, id))
        .limit(1);
      return client;
    },

    /**
     * Find an OAuth client of the realm by ID, throwing an error if not found
     *
     * @param realmId - Realm the request was resolved to
     * @param id - OAuth client ID
     * @param tx - Optional transaction client
     * @returns OAuth client
     * @throws NotFoundError if the realm has no such OAuth client
     */
    async findByIdOrThrow(realmId: string, id: string, tx?: DbClient): Promise<OAuthClient> {
      const client = await this.findById(realmId, id, tx);
      if (!client) {
        throw new NotFoundError('OAuthClient', id);
      }
      return client;
    },

    /**
     * Find an OAuth client by client ID within a realm
     *
     * @param realmId - Realm ID
     * @param clientId - Client ID
     * @param tx - Optional transaction client
     * @returns OAuth client if found, undefined otherwise
     */
    async findByClientId(
      realmId: string,
      clientId: string,
      tx?: DbClient
    ): Promise<OAuthClient | undefined> {
      const invoker = tx ?? defaultDb;
      const [client] = await invoker
        .select()
        .from(oauthClients)
        .where(and(eq(oauthClients.realmId, realmId), eq(oauthClients.clientId, clientId)))
        .limit(1);
      return client;
    },

    /**
     * List the OAuth clients of the realm owned by a developer, newest first.
     *
     * Scoped strictly by `developer_id` so a developer only ever sees their
     * own clients. Dynamically registered clients (RFC 7591) carry a null
     * `developer_id` and are excluded by the equality filter.
     *
     * @param realmId - Realm the request was resolved to
     * @param developerId - Owning developer's user id
     * @param tx - Optional transaction client
     * @returns Owned OAuth clients ordered by creation time, newest first
     */
    async listByDeveloper(
      realmId: string,
      developerId: string,
      tx?: DbClient
    ): Promise<OAuthClient[]> {
      const invoker = tx ?? defaultDb;
      return invoker
        .select()
        .from(oauthClients)
        .where(ownedBy(realmId, developerId))
        .orderBy(desc(oauthClients.createdAt));
    },

    /**
     * One page of the OAuth clients of the realm a developer owns, newest
     * first (#524): the filter of {@link listByDeveloper}, ordered by
     * `created_at` and then `id`, both descending, so rows created in the same
     * millisecond still have one order, starting after `page.after`.
     *
     * @param realmId - Realm the request was resolved to
     * @param developerId - Owning developer's user id
     * @param page - How many rows, and the last row of the previous page
     * @param tx - Optional transaction client
     * @returns At most `page.limit` owned OAuth clients
     */
    async pageByDeveloper(
      realmId: string,
      developerId: string,
      page: KeysetPage,
      tx?: DbClient
    ): Promise<OAuthClient[]> {
      const invoker = tx ?? defaultDb;
      const after = page.after;
      return invoker
        .select()
        .from(oauthClients)
        .where(
          and(
            ownedBy(realmId, developerId),
            after === undefined
              ? undefined
              : or(
                  lt(oauthClients.createdAt, after.at),
                  and(eq(oauthClients.createdAt, after.at), lt(oauthClients.id, after.id))
                )
          )
        )
        .orderBy(desc(oauthClients.createdAt), desc(oauthClients.id))
        .limit(page.limit);
    },

    /**
     * Find an OAuth client of the realm by ID and lock its row
     * (`SELECT … FOR UPDATE`) until `tx` ends (#524). A write conditional on
     * what was read (`If-Match`) reads through this, so no other write lands
     * between the read and the write.
     *
     * @param realmId - Realm the request was resolved to
     * @param id - OAuth client ID
     * @param tx - The transaction that holds the lock
     * @returns OAuth client if found, undefined otherwise
     */
    async findByIdForUpdate(
      realmId: string,
      id: string,
      tx: DbClient
    ): Promise<OAuthClient | undefined> {
      const [client] = await tx
        .select()
        .from(oauthClients)
        .where(clientOfRealm(realmId, id))
        .limit(1)
        .for('update');
      return client;
    },

    /**
     * Find an OAuth client of the realm by ID and lock its row
     * `FOR NO KEY UPDATE` until `tx` ends (#632): the admin API's client
     * operations read through this, so a first-party profile's removal can
     * wait for the client's token lock without a deadlock (#631).
     */
    async findByIdForAdminUpdate(
      realmId: string,
      id: string,
      tx: DbClient
    ): Promise<OAuthClient | undefined> {
      const [client] = await tx
        .select()
        .from(oauthClients)
        .where(clientOfRealm(realmId, id))
        .limit(1)
        .for('no key update');
      return client;
    },

    /**
     * One page of every OAuth client of the realm, whoever owns it (#632):
     * the admin API's list, newest first by `created_at` and then `id`.
     * `filter.search` keeps the clients whose `client_id` or name holds it,
     * case-insensitively, its `%`, `_` and backslash taken literally. Never
     * called by a developer route (ADR-012 Decision 4).
     */
    async pageByRealm(
      realmId: string,
      page: KeysetPage,
      filter: RealmClientFilter = {},
      tx?: DbClient
    ): Promise<OAuthClient[]> {
      const invoker = tx ?? defaultDb;
      const after = page.after;
      const search =
        filter.search === undefined || filter.search === ''
          ? undefined
          : containsPattern(filter.search);
      return invoker
        .select()
        .from(oauthClients)
        .where(
          and(
            eq(oauthClients.realmId, realmId),
            search === undefined
              ? undefined
              : or(
                  sql`${oauthClients.clientId} ILIKE ${search} ESCAPE '\\'`,
                  sql`${oauthClients.name} ILIKE ${search} ESCAPE '\\'`
                ),
            after === undefined
              ? undefined
              : or(
                  lt(oauthClients.createdAt, after.at),
                  and(eq(oauthClients.createdAt, after.at), lt(oauthClients.id, after.id))
                )
          )
        )
        .orderBy(desc(oauthClients.createdAt), desc(oauthClients.id))
        .limit(page.limit);
    },

    /**
     * Create a client an admin registered (#632), its operator-set columns
     * as given: the admin API is the operator's path, as the seed manifest
     * is. The CHECKs of the table still hold the first-party rules.
     *
     * @throws UniqueConstraintError if the realm already has the `client_id`
     */
    async createByAdmin(data: NewOAuthClient, tx?: DbClient): Promise<OAuthClient> {
      const invoker = tx ?? defaultDb;
      try {
        const [client] = await invoker.insert(oauthClients).values(data).returning();
        return client;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint =
            extractConstraintName(error) || 'idx_oauth_clients_realm_client_id_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    /**
     * Update a client as the admin API does (#632): the columns of
     * `AdminUpdateOAuthClient` alone, every other key dropped, and
     * `updated_at`.
     *
     * @throws NotFoundError if the realm has no such OAuth client
     */
    async updateByAdmin(
      realmId: string,
      id: string,
      data: AdminUpdateOAuthClient,
      tx?: DbClient
    ): Promise<OAuthClient> {
      const invoker = tx ?? defaultDb;
      const [client] = await invoker
        .update(oauthClients)
        .set({ ...adminColumnsOf(data), updatedAt: Date.now() })
        .where(clientOfRealm(realmId, id))
        .returning();
      if (!client) {
        throw new NotFoundError('OAuthClient', id);
      }
      return client;
    },

    /**
     * Give the client named `clientId` in EVERY realm exactly `audience`,
     * where its audience differs, in one statement (#524): the boot step that
     * gives the system client the developer API's audience. Not realm-scoped
     * on purpose, and never called with an id from a request: the system
     * client has the same configured `client_id` in every realm.
     *
     * @param clientId - The configured client_id, the same in every realm
     * @param audience - The audience the row must hold
     * @param tx - Optional transaction client
     * @returns How many rows changed
     */
    async setAudienceInEveryRealm(
      clientId: string,
      audience: readonly string[],
      tx?: DbClient
    ): Promise<number> {
      const invoker = tx ?? defaultDb;
      const changed = await invoker
        .update(oauthClients)
        .set({ audience: [...audience], updatedAt: Date.now() })
        .where(
          and(
            eq(oauthClients.clientId, clientId),
            sql`${oauthClients.audience} IS DISTINCT FROM ${JSON.stringify(audience)}::jsonb`
          )
        )
        .returning({ id: oauthClients.id });
      return changed.length;
    },

    /**
     * Count the OAuth clients owned by a developer, without loading them.
     *
     * Same filter as {@link listByDeveloper}. The per-developer client ceiling
     * (`MAX_CLIENTS_PER_DEVELOPER`) is checked against this before a create.
     *
     * @param realmId - Realm the request was resolved to
     * @param developerId - Owning developer's user id
     * @param tx - Optional transaction client
     * @returns Number of OAuth clients of the realm the developer owns
     */
    async countByDeveloper(realmId: string, developerId: string, tx?: DbClient): Promise<number> {
      const invoker = tx ?? defaultDb;
      const [row] = await invoker
        .select({ value: count() })
        .from(oauthClients)
        .where(ownedBy(realmId, developerId));
      return row?.value ?? 0;
    },

    /**
     * Idempotently materialise a CIMD client keyed by (realm_id, client_id).
     *
     * Uses a single INSERT ... ON CONFLICT so concurrent authorize requests
     * for the same metadata-document client_id collapse onto one row instead
     * of racing on a find-then-create. On conflict we refresh only the
     * document-derived fields (name / redirect_uris / post_logout_redirect_uris /
     * grant+response types / auth method + key set) and bump `updatedAt`; identity columns and the
     * secret sentinel are left as-is. `enabled` can only be narrowed: a row
     * that is disabled when the statement runs stays disabled, whatever
     * `data.enabled` says. `provisioned_by_operator` is always written
     * `false`: the document, not an operator, decides the redirect URIs.
     * The operator's grant (`scopes`, `audience`, `client_credentials_scopes`)
     * is never named on conflict, and `client_credentials_scopes` is written
     * NULL on insert (#956): only the seed's `cimd_clients` grant sets it.
     */
    async upsertCimdClient(data: NewOAuthClient, tx?: DbClient): Promise<OAuthClient> {
      const invoker = tx ?? defaultDb;
      const [client] = await invoker
        .insert(oauthClients)
        // A CIMD client is never operator-provisioned (ANT-2026-O8U3P920),
        // whatever the caller passed.
        // Nor first party (#631): its document is self-asserted. The conflict
        // update below never names the first-party columns either.
        // Its back-channel logout URI is the document's, so the client's own
        // (#624): never one an admin set, which the egress allowlist may open.
        // Nor does a resolution open `client_credentials` (#956): the list is
        // the operator's, written by the seed's `cimd_clients` grant, and the
        // conflict update below never names it, so a list the operator wrote
        // into a pending row survives the first resolution.
        .values({
          ...data,
          provisionedByOperator: false,
          ...NOT_FIRST_PARTY,
          clientCredentialsScopes: null,
          ...cimdBackchannelLogout(data),
        })
        .onConflictDoUpdate({
          target: [oauthClients.realmId, oauthClients.clientId],
          set: {
            name: data.name,
            description: data.description,
            redirectUris: data.redirectUris,
            // #675: document-derived like `redirectUris`; a document that
            // drops the field clears the list.
            postLogoutRedirectUris: data.postLogoutRedirectUris ?? [],
            // #624: document-derived too; a document that drops the URI
            // clears it, with its source and the sid flag.
            ...cimdBackchannelLogout(data),
            grantTypes: data.grantTypes,
            responseTypes: data.responseTypes,
            tokenEndpointAuthMethod: data.tokenEndpointAuthMethod,
            // The key set MUST be refreshed alongside `tokenEndpointAuthMethod`
            // (#384, CIMD §6.2). These two are one decision: a document that adds
            // `private_key_jwt` on a LATER resolution would otherwise flip the
            // method while the key columns stayed NULL, leaving the client
            // permanently unauthenticable, and a client that ROTATES its keys
            // would keep the stale set forever. Both are document-derived fields
            // like everything else in this set-list.
            jwks: data.jwks,
            jwksUri: data.jwksUri,
            // Keep the agent classification in sync with the metadata document
            // (ADR-007 §2) so a CIMD doc that flips `is_agent` is reflected on
            // re-resolution, matching the other document-derived fields above.
            isAgent: data.isAgent,
            metadata: data.metadata,
            // ANT-2026-O8U3P920: the document's host controls the redirect
            // URIs this statement just refreshed, so no operator's
            // `provisioned_by_operator` can vouch for them any more. Written
            // `false` (never `true`, whatever `data` says) so a CIMD client
            // never receives automatic error redirects.
            provisionedByOperator: false,
            // Narrow-only, evaluated against the row as it is under this
            // statement's lock (ANT-2026-SSI34ODQ). The caller read
            // `data.enabled` BEFORE fetching the metadata document, and the
            // client's own host decides how long that fetch takes, so writing
            // the snapshot verbatim would undo an operator's `enabled = false`
            // that landed in between.
            enabled: sql`${oauthClients.enabled} AND excluded.enabled`,
            updatedAt: Date.now(),
          },
        })
        .returning();
      return client;
    },

    /**
     * Update an OAuth client of the realm by ID
     *
     * @param realmId - Realm the request was resolved to
     * @param id - OAuth client ID
     * @param data - Fields to update
     * @param tx - Optional transaction client
     * @returns Updated OAuth client
     * @throws NotFoundError if the realm has no such OAuth client
     * @throws UniqueConstraintError if client_id would violate uniqueness
     */
    async update(
      realmId: string,
      id: string,
      data: UpdateOAuthClient,
      tx?: DbClient
    ): Promise<OAuthClient> {
      const invoker = tx ?? defaultDb;
      const updateData = {
        ...withoutFirstPartyColumns(data),
        updatedAt: data.updatedAt ?? Date.now(),
      };

      try {
        const [client] = await invoker
          .update(oauthClients)
          .set(updateData)
          .where(clientOfRealm(realmId, id))
          .returning();

        if (!client) {
          throw new NotFoundError('OAuthClient', id);
        }

        return client;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint =
            extractConstraintName(error) || 'idx_oauth_clients_realm_client_id_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    /**
     * Delete an OAuth client of the realm by ID
     *
     * @param realmId - Realm the request was resolved to
     * @param id - OAuth client ID
     * @param tx - Optional transaction client
     * @returns True if deleted, false if the realm has no such OAuth client
     */
    async delete(realmId: string, id: string, tx?: DbClient): Promise<boolean> {
      const invoker = tx ?? defaultDb;
      const [client] = await invoker
        .delete(oauthClients)
        .where(clientOfRealm(realmId, id))
        .returning();
      return !!client;
    },

    /**
     * The clients holding a redirect URI the consent screen cannot show
     * (#914), a page of `REDIRECT_URI_SCAN_PAGE_SIZE` rows at a time in
     * `id` order (the primary key), with the realm's name. Not realm-scoped
     * unless `options.realmId` is given: the operator's listing command and
     * the boot warning read every realm.
     *
     * @param options - One realm only, and when to stop
     * @param tx - Optional transaction client
     * @returns The clients found, how many were read, and whether all were
     */
    async findUnshowableRedirectUris(
      options: UnshowableRedirectUriScanOptions = {},
      tx?: DbClient
    ): Promise<UnshowableRedirectUriScan> {
      const invoker = tx ?? defaultDb;
      return scanUnshowableRedirectUris({
        ...(options.deadline === undefined ? {} : { deadline: options.deadline }),
        page: (after, limit) =>
          invoker
            .select({
              id: oauthClients.id,
              realmId: oauthClients.realmId,
              realmName: realms.name,
              clientId: oauthClients.clientId,
              redirectUris: oauthClients.redirectUris,
              metadata: oauthClients.metadata,
              provisionedByOperator: oauthClients.provisionedByOperator,
              developerId: oauthClients.developerId,
            })
            .from(oauthClients)
            .innerJoin(realms, eq(realms.id, oauthClients.realmId))
            .where(
              and(
                options.realmId === undefined
                  ? undefined
                  : eq(oauthClients.realmId, options.realmId),
                after === undefined ? undefined : gt(oauthClients.id, after)
              )
            )
            .orderBy(asc(oauthClients.id))
            .limit(limit),
      });
    },
  };
}
