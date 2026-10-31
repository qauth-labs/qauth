import {
  extractConstraintName,
  isUniqueConstraintError,
  NotFoundError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { and, count, desc, eq, lt, or, sql } from 'drizzle-orm';

import type {
  KeysetPage,
  NewOAuthClient,
  OAuthClient,
  OAuthClientsRepository,
  UpdateOAuthClient,
} from '../../types/repository';
import { DbClient } from '../db';
import { oauthClients } from '../schema/core';

/** The client row `id` names in `realmId`: a client of another realm matches nothing (#489). */
function clientOfRealm(realmId: string, id: string) {
  return and(eq(oauthClients.realmId, realmId), eq(oauthClients.id, id));
}

/** The clients of `realmId` a developer owns. */
function ownedBy(realmId: string, developerId: string) {
  return and(eq(oauthClients.realmId, realmId), eq(oauthClients.developerId, developerId));
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
     * document-derived fields (name / redirect_uris / grant+response types /
     * auth method + key set) and bump `updatedAt`; identity columns and the
     * secret sentinel are left as-is. `enabled` can only be narrowed: a row
     * that is disabled when the statement runs stays disabled, whatever
     * `data.enabled` says. `provisioned_by_operator` is always written
     * `false`: the document, not an operator, decides the redirect URIs.
     */
    async upsertCimdClient(data: NewOAuthClient, tx?: DbClient): Promise<OAuthClient> {
      const invoker = tx ?? defaultDb;
      const [client] = await invoker
        .insert(oauthClients)
        // A CIMD client is never operator-provisioned (ANT-2026-O8U3P920),
        // whatever the caller passed.
        .values({ ...data, provisionedByOperator: false })
        .onConflictDoUpdate({
          target: [oauthClients.realmId, oauthClients.clientId],
          set: {
            name: data.name,
            description: data.description,
            redirectUris: data.redirectUris,
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
        ...data,
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
  };
}
