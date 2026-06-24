import {
  extractConstraintName,
  isUniqueConstraintError,
  NotFoundError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { and, eq } from 'drizzle-orm';

import type {
  NewOAuthClient,
  OAuthClient,
  OAuthClientsRepository,
  UpdateOAuthClient,
} from '../../types/repository';
import { DbClient } from '../db';
import { oauthClients } from '../schema/core';

/**
 * Factory function that creates an OAuth clients repository with CRUD operations
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository object with CRUD methods implementing BaseRepository
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
     * Find an OAuth client by ID
     *
     * @param id - OAuth client ID
     * @param tx - Optional transaction client
     * @returns OAuth client if found, undefined otherwise
     */
    async findById(id: string, tx?: DbClient): Promise<OAuthClient | undefined> {
      const invoker = tx ?? defaultDb;
      const [client] = await invoker
        .select()
        .from(oauthClients)
        .where(eq(oauthClients.id, id))
        .limit(1);
      return client;
    },

    /**
     * Find an OAuth client by ID, throwing an error if not found
     *
     * @param id - OAuth client ID
     * @param tx - Optional transaction client
     * @returns OAuth client
     * @throws NotFoundError if OAuth client is not found
     */
    async findByIdOrThrow(id: string, tx?: DbClient): Promise<OAuthClient> {
      const client = await this.findById(id, tx);
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
     * Idempotently materialise a CIMD client keyed by (realm_id, client_id).
     *
     * Uses a single INSERT ... ON CONFLICT so concurrent authorize requests
     * for the same metadata-document client_id collapse onto one row instead
     * of racing on a find-then-create. On conflict we refresh only the
     * document-derived fields (name / redirect_uris / grant+response types)
     * and bump `updatedAt`; identity columns and the secret sentinel are
     * left as-is.
     */
    async upsertCimdClient(data: NewOAuthClient, tx?: DbClient): Promise<OAuthClient> {
      const invoker = tx ?? defaultDb;
      const [client] = await invoker
        .insert(oauthClients)
        .values(data)
        .onConflictDoUpdate({
          target: [oauthClients.realmId, oauthClients.clientId],
          set: {
            name: data.name,
            description: data.description,
            redirectUris: data.redirectUris,
            grantTypes: data.grantTypes,
            responseTypes: data.responseTypes,
            tokenEndpointAuthMethod: data.tokenEndpointAuthMethod,
            metadata: data.metadata,
            enabled: data.enabled,
            updatedAt: Date.now(),
          },
        })
        .returning();
      return client;
    },

    /**
     * Update an OAuth client by ID
     *
     * @param id - OAuth client ID
     * @param data - Fields to update
     * @param tx - Optional transaction client
     * @returns Updated OAuth client
     * @throws NotFoundError if OAuth client is not found
     * @throws UniqueConstraintError if client_id would violate uniqueness
     */
    async update(id: string, data: UpdateOAuthClient, tx?: DbClient): Promise<OAuthClient> {
      const invoker = tx ?? defaultDb;
      const updateData = {
        ...data,
        updatedAt: data.updatedAt ?? Date.now(),
      };

      try {
        const [client] = await invoker
          .update(oauthClients)
          .set(updateData)
          .where(eq(oauthClients.id, id))
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
     * Delete an OAuth client by ID
     *
     * @param id - OAuth client ID
     * @param tx - Optional transaction client
     * @returns True if deleted, false if not found
     */
    async delete(id: string, tx?: DbClient): Promise<boolean> {
      const invoker = tx ?? defaultDb;
      const [client] = await invoker
        .delete(oauthClients)
        .where(eq(oauthClients.id, id))
        .returning();
      return !!client;
    },
  };
}
