import {
  BadRequestError,
  extractConstraintName,
  isUniqueConstraintError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { ADMIN_API_AUDIENCE, ADMIN_API_SCOPES } from '@qauth-labs/shared-validation';
import { and, asc, eq, type InferSelectModel } from 'drizzle-orm';
import { z } from 'zod';

import type { DbClient } from '../../types';
import { oauthClients, realms, users } from '../schema/core';
import {
  SERVICE_ACCOUNT_NAME_MAX_LENGTH,
  SERVICE_ACCOUNT_NAME_PATTERN,
  serviceAccounts,
} from '../schema/service-accounts';
import { publicJwkSchema } from '../system-client/public-jwk';
import { unusableSecretHash } from '../unusable-secret-hash';

/** A stored service account (issue #522). */
export type ServiceAccount = InferSelectModel<typeof serviceAccounts>;

/** A new service account, as {@link ServiceAccountsRepository.create} takes it. */
export interface NewServiceAccount {
  /** The realm it lives in: the operator realm, or the write is refused. */
  readonly realmId: string;
  /** Unique in the realm, in the grammar of `SERVICE_ACCOUNT_NAME_PATTERN`. */
  readonly name: string;
  /** The OAuth `client_id` its client is registered under, unused in the realm. */
  readonly clientId: string;
  /**
   * The client's public keys, the ones its `private_key_jwt` assertions are
   * verified with: an inline JWK Set, or an https URL that serves one. Exactly
   * one of the two.
   */
  readonly jwks?: { readonly keys: readonly Readonly<Record<string, unknown>>[] };
  readonly jwksUri?: string;
  /** The admin who creates it; `null` for the host's command or QAuth itself. */
  readonly createdBy: string | null;
}

/** What {@link ServiceAccountsRepository.create} wrote. */
export interface CreatedServiceAccount {
  readonly serviceAccount: ServiceAccount;
  /**
   * The account's user id: what its admin grants name, and the `sub` of
   * every token it gets.
   */
  readonly userId: string;
  /** Its OAuth client: the row id and the `client_id` it authenticates as. */
  readonly client: { readonly id: string; readonly clientId: string };
}

/**
 * Service accounts (ADR-019 Decision 7, issue #522). See the table
 * (`schema/service-accounts.ts`) for what one is.
 *
 * Every read takes the realm the request was resolved to (#489): a service
 * account of another realm is not found, as an unknown one is not.
 */
export interface ServiceAccountsRepository {
  /**
   * Create a service account in the operator realm, in one transaction: the
   * account (a `users` row with no credential), its OAuth client and the
   * row that binds them. Its admin grants are written after, on the user id,
   * with the admin grants repository, as a person's are.
   *
   * The client is written whole here, and nothing else writes a service
   * account's client: `private_key_jwt` with the given keys and no secret
   * anyone holds, the `client_credentials` grant only, every token bound to
   * a DPoP key (`dpop_bound_access_tokens`), the admin API's audience and its
   * three scopes, which the account's grants narrow, and no redirect URI. It
   * is the operator's (`provisioned_by_operator`), never a developer's, an
   * agent or a registration.
   *
   * With `tx`, every row is written in the caller's transaction; without,
   * in a transaction of its own.
   *
   * @throws BadRequestError when the realm is not the operator realm, or the
   *   name, the client id, the keys or `createdBy` are malformed
   * @throws UniqueConstraintError when the realm already holds the name, or
   *   a client with the client id
   */
  create(input: NewServiceAccount, tx?: DbClient): Promise<CreatedServiceAccount>;

  /** The service account with this id in the realm. */
  findById(realmId: string, id: string, tx?: DbClient): Promise<ServiceAccount | undefined>;

  /** The service account with this name in the realm. */
  findByName(realmId: string, name: string, tx?: DbClient): Promise<ServiceAccount | undefined>;

  /**
   * The service account whose account is `userId`, in the realm: whether a
   * user is a service account at all. The admin API reads it on every call.
   */
  findByUser(realmId: string, userId: string, tx?: DbClient): Promise<ServiceAccount | undefined>;

  /**
   * The service account whose OAuth client is `clientRowId` (`oauth_clients.id`,
   * not the `client_id`), in the realm. The token endpoint reads it for every
   * `client_credentials` request.
   */
  findByClient(
    realmId: string,
    clientRowId: string,
    tx?: DbClient
  ): Promise<ServiceAccount | undefined>;

  /** The realm's service accounts, oldest first. */
  list(realmId: string, tx?: DbClient): Promise<ServiceAccount[]>;

  /**
   * Enable or disable the service account. A disabled one gets no token and
   * makes no admin call from the next request on, whatever token it holds.
   * `undefined` when the realm holds no such service account.
   */
  setEnabled(
    realmId: string,
    id: string,
    enabled: boolean,
    tx?: DbClient
  ): Promise<ServiceAccount | undefined>;
}

/** A uuid, as Postgres prints and takes it; anything else names no row. */
const idSchema = z.guid();

function isId(value: unknown): value is string {
  return idSchema.safeParse(value).success;
}

/** The keys of a service account's client: exactly one of an inline set and an https URL. */
const keysSchema = z
  .object({
    jwks: z.object({ keys: z.array(publicJwkSchema).min(1).max(20) }).optional(),
    jwksUri: z
      .url()
      .max(2048)
      .refine((uri) => new URL(uri).protocol === 'https:', {
        message: 'jwksUri must be an https URL',
      })
      .optional(),
  })
  .refine((keys) => (keys.jwks === undefined) !== (keys.jwksUri === undefined), {
    message:
      "a service account's client authenticates with private_key_jwt: give exactly one of jwks and jwksUri, its public keys",
  });

/** Check `input` before anything is read, and return its keys in their stored form. */
function checkedInput(input: NewServiceAccount): {
  jwks: { keys: Record<string, unknown>[] } | null;
  jwksUri: string | null;
} {
  if (!isId(input.realmId)) {
    throw new BadRequestError('A service account needs the id of its realm');
  }
  if (
    typeof input.name !== 'string' ||
    input.name.length > SERVICE_ACCOUNT_NAME_MAX_LENGTH ||
    !SERVICE_ACCOUNT_NAME_PATTERN.test(input.name)
  ) {
    throw new BadRequestError(
      `A service account's name is lower-case ASCII letters and digits in words joined by single hyphens, starting with a letter, at most ${SERVICE_ACCOUNT_NAME_MAX_LENGTH} characters`
    );
  }
  if (
    typeof input.clientId !== 'string' ||
    input.clientId.length === 0 ||
    input.clientId.length > 255 ||
    input.clientId.trim() !== input.clientId
  ) {
    throw new BadRequestError(
      "A service account's client id is 1 to 255 characters, with no white space around it"
    );
  }
  if (input.createdBy !== null && !isId(input.createdBy)) {
    throw new BadRequestError('A service account is created by an account id, or null');
  }
  const keys = keysSchema.safeParse({ jwks: input.jwks, jwksUri: input.jwksUri });
  if (!keys.success) {
    throw new BadRequestError(keys.error.issues.map((issue) => issue.message).join('; '));
  }
  return {
    jwks:
      keys.data.jwks === undefined
        ? null
        : { keys: keys.data.jwks.keys.map((key) => ({ ...key })) },
    jwksUri: keys.data.jwksUri ?? null,
  };
}

/**
 * Factory for service accounts (issue #522). See
 * {@link ServiceAccountsRepository} for the guarantees.
 *
 * @param defaultDb - the server's database
 */
export function createServiceAccountsRepository(defaultDb: DbClient): ServiceAccountsRepository {
  const findOne = async (db: DbClient, realmId: string, condition: ReturnType<typeof eq>) => {
    const [row] = await db
      .select()
      .from(serviceAccounts)
      .where(and(eq(serviceAccounts.realmId, realmId), condition))
      .limit(1);
    return row;
  };

  return {
    async create(input, tx) {
      const keys = checkedInput(input);
      const write = async (db: DbClient): Promise<CreatedServiceAccount> => {
        const [realm] = await db
          .select({ id: realms.id, isOperator: realms.isOperator })
          .from(realms)
          .where(eq(realms.id, input.realmId))
          .limit(1);
        if (realm === undefined || !realm.isOperator) {
          throw new BadRequestError('A service account lives in the operator realm');
        }
        try {
          // The account: no credential, so it signs in nowhere.
          const [user] = await db
            .insert(users)
            .values({ realmId: realm.id })
            .returning({ id: users.id });
          const [client] = await db
            .insert(oauthClients)
            .values({
              realmId: realm.id,
              clientId: input.clientId,
              clientSecretHash: unusableSecretHash(),
              name: `Service account ${input.name}`,
              redirectUris: [],
              scopes: [...ADMIN_API_SCOPES],
              grantTypes: ['client_credentials'],
              responseTypes: [],
              audience: [ADMIN_API_AUDIENCE],
              tokenEndpointAuthMethod: 'private_key_jwt',
              jwks: keys.jwks,
              jwksUri: keys.jwksUri,
              dpopBoundAccessTokens: true,
              provisionedByOperator: true,
              developerId: null,
              isAgent: false,
              enabled: true,
            })
            .returning({ id: oauthClients.id, clientId: oauthClients.clientId });
          const [serviceAccount] = await db
            .insert(serviceAccounts)
            .values({
              realmId: realm.id,
              name: input.name,
              userId: user.id,
              clientId: client.id,
              createdBy: input.createdBy,
            })
            .returning();
          return { serviceAccount, userId: user.id, client };
        } catch (error) {
          if (isUniqueConstraintError(error)) {
            throw new UniqueConstraintError(
              extractConstraintName(error) || 'service_accounts_realm_name_unique',
              error
            );
          }
          throw error;
        }
      };
      return tx === undefined ? defaultDb.transaction(write) : write(tx);
    },

    async findById(realmId, id, tx) {
      if (!isId(realmId) || !isId(id)) return undefined;
      return findOne(tx ?? defaultDb, realmId, eq(serviceAccounts.id, id));
    },

    async findByName(realmId, name, tx) {
      if (!isId(realmId) || typeof name !== 'string' || name.length === 0) return undefined;
      return findOne(tx ?? defaultDb, realmId, eq(serviceAccounts.name, name));
    },

    async findByUser(realmId, userId, tx) {
      if (!isId(realmId) || !isId(userId)) return undefined;
      return findOne(tx ?? defaultDb, realmId, eq(serviceAccounts.userId, userId));
    },

    async findByClient(realmId, clientRowId, tx) {
      if (!isId(realmId) || !isId(clientRowId)) return undefined;
      return findOne(tx ?? defaultDb, realmId, eq(serviceAccounts.clientId, clientRowId));
    },

    async list(realmId, tx) {
      if (!isId(realmId)) return [];
      return (tx ?? defaultDb)
        .select()
        .from(serviceAccounts)
        .where(eq(serviceAccounts.realmId, realmId))
        .orderBy(asc(serviceAccounts.createdAt), asc(serviceAccounts.id));
    },

    async setEnabled(realmId, id, enabled, tx) {
      if (!isId(realmId) || !isId(id)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .update(serviceAccounts)
        .set({ enabled })
        .where(and(eq(serviceAccounts.realmId, realmId), eq(serviceAccounts.id, id)))
        .returning();
      return row;
    },
  };
}
