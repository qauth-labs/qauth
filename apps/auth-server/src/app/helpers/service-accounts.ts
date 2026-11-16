/**
 * Service accounts of the admin API (ADR-019 Decision 7, issue #522).
 *
 * A service account is automation that reaches the admin API as itself: a
 * `users` row with no credential, in the operator realm, and the OAuth client
 * it signs in with (`service_accounts`, migration 0078). Its admin grants
 * attach to the user row, so the admin API reads them as it reads a person's.
 * What sets it apart:
 *
 * - Its client authenticates with `private_key_jwt` only, and gets an admin
 *   token through `client_credentials` with a DPoP proof. The token's `sub` is
 *   the service account's user id, not the `client_id`, and its lifetime is
 *   the realm's admin token lifetime (`tokens.adminAccessTokenLifespanSeconds`,
 *   at most 900 seconds). No refresh token, no secret, no static key.
 * - It reaches the admin API only through its own client: a token for its
 *   account that another client holds is refused, and so is every call once
 *   the service account, its account or its client is disabled.
 * - Being one is a lasting fact of its account (`users.is_service_account`,
 *   set when it is created and never changed): an account so marked whose
 *   binding is gone, or a binding to an account not so marked, is refused,
 *   never taken for a person's.
 * - It never approves, and never counts as one of two admins: every approval
 *   of a security operation it files comes from a human admin. The admin
 *   audit log names it with the actor kind `service_account`.
 *
 * The token endpoint and the admin API decide with the functions below, so
 * the two read one rule.
 */
import type { FastifyInstance } from 'fastify';

import { mayHoldAdminAudience } from './admin-audience';
import type { OAuthClientLike } from './client-auth';
import { isClientUsable } from './client-status';
import type { RealmRow } from './request-realm';

/** A stored service account, as the repository reads it. */
export type ServiceAccountRow = NonNullable<
  Awaited<ReturnType<FastifyInstance['repositories']['serviceAccounts']['findByUser']>>
>;

/** A transaction of the repositories, or none. */
type Transaction = Parameters<FastifyInstance['repositories']['serviceAccounts']['findByUser']>[2];

/** The service account an admin call comes from, as the admin API records it. */
export interface ServiceAccountCaller {
  /** `service_accounts.id`. */
  readonly id: string;
  /** Its name, unique in the operator realm. */
  readonly name: string;
  /** Its OAuth client's `client_id`: what its tokens carry as `client_id`. */
  readonly clientId: string;
}

/**
 * Why a service account may not act now, or `null` when it may:
 *
 * - `realm_not_operator`: its realm is no longer the operator realm (the flag
 *   moved), so it administers nothing;
 * - `disabled`: the service account is disabled;
 * - `client_unusable`: its client is gone, disabled or suspended;
 * - `client_not_private_key_jwt`: its client was rewritten to authenticate
 *   some other way, so it may hold no admin audience (`mayHoldAdminAudience`).
 *
 * Logged and recorded as an event reason, never sent.
 */
export type ServiceAccountRefusal =
  | 'realm_not_operator'
  | 'disabled'
  | 'client_unusable'
  | 'client_not_private_key_jwt';

/**
 * Why `serviceAccount` of `realm`, whose client is `client`, may not act now.
 * Pure: the token endpoint and the admin API read the rows, and decide here.
 */
export function serviceAccountRefusal(
  realm: Pick<RealmRow, 'isOperator'>,
  serviceAccount: Pick<ServiceAccountRow, 'enabled'>,
  client:
    | (Pick<OAuthClientLike, 'enabled' | 'suspended' | 'tokenEndpointAuthMethod'> & object)
    | undefined
): ServiceAccountRefusal | null {
  if (!realm.isOperator) return 'realm_not_operator';
  if (!serviceAccount.enabled) return 'disabled';
  if (client === undefined || !isClientUsable(client)) return 'client_unusable';
  if (!mayHoldAdminAudience(client)) return 'client_not_private_key_jwt';
  return null;
}

/** Who an admin call comes from, by the account its token names. */
export type AdminCallerAccount =
  | { readonly kind: 'human'; readonly serviceAccount: null }
  | { readonly kind: 'service_account'; readonly serviceAccount: ServiceAccountCaller }
  | {
      readonly kind: 'refused';
      readonly reason:
        | ServiceAccountRefusal
        | 'other_client'
        | 'no_client'
        | 'binding_missing'
        | 'account_not_marked';
    };

/** The parts of an account {@link adminCallerAccount} reads. */
export interface CallerUser {
  readonly id: string;
  /** `users.is_service_account`; absent reads as `false`. */
  readonly isServiceAccount?: boolean;
}

/**
 * Who the account `userId` of `realm` is as an admin caller: a person, or a
 * service account that may act now through the client `tokenClientId` names.
 *
 * A service account acts only through its own client: a token for its
 * account with another `client_id` (`other_client`), or a request that names
 * no client at all (`no_client`, such as the approval page, where a person
 * signs in), is refused, as is one {@link serviceAccountRefusal} refuses.
 *
 * Only an account neither marked a service account's nor bound by one is a
 * person's. A marked account whose `service_accounts` row is gone
 * (`binding_missing`), and a row that binds an account not marked
 * (`account_not_marked`, written some other way than the repository), fail
 * closed.
 *
 * @param tokenClientId - the token's `client_id`; `undefined` where no token
 *   is read
 */
export async function adminCallerAccount(
  fastify: FastifyInstance,
  realm: Pick<RealmRow, 'id' | 'isOperator'>,
  user: CallerUser,
  tokenClientId: string | undefined,
  tx?: Transaction
): Promise<AdminCallerAccount> {
  const { repositories } = fastify;
  const serviceAccount = await repositories.serviceAccounts.findByUser(realm.id, user.id, tx);
  const marked = user.isServiceAccount === true;
  if (serviceAccount === undefined) {
    return marked
      ? { kind: 'refused', reason: 'binding_missing' }
      : { kind: 'human', serviceAccount: null };
  }
  if (!marked) return { kind: 'refused', reason: 'account_not_marked' };
  const client = await repositories.oauthClients.findById(realm.id, serviceAccount.clientId, tx);
  const refusal = serviceAccountRefusal(realm, serviceAccount, client);
  if (refusal !== null) return { kind: 'refused', reason: refusal };
  if (tokenClientId === undefined) return { kind: 'refused', reason: 'no_client' };
  // A `client_id` is public: nothing secret to compare in constant time.
  if (client?.clientId !== tokenClientId) return { kind: 'refused', reason: 'other_client' };
  return {
    kind: 'service_account',
    serviceAccount: { id: serviceAccount.id, name: serviceAccount.name, clientId: client.clientId },
  };
}

/**
 * Whether the account `user` of `realmId` is a service account's: marked one
 * (`users.is_service_account`), or bound by a `service_accounts` row. Such an
 * account never gives an approval, and is never counted as one who could
 * (the two-admin rule's rule 1, `admin/approvals/two-admin.ts`), whether its
 * binding is whole or not.
 */
export async function isServiceAccountUser(
  fastify: FastifyInstance,
  realmId: string,
  user: CallerUser,
  tx?: Transaction
): Promise<boolean> {
  if (user.isServiceAccount === true) return true;
  return (
    (await fastify.repositories.serviceAccounts.findByUser(realmId, user.id, tx)) !== undefined
  );
}
