import type { FastifyInstance } from 'fastify';

import { accountCredentialRefusal } from '../../helpers/account-validity';
import { grantCoversRealm, grantedPermissionIds } from '../../helpers/admin-authority';
import { PERMISSION_REGISTRY } from '../../helpers/admin-permissions';
import { effectivePermissions } from '../../helpers/admin-roles';
import { ADMIN_SCOPE_LIST } from '../../helpers/admin-scopes';
import type { RealmRow } from '../../helpers/request-realm';
import type { ApprovalAccount } from './standing';

/**
 * WHO MAY APPROVE A REQUEST ON A REALM, COUNTED (ADR-019 Decision 7, #589).
 *
 * The preview of a security change (`realms.policies.preview`) says how many
 * admins could give its approval besides the requester, so the admin console
 * can warn a realm with one admin (ADR-020 §4) before anything is filed.
 *
 * The count follows who may approve today (`approvalStanding`, `./standing.ts`): a
 * different human account, enabled, of an enabled realm with an issuer (the
 * approval page signs it in there), holding `approvals.approve` on the realm
 * through a live grant that covers it, read as the admin API reads a
 * caller's grants (`grantCoversRealm`). The two-admin rule (#521) narrows it
 * (no account created, granted a role or changed in the last 7 days, no
 * credential of the requester); it narrows it here, so the preview and the
 * approval it announces read one rule.
 *
 * Every read takes `tx`: inside an admin handler a repository call outside
 * the handler's transaction is refused (`admin/handler-scope.ts`).
 */

/** The permission an approver holds on the realm. */
const APPROVE = 'approvals.approve';

/** What {@link eligibleApproverCount} counts for. */
export interface EligibleApproversInput {
  /** The realm the request acts on. */
  readonly targetRealm: Pick<RealmRow, 'id' | 'isOperator'>;
  /** The account that files the request: never counted. */
  readonly requester: ApprovalAccount;
  /** The admin handler's transaction. */
  readonly tx: Parameters<FastifyInstance['repositories']['adminGrants']['listLiveOnTarget']>[2];
  /** The clock, in epoch milliseconds. Defaults to `Date.now`. */
  readonly now?: number;
}

/**
 * How many accounts other than the requester may give an approval of a
 * request on `targetRealm` now: the admins a second approval could come
 * from. Zero means the requester is the only one.
 */
export async function eligibleApproverCount(
  fastify: FastifyInstance,
  input: EligibleApproversInput
): Promise<number> {
  const { targetRealm, requester, tx } = input;
  const now = input.now ?? Date.now();

  // The grants on the realm, its own admins' and the operator realm's (#489),
  // and the operator realm's grants on every realm, which it alone sees.
  const grants = await fastify.repositories.adminGrants.listLiveOnTarget(
    targetRealm.id,
    targetRealm.id,
    tx
  );
  const operator = await fastify.repositories.realms.findOperator(tx);
  if (operator !== undefined) {
    grants.push(
      ...(await fastify.repositories.adminGrants.listLiveOnTarget(operator.id, null, tx))
    );
  }

  const accountRealms = new Map<string, RealmRow | undefined>();
  const accountRealm = async (realmId: string) => {
    if (!accountRealms.has(realmId)) {
      accountRealms.set(realmId, await fastify.repositories.realms.findById(realmId, tx));
    }
    return accountRealms.get(realmId);
  };

  const permissionsByAccount = new Map<string, string[]>();
  for (const live of grants) {
    const { account } = live;
    if (account.realmId === requester.realmId && live.grant.userId === requester.accountId) {
      continue;
    }
    // An account is only ever disabled from the past, so `now` stands in for
    // the time the approval page's session is issued (#748).
    if (accountCredentialRefusal(account, now) !== null) continue;
    const realm = await accountRealm(account.realmId);
    if (realm === undefined || !realm.enabled || realm.issuer === null) continue;
    // A realm-local admin never acts on the operator realm (rule 4).
    if (!realm.isOperator && targetRealm.isOperator) continue;
    if (!grantCoversRealm(live, realm, targetRealm.id)) continue;
    const key = `${account.realmId}/${live.grant.userId}`;
    permissionsByAccount.set(key, [
      ...(permissionsByAccount.get(key) ?? []),
      ...grantedPermissionIds(live),
    ]);
  }

  let count = 0;
  for (const granted of permissionsByAccount.values()) {
    if (effectivePermissions(granted, ADMIN_SCOPE_LIST, PERMISSION_REGISTRY).has(APPROVE)) {
      count += 1;
    }
  }
  return count;
}
