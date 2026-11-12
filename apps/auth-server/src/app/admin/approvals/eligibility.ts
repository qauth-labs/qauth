import type { FastifyInstance } from 'fastify';

import { accountCredentialRefusal } from '../../helpers/account-validity';
import { grantCoversRealm, grantedPermissionIds } from '../../helpers/admin-authority';
import { PERMISSION_REGISTRY } from '../../helpers/admin-permissions';
import { effectivePermissions } from '../../helpers/admin-roles';
import { ADMIN_SCOPE_LIST } from '../../helpers/admin-scopes';
import type { RealmRow } from '../../helpers/request-realm';
import type { ApprovalAccount } from './standing';

/**
 * WHO COULD GIVE A SECOND APPROVAL OF A REQUEST ON A REALM, COUNTED
 * (ADR-019 Decision 7, ADR-020 §4, #589).
 *
 * The preview of a security change (`realms.policies.preview`) says how many
 * admins besides the requester could give a second admin's approval, so the
 * admin console can warn a realm with one admin before anything is filed.
 * Today an approval takes the requester's own step-up alone
 * (`approvalsRequiredFor`, `./engine.ts`): a second admin's approval is
 * recommended, and the engine asks for none. The two-admin rule (#521),
 * which makes one mandatory where the realm says so, lets these accounts
 * give it.
 *
 * The count reads who holds the right to approve as the approval standing
 * does (`approvalStanding`, `./standing.ts`): a different human account,
 * enabled, of an enabled realm with an issuer (the approval page signs it in
 * there), holding `approvals.approve` on the realm through a live grant that
 * covers it, read as the admin API reads a caller's grants
 * (`grantCoversRealm`). When #521 narrows who may give the second approval
 * (no account created, granted a role or changed in the last 7 days, no
 * credential of the requester), this count must take the same narrowing, so
 * the preview and the approval it announces read one rule. It does not yet.
 *
 * The preview needs only `realms.read`, and must show nothing the request
 * may not see (#489). It acts on `targetRealm`, which sees every grant on it,
 * whoever holds it: a realm-local admin's and an operator-realm admin's.
 * Those it counts for any caller authorized there. A grant on every realm
 * is the operator realm's alone, seen from no other realm, so it counts only
 * for an operator-realm caller: a realm-local admin never learns from the
 * count who in the operator realm holds one.
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
  /**
   * The realm of the caller who asks: a grant on every realm is counted only
   * when it is the operator realm, the one realm that sees such a grant (#489).
   */
  readonly callerRealm: Pick<RealmRow, 'isOperator'>;
  /** The admin handler's transaction. */
  readonly tx: Parameters<FastifyInstance['repositories']['adminGrants']['listLiveOnTarget']>[2];
  /** The clock, in epoch milliseconds. Defaults to `Date.now`. */
  readonly now?: number;
}

/**
 * How many accounts other than the requester hold the right to approve a
 * request on `targetRealm`, among the grants `callerRealm` sees: the admins
 * a second approval could come from. Zero means the requester is the only
 * one the caller can see.
 */
export async function eligibleApproverCount(
  fastify: FastifyInstance,
  input: EligibleApproversInput
): Promise<number> {
  const { targetRealm, requester, callerRealm, tx } = input;
  const now = input.now ?? Date.now();

  // The grants on the realm, its own admins' and the operator realm's (#489),
  // and, for an operator-realm caller, the operator realm's grants on every
  // realm, which it alone sees.
  const grants = await fastify.repositories.adminGrants.listLiveOnTarget(
    targetRealm.id,
    targetRealm.id,
    tx
  );
  const operator = callerRealm.isOperator
    ? await fastify.repositories.realms.findOperator(tx)
    : undefined;
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
