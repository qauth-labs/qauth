import type { FastifyInstance } from 'fastify';

import { accountCredentialRefusal } from '../../helpers/account-validity';
import type { RealmRow } from '../../helpers/request-realm';
import type { ApprovalAccount } from './standing';
import { approverRecord, approverRefusal, grantGivesApprove } from './two-admin';

/**
 * WHO COULD GIVE A SECOND APPROVAL OF A REQUEST ON A REALM, COUNTED
 * (ADR-019 Decision 7, ADR-020 §4, #589, #521).
 *
 * The preview of a security change (`realms.policies.preview`,
 * `clients.preview`) and the filing of an approval (`approvals.create`) say
 * how many admins besides the requester could give a second admin's
 * approval, so the admin console can warn a realm with one admin before
 * anything is filed; and where the realm makes a second admin mandatory, a
 * filing with no one to give it fails closed (`approval_unavailable`).
 *
 * The count reads who holds the right to approve as the approval standing
 * does (`approvalStanding`, `./standing.ts`): a different human account,
 * enabled, of an enabled realm with an issuer (the approval page signs it in
 * there), holding `approvals.approve` on the realm through a live grant that
 * covers it, read as the admin API reads a caller's grants
 * (`grantCoversRealm`). Of those it counts only the eligible ones, by the
 * two-admin rule's rules 1 to 3 (`./two-admin.ts`), with the request made
 * now: none created, granted a role or changed in the last 7 days. Rule 4,
 * the credential an approver uses, is judged only when it approves.
 *
 * The preview needs only `realms.read`, and must show nothing the request
 * may not see (#489). It acts on `targetRealm`, which sees every grant on it,
 * whoever holds it: a realm-local admin's and an operator-realm admin's.
 * Those it counts for any caller authorized there (`visible`). A grant on
 * every realm is the operator realm's alone, seen from no other realm, so it
 * counts in `visible` only for an operator-realm caller: a realm-local admin
 * never learns from the count who in the operator realm holds one. `total`
 * counts every eligible approver, whoever sees it: an operator-realm admin
 * with a grant on every realm can approve a request on any realm, so the
 * fail-closed check reads it, and never shows it.
 *
 * Every read takes `tx`: inside an admin handler a repository call outside
 * the handler's transaction is refused (`admin/handler-scope.ts`).
 */

/** What {@link eligibleApprovers} counts for. */
export interface EligibleApproversInput {
  /** The realm the request acts on. */
  readonly targetRealm: Pick<RealmRow, 'id' | 'isOperator'>;
  /** The account that files the request: never counted. */
  readonly requester: ApprovalAccount;
  /**
   * The realm of the caller who asks: a grant on every realm is counted in
   * `visible` only when it is the operator realm, the one realm that sees
   * such a grant (#489).
   */
  readonly callerRealm: Pick<RealmRow, 'isOperator'>;
  /** The admin handler's transaction. */
  readonly tx: Parameters<FastifyInstance['repositories']['adminGrants']['listLiveOnTarget']>[2];
  /** The clock, in epoch milliseconds, and the time of the request. Defaults to `Date.now`. */
  readonly now?: number;
}

/** The eligible approvers of a request, counted. */
export interface EligibleApprovers {
  /** Those the caller's realm sees: what an answer may show. */
  readonly visible: number;
  /** All of them, whoever sees them: what the fail-closed check reads, never shown. */
  readonly total: number;
}

/**
 * How many accounts other than the requester could give a request on
 * `targetRealm`, made now, a second admin's approval: the admins it could
 * come from. Zero means no one but the requester can.
 */
export async function eligibleApprovers(
  fastify: FastifyInstance,
  input: EligibleApproversInput
): Promise<EligibleApprovers> {
  const { targetRealm, requester, callerRealm, tx } = input;
  const now = input.now ?? Date.now();
  const { repositories } = fastify;

  // The grants on the realm, its own admins' and the operator realm's (#489),
  // which every caller authorized there sees, and the operator realm's grants
  // on every realm, which only an operator-realm caller sees.
  const onTarget = await repositories.adminGrants.listLiveOnTarget(
    targetRealm.id,
    targetRealm.id,
    tx
  );
  const operator = await repositories.realms.findOperator(tx);
  const onEvery =
    operator === undefined
      ? []
      : await repositories.adminGrants.listLiveOnTarget(operator.id, null, tx);

  const accountRealms = new Map<string, RealmRow | undefined>();
  const accountRealm = async (realmId: string) => {
    if (!accountRealms.has(realmId)) {
      accountRealms.set(realmId, await repositories.realms.findById(realmId, tx));
    }
    return accountRealms.get(realmId);
  };

  interface Candidate {
    readonly account: ApprovalAccount & { readonly createdAt: number };
    readonly approveGrantIds: Set<string>;
    visible: boolean;
  }
  const candidates = new Map<string, Candidate>();
  const seen = [
    ...onTarget.map((live) => ({ live, visible: true })),
    ...onEvery.map((live) => ({ live, visible: callerRealm.isOperator })),
  ];
  for (const { live, visible } of seen) {
    const { account } = live;
    if (account.realmId === requester.realmId && live.grant.userId === requester.accountId) {
      continue;
    }
    // An account is only ever disabled from the past, so `now` stands in for
    // the time the approval page's session is issued (#748).
    if (accountCredentialRefusal(account, now) !== null) continue;
    const realm = await accountRealm(account.realmId);
    if (realm === undefined || !realm.enabled || realm.issuer === null) continue;
    if (!grantGivesApprove(live, realm, targetRealm)) continue;
    const key = `${account.realmId}/${live.grant.userId}`;
    const candidate = candidates.get(key) ?? {
      account: {
        realmId: account.realmId,
        accountId: live.grant.userId,
        // Every admin account is a person's until service accounts exist
        // (#522); rule 1 must then read the account's kind here.
        kind: 'human' as const,
        createdAt: account.createdAt,
      },
      approveGrantIds: new Set<string>(),
      visible: false,
    };
    candidate.approveGrantIds.add(live.grant.id);
    candidate.visible ||= visible;
    candidates.set(key, candidate);
  }

  let visible = 0;
  let total = 0;
  for (const candidate of candidates.values()) {
    // Every grant the account holds or held, as its own realm sees them:
    // rule 3 reads them all.
    const grants = await repositories.adminGrants.listByUser(
      candidate.account.realmId,
      candidate.account.accountId,
      tx
    );
    const record = approverRecord(candidate.account, grants, candidate.approveGrantIds);
    const request = { realmId: targetRealm.id, requester, createdAt: now };
    if (approverRefusal(record, request, targetRealm, now) !== null) continue;
    total += 1;
    if (candidate.visible) visible += 1;
  }
  return { visible, total };
}

/**
 * How many eligible approvers the caller's realm sees ({@link eligibleApprovers}'s
 * `visible`): what a preview or a filing shows.
 */
export async function eligibleApproverCount(
  fastify: FastifyInstance,
  input: EligibleApproversInput
): Promise<number> {
  return (await eligibleApprovers(fastify, input)).visible;
}
