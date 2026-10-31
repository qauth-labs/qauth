import type { AdminApproval } from '@qauth-labs/fastify-plugin-db';

import type { AdminCaller } from '../pipeline';

/**
 * WHO STANDS WHERE TOWARDS ONE APPROVAL (ADR-019 Decision 7, issue #512).
 * Pure: the approval engine, the approval routes and the cancel operation's
 * state read all decide with these.
 *
 * An approval needs `approvals_required` approvals, each from a different
 * account:
 *
 * - A human requester's own fresh step-up is one of them, and only the
 *   requester gives it. Every other one comes from a different human account
 *   that holds `approvals.approve` on the realm, once each (a required second
 *   approval, #521).
 * - A service account has no passkey (#522): every approval it needs comes
 *   from a human account that holds `approvals.approve`, the first standing in
 *   for the requester's own step-up, each a different one.
 *
 * Who may read an approval: its requester, an account that gave one of its
 * approvals, and an account that may still give one. Anyone else is answered
 * as if it did not exist.
 */

/** An account, as an approval sees it. */
export interface ApprovalAccount {
  /** The realm the account lives in. */
  readonly realmId: string;
  readonly accountId: string;
  /** A service account never approves. */
  readonly kind: 'human' | 'service_account';
}

/**
 * The account of an admin API caller. The admin family's guard admits only a
 * user as the subject, an admin account: service accounts arrive with #522.
 */
export function callerAccount(
  caller: Pick<AdminCaller, 'issuerRealm' | 'userId'>
): ApprovalAccount {
  return { realmId: caller.issuerRealm.id, accountId: caller.userId, kind: 'human' };
}

/** The parts of a stored approval its standings are read from. */
export type ApprovalRecord = Pick<
  AdminApproval,
  'requesterKind' | 'requesterRealmId' | 'requesterId' | 'approvalsRequired' | 'approvals'
>;

/** What one account may do with one approval, its status and expiry aside. */
export interface ApprovalStanding {
  /** The account filed the approval. */
  readonly isRequester: boolean;
  /** The account gave one of its approvals. */
  readonly hasApproved: boolean;
  /** The account may give the approval one more approval, or decline it. */
  readonly mayApprove: boolean;
  /** The account may read the approval. */
  readonly mayRead: boolean;
}

/**
 * The standing of `account` towards `approval`. `holdsApprove` says whether
 * the account's grants on the approval's realm hold `approvals.approve`.
 */
export function approvalStanding(
  approval: ApprovalRecord,
  account: ApprovalAccount,
  holdsApprove: boolean
): ApprovalStanding {
  const isAccount = (realmId: string, accountId: string) =>
    realmId === account.realmId && accountId === account.accountId;
  const isRequester =
    approval.requesterKind === account.kind &&
    isAccount(approval.requesterRealmId, approval.requesterId);
  const hasApproved = approval.approvals.some((given) =>
    isAccount(given.approverRealmId, given.approverId)
  );

  const humanRequester = approval.requesterKind === 'human';
  const fromRequester = approval.approvals.filter(
    (given) =>
      humanRequester &&
      given.approverRealmId === approval.requesterRealmId &&
      given.approverId === approval.requesterId
  ).length;
  // The approvals that come from accounts other than the requester.
  const othersNeeded = approval.approvalsRequired - (humanRequester ? 1 : 0);
  const othersGiven = approval.approvals.length - fromRequester;

  const human = account.kind === 'human';
  const mayApprove =
    human &&
    !hasApproved &&
    (isRequester
      ? humanRequester && fromRequester === 0
      : holdsApprove && othersGiven < othersNeeded);
  const mayRead = isRequester || hasApproved || mayApprove;

  return { isRequester, hasApproved, mayApprove, mayRead };
}

/** Where an approval stands, as the API shows it: its stored status, or `expired`. */
export type ApprovalShownStatus = AdminApproval['status'] | 'expired';

/**
 * The status the API shows at `now`: an approval that was never used, denied
 * or cancelled is `expired` from its expiry on, whatever its stored status.
 */
export function shownStatus(
  approval: Pick<AdminApproval, 'status' | 'expiresAt'>,
  now: number
): ApprovalShownStatus {
  const open = approval.status === 'pending' || approval.status === 'approved';
  return open && now >= approval.expiresAt ? 'expired' : approval.status;
}

/**
 * The version of an approval, which its `ETag` carries and a cancellation's
 * `If-Match` names: its stored status and how many approvals it holds. Every
 * move changes one of the two.
 */
export function approvalVersion(approval: Pick<AdminApproval, 'status' | 'approvals'>): string {
  return `${approval.status}.${approval.approvals.length}`;
}

/** The state {@link approvalVersion} names, or `undefined` for a value it never gives. */
export function parseApprovalVersion(
  version: string
): { readonly status: AdminApproval['status']; readonly approvalCount: number } | undefined {
  const match = /^(pending|approved|denied|cancelled|consumed)\.(0|[1-9][0-9]?)$/.exec(version);
  if (match === null) return undefined;
  return { status: match[1] as AdminApproval['status'], approvalCount: Number(match[2]) };
}
