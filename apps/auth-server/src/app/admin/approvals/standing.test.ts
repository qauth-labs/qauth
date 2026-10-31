import { describe, expect, it } from 'vitest';

import {
  type ApprovalAccount,
  type ApprovalRecord,
  approvalStanding,
  approvalVersion,
  parseApprovalVersion,
  shownStatus,
} from './standing';

/**
 * WHO STANDS WHERE TOWARDS AN APPROVAL (#512): a human requester's own fresh
 * step-up is its first approval; a required second one comes only from a
 * different human account holding `approvals.approve`; a service account's
 * approvals all come from humans; and only these accounts read it.
 */

const OPERATOR = '018f2d6e-0000-7000-8000-00000000000a';
const TENANT = '018f2d6e-0000-7000-8000-00000000000b';

const human = (accountId: string, realmId = OPERATOR): ApprovalAccount => ({
  realmId,
  accountId,
  kind: 'human',
});
const requester = human('requester');
const second = human('second');
const third = human('third');
const robot: ApprovalAccount = { realmId: OPERATOR, accountId: 'robot', kind: 'service_account' };

function approval(
  required: number,
  given: readonly ApprovalAccount[] = [],
  by: ApprovalAccount = requester
): ApprovalRecord {
  return {
    requesterKind: by.kind,
    requesterRealmId: by.realmId,
    requesterId: by.accountId,
    approvalsRequired: required,
    approvals: given.map((account, index) => ({
      approverRealmId: account.realmId,
      approverId: account.accountId,
      credentialId: `credential-${index}`,
      factor: 'test',
      approvedAt: index,
    })),
  };
}

describe('approval standings (#512)', () => {
  it("counts a human requester's own step-up as the one approval, which only it gives", () => {
    const filed = approval(1);
    expect(approvalStanding(filed, requester, false)).toEqual({
      isRequester: true,
      hasApproved: false,
      mayApprove: true,
      mayRead: true,
    });
    // An admin who may approve others' requests can neither approve nor read
    // it: nobody but the requester gives this one.
    expect(approvalStanding(filed, second, true)).toMatchObject({
      mayApprove: false,
      mayRead: false,
    });
    // Once given, it is not given twice.
    expect(approvalStanding(approval(1, [requester]), requester, true).mayApprove).toBe(false);
  });

  it('takes a required second approval only from a different human account with approvals.approve', () => {
    const afterStepUp = approval(2, [requester]);
    expect(approvalStanding(afterStepUp, requester, true).mayApprove).toBe(false);
    expect(approvalStanding(afterStepUp, second, true)).toMatchObject({
      mayApprove: true,
      mayRead: true,
    });
    expect(approvalStanding(afterStepUp, second, false)).toMatchObject({
      mayApprove: false,
      mayRead: false,
    });
    // The same account id in another realm is another account.
    expect(approvalStanding(afterStepUp, human('requester', TENANT), true).mayApprove).toBe(true);
    // A service account never approves.
    expect(approvalStanding(afterStepUp, robot, true).mayApprove).toBe(false);
    // Once the second is in, a third admin has nothing to give, and cannot
    // read it.
    const full = approval(2, [requester, second]);
    expect(approvalStanding(full, third, true)).toMatchObject({
      mayApprove: false,
      mayRead: false,
    });
    expect(approvalStanding(full, second, true)).toMatchObject({
      hasApproved: true,
      mayApprove: false,
      mayRead: true,
    });
  });

  it("lets the second admin approve before the requester's step-up, and keeps the step-up the requester's", () => {
    const secondFirst = approval(2, [second]);
    expect(approvalStanding(secondFirst, third, true).mayApprove).toBe(false);
    expect(approvalStanding(secondFirst, requester, false).mayApprove).toBe(true);
  });

  it("has humans approve in a service account's place, each a different one", () => {
    const filed = approval(2, [], robot);
    expect(approvalStanding(filed, robot, true)).toMatchObject({
      isRequester: true,
      mayApprove: false,
      mayRead: true,
    });
    expect(approvalStanding(filed, second, true).mayApprove).toBe(true);
    const one = approval(2, [second], robot);
    expect(approvalStanding(one, second, true).mayApprove).toBe(false);
    expect(approvalStanding(one, third, true).mayApprove).toBe(true);
    expect(approvalStanding(approval(1, [second], robot), third, true).mayApprove).toBe(false);
  });

  it('shows an open approval as expired from its expiry on, and a closed one as it is', () => {
    expect(shownStatus({ status: 'pending', expiresAt: 10 }, 9)).toBe('pending');
    expect(shownStatus({ status: 'pending', expiresAt: 10 }, 10)).toBe('expired');
    expect(shownStatus({ status: 'approved', expiresAt: 10 }, 11)).toBe('expired');
    expect(shownStatus({ status: 'consumed', expiresAt: 10 }, 11)).toBe('consumed');
    expect(shownStatus({ status: 'cancelled', expiresAt: 10 }, 11)).toBe('cancelled');
  });

  it('names a version every move changes, and reads back only what it names', () => {
    const versions = [
      approvalVersion({ status: 'pending', approvals: [] }),
      approvalVersion({ status: 'pending', approvals: approval(2, [requester]).approvals }),
      approvalVersion({
        status: 'approved',
        approvals: approval(2, [requester, second]).approvals,
      }),
      approvalVersion({
        status: 'consumed',
        approvals: approval(2, [requester, second]).approvals,
      }),
    ];
    expect(versions).toEqual(['pending.0', 'pending.1', 'approved.2', 'consumed.2']);
    expect(parseApprovalVersion('approved.2')).toEqual({ status: 'approved', approvalCount: 2 });
    for (const other of ['expired.0', 'pending.-1', 'pending.01', 'pending', '"pending.0"']) {
      expect(parseApprovalVersion(other), other).toBeUndefined();
    }
  });
});
