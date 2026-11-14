import { createPasswordHardAction } from '@qauth-labs/fastify-plugin-sign-in-engine';
import { SECURITY_LOG_KINDS } from '@qauth-labs/shared-account-contract';
import type { FastifyRequest } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createTestApprovalFactor } from '../../../testing/approval-factor';
import { SECURITY_CHANGE_EVENTS, securityChangeOfEvent } from '../../helpers/admin-security-change';
import { emitUserEvent } from '../../helpers/user-events';
import { REALM_OPERATION_IDS } from '../realms/operations';
import {
  type ApprovalRequestRecord,
  approvalRequirementOf,
  approvalsFromOthers,
  approvalsRequiredFor,
  type ApproverGrantRecord,
  type ApproverRecord,
  approverRefusal,
  isEligibleApprover,
  operationApprovalRequirement,
  sharedWithAnEarlierApprover,
  TWO_ADMIN_WINDOW_MS,
} from './two-admin';

/**
 * THE TWO-ADMIN RULE (#521, ADR-019 Decision 7): how many approvals a
 * request needs, and who may give the second. One case per acceptance
 * criterion of the issue that a unit can hold, with a fake clock where the
 * 7-day window is measured.
 */

const DAY = 24 * 60 * 60 * 1000;
const REALM = { id: '0199fa20-0000-7000-8000-00000000aaaa' };
const OTHER_REALM = { id: '0199fa20-0000-7000-8000-00000000bbbb' };
const REQUESTER = {
  kind: 'human' as const,
  realmId: REALM.id,
  accountId: '0199fa20-5e1a-7000-8000-000000000001',
};
const APPROVER_ID = '0199fa20-5e1a-7000-8000-000000000002';
/** When the request was filed. */
const FILED = Date.UTC(2026, 10, 14, 12, 0, 0);

afterEach(() => {
  vi.useRealTimers();
});

/** A grant that gives `approvals.approve`, made long before the request and unchanged since. */
function oldGrant(overrides: Partial<ApproverGrantRecord> = {}): ApproverGrantRecord {
  return {
    createdAt: FILED - 30 * DAY,
    revokedAt: null,
    lastSecurityChangeAt: FILED - 30 * DAY,
    givesApprove: true,
    ...overrides,
  };
}

/** An approver that meets every rule: an old account with an old grant. */
function approver(overrides: Partial<ApproverRecord> = {}): ApproverRecord {
  return {
    kind: 'human',
    realmId: REALM.id,
    accountId: APPROVER_ID,
    createdAt: FILED - 30 * DAY,
    grants: [oldGrant()],
    credential: { registeredToRequester: false },
    ...overrides,
  };
}

const REQUEST: ApprovalRequestRecord = {
  realmId: REALM.id,
  requester: REQUESTER,
  createdAt: FILED,
};

/** The refusal of `candidate` for {@link REQUEST}, a minute after it was filed. */
const refusalOf = (candidate: ApproverRecord) =>
  approverRefusal(candidate, REQUEST, REALM, FILED + 60_000);

describe('who may approve (#521)', () => {
  it('accepts an old admin of the realm with an old grant and a credential of its own', () => {
    expect(refusalOf(approver())).toBeNull();
    expect(isEligibleApprover(approver(), REQUEST, REALM, FILED + 60_000)).toBe(true);
  });

  // Acceptance criterion: self-approval is refused.
  it('refuses the requester', () => {
    const self = approver({ accountId: REQUESTER.accountId });
    expect(refusalOf(self)).toBe('requester');
    expect(isEligibleApprover(self, REQUEST, REALM, FILED + 60_000)).toBe(false);
    // The same id in another realm is another account.
    expect(refusalOf(approver({ accountId: REQUESTER.accountId, realmId: OTHER_REALM.id }))).toBe(
      null
    );
  });

  // Acceptance criterion: an approval made with the requester's own
  // credential id is refused.
  it("refuses an approval given with a credential registered to the requester's account", async () => {
    const test = createTestApprovalFactor();
    const other = { realmId: REALM.id, accountId: APPROVER_ID };
    const shared = test.credentialOf(REQUESTER);
    test.register(other, shared);
    // The factor says whose the credential is; the rule refuses it.
    const registeredToRequester = await test.factor.isRegisteredTo(shared, REQUESTER);
    expect(registeredToRequester).toBe(true);
    expect(refusalOf(approver({ credential: { registeredToRequester } }))).toBe(
      'requester-credential'
    );
    // The approver's own credential is not the requester's.
    expect(await test.factor.isRegisteredTo(test.credentialOf(other), REQUESTER)).toBe(false);
    expect(refusalOf(approver({ credential: { registeredToRequester: false } }))).toBeNull();
    // Before the factor named the credential, rules 1 to 3 alone are judged.
    expect(refusalOf(approver({ credential: null }))).toBeNull();
  });

  // Where every approval comes from another admin (a service account's
  // request), one passkey on two approver accounts is still one person.
  it('refuses a credential an earlier approval of the request was given with, or whose account gave one', async () => {
    const test = createTestApprovalFactor();
    const first = { realmId: REALM.id, accountId: '00000000-0000-4000-8000-0000000000f1' };
    const second = { realmId: REALM.id, accountId: APPROVER_ID };
    const given = [
      {
        approverRealmId: first.realmId,
        approverId: first.accountId,
        credentialId: test.credentialOf(first),
      },
    ];
    expect(await sharedWithAnEarlierApprover(test.factor, test.credentialOf(second), given)).toBe(
      false
    );
    // The same credential id, and a passkey the first approver holds too.
    expect(await sharedWithAnEarlierApprover(test.factor, test.credentialOf(first), given)).toBe(
      true
    );
    const shared = 'shared-passkey';
    test.register(first, shared);
    test.register(second, shared);
    expect(await sharedWithAnEarlierApprover(test.factor, shared, given)).toBe(true);
    expect(await sharedWithAnEarlierApprover(test.factor, shared, [])).toBe(false);
    expect(
      refusalOf(
        approver({
          credential: { registeredToRequester: false, sharedWithAnEarlierApprover: true },
        })
      )
    ).toBe('approver-credential');
  });

  // Acceptance criterion: created 6 days before the request is refused, 7
  // days before is accepted (fake clock).
  it('refuses an account created within 7 days of the request, and accepts one created 7 days before', () => {
    vi.useFakeTimers();
    vi.setSystemTime(FILED - 7 * DAY);
    const sevenDays = approver({ createdAt: Date.now(), grants: [oldGrant()] });
    vi.setSystemTime(FILED - 6 * DAY);
    const sixDays = approver({ createdAt: Date.now(), grants: [oldGrant()] });
    vi.setSystemTime(FILED);
    const request = { ...REQUEST, createdAt: Date.now() };
    vi.setSystemTime(FILED + 60_000);
    expect(approverRefusal(sixDays, request, REALM, Date.now())).toBe('new-account');
    expect(approverRefusal(sevenDays, request, REALM, Date.now())).toBeNull();
    // The window is a constant: 7 days to the millisecond.
    expect(TWO_ADMIN_WINDOW_MS).toBe(7 * DAY);
    expect(refusalOf(approver({ createdAt: FILED - 7 * DAY + 1 }))).toBe('new-account');
  });

  // Acceptance criterion: an approver granted a role yesterday is refused.
  it('refuses an account granted a role in the 7 days before the request', () => {
    const yesterday = FILED - DAY;
    expect(
      refusalOf(
        approver({
          grants: [
            oldGrant(),
            oldGrant({
              createdAt: yesterday,
              lastSecurityChangeAt: yesterday,
              givesApprove: false,
            }),
          ],
        })
      )
    ).toBe('new-grant');
    // A role granted yesterday and revoked since was still granted then.
    expect(
      refusalOf(
        approver({
          grants: [
            oldGrant(),
            oldGrant({ createdAt: yesterday, revokedAt: FILED - 1_000, givesApprove: false }),
          ],
        })
      )
    ).toBe('new-grant');
  });

  it('refuses an account whose right to approve came after the request, or is gone', () => {
    expect(refusalOf(approver({ grants: [oldGrant({ givesApprove: false })] }))).toBe(
      'no-approval-right'
    );
    expect(refusalOf(approver({ grants: [oldGrant({ revokedAt: FILED })] }))).toBe(
      'no-approval-right'
    );
    expect(refusalOf(approver({ grants: [oldGrant({ createdAt: FILED + 1 })] }))).toBe(
      'no-approval-right'
    );
    expect(refusalOf(approver({ grants: [] }))).toBe('no-approval-right');
  });

  // Acceptance criterion: a service account is never an eligible approver.
  it('never accepts a service account', () => {
    const service = approver({ kind: 'service_account' });
    expect(refusalOf(service)).toBe('service-account');
    expect(isEligibleApprover(service, REQUEST, REALM, FILED + 60_000)).toBe(false);
  });

  it('refuses a request of another realm', () => {
    expect(approverRefusal(approver(), REQUEST, OTHER_REALM, FILED + 60_000)).toBe('other-realm');
  });
});

/**
 * The grants of one account, as the store keeps them, and a fake server whose
 * event store records an event and whose grants repository moves
 * `last_security_change_at` as migration 0074's function does.
 */
function serverWithGrants(grants: ApproverGrantRecord[]) {
  const recordSecurityChange = vi.fn(async (_realmId: string, userId: string) => {
    if (userId !== APPROVER_ID) return 0;
    let moved = 0;
    for (const [index, grant] of grants.entries()) {
      if (grant.revokedAt !== null) continue;
      grants[index] = {
        ...grant,
        lastSecurityChangeAt: Math.max(Date.now(), grant.lastSecurityChangeAt),
      };
      moved += 1;
    }
    return moved;
  });
  const emit = vi.fn(async () => '0199fa20-0000-7000-8000-0000000000ee');
  const server = {
    repositories: {
      events: { emit, emitInOwnTransaction: emit },
      adminGrants: { recordSecurityChange },
    },
    log: { info: vi.fn() },
  };
  const request = {
    server,
    id: 'req-1',
    ip: '192.0.2.1',
    headers: {},
  } as unknown as FastifyRequest;
  return { request, recordSecurityChange };
}

describe('what moves the window (#521)', () => {
  // Acceptance criterion: a requester who changed its own credentials 2
  // days ago cannot approve for another admin.
  it('refuses an admin that changed its own credentials 2 days before the request', async () => {
    const grants = [oldGrant()];
    const { request, recordSecurityChange } = serverWithGrants(grants);
    vi.useFakeTimers();
    vi.setSystemTime(FILED - 2 * DAY);
    // The account API's password change records its event in the change's
    // transaction: the event records the change for the rule too.
    const tx = {} as never;
    await emitUserEvent(
      request,
      'urn:qauth:event:user.password_changed:v1-rc.0',
      {},
      { tx, realmId: REALM.id, userId: APPROVER_ID, actor: 'user' }
    );
    expect(recordSecurityChange).toHaveBeenCalledWith(REALM.id, APPROVER_ID, tx);
    vi.setSystemTime(FILED + 60_000);
    // It filed requests of its own before; another admin's now finds it changed.
    const other = { ...REQUEST, requester: { ...REQUESTER, accountId: 'another-admin' } };
    expect(approverRefusal(approver({ grants }), other, REALM, Date.now())).toBe('security-change');
    // 7 days after the change it approves again.
    const later = { ...other, createdAt: FILED - 2 * DAY + TWO_ADMIN_WINDOW_MS };
    expect(approverRefusal(approver({ grants }), later, REALM, later.createdAt + 1)).toBeNull();
  });

  it('records a change only for the events of a changed credential, identifier or contact address', async () => {
    const { request, recordSecurityChange } = serverWithGrants([oldGrant()]);
    await emitUserEvent(
      request,
      'urn:qauth:event:user.passkey_renamed:v1-rc.0',
      { credentialId: '0199fa20-0000-7000-8000-0000000000c1' },
      { realmId: REALM.id, userId: APPROVER_ID, actor: 'user' }
    );
    await emitUserEvent(
      request,
      'urn:qauth:event:user.signed_in:v1-rc.0',
      { method: 'password' } as never,
      { realmId: REALM.id, userId: APPROVER_ID, actor: 'user' }
    );
    expect(recordSecurityChange).not.toHaveBeenCalled();
    expect(securityChangeOfEvent('urn:qauth:event:user.credential_removed:v1-rc.0')).toBe(
      'credentials'
    );
    expect(securityChangeOfEvent('urn:qauth:event:user.passkey_renamed:v1-rc.0')).toBeUndefined();
    expect(securityChangeOfEvent('not an event type')).toBeUndefined();
  });

  // The account security log's entries for a changed credential, identifier
  // or contact address name the events that record one: each is a security
  // change, and the automatic disable is not.
  it("lists every event the account security log shows as a change of the account's credentials", () => {
    const changes = [
      SECURITY_LOG_KINDS.password_changed,
      SECURITY_LOG_KINDS.credential_added,
      SECURITY_LOG_KINDS.credential_removed,
      SECURITY_LOG_KINDS.recovery_codes_regenerated,
      SECURITY_LOG_KINDS.identifier_changed,
      SECURITY_LOG_KINDS.account_linked,
      SECURITY_LOG_KINDS.account_unlinked,
    ];
    const registered = changes.flatMap((kind) =>
      kind.sources.filter((source) => source.status === 'registered').map((source) => source.event)
    );
    expect(Object.keys(SECURITY_CHANGE_EVENTS).sort()).toEqual([...registered].sort());
    for (const source of SECURITY_LOG_KINDS.credential_disabled.sources) {
      expect(SECURITY_CHANGE_EVENTS).not.toHaveProperty([source.event]);
    }
  });

  // Acceptance criterion: the automatic password disable (ADR-017
  // Decision 7) does not move the window.
  it('is not moved by the automatic password disable', async () => {
    const grants = [oldGrant()];
    const { recordSecurityChange } = serverWithGrants(grants);
    vi.useFakeTimers();
    vi.setSystemTime(FILED - DAY);
    const setDisabledAt = vi.fn(async () => ({ id: 'cred-1' }));
    // The server's hard action, armed, past the failure ceiling.
    const action = createPasswordHardAction({
      credentials: { setDisabledAt, clearDisabledAt: vi.fn(async () => ({ id: 'cred-1' })) },
      arming: {
        hostedReset: () => true,
        notices: { canSend: async () => true, passwordDisabled: async () => undefined },
      },
      log: { warn: vi.fn(), error: vi.fn() },
    });
    await action.ceilingReached({
      realmId: REALM.id,
      userId: APPROVER_ID,
      identifier: 'admin@example.com',
    });
    expect(setDisabledAt).toHaveBeenCalled();
    expect(recordSecurityChange).not.toHaveBeenCalled();
    expect(grants[0]?.lastSecurityChangeAt).toBe(FILED - 30 * DAY);
    vi.setSystemTime(FILED + 60_000);
    expect(approverRefusal(approver({ grants }), REQUEST, REALM, Date.now())).toBeNull();
  });
});

describe('a self-protecting operation on the operator realm (#521)', () => {
  const OPERATOR = { id: '0199fa20-0000-7000-8000-00000000cccc', isOperator: true };
  const TENANT = { id: REALM.id, isOperator: false };
  const grantCreate = { id: 'adminGrants.create', selfProtecting: true as const };

  /** A server whose realms hold `sets`; a set of `'unreadable'` fails to parse. */
  function serverOf(sets: Record<string, readonly string[] | 'unreadable'>) {
    const snapshot = (id: string) => {
      const set = sets[id];
      if (set === 'unreadable') throw new Error('PolicyValidationError');
      return { policies: { admin: { twoAdminMandatoryOperations: set ?? [] } } };
    };
    return {
      policyStore: {
        ofRealm: (row: { id: string }) => snapshot(row.id),
        get: async (id: string) => (id in sets ? snapshot(id) : undefined),
      },
      repositories: {
        realms: {
          listPolicyRecords: vi.fn(async () => Object.keys(sets).map((realmId) => ({ realmId }))),
        },
      },
    } as unknown as Parameters<typeof operationApprovalRequirement>[0];
  }
  const required = async (
    server: Parameters<typeof operationApprovalRequirement>[0],
    operation: { readonly id: string; readonly selfProtecting?: true },
    realm: { readonly id: string; readonly isOperator: boolean }
  ) =>
    (
      await operationApprovalRequirement(server, {
        operation,
        realm: realm as unknown as Parameters<typeof operationApprovalRequirement>[1]['realm'],
      })
    ).approvalsRequired;

  it("needs two admins while any realm's set is not empty, since its admins administer every realm", async () => {
    const tightened = serverOf({ [OPERATOR.id]: [], [TENANT.id]: ['keys.rotate'] });
    expect(await required(tightened, grantCreate, OPERATOR)).toBe(2);
    expect(
      await required(serverOf({ [OPERATOR.id]: [], [TENANT.id]: [] }), grantCreate, OPERATOR)
    ).toBe(1);
    // A realm whose policies cannot be read counts as one that is tightened.
    expect(
      await required(
        serverOf({ [OPERATOR.id]: [], [TENANT.id]: 'unreadable' }),
        grantCreate,
        OPERATOR
      )
    ).toBe(2);
  });

  it("reads only the target realm's set for any other operation or realm", async () => {
    const server = serverOf({ [OPERATOR.id]: [], [TENANT.id]: ['keys.rotate'] });
    expect(await required(server, { id: 'keys.retire' }, OPERATOR)).toBe(1);
    const tenantOnly = serverOf({ [OPERATOR.id]: ['keys.rotate'], [TENANT.id]: [] });
    expect(await required(tenantOnly, grantCreate, TENANT)).toBe(1);
    expect(tenantOnly.repositories.realms.listPolicyRecords).not.toHaveBeenCalled();
  });

  // An admin handler's repository calls must name its transaction.
  it("reads every realm's policies in the handler's transaction when it is given one", async () => {
    const server = serverOf({ [OPERATOR.id]: [], [TENANT.id]: [] });
    const get = vi.spyOn(server.policyStore, 'get');
    const tx = { handler: 'tx' } as unknown as Parameters<typeof operationApprovalRequirement>[2];
    await operationApprovalRequirement(
      server,
      {
        operation: grantCreate,
        realm: OPERATOR as unknown as Parameters<typeof operationApprovalRequirement>[1]['realm'],
      },
      tx
    );
    expect(server.repositories.realms.listPolicyRecords).toHaveBeenCalledWith(tx);
    expect(get).toHaveBeenCalledWith(TENANT.id, tx);
  });
});

describe('how many approvals a request needs (#521)', () => {
  const keysRotate = { id: 'keys.rotate' };
  const grantCreate = { id: 'adminGrants.create', selfProtecting: true as const };
  const updatePolicies = { id: REALM_OPERATION_IDS.updatePolicies };
  const setTo = (ids: unknown) => ({ admin: { twoAdminMandatoryOperations: ids } });

  it('needs a second admin for an operation the realm makes mandatory, and recommends one elsewhere', () => {
    expect(approvalsRequiredFor({ operation: keysRotate, mandatory: ['keys.rotate'] })).toBe(2);
    expect(approvalsRequiredFor({ operation: keysRotate, mandatory: ['keys.retire'] })).toBe(1);
    expect(approvalsRequiredFor({ operation: keysRotate, mandatory: [] })).toBe(1);
    expect(approvalRequirementOf(2)).toEqual({ approvalsRequired: 2, twoAdmin: 'mandatory' });
    expect(approvalRequirementOf(1)).toEqual({ approvalsRequired: 1, twoAdmin: 'recommended' });
  });

  it('needs a second admin for a self-protecting operation once the set is not empty', () => {
    expect(approvalsRequiredFor({ operation: grantCreate, mandatory: ['keys.rotate'] })).toBe(2);
    expect(approvalsRequiredFor({ operation: grantCreate, mandatory: [] })).toBe(1);
  });

  it('lets one admin add to the mandatory set, and needs two for any other change of it', () => {
    const mandatory = ['keys.rotate'];
    const needs = (body: unknown, set = mandatory) =>
      approvalsRequiredFor({ operation: updatePolicies, mandatory: set, body });
    // Adding only.
    expect(needs(setTo(['keys.rotate', 'keys.retire']))).toBe(1);
    expect(needs(setTo(['keys.rotate']))).toBe(1);
    expect(needs(setTo(['keys.retire']), [])).toBe(1);
    // Adding, even where the policy update is itself mandatory.
    expect(
      needs(setTo(['keys.rotate', 'realms.policies.update', 'keys.retire']), [
        'keys.rotate',
        'realms.policies.update',
      ])
    ).toBe(1);
    // Removing, replacing, emptying or resetting.
    expect(needs(setTo(['keys.retire']))).toBe(2);
    expect(needs(setTo([]))).toBe(2);
    expect(needs(setTo(null))).toBe(2);
    expect(needs({ admin: null })).toBe(2);
    expect(needs({ admin: {} })).toBe(2);
    expect(needs(null)).toBe(2);
    // A value the schema would refuse counts as emptying it.
    expect(needs(setTo('keys.rotate'))).toBe(2);
    // An empty set: nothing to remove.
    expect(needs(setTo([]), [])).toBe(1);
    expect(needs({ admin: null }, [])).toBe(1);
  });

  it('judges the rest of a policy patch that adds to the set as any other', () => {
    const body = { ...setTo(['keys.rotate', 'keys.retire']), password: { minLength: 8 } };
    expect(
      approvalsRequiredFor({ operation: updatePolicies, mandatory: ['keys.rotate'], body })
    ).toBe(1);
    expect(
      approvalsRequiredFor({
        operation: updatePolicies,
        mandatory: ['keys.rotate', 'realms.policies.update'],
        body,
      })
    ).toBe(2);
    // A patch that leaves the set alone is the operation's own case.
    expect(
      approvalsRequiredFor({
        operation: updatePolicies,
        mandatory: ['realms.policies.update'],
        body: { password: { minLength: 8 } },
      })
    ).toBe(2);
  });

  it('counts the requester’s own step-up as the first approval of a human', () => {
    expect(approvalsFromOthers(2, 'human')).toBe(1);
    expect(approvalsFromOthers(1, 'human')).toBe(0);
    expect(approvalsFromOthers(2, 'service_account')).toBe(2);
    expect(approvalsFromOthers(1, 'service_account')).toBe(1);
  });
});
