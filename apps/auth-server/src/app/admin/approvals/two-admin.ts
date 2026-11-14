import type { FastifyInstance } from 'fastify';

import { grantCoversRealm, grantedPermissionIds } from '../../helpers/admin-authority';
import { mergePatchLeafPaths } from '../../helpers/admin-classification';
import { PERMISSION_REGISTRY } from '../../helpers/admin-permissions';
import { effectivePermissions } from '../../helpers/admin-roles';
import { ADMIN_SCOPE_LIST } from '../../helpers/admin-scopes';
import type { RealmRow } from '../../helpers/request-realm';
import { REALM_OPERATION_IDS } from '../realms/operations';
import type { ApprovalAccount } from './standing';

/**
 * THE TWO-ADMIN RULE (ADR-019 Decision 7, ADR-020 §4, issue #521).
 *
 * A second admin's approval is recommended for every security operation. A
 * realm makes it mandatory for the operations it lists in its policy
 * `admin.twoAdminMandatoryOperations`. This module says how many approvals
 * one request needs ({@link approvalsRequiredFor}) and who may give the
 * second one ({@link isEligibleApprover}).
 *
 * How the rule protects itself: once the set is not empty, the operations
 * marked `selfProtecting` (creating an admin, granting or removing an admin
 * role, changing an admin's credentials through the admin API) need two
 * admins too, and so does every change of the set but one that only adds
 * operation ids.
 *
 * Who may approve. The rule binds accounts, not people. An approver other
 * than the requester is eligible only when all of these hold:
 *
 * 1. It is a human account, and not the requester's. A service account never
 *    approves.
 * 2. It held a live grant with `approvals.approve` on the target realm before
 *    the request was made, and still does.
 * 3. In the {@link TWO_ADMIN_WINDOW_MS 7 days} before the request it was not
 *    created and not granted a role, and its credentials, identifier and
 *    contact address did not change, whoever changed them. A change moves
 *    `admin_grants.last_security_change_at` of its live grants
 *    (`recordAdminSecurityChange`); a change of what a grant's custom role
 *    gives moves it too (the admin roles repository), and the operation that
 *    makes one, `adminRoles.update`, is self-protecting. The automatic
 *    password disable of ADR-017 Decision 7 moves nothing.
 * 4. The credential it approves with is not registered to the requester's
 *    account, did not give the same request an earlier approval and is not
 *    registered to an account that did.
 *
 * A human requester's own fresh step-up is the first approval and none of
 * this applies to it. Where a service account files the request, every
 * approval comes from an eligible human admin, the first standing in for the
 * requester's step-up.
 */

/** The window of rule 3: 7 days. A constant, not a setting (ADR-019 Decision 7). */
export const TWO_ADMIN_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

/** The permission an approver holds on the realm. */
export const APPROVE_PERMISSION = 'approvals.approve';

/** Whether a second admin's approval is `recommended` or `mandatory`. */
export type TwoAdmin = 'recommended' | 'mandatory';

/** How many approvals one request needs, and so whether a second admin is mandatory. */
export interface ApprovalRequirement {
  readonly approvalsRequired: 1 | 2;
  readonly twoAdmin: TwoAdmin;
}

/** The JSON Pointer of the mandatory set in a policy patch, as `mergePatchLeafPaths` names it. */
const MANDATORY_SET_POINTER = '/admin/twoAdminMandatoryOperations';

/**
 * What a policy patch does to the mandatory set: the set it leaves, and
 * whether the set is all the patch names. `null` when the patch does not name
 * the set. The patch has passed the route's schema, so the set is a list of
 * operation ids, or `null`, which resets it to its default, the empty set. A
 * value of any other shape counts as emptying it, the change that needs most.
 */
function mandatorySetPatch(
  body: unknown
): { readonly after: readonly string[]; readonly onlyTheSet: boolean } | null {
  const leaves = mergePatchLeafPaths(body);
  // A body that replaces the whole document, or the `admin` group (`null`
  // or `{}`), may empty the set: judged as emptying it.
  if (leaves.includes('') || leaves.includes('/admin')) return { after: [], onlyTheSet: false };
  if (!leaves.includes(MANDATORY_SET_POINTER)) return null;
  const admin = (body as { admin?: unknown }).admin as Record<string, unknown>;
  const value = admin['twoAdminMandatoryOperations'];
  const after =
    Array.isArray(value) && value.every((id) => typeof id === 'string') ? (value as string[]) : [];
  return { after, onlyTheSet: leaves.every((leaf) => leaf === MANDATORY_SET_POINTER) };
}

/** What {@link approvalsRequiredFor} decides from. */
export interface ApprovalsRequiredInput {
  /** The operation, as the registry holds it. */
  readonly operation: { readonly id: string; readonly selfProtecting?: true };
  /** The target realm's mandatory set as it stands now. */
  readonly mandatory: readonly string[];
  /** The operation's request body, which a policy patch is judged on. */
  readonly body?: unknown;
}

/**
 * How many approvals one request of `operation` needs on a realm whose
 * mandatory set is `mandatory` (ADR-019 Decision 7):
 *
 * - a policy patch (`realms.policies.update`) that changes the set in any
 *   other way than adding operation ids needs 2 while the set is not empty;
 *   one whose only change is adding ids needs 1, even where the policy
 *   update itself is mandatory, so one admin can always tighten the set;
 * - an operation in the set needs 2;
 * - a `selfProtecting` operation needs 2 while the set is not empty;
 * - every other one needs 1.
 */
export function approvalsRequiredFor(input: ApprovalsRequiredInput): 1 | 2 {
  const { operation, mandatory } = input;
  if (operation.id === REALM_OPERATION_IDS.updatePolicies) {
    const change = mandatorySetPatch(input.body);
    if (change !== null) {
      const after = new Set(change.after);
      if (mandatory.some((id) => !after.has(id))) return 2;
      if (change.onlyTheSet) return 1;
    }
  }
  if (mandatory.includes(operation.id)) return 2;
  if (operation.selfProtecting === true && mandatory.length > 0) return 2;
  return 1;
}

/** The requirement of `approvalsRequired` approvals. */
export function approvalRequirementOf(approvalsRequired: 1 | 2): ApprovalRequirement {
  return { approvalsRequired, twoAdmin: approvalsRequired > 1 ? 'mandatory' : 'recommended' };
}

/**
 * The realm's mandatory set, from its row as the request already loaded it
 * (`policyStore.ofRealm`). A stored document the schema refuses throws: the
 * operation then fails rather than run on a set it cannot read.
 */
export function mandatoryOperationsOf(
  fastify: Pick<FastifyInstance, 'policyStore'>,
  realm: RealmRow
): readonly string[] {
  return fastify.policyStore.ofRealm(realm).policies.admin.twoAdminMandatoryOperations;
}

/** What one request of `operation` on `realm` needs ({@link approvalsRequiredFor}). */
export function requestApprovalRequirement(
  fastify: Pick<FastifyInstance, 'policyStore'>,
  input: {
    readonly operation: ApprovalsRequiredInput['operation'];
    readonly realm: RealmRow;
    readonly body?: unknown;
  }
): ApprovalRequirement {
  return approvalRequirementOf(
    approvalsRequiredFor({
      operation: input.operation,
      mandatory: mandatoryOperationsOf(fastify, input.realm),
      body: input.body,
    })
  );
}

/**
 * What one request of `operation` on `realm` needs, as the gate and the
 * filing judge it: {@link requestApprovalRequirement}, and for a
 * `selfProtecting` operation on the operator realm, every realm's set. The
 * operator realm's admins administer every realm, so an admin made or granted
 * there can approve anywhere: such an operation needs two admins while any
 * realm's set is not empty. A realm whose policies cannot be read counts as
 * one whose set is not empty.
 */
export async function operationApprovalRequirement(
  fastify: Pick<FastifyInstance, 'policyStore' | 'repositories'>,
  input: {
    readonly operation: ApprovalsRequiredInput['operation'];
    readonly realm: RealmRow;
    readonly body?: unknown;
  }
): Promise<ApprovalRequirement> {
  const own = requestApprovalRequirement(fastify, input);
  if (
    own.approvalsRequired > 1 ||
    input.operation.selfProtecting !== true ||
    !input.realm.isOperator
  ) {
    return own;
  }
  for (const record of await fastify.repositories.realms.listPolicyRecords()) {
    if (record.realmId === input.realm.id) continue;
    let mandatory: readonly string[];
    try {
      const snapshot = await fastify.policyStore.get(record.realmId);
      // A realm removed since the list was read administers nobody.
      if (snapshot === undefined) continue;
      mandatory = snapshot.policies.admin.twoAdminMandatoryOperations;
    } catch {
      return approvalRequirementOf(2);
    }
    if (mandatory.length > 0) return approvalRequirementOf(2);
  }
  return own;
}

/**
 * How many approvals must come from accounts other than the requester: all
 * of them for a service account, all but its own step-up for a human.
 */
export function approvalsFromOthers(
  approvalsRequired: number,
  requesterKind: ApprovalAccount['kind']
): number {
  return requesterKind === 'human' ? approvalsRequired - 1 : approvalsRequired;
}

/** One grant of an approver, as rule 2 and rule 3 read it. */
export interface ApproverGrantRecord {
  readonly createdAt: number;
  /** When it was revoked; `null` while it is live. */
  readonly revokedAt: number | null;
  readonly lastSecurityChangeAt: number;
  /** The grant gives `approvals.approve` on the target realm now: live, covering it, its role holding it. */
  readonly givesApprove: boolean;
}

/** What the rule knows of an account that would give an approval. */
export interface ApproverRecord extends ApprovalAccount {
  /** When the account was created. */
  readonly createdAt: number;
  /** Every grant of the account, revoked ones included. */
  readonly grants: readonly ApproverGrantRecord[];
  /**
   * The credential the approval is given with, once the factor named it:
   * whether it is registered to the requester's account (rule 4), and
   * whether an earlier approval of the same request was given with it, or by
   * an account it is registered to. `null` before then, when only rules 1 to
   * 3 can be judged.
   */
  readonly credential: {
    readonly registeredToRequester: boolean;
    /** Absent when no other admin approved yet. */
    readonly sharedWithAnEarlierApprover?: boolean;
  } | null;
}

/** What the rule knows of the request an approval is for. */
export interface ApprovalRequestRecord {
  /** The realm the request acts on. */
  readonly realmId: string;
  readonly requester: ApprovalAccount;
  /** When the request was made: the approval's `createdAt`. */
  readonly createdAt: number;
}

/** Why an account may not give a second admin's approval. Logged, never sent. */
export type ApproverRefusal =
  | 'other-realm'
  | 'service-account'
  | 'requester'
  | 'no-approval-right'
  | 'new-account'
  | 'new-grant'
  | 'security-change'
  | 'requester-credential'
  | 'approver-credential';

/**
 * Why `approver` may not give an approval of `request` on `realm` at `now`,
 * or `null` when it may (rules 1 to 4 above). Pure.
 */
export function approverRefusal(
  approver: ApproverRecord,
  request: ApprovalRequestRecord,
  realm: Pick<RealmRow, 'id'>,
  now: number
): ApproverRefusal | null {
  if (request.realmId !== realm.id) return 'other-realm';
  // Rule 1.
  if (approver.kind !== 'human') return 'service-account';
  if (
    approver.realmId === request.requester.realmId &&
    approver.accountId === request.requester.accountId
  ) {
    return 'requester';
  }
  // Rule 2: the right to approve came from a grant made before the request.
  const live = (grant: ApproverGrantRecord) => grant.revokedAt === null || grant.revokedAt > now;
  if (
    !approver.grants.some(
      (grant) => grant.givesApprove && live(grant) && grant.createdAt < request.createdAt
    )
  ) {
    return 'no-approval-right';
  }
  // Rule 3: nothing new or changed since the window before the request
  // opened, to now.
  const opened = request.createdAt - TWO_ADMIN_WINDOW_MS;
  if (approver.createdAt > opened) return 'new-account';
  if (approver.grants.some((grant) => grant.createdAt > opened)) return 'new-grant';
  if (approver.grants.some((grant) => live(grant) && grant.lastSecurityChangeAt > opened)) {
    return 'security-change';
  }
  // Rule 4.
  if (approver.credential?.registeredToRequester === true) return 'requester-credential';
  // Rule 4, kept for every approval a request gathers: one passkey on two
  // approver accounts is one person, whichever of them files.
  if (approver.credential?.sharedWithAnEarlierApprover === true) return 'approver-credential';
  return null;
}

/**
 * Whether `credentialId` gave one of `approvals` already, or is registered to
 * an account that gave one: rule 4 for every approval after the first
 * ({@link ApproverRecord}'s `credential`). `factor` answers whether a
 * credential is registered to an account.
 */
export async function sharedWithAnEarlierApprover(
  factor: {
    isRegisteredTo(
      credentialId: string,
      account: { readonly realmId: string; readonly accountId: string }
    ): Promise<boolean>;
  },
  credentialId: string,
  approvals: readonly {
    readonly approverRealmId: string;
    readonly approverId: string;
    readonly credentialId: string;
  }[]
): Promise<boolean> {
  for (const given of approvals) {
    if (given.credentialId === credentialId) return true;
    const account = { realmId: given.approverRealmId, accountId: given.approverId };
    if (await factor.isRegisteredTo(credentialId, account)) return true;
  }
  return false;
}

/** Whether `approver` may give a second admin's approval of `request` ({@link approverRefusal}). */
export function isEligibleApprover(
  approver: ApproverRecord,
  request: ApprovalRequestRecord,
  realm: Pick<RealmRow, 'id'>,
  now: number
): boolean {
  return approverRefusal(approver, request, realm, now) === null;
}

/** Whether one live grant of an account of `accountRealm` gives `approvals.approve` on `targetRealm`. */
export function grantGivesApprove(
  live: Parameters<typeof grantCoversRealm>[0],
  accountRealm: Pick<RealmRow, 'id' | 'isOperator'>,
  targetRealm: Pick<RealmRow, 'id' | 'isOperator'>
): boolean {
  // A realm-local admin never acts on the operator realm.
  if (!accountRealm.isOperator && targetRealm.isOperator) return false;
  return (
    grantCoversRealm(live, accountRealm, targetRealm.id) &&
    effectivePermissions(grantedPermissionIds(live), ADMIN_SCOPE_LIST, PERMISSION_REGISTRY).has(
      APPROVE_PERMISSION
    )
  );
}

/** A stored admin grant, as the repositories read it. */
type StoredGrant = Awaited<
  ReturnType<FastifyInstance['repositories']['adminGrants']['listByUser']>
>[number];

/** {@link ApproverRecord} of an account, from its rows. */
export function approverRecord(
  account: ApprovalAccount & { readonly createdAt: number },
  grants: readonly Pick<StoredGrant, 'id' | 'createdAt' | 'revokedAt' | 'lastSecurityChangeAt'>[],
  approveGrantIds: ReadonlySet<string>,
  credential: ApproverRecord['credential'] = null
): ApproverRecord {
  return {
    realmId: account.realmId,
    accountId: account.accountId,
    kind: account.kind,
    createdAt: account.createdAt,
    grants: grants.map((grant) => ({
      createdAt: grant.createdAt,
      revokedAt: grant.revokedAt,
      lastSecurityChangeAt: grant.lastSecurityChangeAt,
      givesApprove: approveGrantIds.has(grant.id),
    })),
    credential,
  };
}

/** A transaction of the repositories, or none. */
type Transaction = Parameters<FastifyInstance['repositories']['adminGrants']['listByUser']>[2];

/** An approver's record, and who created it, as the engine reads them. */
export interface LoadedApprover {
  readonly record: ApproverRecord;
  /**
   * Who made the account an approver on the realm: the admin who created its
   * oldest live grant that gives `approvals.approve` there, or, for an
   * account that holds none (a requester's own step-up), its oldest live
   * grant covering the realm. `null` when the operator CLI or QAuth created
   * that grant, or its creator's account was deleted. The admin events show
   * it with each approval: the rule binds accounts, not people.
   */
  readonly createdBy: string | null;
}

/**
 * Read what the rule needs of `account` towards a request on `targetRealm`:
 * the account's creation, every grant it holds or held, and which of its
 * live grants give `approvals.approve` there. `undefined` when the account
 * or its realm is gone.
 */
export async function loadApprover(
  fastify: FastifyInstance,
  account: ApprovalAccount,
  targetRealm: Pick<RealmRow, 'id' | 'isOperator'>,
  options: { readonly tx?: Transaction; readonly credential?: ApproverRecord['credential'] } = {}
): Promise<LoadedApprover | undefined> {
  const { tx } = options;
  const { repositories } = fastify;
  const accountRealm = await repositories.realms.findById(account.realmId, tx);
  const user = await repositories.users.findById(account.realmId, account.accountId, tx);
  if (accountRealm === undefined || user === undefined) return undefined;
  const grants = await repositories.adminGrants.listByUser(account.realmId, account.accountId, tx);
  const live = await repositories.adminGrants.listLive(account.realmId, account.accountId, tx);
  const approving = live.filter((grant) => grantGivesApprove(grant, accountRealm, targetRealm));
  const covering = live.filter((grant) => grantCoversRealm(grant, accountRealm, targetRealm.id));
  // `listLive` reads oldest first.
  const source = approving[0] ?? covering[0];
  return {
    record: approverRecord(
      { ...account, createdAt: user.createdAt },
      grants,
      new Set(approving.map(({ grant }) => grant.id)),
      options.credential ?? null
    ),
    createdBy: source?.grant.createdBy ?? null,
  };
}
