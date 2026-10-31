import { and, eq, gt, inArray, type InferSelectModel, lte, sql } from 'drizzle-orm';

import type { DbClient } from '../../types';
import {
  type AdminApprovalClassification,
  type AdminApprovalEntry,
  type AdminApprovalRequesterKind,
  adminApprovals,
  type AdminApprovalStatus,
} from '../schema/admin-approvals';
import { isAdminRecordId } from './admin-roles.repository';

/** A stored approval request (issue #512). */
export type AdminApproval = InferSelectModel<typeof adminApprovals>;

/** A new approval request, as the approval engine files it. */
export interface NewAdminApproval {
  readonly realmId: string;
  readonly requesterKind: AdminApprovalRequesterKind;
  readonly requesterRealmId: string;
  readonly requesterId: string;
  readonly operationId: string;
  /** The canonical request without the nonce. */
  readonly canonicalRequest: Record<string, unknown>;
  readonly requestHash: Buffer;
  readonly opHash: Buffer;
  readonly nonce: Buffer;
  readonly reason: string | null;
  readonly classification: AdminApprovalClassification;
  readonly approvalsRequired: number;
  /** Epoch milliseconds. */
  readonly createdAt: number;
  /** Epoch milliseconds, after `createdAt`. */
  readonly expiresAt: number;
}

/** The state a write expects to find, as the approval's version names it. */
export interface AdminApprovalExpectedState {
  readonly status: AdminApprovalStatus;
  /** How many approvals it holds. */
  readonly approvalCount: number;
}

/**
 * Approval requests for security operations (ADR-019 Decision 7, issue
 * #512). Every write is one conditional `UPDATE … RETURNING` that names the
 * state it moves from and the time it is made at: it returns the row it
 * changed, or `undefined` when the approval is not in that state any more,
 * has expired, or is not the one named. So two writers that race cannot both
 * move one approval, and a write that rolls back moves nothing.
 *
 * Who may make each write is the approval engine's to decide
 * (`apps/auth-server/src/app/admin/approvals`); the repository only keeps
 * the moves consistent.
 *
 * A move that closes an approval (consumed, cancelled, denied) drops the
 * operation's body from the stored request: the body may hold a secret, such
 * as a credential the operation sets, and nothing reads it once no approval
 * can be given or used. No job removes approvals: an approval that expires
 * unused keeps its body until the next one is filed in its realm, which drops
 * it.
 */
export interface AdminApprovalsRepository {
  /**
   * File an approval request, `pending`, with no approval yet. First drops
   * the body of every approval of the realm that expired unused by the new
   * one's `createdAt`.
   */
  create(approval: NewAdminApproval, tx?: DbClient): Promise<AdminApproval>;

  /** The approval with this id in the realm; `undefined` for another realm's, or an id that is not a UUID. */
  findById(realmId: string, id: string, tx?: DbClient): Promise<AdminApproval | undefined>;

  /**
   * Add one approval to a `pending`, unexpired approval that holds exactly
   * `expectedCount` approvals and none from the same approver. It becomes
   * `approved` when the approval was the last one it needed.
   */
  addApproval(
    realmId: string,
    id: string,
    change: {
      readonly expectedCount: number;
      readonly entry: AdminApprovalEntry;
      readonly now: number;
    },
    tx?: DbClient
  ): Promise<AdminApproval | undefined>;

  /** Deny a `pending`, unexpired approval that holds exactly `expectedCount` approvals. */
  deny(
    realmId: string,
    id: string,
    change: { readonly expectedCount: number; readonly now: number },
    tx?: DbClient
  ): Promise<AdminApproval | undefined>;

  /**
   * Cancel an unexpired approval of this requester that is still in the
   * `expected` state, `pending` or `approved`.
   */
  cancel(
    realmId: string,
    id: string,
    change: {
      readonly requesterRealmId: string;
      readonly requesterId: string;
      readonly expected: AdminApprovalExpectedState;
      readonly now: number;
    },
    tx?: DbClient
  ): Promise<AdminApproval | undefined>;

  /**
   * Use an `approved`, unexpired approval for the request whose
   * `request_hash` is `requestHash`: it becomes `consumed`, with `used_at`.
   * Run it in the transaction of the operation, so the operation's rollback
   * takes the consumption back with it.
   */
  consume(
    realmId: string,
    id: string,
    change: { readonly requestHash: Buffer; readonly now: number },
    tx: DbClient
  ): Promise<AdminApproval | undefined>;
}

/** The rows of one approval of the realm, and only while it is unexpired at `now`. */
function openApproval(realmId: string, id: string, now: number) {
  return and(
    eq(adminApprovals.realmId, realmId),
    eq(adminApprovals.id, id),
    gt(adminApprovals.expiresAt, now)
  );
}

/** The approval holds exactly `count` approvals. */
const holds = (count: number) => sql`jsonb_array_length(${adminApprovals.approvals}) = ${count}`;

/**
 * The stored request without its body. An approval that is used, cancelled or
 * denied keeps no body: it may hold a secret, and the two hashes are what the
 * audit log binds to.
 */
const withoutBody = sql`${adminApprovals.canonicalRequest} - 'body'`;

/**
 * Factory for the approval request repository (issue #512).
 *
 * @param defaultDb - The database a call without a transaction runs on.
 */
export function createAdminApprovalsRepository(defaultDb: DbClient): AdminApprovalsRepository {
  return {
    async create(approval, tx) {
      const invoker = tx ?? defaultDb;
      await invoker
        .update(adminApprovals)
        .set({ canonicalRequest: withoutBody })
        .where(
          and(
            eq(adminApprovals.realmId, approval.realmId),
            inArray(adminApprovals.status, ['pending', 'approved']),
            lte(adminApprovals.expiresAt, approval.createdAt),
            sql`${adminApprovals.canonicalRequest} ? 'body'`
          )
        );
      const [record] = await invoker
        .insert(adminApprovals)
        // The fields a new approval has, named one by one: its id, status,
        // approvals and time of use are the table's, never the caller's.
        .values({
          realmId: approval.realmId,
          requesterKind: approval.requesterKind,
          requesterRealmId: approval.requesterRealmId,
          requesterId: approval.requesterId,
          operationId: approval.operationId,
          canonicalRequest: approval.canonicalRequest,
          requestHash: approval.requestHash,
          opHash: approval.opHash,
          nonce: approval.nonce,
          reason: approval.reason,
          approvalsRequired: approval.approvalsRequired,
          createdAt: approval.createdAt,
          expiresAt: approval.expiresAt,
          classification: {
            class: approval.classification.class,
            effects: [...approval.classification.effects],
            permissions: [...approval.classification.permissions],
          },
        })
        .returning();
      return record;
    },

    async findById(realmId, id, tx) {
      if (!isAdminRecordId(realmId) || !isAdminRecordId(id)) return undefined;
      const [record] = await (tx ?? defaultDb)
        .select()
        .from(adminApprovals)
        .where(and(eq(adminApprovals.realmId, realmId), eq(adminApprovals.id, id)))
        .limit(1);
      return record;
    },

    async addApproval(realmId, id, { expectedCount, entry, now }, tx) {
      if (!isAdminRecordId(realmId) || !isAdminRecordId(id)) return undefined;
      const stored: AdminApprovalEntry = {
        approverRealmId: entry.approverRealmId,
        approverId: entry.approverId,
        credentialId: entry.credentialId,
        factor: entry.factor,
        approvedAt: entry.approvedAt,
      };
      const sameApprover = JSON.stringify([
        { approverRealmId: entry.approverRealmId, approverId: entry.approverId },
      ]);
      const [record] = await (tx ?? defaultDb)
        .update(adminApprovals)
        .set({
          approvals: sql`${adminApprovals.approvals} || ${JSON.stringify([stored])}::jsonb`,
          status: sql`case when jsonb_array_length(${adminApprovals.approvals}) + 1 >= ${adminApprovals.approvalsRequired} then 'approved' else 'pending' end`,
        })
        .where(
          and(
            openApproval(realmId, id, now),
            eq(adminApprovals.status, 'pending'),
            holds(expectedCount),
            sql`not (${adminApprovals.approvals} @> ${sameApprover}::jsonb)`
          )
        )
        .returning();
      return record;
    },

    async deny(realmId, id, { expectedCount, now }, tx) {
      if (!isAdminRecordId(realmId) || !isAdminRecordId(id)) return undefined;
      const [record] = await (tx ?? defaultDb)
        .update(adminApprovals)
        .set({ status: 'denied', canonicalRequest: withoutBody })
        .where(
          and(
            openApproval(realmId, id, now),
            eq(adminApprovals.status, 'pending'),
            holds(expectedCount)
          )
        )
        .returning();
      return record;
    },

    async cancel(realmId, id, { requesterRealmId, requesterId, expected, now }, tx) {
      if (!isAdminRecordId(realmId) || !isAdminRecordId(id)) return undefined;
      if (expected.status !== 'pending' && expected.status !== 'approved') return undefined;
      const [record] = await (tx ?? defaultDb)
        .update(adminApprovals)
        .set({ status: 'cancelled', canonicalRequest: withoutBody })
        .where(
          and(
            openApproval(realmId, id, now),
            inArray(adminApprovals.status, ['pending', 'approved']),
            eq(adminApprovals.status, expected.status),
            holds(expected.approvalCount),
            eq(adminApprovals.requesterRealmId, requesterRealmId),
            eq(adminApprovals.requesterId, requesterId)
          )
        )
        .returning();
      return record;
    },

    async consume(realmId, id, { requestHash, now }, tx) {
      if (!isAdminRecordId(realmId) || !isAdminRecordId(id)) return undefined;
      const [record] = await tx
        .update(adminApprovals)
        .set({ status: 'consumed', usedAt: now, canonicalRequest: withoutBody })
        .where(
          and(
            openApproval(realmId, id, now),
            eq(adminApprovals.status, 'approved'),
            eq(adminApprovals.requestHash, requestHash)
          )
        )
        .returning();
      return record;
    },
  };
}
