import { and, eq, inArray, type InferSelectModel, lte, sql } from 'drizzle-orm';

import type { DbClient } from '../../types';
import {
  ADMIN_APPROVAL_OPEN_STATUSES,
  type AdminApprovalClassification,
  type AdminApprovalDisplay,
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
  /** The operation's method, upper case. */
  readonly method: string;
  /** The operation's path parameters, `realmId` included. */
  readonly params: Record<string, unknown>;
  readonly query: Record<string, unknown>;
  /** What an approver is shown, rendered from the request as it was filed. */
  readonly display: AdminApprovalDisplay;
  /** SHA-256 of the canonical request with `nonce`; the body is bound only through it. */
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
 * #512). Every write takes the approval's row lock, then makes one
 * conditional `UPDATE … RETURNING` that names the state it moves from: it
 * returns the row it changed, or `undefined` when the approval is not in that
 * state any more, has expired, or is not the one named. So two writers that
 * race cannot both move one approval, and a write that rolls back moves
 * nothing. A write given no transaction runs in one of its own.
 *
 * The expiry is checked once the row is held, at the later of the caller's
 * `now` and the database's clock: a write that waited on the row, for a
 * writer that then rolled back, moves nothing that expired while it waited.
 *
 * Who may make each write is the approval engine's to decide
 * (`apps/auth-server/src/app/admin/approvals`); the repository only keeps
 * the moves consistent.
 *
 * The row holds no body of the operation, nor a hash of the request without
 * the nonce (#901). A move that closes an approval (consumed, cancelled,
 * denied), and the expiry sweep ({@link AdminApprovalsRepository.expireLapsed}),
 * overwrite its nonce with random bytes in the same `UPDATE`: once no approval
 * can be given or used, the stored `op_hash`, and the audit log's copy of it,
 * can no longer be tested against a guessed body. No job removes approvals.
 */
export interface AdminApprovalsRepository {
  /** File an approval request, `pending`, with no approval yet. */
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
   * Use an `approved`, unexpired approval for the request whose `op_hash`,
   * computed with the approval's nonce, is `opHash`: it becomes `consumed`,
   * with `used_at`. Run it in the transaction of the operation, so the
   * operation's rollback takes the consumption back with it.
   */
  consume(
    realmId: string,
    id: string,
    change: { readonly opHash: Buffer; readonly now: number },
    tx: DbClient
  ): Promise<AdminApproval | undefined>;

  /**
   * Mark `expired`, with a fresh random nonce, at most `limit` open approvals
   * (`pending` or `approved`) of any realm that expired by `now`. An approval
   * another transaction holds is skipped, and found again by the next call.
   *
   * @returns how many it marked
   */
  expireLapsed(now: number, limit: number): Promise<number>;
}

/** The row of one approval of the realm. */
function approvalRow(realmId: string, id: string) {
  return and(eq(adminApprovals.realmId, realmId), eq(adminApprovals.id, id));
}

/**
 * The time a write checks the expiry at, in epoch milliseconds: the later of
 * the caller's `now` and the database's clock as the check runs. The caller
 * samples `now` before the write may wait on the row. `clock_timestamp()`,
 * since `now()` is when the transaction began, which an operation's
 * transaction may be long before its write.
 */
const checkedAt = (now: number) =>
  sql`greatest(${now}::bigint, floor(extract(epoch from clock_timestamp()) * 1000)::bigint)`;

/**
 * The row of one approval of the realm, and only while it is unexpired at
 * {@link checkedAt}. Run it only on a row the transaction holds
 * ({@link lockApproval}).
 */
function openApproval(realmId: string, id: string, now: number) {
  return and(approvalRow(realmId, id), sql`${adminApprovals.expiresAt} > ${checkedAt(now)}`);
}

/**
 * Take the row lock of one approval of the realm in `tx`, waiting for a
 * writer that holds it. PostgreSQL evaluates an `UPDATE`'s condition before
 * it waits on a row, and evaluates it again only when the holder commits: one
 * that rolls back leaves the waiter to write on the condition it read before
 * the wait, an expiry check included. Taken first, the lock puts the wait
 * before the conditional `UPDATE`, whose check then runs on the held row.
 *
 * @returns whether the approval exists
 */
async function lockApproval(tx: DbClient, realmId: string, id: string): Promise<boolean> {
  const [row] = await tx
    .select({ id: adminApprovals.id })
    .from(adminApprovals)
    .where(approvalRow(realmId, id))
    .for('no key update');
  return row !== undefined;
}

/** The approval holds exactly `count` approvals. */
const holds = (count: number) => sql`jsonb_array_length(${adminApprovals.approvals}) = ${count}`;

/**
 * 32 random bytes, a fresh value on each row an `UPDATE` sets it on: the
 * nonce of an approval that is closed or expired (#901). The SHA-256 of two
 * random (v4) UUIDs, 244 random bits; the nonce only has to stop being the
 * one `op_hash` was computed with, and no guess of it can be checked against
 * anything.
 */
const retiredNonce = sql`sha256(convert_to(gen_random_uuid()::text || gen_random_uuid()::text, 'UTF8'))`;

/**
 * Factory for the approval request repository (issue #512).
 *
 * @param defaultDb - The database a call without a transaction runs on.
 */
export function createAdminApprovalsRepository(defaultDb: DbClient): AdminApprovalsRepository {
  /**
   * Run `write` once its transaction holds the approval's row
   * ({@link lockApproval}): in `tx`, or in a transaction of its own, so the
   * lock lasts until the write has run.
   */
  function onHeldRow<T>(
    realmId: string,
    id: string,
    tx: DbClient | undefined,
    write: (invoker: DbClient) => Promise<T | undefined>
  ): Promise<T | undefined> {
    const run = async (invoker: DbClient) =>
      (await lockApproval(invoker, realmId, id)) ? write(invoker) : undefined;
    return tx ? run(tx) : defaultDb.transaction((innerTx) => run(innerTx));
  }

  return {
    async create(approval, tx) {
      const [record] = await (tx ?? defaultDb)
        .insert(adminApprovals)
        // The fields a new approval has, named one by one: its id, status,
        // approvals and time of use are the table's, never the caller's.
        .values({
          realmId: approval.realmId,
          requesterKind: approval.requesterKind,
          requesterRealmId: approval.requesterRealmId,
          requesterId: approval.requesterId,
          operationId: approval.operationId,
          method: approval.method,
          params: approval.params,
          query: approval.query,
          display: approval.display,
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
      return onHeldRow(realmId, id, tx, async (invoker) => {
        const [record] = await invoker
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
      });
    },

    async deny(realmId, id, { expectedCount, now }, tx) {
      if (!isAdminRecordId(realmId) || !isAdminRecordId(id)) return undefined;
      return onHeldRow(realmId, id, tx, async (invoker) => {
        const [record] = await invoker
          .update(adminApprovals)
          .set({ status: 'denied', nonce: retiredNonce })
          .where(
            and(
              openApproval(realmId, id, now),
              eq(adminApprovals.status, 'pending'),
              holds(expectedCount)
            )
          )
          .returning();
        return record;
      });
    },

    async cancel(realmId, id, { requesterRealmId, requesterId, expected, now }, tx) {
      if (!isAdminRecordId(realmId) || !isAdminRecordId(id)) return undefined;
      if (expected.status !== 'pending' && expected.status !== 'approved') return undefined;
      return onHeldRow(realmId, id, tx, async (invoker) => {
        const [record] = await invoker
          .update(adminApprovals)
          .set({ status: 'cancelled', nonce: retiredNonce })
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
      });
    },

    async consume(realmId, id, { opHash, now }, tx) {
      if (!isAdminRecordId(realmId) || !isAdminRecordId(id)) return undefined;
      return onHeldRow(realmId, id, tx, async (invoker) => {
        const [record] = await invoker
          .update(adminApprovals)
          .set({ status: 'consumed', usedAt: now, nonce: retiredNonce })
          .where(
            and(
              openApproval(realmId, id, now),
              eq(adminApprovals.status, 'approved'),
              eq(adminApprovals.opHash, opHash)
            )
          )
          .returning();
        return record;
      });
    },

    async expireLapsed(now, limit) {
      // The rows are claimed with SKIP LOCKED: one an operation's transaction
      // holds may yet be consumed, if it is unexpired by the time that
      // transaction checks it, and is left for the next call. A claimed row
      // is held until the update, so no writer moves it in between; and every
      // writer's own condition refuses an expired approval anyway.
      const lapsed = defaultDb
        .select({ id: adminApprovals.id })
        .from(adminApprovals)
        .where(
          and(
            inArray(adminApprovals.status, [...ADMIN_APPROVAL_OPEN_STATUSES]),
            lte(adminApprovals.expiresAt, checkedAt(now))
          )
        )
        .orderBy(adminApprovals.expiresAt)
        .limit(limit)
        .for('update', { skipLocked: true });
      const marked = await defaultDb
        .update(adminApprovals)
        .set({ status: 'expired', nonce: retiredNonce })
        .where(
          and(
            inArray(adminApprovals.id, lapsed),
            inArray(adminApprovals.status, [...ADMIN_APPROVAL_OPEN_STATUSES])
          )
        )
        .returning({ id: adminApprovals.id });
      return marked.length;
    },
  };
}
