import { sql } from 'drizzle-orm';
import { bigint, check, index, jsonb, pgTable, smallint, uuid, varchar } from 'drizzle-orm/pg-core';

import { realms, users } from './core';
import { bytea, JSONB_EMPTY_ARRAY } from './sql-helpers';

/**
 * Who filed an approval request (ADR-019 Decision 7, issue #512):
 *
 * - `human` — an admin account. Its own fresh step-up is the first approval.
 * - `service_account` — an operator-realm service account (#522). It has no
 *   passkey, so a human admin approves in its place.
 */
export const ADMIN_APPROVAL_REQUESTER_KINDS = ['human', 'service_account'] as const;

export type AdminApprovalRequesterKind = (typeof ADMIN_APPROVAL_REQUESTER_KINDS)[number];

/**
 * Where an approval stands, as stored. An approval past `expires_at` that
 * was never used is expired, whatever its stored status says: no job rewrites
 * it, and every write is conditional on the time.
 *
 * - `pending` — waiting for approvals.
 * - `approved` — every approval it needs is in; the operation may use it once.
 * - `denied` — an approver declined it.
 * - `cancelled` — the requester withdrew it.
 * - `consumed` — the operation ran on it (`used_at`).
 */
export const ADMIN_APPROVAL_STATUSES = [
  'pending',
  'approved',
  'denied',
  'cancelled',
  'consumed',
] as const;

export type AdminApprovalStatus = (typeof ADMIN_APPROVAL_STATUSES)[number];

/** The most approvals one request can need: the requester's own, and a second admin's. */
export const ADMIN_APPROVALS_REQUIRED_MAX = 2;

/** The longest reason a requester may give. */
export const ADMIN_APPROVAL_REASON_MAX_LENGTH = 500;

/**
 * One approval an approval request collected: who gave it, with which
 * credential of which factor, and when.
 */
export interface AdminApprovalEntry {
  /** The realm the approver's account lives in. */
  readonly approverRealmId: string;
  /** The approver's account id. */
  readonly approverId: string;
  /** The factor's id of the credential the approval was given with, such as a passkey's. */
  readonly credentialId: string;
  /** The factor that verified it, such as `webauthn`. */
  readonly factor: string;
  /** When it was given, in epoch milliseconds. */
  readonly approvedAt: number;
}

/**
 * What the operation an approval is for needs, as the operation registry
 * declared it when the approval was filed: the admin audit rows of the
 * approval record its class and effects.
 */
export interface AdminApprovalClassification {
  readonly class: 'read' | 'write' | 'security';
  readonly effects: readonly string[];
  readonly permissions: readonly string[];
}

const sqlList = (values: readonly string[]) =>
  sql.raw(values.map((value) => `'${value}'`).join(', '));

/**
 * Approval requests for security operations (ADR-019 Decision 7, issue #512).
 *
 * A security operation runs only with a fresh approval bound to that exact
 * operation. The requester files one with the operation it wants to run; the
 * server stores the canonical request (operation id, method, path parameters,
 * query, body, realm and requester, RFC 8785) and two SHA-256 digests of it:
 * `request_hash` without the server's `nonce`, which the admin pipeline
 * recomputes from the retried call and compares, and `op_hash` with it, which
 * the challenge an approver's factor signs is derived from, so one approval
 * cannot be moved to another request.
 *
 * The approvals collected sit in `approvals`. Once there are
 * `approvals_required` of them the status is `approved`, and the retried
 * operation consumes it, once, with a conditional `UPDATE … WHERE status =
 * 'approved'` in its own transaction: a rolled-back operation leaves it
 * approved, and two concurrent retries cannot both use it. Every approval
 * expires `expires_at`, five minutes after it was filed.
 *
 * The canonical request holds the operation's body as the requester sent it,
 * so it holds whatever that body holds.
 */
export const adminApprovals = pgTable(
  'admin_approvals',
  {
    /** Random (UUID v4), so an id cannot be guessed from another. */
    id: uuid('id')
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    /** The realm the operation acts on. */
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    requesterKind: varchar('requester_kind', { length: 32 })
      .$type<AdminApprovalRequesterKind>()
      .notNull(),
    /** The realm the requester's account lives in: the operator realm or the target realm. */
    requesterRealmId: uuid('requester_realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** The requester's account. */
    requesterId: uuid('requester_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    /** The operation id in the admin operation registry, such as `keys.rotate`. */
    operationId: varchar('operation_id', { length: 128 }).notNull(),
    /** The canonical request without the nonce, as a JSON object. */
    canonicalRequest: jsonb('canonical_request').$type<Record<string, unknown>>().notNull(),
    /** SHA-256 of the RFC 8785 form of the canonical request, without the nonce. */
    requestHash: bytea('request_hash').notNull(),
    /** SHA-256 of the RFC 8785 form of the canonical request with the nonce. */
    opHash: bytea('op_hash').notNull(),
    /** 32 random bytes the server drew when the approval was filed. */
    nonce: bytea('nonce').notNull(),
    /** The requester's reason, shown to an approver as quoted text only. */
    reason: varchar('reason', { length: ADMIN_APPROVAL_REASON_MAX_LENGTH }),
    /** What the operation needs, as the registry declared it when the approval was filed. */
    classification: jsonb('classification').$type<AdminApprovalClassification>().notNull(),
    /** How many approvals the operation needs: 1, or 2 where a second admin is required. */
    approvalsRequired: smallint('approvals_required').notNull(),
    /** The approvals collected, oldest first. */
    approvals: jsonb('approvals')
      .$type<AdminApprovalEntry[]>()
      .notNull()
      .default(JSONB_EMPTY_ARRAY),
    status: varchar('status', { length: 16 })
      .$type<AdminApprovalStatus>()
      .notNull()
      .default('pending'),
    /** Epoch milliseconds, by the server's clock, as every time of an approval. */
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
    /** When the approval stops counting, used or not. */
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    /** When the operation consumed it; `null` until then. */
    usedAt: bigint('used_at', { mode: 'number' }),
  },
  (t) => [
    index('idx_admin_approvals_realm_created').on(t.realmId, t.createdAt),
    index('idx_admin_approvals_requester').on(t.requesterId),
    check(
      'admin_approvals_requester_kind',
      sql`${t.requesterKind} in (${sqlList(ADMIN_APPROVAL_REQUESTER_KINDS)})`
    ),
    check('admin_approvals_status', sql`${t.status} in (${sqlList(ADMIN_APPROVAL_STATUSES)})`),
    check('admin_approvals_operation_id_not_empty', sql`${t.operationId} <> ''`),
    check(
      'admin_approvals_canonical_request_object',
      sql`jsonb_typeof(${t.canonicalRequest}) = 'object'`
    ),
    check('admin_approvals_request_hash_sha256', sql`octet_length(${t.requestHash}) = 32`),
    check('admin_approvals_op_hash_sha256', sql`octet_length(${t.opHash}) = 32`),
    check('admin_approvals_nonce_length', sql`octet_length(${t.nonce}) = 32`),
    check('admin_approvals_reason_not_empty', sql`${t.reason} is null or ${t.reason} <> ''`),
    check(
      'admin_approvals_classification_object',
      sql`jsonb_typeof(${t.classification}) = 'object'`
    ),
    check(
      'admin_approvals_required_range',
      sql`${t.approvalsRequired} between 1 and ${sql.raw(String(ADMIN_APPROVALS_REQUIRED_MAX))}`
    ),
    check(
      'admin_approvals_approvals_array',
      sql`jsonb_typeof(${t.approvals}) = 'array' and jsonb_array_length(${t.approvals}) <= ${t.approvalsRequired}`
    ),
    // An approved or used approval has every approval it needs; a pending one
    // lacks at least one.
    check(
      'admin_approvals_status_matches_approvals',
      sql`(${t.status} not in ('approved', 'consumed') or jsonb_array_length(${t.approvals}) = ${t.approvalsRequired}) and (${t.status} <> 'pending' or jsonb_array_length(${t.approvals}) < ${t.approvalsRequired})`
    ),
    check('admin_approvals_expires_after_created', sql`${t.expiresAt} > ${t.createdAt}`),
    check(
      'admin_approvals_used_exactly_when_consumed',
      sql`(${t.status} = 'consumed') = (${t.usedAt} is not null)`
    ),
  ]
);
