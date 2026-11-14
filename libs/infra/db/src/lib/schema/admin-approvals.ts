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
 * was never used is expired, whatever its stored status says: every write is
 * conditional on the time, and the expiry sweep stores `expired` on it within
 * a minute or so.
 *
 * - `pending` — waiting for approvals.
 * - `approved` — every approval it needs is in; the operation may use it once.
 * - `denied` — an approver declined it.
 * - `cancelled` — the requester withdrew it.
 * - `consumed` — the operation ran on it (`used_at`).
 * - `expired` — it stopped counting unused: the expiry sweep found it past
 *   `expires_at`, or migration 0054 retired it.
 */
export const ADMIN_APPROVAL_STATUSES = [
  'pending',
  'approved',
  'denied',
  'cancelled',
  'consumed',
  'expired',
] as const;

/** The statuses of an approval that is still open: it may still be approved or used. */
export const ADMIN_APPROVAL_OPEN_STATUSES = ['pending', 'approved'] as const;

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
  /**
   * Who made the approver an admin of the realm, as the two-admin rule read
   * it when the approval was given (#521): the account that created the grant
   * it approved through, or `null` when the operator CLI or QAuth did, or
   * that account is gone. The admin events show it, since the rule binds
   * accounts, not people. Absent on an approval given before #521.
   */
  readonly approverCreatedBy?: string | null;
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

/** A line of an approval's display data. */
export interface AdminApprovalDisplayField {
  readonly label: string;
  readonly value: string;
  readonly before?: string;
}

/**
 * What an approver is shown of an approval, as the approval engine rendered
 * it when the approval was filed (`apps/auth-server/src/app/admin/approvals/display.ts`):
 * typed display data, every string already under the display rules of
 * ADR-019 Decision 6. The operation's renderer never shows a secret value of
 * the request, so it holds none.
 */
export interface AdminApprovalDisplay {
  readonly operation: string;
  readonly title: string;
  readonly fields: readonly AdminApprovalDisplayField[];
  readonly reason: {
    readonly type: 'quote';
    readonly source: 'requester';
    readonly text: string;
  } | null;
}

const sqlList = (values: readonly string[]) =>
  sql.raw(values.map((value) => `'${value}'`).join(', '));

/**
 * Approval requests for security operations (ADR-019 Decision 7, issue #512).
 *
 * A security operation runs only with a fresh approval bound to that exact
 * operation. The requester files one with the operation it wants to run; the
 * server draws a `nonce` and stores `op_hash`, the SHA-256 of the canonical
 * request (operation id, method, path parameters, query, body, realm and
 * requester, RFC 8785) with that nonce. The admin pipeline computes the
 * `op_hash` of the retried call with the stored nonce and compares the two,
 * and the challenge an approver's factor signs is derived from it, so one
 * approval cannot be moved to another request.
 *
 * The row never holds the operation's body, which may hold a secret (#901):
 * it keeps the method, path parameters and query, and `display`, what an
 * approver is shown, which the operation's renderer made from the request
 * when it was filed and which holds no secret. Nor does it hold a hash of the
 * request without the nonce. Once an approval is consumed, cancelled, denied
 * or expired, its nonce is overwritten with random bytes, so neither `op_hash`
 * nor the audit log's copy of it (`request_digest`) can be tested against a
 * guessed body any more.
 *
 * The approvals collected sit in `approvals`. Once there are
 * `approvals_required` of them the status is `approved`, and the retried
 * operation consumes it, once, with a conditional `UPDATE … WHERE status =
 * 'approved'` in its own transaction: a rolled-back operation leaves it
 * approved, and two concurrent retries cannot both use it. Every approval
 * expires `expires_at`, five minutes after it was filed. No job removes
 * approvals.
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
    /** The operation's method, upper case, as HTTP names it. */
    method: varchar('method', { length: 16 }).notNull(),
    /** The operation's path parameters, `realmId` included, as its route parsed them. */
    params: jsonb('params').$type<Record<string, unknown>>().notNull(),
    /** The operation's query, as its route parsed it. */
    query: jsonb('query').$type<Record<string, unknown>>().notNull(),
    /**
     * What an approver is shown, rendered when the approval was filed. Never
     * `null` while the approval is open; `null` only on one migration 0054
     * retired, filed before the server stored it.
     */
    display: jsonb('display').$type<AdminApprovalDisplay>(),
    /** SHA-256 of the RFC 8785 form of the canonical request with the nonce. */
    opHash: bytea('op_hash').notNull(),
    /**
     * 32 random bytes the server drew when the approval was filed; once the
     * approval is closed or expired, 32 other random bytes.
     */
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
    // The expiry sweep's scan: the open approvals, by expiry.
    index('idx_admin_approvals_open_expiry')
      .on(t.expiresAt)
      .where(sql`${t.status} in (${sqlList(ADMIN_APPROVAL_OPEN_STATUSES)})`),
    check(
      'admin_approvals_requester_kind',
      sql`${t.requesterKind} in (${sqlList(ADMIN_APPROVAL_REQUESTER_KINDS)})`
    ),
    check('admin_approvals_status', sql`${t.status} in (${sqlList(ADMIN_APPROVAL_STATUSES)})`),
    check('admin_approvals_operation_id_not_empty', sql`${t.operationId} <> ''`),
    check('admin_approvals_method_not_empty', sql`${t.method} <> ''`),
    check('admin_approvals_params_object', sql`jsonb_typeof(${t.params}) = 'object'`),
    check('admin_approvals_query_object', sql`jsonb_typeof(${t.query}) = 'object'`),
    check(
      'admin_approvals_display_object',
      sql`${t.display} is null or jsonb_typeof(${t.display}) = 'object'`
    ),
    // An open approval always has what its approver is shown.
    check(
      'admin_approvals_open_has_display',
      sql`${t.status} not in (${sqlList(ADMIN_APPROVAL_OPEN_STATUSES)}) or ${t.display} is not null`
    ),
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
