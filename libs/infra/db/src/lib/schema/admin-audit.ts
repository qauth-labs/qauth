import { sql } from 'drizzle-orm';
import { bigint, check, jsonb, pgTable, primaryKey, uuid, varchar } from 'drizzle-orm/pg-core';

import type { AdminAuditActChain, AdminAuditApproval, AdminAuditDiff } from '../admin-audit/types';
import { adminActorKindEnum, adminAuditOutcomeEnum, adminOperationClassEnum } from './enums';
import { bytea, EPOCH_MS_NOW } from './sql-helpers';

/**
 * The admin audit log (ADR-019 Decision 7, ADR-020 §3, issue #448).
 *
 * Every admin operation writes one row, in the transaction of the change it
 * records (`appendAdminAudit`). There is one hash chain per target realm:
 * `seq` counts from 1 without a gap, and `row_hash` is SHA-256 over
 * `prev_hash` and the RFC 8785 canonical JSON of the row's other columns
 * (`computeAdminAuditRowHash`). The first row's `prev_hash` is 32 zero bytes.
 *
 * ## What the chain shows
 *
 * A row changed or removed in place breaks the chain at that row or the next,
 * and `verifyAdminAuditChain` reports where. The hash is unkeyed, so whoever
 * can rewrite a row and every row after it, or cut the newest rows, leaves a
 * chain that verifies; only a copy of the head kept outside the database, such
 * as the event that mirrors each row with its `seq` and `row_hash`, shows that.
 *
 * ## Append-only
 *
 * Hand-written triggers in migration 0026 hold for every role whose
 * statements fire them: an inserted row must follow its realm's chain head, no
 * row is updated, neither table is truncated, and a row is deleted only when a
 * checkpoint covers it. A checkpoint ({@link adminAuditLogCheckpoints}) is
 * accepted only for a row still in the log, with its hash, over an unbroken
 * run of rows at least 90 days old. The retention job writes it through the
 * guarded function `admin_audit_log_prune(realm_id, through_seq)`, which
 * deletes the realm's oldest rows up to that `seq` once the checkpoint is in.
 * A table owner or a superuser can still disable a trigger; the per-role
 * grants (#498) keep the application from being either. A role that writes
 * the log is granted `INSERT` and `SELECT` only
 * (`adminAuditLogWriterGrantStatements`).
 *
 * ## No foreign keys
 *
 * `realm_id` and `actor_realm_id` reference no table: the record of a realm's
 * deletion, and every row before it, must outlive the realm row.
 *
 * ## No secrets
 *
 * `masked_diff` is stored only after `maskSecrets`; a secret field holds the
 * marker, never a value. No set-up or reset link, code or token enters a row.
 */
export const adminAuditLog = pgTable(
  'admin_audit_log',
  {
    /** The realm the operation targeted: the chain the row belongs to. */
    realmId: uuid('realm_id').notNull(),
    /** Position in the realm's chain, from 1, without a gap. */
    seq: bigint('seq', { mode: 'number' }).notNull(),
    /** `row_hash` of the row before, or of the last pruned row, or 32 zero bytes. */
    prevHash: bytea('prev_hash').notNull(),
    /** SHA-256 over `prev_hash` and the canonical JSON of the other columns. */
    rowHash: bytea('row_hash').notNull(),
    actorKind: adminActorKindEnum('actor_kind').notNull(),
    /**
     * The actor: an account id for a human admin, a `client_id` for a service
     * account, the operating-system user for the break-glass CLI or a host
     * tool.
     */
    actorId: varchar('actor_id', { length: 255 }).notNull(),
    /**
     * The realm the actor's account lives in (the operator realm, or the target
     * realm for a realm-local admin). `null` exactly for the host-side kinds.
     */
    actorRealmId: uuid('actor_realm_id'),
    /** The full act chain when the actor acted for a user; `null` otherwise. */
    actChain: jsonb('act_chain').$type<AdminAuditActChain | null>(),
    /** The permission catalog id of the operation, such as `realms.policies.write`. */
    operationId: varchar('operation_id', { length: 128 }).notNull(),
    /** The operation's class: `read`, `write` or `security`. */
    operationClass: adminOperationClassEnum('operation_class').notNull(),
    /** The effects that make the operation what it is (ADR-019 Decision 7), as ids. */
    effects: jsonb('effects').$type<string[]>().notNull(),
    outcome: adminAuditOutcomeEnum('outcome').notNull(),
    /** The change, with every secret field masked; `null` when nothing changed. */
    maskedDiff: jsonb('masked_diff').$type<AdminAuditDiff | null>(),
    /** The approvals the operation ran on, both of a two-admin operation. */
    approvals: jsonb('approvals').$type<AdminAuditApproval[]>().notNull(),
    /** SHA-256 of the canonical request, the hash an approval is bound to. */
    requestDigest: bytea('request_digest'),
    /** The id under which QAuth logged the request. */
    traceId: varchar('trace_id', { length: 128 }),
    /** Epoch milliseconds, set by the writer because the hash covers it. */
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
  },
  (t) => [
    primaryKey({ name: 'admin_audit_log_pk', columns: [t.realmId, t.seq] }),
    check('admin_audit_log_seq_positive', sql`${t.seq} >= 1`),
    check('admin_audit_log_prev_hash_sha256', sql`octet_length(${t.prevHash}) = 32`),
    check('admin_audit_log_row_hash_sha256', sql`octet_length(${t.rowHash}) = 32`),
    check(
      'admin_audit_log_first_row_genesis',
      sql`${t.seq} <> 1 or ${t.prevHash} = decode(repeat('00', 32), 'hex')`
    ),
    check(
      'admin_audit_log_request_digest_sha256',
      sql`${t.requestDigest} is null or octet_length(${t.requestDigest}) = 32`
    ),
    check('admin_audit_log_actor_id_not_empty', sql`${t.actorId} <> ''`),
    check(
      'admin_audit_log_actor_realm_matches_kind',
      sql`(${t.actorKind} in ('human_admin', 'service_account')) = (${t.actorRealmId} is not null)`
    ),
    check('admin_audit_log_operation_id_not_empty', sql`${t.operationId} <> ''`),
    check(
      'admin_audit_log_act_chain_shape',
      sql`${t.actChain} is null or (jsonb_typeof(${t.actChain}) = 'object' and ${t.actChain} ? 'sub' and jsonb_typeof(${t.actChain} -> 'act') = 'object')`
    ),
    check('admin_audit_log_effects_is_array', sql`jsonb_typeof(${t.effects}) = 'array'`),
    check(
      'admin_audit_log_masked_diff_shape',
      sql`${t.maskedDiff} is null or (jsonb_typeof(${t.maskedDiff}) = 'object' and ${t.maskedDiff} ? 'before' and ${t.maskedDiff} ? 'after')`
    ),
    check('admin_audit_log_approvals_is_array', sql`jsonb_typeof(${t.approvals}) = 'array'`),
  ]
);

/**
 * Where a realm's chain resumes after a prune (issue #448).
 *
 * `admin_audit_log_prune` writes one row per prune, in the transaction that
 * deletes the rows: the `seq` and `row_hash` of the last row it removed. The
 * oldest retained row must then have `seq + 1` and that hash as its
 * `prev_hash`; a row removed any other way leaves no checkpoint, so
 * verification reports the gap. A trigger accepts a checkpoint only over an
 * unbroken run of rows at least 90 days old. Append-only like the log itself,
 * and no role that writes the log is granted `INSERT` here.
 */
export const adminAuditLogCheckpoints = pgTable(
  'admin_audit_log_checkpoints',
  {
    realmId: uuid('realm_id').notNull(),
    /** `seq` of the last pruned row. */
    seq: bigint('seq', { mode: 'number' }).notNull(),
    /** `row_hash` of the last pruned row. */
    rowHash: bytea('row_hash').notNull(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    primaryKey({ name: 'admin_audit_log_checkpoints_pk', columns: [t.realmId, t.seq] }),
    check('admin_audit_log_checkpoints_seq_positive', sql`${t.seq} >= 1`),
    check('admin_audit_log_checkpoints_row_hash_sha256', sql`octet_length(${t.rowHash}) = 32`),
  ]
);
