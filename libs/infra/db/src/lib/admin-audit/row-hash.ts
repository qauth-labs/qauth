import { createHash } from 'node:crypto';

import type { AdminAuditRecord } from '../../types';
import { canonicalizeJson } from './canonical-json';

/** A row's content: every column but the two hashes. */
export type AdminAuditRowContent = Omit<AdminAuditRecord, 'prevHash' | 'rowHash'>;

/** `prev_hash` of a realm's first row: 32 zero bytes. */
export const ADMIN_AUDIT_GENESIS_HASH: Buffer = Buffer.alloc(32);

/**
 * The object a row's hash covers: every column but `prev_hash` and
 * `row_hash`, under its column name, with `null` for an empty column. The
 * column names make the hash checkable from the table alone; `bytea` is
 * lowercase hex and a `uuid` its lowercase text form, as Postgres prints them.
 *
 * Changing this shape changes every hash, so it is version 1 of the chain
 * format and a unit test pins it to the table's columns.
 */
export function adminAuditHashPayload(row: AdminAuditRowContent): Record<string, unknown> {
  return {
    realm_id: row.realmId,
    seq: row.seq,
    actor_kind: row.actorKind,
    actor_id: row.actorId,
    actor_realm_id: row.actorRealmId ?? null,
    act_chain: row.actChain ?? null,
    operation_id: row.operationId,
    operation_class: row.operationClass,
    effects: row.effects,
    outcome: row.outcome,
    masked_diff: row.maskedDiff ?? null,
    approvals: row.approvals,
    request_digest: row.requestDigest ? row.requestDigest.toString('hex') : null,
    trace_id: row.traceId ?? null,
    created_at: row.createdAt,
  };
}

/**
 * A row's `row_hash`: SHA-256 over the 32 bytes of `prev_hash` followed by the
 * UTF-8 bytes of the RFC 8785 canonical JSON of {@link adminAuditHashPayload}.
 *
 * @throws TypeError when a JSON column holds a value outside the I-JSON model.
 */
export function computeAdminAuditRowHash(prevHash: Buffer, row: AdminAuditRowContent): Buffer {
  return createHash('sha256')
    .update(prevHash)
    .update(canonicalizeJson(adminAuditHashPayload(row)), 'utf8')
    .digest();
}
